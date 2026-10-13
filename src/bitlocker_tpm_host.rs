//! Experimental bounded TPM 2.0 policy unsealing over an exclusive command channel.
//!
//! This implements a narrow SHA-256 policy profile, without PIN authorization,
//! salted sessions or transport encryption. The command channel must be
//! trusted and exclusively assigned; never attach it concurrently to QEMU.
//! Initialization, PCR changes and emulator state restoration belong to the
//! caller's lifecycle controller. No command is retried after uncertain completion.
//!
//! Stack evaluation: `tss-esapi` and `tpm2-tss` provide full ESAPI and swtpm TCTI
//! support but require native libtss2. This seven-command profile avoids that native
//! dependency and deliberately omits general TPM functionality. Wire definitions
//! follow the TPM reference implementation and tpm2-tss public types:
//! <https://github.com/microsoft/ms-tpm-20-ref>,
//! <https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h>.
//! swtpm command traffic is raw TPM framing, separate from its control interface:
//! <https://github.com/tpm2-software/tpm2-tss/blob/master/src/tss2-tcti/tcti-swtpm.c>.
use crate::fs_core::{Reservation, Resources};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{fmt, io};
use zeroize::Zeroizing;

const CAPACITY: usize = 4096;
const LOAD: u32 = 0x157;
const START_AUTH_SESSION: u32 = 0x176;
const POLICY_PCR: u32 = 0x17f;
const POLICY_AUTH_VALUE: u32 = 0x16b;
const POLICY_OR: u32 = 0x171;
const UNSEAL: u32 = 0x15e;
const FLUSH_CONTEXT: u32 = 0x165;
const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const NULL_HANDLE: u32 = 0x4000_0007;
const PASSWORD_SESSION: u32 = 0x4000_0009;

/// One synchronous exclusive exchange. Implementations must apply finite
/// deadlines and return exactly one complete TPM response, including its header.
/// Any error is treated as uncertain completion, never as permission to replay.
pub trait CommandTransport {
    /// Transmit once and receive into caller-bounded storage.
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> io::Result<usize>;
}

/// Host-provider failure category, independent of BitLocker key authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Request outside the exact supported profile.
    InvalidInput,
    /// TPM response framing or payload is malformed.
    MalformedResponse,
    /// Command completion is uncertain; the provider cannot be reused.
    Transport,
    /// The TPM rejected the policy or PCR binding.
    PolicyFailed,
    /// The TPM reports dictionary-attack lockout; no retry was attempted.
    Lockout,
    /// Another TPM return code; retained without alteration.
    Tpm,
    /// Caller cancellation before the next bounded operation.
    Cancelled,
    /// Caller scratch/retained memory budget exhausted.
    ResourceLimit,
    /// An earlier uncertain exchange fenced this provider.
    UncertainCompletion,
}
/// Cleanup that could not be completed for a handle allocated by this provider.
#[derive(Clone, Copy, Debug)]
pub struct CleanupIssue {
    /// Transient object or policy-session handle.
    pub handle: u32,
    /// Exact TPM response code, if an intact TPM rejection was received.
    pub response_code: Option<u32>,
}
/// Non-secret diagnostic retaining native return codes and underlying I/O.
#[derive(Debug)]
pub struct Error {
    /// Semantic category.
    pub kind: ErrorKind,
    /// TPM command code; zero when failure preceded command construction.
    pub command: u32,
    /// Exact TPM return code, without truncating handle/session bits.
    pub response_code: Option<u32>,
    /// Transport cause, if any.
    pub source: Option<io::Error>,
    /// Unknown completion or known unflushed transient state needs external cleanup.
    pub cleanup_required: bool,
    /// Known handles whose cleanup failed or was prohibited after uncertainty.
    pub cleanup: [Option<CleanupIssue>; 2],
}
impl Error {
    fn new(kind: ErrorKind, command: u32) -> Self {
        Self {
            kind,
            command,
            response_code: None,
            source: None,
            cleanup_required: false,
            cleanup: [None, None],
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM {:?} during command {:#x}", self.kind, self.command)?;
        if let Some(code) = self.response_code {
            write!(f, " (response {code:#x})")?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}
/// Host unseal result.
pub type Result<T> = std::result::Result<T, Error>;

/// Explicit object, parent and policy inputs. All byte encodings are big-endian
/// TPM wire encodings; the portable BitLocker parser owns envelope interpretation.
pub struct UnsealRequest<'a> {
    /// TPM2B_PRIVATE payload, without its two-byte size prefix.
    pub private: &'a [u8],
    /// TPMT_PUBLIC payload, without the enclosing TPM2B_PUBLIC size prefix.
    pub public: &'a [u8],
    /// Existing persistent storage parent, explicitly chosen by the caller.
    /// Only an empty parent authorization value is supported.
    pub parent_handle: u32,
    /// Fresh caller-provided cryptographic nonce for this invocation.
    pub nonce_caller: &'a [u8; 32],
    /// Complete marshaled TPML_PCR_SELECTION: explicit SHA-1/SHA-256 banks,
    /// nonempty three-byte PCR masks, no duplicate banks.
    pub pcr_selection: &'a [u8],
    /// Expected SHA-256 hash of the selected PCR values, or `None` to let the
    /// TPM calculate its current PCR digest (requires a supplied PolicyOR list).
    /// The final policy digest is checked against the public object before loading.
    pub pcr_digest: Option<&'a [u8; 32]>,
    /// Optional single PolicyOR step with two through eight SHA-256 branch hashes.
    pub policy_or: &'a [[u8; 32]],
    /// Execute PolicyAuthValue before PolicyPCR. Only an empty object authValue
    /// is supported; nonempty PIN or password factors must not be discarded.
    pub policy_auth_value: bool,
}

/// Zeroizing unsealed bytes. The portable engine must validate the BitLocker key
/// record and authenticate the wrapped key chain before exposing a volume reader.
pub struct UnsealedSecret {
    bytes: Zeroizing<Vec<u8>>,
    _reservation: Reservation,
}
impl UnsealedSecret {
    /// Borrow the unsealed payload, bounded to 64 bytes by this profile.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for UnsealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnsealedSecret([REDACTED])")
    }
}

/// Owns command serialization and a sticky fence after uncertain completion.
pub struct Tpm2Provider<T> {
    transport: T,
    poisoned: bool,
}
impl<T: CommandTransport> Tpm2Provider<T> {
    /// Take ownership of an already lifecycle-initialized exclusive transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            poisoned: false,
        }
    }
    /// Whether an uncertain exchange prohibits further traffic, including cleanup.
    pub fn uncertain_completion(&self) -> bool {
        self.poisoned
    }
    /// Release the transport for explicit lifecycle cleanup. This does not erase
    /// an uncertainty obligation or authorize command replay.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Execute Load, a SHA-256 policy session, optional PolicyAuthValue, PolicyPCR,
    /// optional PolicyOR, Unseal,
    /// and cleanup of only the handles allocated here. No Startup/Clear/PCR writes.
    pub fn unseal(
        &mut self,
        request: &UnsealRequest<'_>,
        resources: &Resources,
    ) -> Result<UnsealedSecret> {
        if self.poisoned {
            return Err(Error::new(ErrorKind::UncertainCompletion, 0));
        }
        validate_request(request)?;
        cancelled(resources)?;
        // Include command locals even on builds that do not reuse their stack
        // slots, plus the response and policy/HMAC state.
        let _scratch_charge = resources
            .memory
            .reserve((CAPACITY * 10) as u64)
            .map_err(|_| Error::new(ErrorKind::ResourceLimit, 0))?;
        let retained = resources
            .memory
            .reserve(64)
            .map_err(|_| Error::new(ErrorKind::ResourceLimit, 0))?;
        let mut response = Zeroizing::new([0; CAPACITY]);
        let mut object = None;
        let mut session = None;
        let mut nonce_tpm = [0u8; 32];
        let mut object_name = [0u8; 34];
        let result = (|| {
            let mut command = Command::new(SESSIONS, LOAD);
            command.u32(request.parent_handle)?;
            command.authorization(PASSWORD_SESSION)?;
            command.sized(request.private)?;
            command.sized(request.public)?;
            let n = self.exchange(&mut command, &mut response)?;
            let mut cursor = Cursor::new(&response[10..n], LOAD);
            let handle = cursor.u32()?;
            if handle >> 24 != 0x80 {
                return Err(malformed(LOAD));
            }
            object = Some(handle);
            let parameters = cursor.u32()? as usize;
            let mut parameters = Cursor::new(cursor.take(parameters)?, LOAD);
            let name = parameters.sized()?;
            let digest = Sha256::digest(request.public);
            if name.len() != 34 || name[..2] != [0, 0x0b] || name[2..] != digest[..] {
                return Err(malformed(LOAD));
            }
            object_name.copy_from_slice(name);
            parameters.end()?;
            response_auth(&mut cursor, false)?;
            cancelled(resources)?;

            let mut command = Command::new(NO_SESSIONS, START_AUTH_SESSION);
            command.u32(NULL_HANDLE)?;
            command.u32(NULL_HANDLE)?;
            command.sized(request.nonce_caller)?;
            command.sized(&[])?;
            command.bytes(&[1])?; // TPM_SE_POLICY
            command.u16(0x10)?; // TPM_ALG_NULL symmetric algorithm
            command.u16(0x0b)?; // SHA-256 policy hash
            let n = self.exchange(&mut command, &mut response)?;
            let mut cursor = Cursor::new(&response[10..n], START_AUTH_SESSION);
            let handle = cursor.u32()?;
            if handle >> 24 != 0x03 {
                return Err(malformed(START_AUTH_SESSION));
            }
            session = Some(handle);
            let nonce = cursor.sized()?;
            if nonce.len() != 32 {
                return Err(malformed(START_AUTH_SESSION));
            }
            nonce_tpm.copy_from_slice(nonce);
            cursor.end()?;
            cancelled(resources)?;

            if request.policy_auth_value {
                let mut command = Command::new(NO_SESSIONS, POLICY_AUTH_VALUE);
                command.u32(handle)?;
                self.empty_response(&mut command, &mut response)?;
                cancelled(resources)?;
            }
            let mut command = Command::new(NO_SESSIONS, POLICY_PCR);
            command.u32(handle)?;
            command.sized(request.pcr_digest.map_or(&[][..], |digest| &digest[..]))?;
            command.bytes(request.pcr_selection)?;
            self.empty_response(&mut command, &mut response)?;
            cancelled(resources)?;
            if !request.policy_or.is_empty() {
                let mut command = Command::new(NO_SESSIONS, POLICY_OR);
                command.u32(handle)?;
                command.u32(request.policy_or.len() as u32)?;
                for digest in request.policy_or {
                    command.sized(digest)?;
                }
                self.empty_response(&mut command, &mut response)?;
                cancelled(resources)?;
            }
            let mut command = Command::new(SESSIONS, UNSEAL);
            command.u32(object.ok_or_else(|| malformed(UNSEAL))?)?;
            let mut cp_hash = Sha256::new();
            cp_hash.update(UNSEAL.to_be_bytes());
            cp_hash.update(object_name);
            let cp_hash: [u8; 32] = cp_hash.finalize().into();
            if request.policy_auth_value {
                let auth = session_hmac(&cp_hash, request.nonce_caller, &nonce_tpm, 1)?;
                command.u32(73)?; // handle, nonce32, attributes, HMAC32
                command.u32(handle)?;
                command.sized(request.nonce_caller)?;
                command.bytes(&[1])?;
                command.sized(&auth)?;
            } else {
                command.authorization(handle)?;
            }
            let n = self.exchange(&mut command, &mut response)?;
            let mut cursor = Cursor::new(&response[10..n], UNSEAL);
            let parameters = cursor.u32()? as usize;
            let parameter_bytes = cursor.take(parameters)?;
            let mut parameters = Cursor::new(parameter_bytes, UNSEAL);
            let secret = parameters.sized()?;
            if secret.is_empty() || secret.len() > 64 {
                return Err(malformed(UNSEAL));
            }
            parameters.end()?;
            if request.policy_auth_value {
                let nonce = cursor.sized()?;
                if nonce.len() != 32 || cursor.take(1)? != [1] {
                    return Err(malformed(UNSEAL));
                }
                let auth = cursor.sized()?;
                let mut rp_hash = Sha256::new();
                rp_hash.update(0u32.to_be_bytes());
                rp_hash.update(UNSEAL.to_be_bytes());
                rp_hash.update(parameter_bytes);
                let rp_hash: [u8; 32] = rp_hash.finalize().into();
                let mut hmac =
                    Hmac::<Sha256>::new_from_slice(&[]).map_err(|_| malformed(UNSEAL))?;
                hmac.update(&rp_hash);
                hmac.update(nonce);
                hmac.update(request.nonce_caller);
                hmac.update(&[1]);
                hmac.verify_slice(auth).map_err(|_| malformed(UNSEAL))?;
                cursor.end()?;
            } else {
                response_auth(&mut cursor, true)?;
            }
            let mut bytes = Zeroizing::new(Vec::new());
            bytes
                .try_reserve_exact(secret.len())
                .map_err(|_| Error::new(ErrorKind::ResourceLimit, UNSEAL))?;
            bytes.extend_from_slice(secret);
            cancelled(resources)?;
            Ok(UnsealedSecret {
                bytes,
                _reservation: retained,
            })
        })();
        if result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::MalformedResponse)
        {
            self.poisoned = true;
        }
        // Ignore cancellation only for cleanup of our own already-created handles.
        let mut cleanup = [None, None];
        let mut cleanup_error = None;
        for (i, handle) in [session, object].into_iter().enumerate() {
            let Some(handle) = handle else {
                continue;
            };
            if self.poisoned {
                cleanup[i] = Some(CleanupIssue {
                    handle,
                    response_code: None,
                });
                continue;
            }
            let mut command = Command::new(NO_SESSIONS, FLUSH_CONTEXT);
            let failure = command
                .u32(handle)
                .and_then(|()| self.empty_response(&mut command, &mut response));
            if let Err(error) = failure {
                cleanup[i] = Some(CleanupIssue {
                    handle,
                    response_code: error.response_code,
                });
                if cleanup_error.is_none() {
                    cleanup_error = Some(error);
                }
            }
        }
        self.poisoned |= cleanup.iter().any(Option::is_some);
        match (result, cleanup_error) {
            (Ok(secret), None) => Ok(secret),
            (Err(mut error), _) | (Ok(_), Some(mut error)) => {
                error.cleanup = cleanup;
                error.cleanup_required = self.poisoned || cleanup.iter().any(Option::is_some);
                Err(error)
            }
        }
    }
    fn empty_response(
        &mut self,
        command: &mut Command,
        response: &mut [u8; CAPACITY],
    ) -> Result<()> {
        if self.exchange(command, response)? != 10 {
            self.poisoned = true;
            return Err(malformed(command.code));
        }
        Ok(())
    }
    fn exchange(&mut self, command: &mut Command, response: &mut [u8; CAPACITY]) -> Result<usize> {
        if self.poisoned {
            return Err(Error::new(ErrorKind::UncertainCompletion, command.code));
        }
        let expected_tag = u16::from_be_bytes([command.bytes[0], command.bytes[1]]);
        let n = self
            .transport
            .transact(command.finish(), response)
            .map_err(|source| {
                self.poisoned = true;
                let mut error = Error::new(ErrorKind::Transport, command.code);
                error.source = Some(source);
                error.cleanup_required = true;
                error
            })?;
        if !(10..=CAPACITY).contains(&n)
            || u32::from_be_bytes(
                response[2..6]
                    .try_into()
                    .map_err(|_| malformed(command.code))?,
            ) as usize
                != n
        {
            self.poisoned = true;
            return Err(malformed(command.code));
        }
        let tag = u16::from_be_bytes([response[0], response[1]]);
        let code = u32::from_be_bytes(
            response[6..10]
                .try_into()
                .map_err(|_| malformed(command.code))?,
        );
        if code != 0 {
            if n != 10 || tag != NO_SESSIONS {
                self.poisoned = true;
                return Err(malformed(command.code));
            }
            let kind = if code == 0x921 {
                ErrorKind::Lockout
            } else if matches!(code & 0xbf, 0x9d | 0xa4)
                || matches!(code, 0x127 | 0x128)
                // PolicyPCR returns TPM_RC_VALUE for parameter 1 when its
                // supplied digest differs from the TPM's current PCR digest.
                || (command.code == POLICY_PCR && code == 0x1c4)
            {
                ErrorKind::PolicyFailed
            } else {
                ErrorKind::Tpm
            };
            let mut error = Error::new(kind, command.code);
            error.response_code = Some(code);
            return Err(error);
        }
        if tag != expected_tag {
            self.poisoned = true;
            return Err(malformed(command.code));
        }
        Ok(n)
    }
}
fn session_hmac(hash: &[u8; 32], newer: &[u8], older: &[u8], attributes: u8) -> Result<[u8; 32]> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(&[])
        .map_err(|_| Error::new(ErrorKind::InvalidInput, UNSEAL))?;
    hmac.update(hash);
    hmac.update(newer);
    hmac.update(older);
    hmac.update(&[attributes]);
    Ok(hmac.finalize().into_bytes().into())
}
fn cancelled(resources: &Resources) -> Result<()> {
    resources
        .cancellation
        .check()
        .map_err(|_| Error::new(ErrorKind::Cancelled, 0))
}
fn malformed(command: u32) -> Error {
    Error::new(ErrorKind::MalformedResponse, command)
}
fn validate_request(request: &UnsealRequest<'_>) -> Result<()> {
    let bad = || Error::new(ErrorKind::InvalidInput, 0);
    if request.parent_handle >> 24 != 0x81
        || request.private.is_empty()
        || request.private.len() > 2048
        || request.public.len() != 78
        || request.public[..4] != [0, 8, 0, 0x0b]
        || request.public[8..10] != [0, 32]
        || request.public[42..46] != [0, 0x10, 0, 32]
        || (!request.policy_or.is_empty() && !(2..=8).contains(&request.policy_or.len()))
    {
        return Err(bad());
    }
    let mut cursor = Cursor::new(request.pcr_selection, 0);
    let count = cursor.u32().map_err(|_| bad())?;
    if !(1..=2).contains(&count) {
        return Err(bad());
    }
    let mut previous = 0;
    for _ in 0..count {
        let bank = cursor.u16().map_err(|_| bad())?;
        if !matches!(bank, 4 | 0x0b)
            || bank <= previous
            || cursor.take(1).map_err(|_| bad())? != [3]
        {
            return Err(bad());
        }
        if cursor
            .take(3)
            .map_err(|_| bad())?
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(bad());
        }
        previous = bank;
    }
    cursor.end().map_err(|_| bad())?;
    let mut policy = [0u8; 32];
    if request.policy_auth_value {
        let mut digest = Sha256::new();
        digest.update(policy);
        digest.update(POLICY_AUTH_VALUE.to_be_bytes());
        policy = digest.finalize().into();
    }
    if let Some(pcr_digest) = request.pcr_digest {
        let mut digest = Sha256::new();
        digest.update(policy);
        digest.update(POLICY_PCR.to_be_bytes());
        digest.update(request.pcr_selection);
        digest.update(pcr_digest);
        policy = digest.finalize().into();
        if !request.policy_or.is_empty() && !request.policy_or.contains(&policy) {
            return Err(bad());
        }
    } else if request.policy_or.is_empty() {
        return Err(bad());
    }
    if !request.policy_or.is_empty() {
        let mut digest = Sha256::new();
        digest.update([0u8; 32]);
        digest.update(POLICY_OR.to_be_bytes());
        for branch in request.policy_or {
            digest.update(branch);
        }
        policy = digest.finalize().into();
    }
    if request.public[10..42] != policy {
        return Err(bad());
    }
    Ok(())
}
fn response_auth(cursor: &mut Cursor<'_>, policy: bool) -> Result<()> {
    let nonce = cursor.sized()?;
    if nonce.len() != if policy { 32 } else { 0 }
        || cursor.take(1)? != [1]
        || !cursor.sized()?.is_empty()
    {
        return Err(malformed(cursor.command));
    }
    cursor.end()
}
struct Cursor<'a> {
    bytes: &'a [u8],
    command: u32,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], command: u32) -> Self {
        Self { bytes, command }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let bytes = self.bytes.get(..n).ok_or_else(|| malformed(self.command))?;
        self.bytes = &self.bytes[n..];
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| malformed(self.command))?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| malformed(self.command))?,
        ))
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(malformed(self.command))
        }
    }
}
struct Command {
    bytes: [u8; CAPACITY],
    len: usize,
    code: u32,
}
impl Command {
    fn new(tag: u16, code: u32) -> Self {
        let mut bytes = [0; CAPACITY];
        bytes[..2].copy_from_slice(&tag.to_be_bytes());
        bytes[6..10].copy_from_slice(&code.to_be_bytes());
        Self {
            bytes,
            len: 10,
            code,
        }
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|end| *end <= CAPACITY)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, self.code))?;
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    fn u16(&mut self, n: u16) -> Result<()> {
        self.bytes(&n.to_be_bytes())
    }
    fn u32(&mut self, n: u32) -> Result<()> {
        self.bytes(&n.to_be_bytes())
    }
    fn sized(&mut self, bytes: &[u8]) -> Result<()> {
        self.u16(
            u16::try_from(bytes.len())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, self.code))?,
        )?;
        self.bytes(bytes)
    }
    fn authorization(&mut self, handle: u32) -> Result<()> {
        self.u32(9)?;
        self.u32(handle)?;
        self.u16(0)?;
        self.bytes(&[1])?; // retain the policy session for explicit cleanup
        self.u16(0)
    }
    fn finish(&mut self) -> &[u8] {
        self.bytes[2..6].copy_from_slice(&(self.len as u32).to_be_bytes());
        &self.bytes[..self.len]
    }
}

/// swtpm raw TPM command socket, not the control socket and not the mssim protocol.
/// A timeout covers the complete exchange, including fragmented reads/writes.
#[cfg(unix)]
pub struct UnixCommandTransport {
    stream: std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
    poisoned: bool,
}
#[cfg(unix)]
impl UnixCommandTransport {
    /// Connect to an explicit, exclusively assigned swtpm command endpoint.
    /// The deadline governs command I/O; socket acquisition is a local connect.
    pub fn connect(path: &std::path::Path, timeout: std::time::Duration) -> io::Result<Self> {
        Self::from_stream(std::os::unix::net::UnixStream::connect(path)?, timeout)
    }
    /// Adopt an already connected stream. No handshake or lifecycle command is sent.
    pub fn from_stream(
        stream: std::os::unix::net::UnixStream,
        timeout: std::time::Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero TPM command timeout",
            ));
        }
        stream.set_nonblocking(false)?;
        Ok(Self {
            stream,
            timeout,
            poisoned: false,
        })
    }
    fn remaining(&self, deadline: std::time::Instant) -> io::Result<std::time::Duration> {
        deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TPM command deadline"))
    }
    fn read_exact(&mut self, mut bytes: &mut [u8], deadline: std::time::Instant) -> io::Result<()> {
        use std::io::Read;
        while !bytes.is_empty() {
            self.stream
                .set_read_timeout(Some(self.remaining(deadline)?))?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    bytes = &mut bytes[n..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
#[cfg(unix)]
impl CommandTransport for UnixCommandTransport {
    fn transact(&mut self, mut command: &[u8], response: &mut [u8]) -> io::Result<usize> {
        use std::io::Write;
        if self.poisoned {
            return Err(io::Error::other("uncertain TPM command completion"));
        }
        if command.len() < 10 || command.len() > CAPACITY || response.len() < 10 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let size = u32::from_be_bytes(
            command[2..6]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidInput)?,
        ) as usize;
        if size != command.len()
            || !matches!(
                u16::from_be_bytes([command[0], command[1]]),
                NO_SESSIONS | SESSIONS
            )
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = std::time::Instant::now()
            .checked_add(self.timeout)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let result = (|| {
            while !command.is_empty() {
                self.stream
                    .set_write_timeout(Some(self.remaining(deadline)?))?;
                match self.stream.write(command) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => command = &command[n..],
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            self.read_exact(&mut response[..10], deadline)?;
            let size = u32::from_be_bytes(
                response[2..6]
                    .try_into()
                    .map_err(|_| io::ErrorKind::InvalidData)?,
            ) as usize;
            if size < 10 || size > response.len() || size > CAPACITY {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.read_exact(&mut response[10..size], deadline)?;
            Ok(size)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
