//! Experimental read-only BitLocker volume support, enabled by `bitlocker`.
//!
//! Inspect an immutable bounded volume, explicitly select its metadata and key
//! protector, then pass the decrypted [`UnlockedVolume`] to existing filesystem
//! readers. Only version-2, completed full-volume XTS software encryption is
//! readable. TPM, used-space-only encryption, conversion, and writes are refused.
//! Sources must remain stable for the entire lifetime of inspection and reads;
//! checking length does not establish snapshot isolation. Key-record authentication
//! does not authenticate data sectors. Native Windows qualification is pending.
//!
//! ```no_run
//! use std::sync::Arc;
//! use partmgr::{
//!     bitlocker::{BitLockerVolume, Limits, MetadataSelection, RecoveryPassword},
//!     fs_core::Resources,
//!     io::ReadAt,
//! };
//!
//! fn open_volume(
//!     source: Arc<dyn ReadAt>,
//!     protector_id: [u8; 16],
//!     recovery_password: &str,
//!     resources: &Resources,
//! ) -> partmgr::bitlocker::Result<Arc<dyn ReadAt>> {
//!     let volume = BitLockerVolume::inspect(
//!         source, MetadataSelection::RequireAgreement, Limits::default(), resources,
//!     )?;
//!     let password = RecoveryPassword::parse(recovery_password)?;
//!     Ok(Arc::new(volume.unlock_recovery(protector_id, &password)?))
//! }
//! ```

use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

use crate::{
    bitlocker_crypto::{self as crypto, SectorCipher},
    bitlocker_disk::{self as disk, Metadata},
    fs_core::{Error as ResourceError, Reservation, Resources},
    io::{self, ReadAt, ReadBudget, ReadContext, SourceIdentity},
};

/// Raw Windows GUID bytes identifying one key protector or volume.
pub type Identifier = [u8; 16];

/// Caller-supplied diagnostic FVEK bound to one supported encryption method.
///
/// Key bytes are erased on drop, are not clonable, and are never exposed by
/// formatting. The caller remains responsible for erasing the input buffer.
/// Possessing this key does not establish key authenticity or source stability.
pub struct FullVolumeKey {
    bytes: Zeroizing<[u8; 64]>,
    method: u16,
    length: usize,
}
impl FullVolumeKey {
    /// Validate and retain XTS-AES-128 (`0x8004`, 32 bytes) or XTS-AES-256
    /// (`0x8005`, 64 bytes) key material, data key first and tweak key second.
    pub fn new(encryption_method: u16, key: &[u8]) -> Result<Self> {
        let length = match encryption_method {
            0x8004 => 32,
            0x8005 => 64,
            _ => return Err(unsupported("supplied FVEK encryption method")),
        };
        if key.len() != length {
            return Err(Error::new(
                ErrorKind::InvalidCredential,
                "supplied FVEK length",
            ));
        }
        let mut bytes = Zeroizing::new([0; 64]);
        bytes[..length].copy_from_slice(key);
        Ok(Self {
            bytes,
            method: encryption_method,
            length,
        })
    }

    /// Non-secret native encryption method associated with this key.
    pub fn encryption_method(&self) -> u16 {
        self.method
    }
}
impl fmt::Debug for FullVolumeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FullVolumeKey")
            .field("encryption_method", &self.method)
            .finish_non_exhaustive()
    }
}

/// Machine-readable limitation of the selected logical read profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadLimitation {
    /// Used-space-only encryption requires a separately qualified mapping.
    UsedSpaceOnly,
    /// Current/target states do not both describe completed full encryption.
    ConversionState,
    /// The data cipher is outside the implemented XTS profiles.
    EncryptionMethod,
    /// A recognized mapping feature is outside the implemented profile.
    Mapping,
}

/// Capability of the selected volume profile before any credential operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadSupport {
    /// The profile permits diagnostic FVEK reading; credentials remain unchecked.
    Supported,
    /// A recognized profile feature prevents logical reading.
    Unsupported(ReadLimitation),
}

/// BitLocker operation failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid native structures, ranges, or checksums.
    InvalidData,
    /// Recognized format or protector outside the implemented profile.
    Unsupported,
    /// Usable metadata copies disagree and require explicit selection.
    AmbiguousMetadata,
    /// No unique protector matches the explicit identifier.
    ProtectorNotFound,
    /// Invalid recovery-password syntax, key length, or declared key method.
    InvalidCredential,
    /// Authenticated key unwrap rejected the supplied credential or altered data.
    AuthenticationFailed,
    /// A memory, read, entry, or derivation limit was reached.
    ResourceLimit,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// Backing length changed after inspection.
    SourceChanged,
    /// An underlying read failed.
    Io,
}

/// Failure retaining an optional causal I/O error; contains no key material.
#[derive(Debug)]
pub struct Error {
    /// Machine-readable category.
    pub kind: ErrorKind,
    /// Non-secret operation context.
    pub context: &'static str,
    /// Backend or resource failure, when present.
    pub source: Option<io::Error>,
}
impl Error {
    pub(crate) fn new(kind: ErrorKind, context: &'static str) -> Self {
        Self {
            kind,
            context,
            source: None,
        }
    }
    pub(crate) fn backend(context: &'static str, source: io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            context,
            source: Some(source),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.context)
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source.as_ref().map(|s| s as _)
    }
}
/// BitLocker operation result.
pub type Result<T> = core::result::Result<T, Error>;

/// Failure of experimental TPM unlocking, retaining either format/crypto errors
/// or the provider's exact TPM return code and cleanup obligations.
#[cfg(feature = "bitlocker-tpm")]
#[derive(Debug)]
pub enum TpmUnlockError {
    /// Metadata, source stability, resource policy, or key authentication failed.
    Volume(Error),
    /// The TPM provider failed; inspect its code and cleanup requirements.
    Provider(crate::bitlocker_tpm_host::Error),
}
#[cfg(feature = "bitlocker-tpm")]
impl fmt::Display for TpmUnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Volume(error) => error.fmt(f),
            Self::Provider(error) => error.fmt(f),
        }
    }
}
#[cfg(feature = "bitlocker-tpm")]
impl core::error::Error for TpmUnlockError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(match self {
            Self::Volume(error) => error,
            Self::Provider(error) => error,
        })
    }
}
#[cfg(feature = "bitlocker-tpm")]
impl From<Error> for TpmUnlockError {
    fn from(error: Error) -> Self {
        Self::Volume(error)
    }
}
#[cfg(feature = "bitlocker-tpm")]
impl From<crate::bitlocker_tpm_host::Error> for TpmUnlockError {
    fn from(error: crate::bitlocker_tpm_host::Error) -> Self {
        Self::Provider(error)
    }
}

pub(crate) fn invalid(context: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, context)
}
pub(crate) fn unsupported(context: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported, context)
}
pub(crate) fn resource(error: ResourceError) -> Error {
    let kind = if error.kind == crate::fs_core::ErrorKind::Cancelled {
        ErrorKind::Cancelled
    } else {
        ErrorKind::ResourceLimit
    };
    Error {
        kind,
        context: "BitLocker resource policy",
        source: Some(io::Error::other(error)),
    }
}

/// Bounds for inspection, key derivation, and deferred reading.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum bytes of one metadata block, including its validation header.
    pub max_metadata_bytes: usize,
    /// Maximum entries across a metadata copy, including nested properties.
    pub max_entries: usize,
    /// Maximum nested property depth; capped at eight.
    pub max_depth: usize,
    /// Maximum recovery derivation iterations per explicit unlock attempt.
    pub max_kdf_iterations: u64,
    /// Cumulative backend bytes across inspection and all readers of this volume.
    pub max_read_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_metadata_bytes: 65_536,
            max_entries: 4096,
            max_depth: 8,
            max_kdf_iterations: 1_048_576,
            max_read_bytes: 1 << 40,
        }
    }
}

/// Candidate volume envelope, without a metadata or unlock claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Candidate {
    /// The examined signatures do not identify BitLocker.
    Unrecognized,
    /// Conventional fixed-volume BitLocker signature.
    BitLocker,
    /// Legacy removable-volume discovery envelope; not readable here.
    BitLockerToGo,
}

/// Examine only a bounded boot-header signature, preserving backend errors.
pub fn probe(source: &dyn ReadAt, resources: &Resources) -> Result<Candidate> {
    resources.cancellation.check().map_err(resource)?;
    let _scratch = resources.memory.reserve(512).map_err(resource)?;
    let length = source.len();
    let mut boot = [0; 512];
    let n = length.min(512) as usize;
    source
        .read_exact_at(0, &mut boot[..n])
        .map_err(|e| Error::backend("BitLocker signature read", e))?;
    resources.cancellation.check().map_err(resource)?;
    if source.len() != length {
        return Err(Error::new(
            ErrorKind::SourceChanged,
            "source changed during probe",
        ));
    }
    Ok(if n >= 11 && &boot[3..11] == b"-FVE-FS-" {
        Candidate::BitLocker
    } else if n >= 464 && boot[424..440] == disk::FULL_VOLUME_GUID {
        Candidate::BitLockerToGo
    } else {
        Candidate::Unrecognized
    })
}

/// Metadata selection policy; no automatic newest-copy guess is made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataSelection {
    /// All structurally valid CRC-checked copies must agree byte for byte.
    RequireAgreement,
    /// Use one explicitly chosen copy, indexed zero through two.
    Copy(usize),
}

/// Result of inspecting one redundant metadata copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyStatus {
    /// The copy passed structural and CRC validation; CRC is not authentication.
    Valid,
    /// The copy was rejected before selection.
    Rejected(ErrorKind),
}

/// Non-secret selected volume information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeInfo {
    /// Raw native volume identifier.
    pub identifier: Identifier,
    /// Logical encryption unit size.
    pub sector_size: u16,
    /// Metadata-declared encrypted byte length, not proof of conversion completion.
    pub encrypted_length: u64,
    /// Raw software encryption method; readable methods are `0x8004` and `0x8005`.
    pub encryption_method: u16,
    /// Raw current conversion state.
    pub current_state: u16,
    /// Raw target conversion state.
    pub target_state: u16,
    /// Whether the volume has the used-space-only identifier.
    pub used_space_only: bool,
    /// Selected metadata index.
    pub selected_copy: usize,
    /// Diagnostics for all redundant copies.
    pub copies: [CopyStatus; 3],
}

/// Non-secret key protector summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Protector {
    /// Raw native protector identifier.
    pub identifier: Identifier,
    /// Raw protection type, e.g. recovery password `0x0800` or TPM `0x0100`.
    pub protection_type: u16,
}

/// Validated recovery-password encoding; zeroed on drop and never debug-printed.
pub struct RecoveryPassword(Zeroizing<[u8; 16]>);
impl RecoveryPassword {
    /// Parse exactly eight hyphen-separated groups of six decimal digits.
    /// Each group must be divisible by eleven and encode a 16-bit integer.
    pub fn parse(password: &str) -> Result<Self> {
        let bytes = password.as_bytes();
        if bytes.len() != 55 {
            return Err(Error::new(
                ErrorKind::InvalidCredential,
                "recovery password format",
            ));
        }
        let mut key = Zeroizing::new([0; 16]);
        for i in 0..8 {
            let start = i * 7;
            if i < 7 && bytes[start + 6] != b'-' {
                return Err(Error::new(
                    ErrorKind::InvalidCredential,
                    "recovery password separator",
                ));
            }
            let mut number = 0u32;
            for &digit in &bytes[start..start + 6] {
                if !digit.is_ascii_digit() {
                    return Err(Error::new(
                        ErrorKind::InvalidCredential,
                        "recovery password digit",
                    ));
                }
                number = number * 10 + u32::from(digit - b'0');
            }
            if !number.is_multiple_of(11) || number / 11 > u32::from(u16::MAX) {
                return Err(Error::new(
                    ErrorKind::InvalidCredential,
                    "recovery password group",
                ));
            }
            key[i * 2..i * 2 + 2].copy_from_slice(&((number / 11) as u16).to_le_bytes());
        }
        Ok(Self(key))
    }
}

/// Private acquisition boundary shared by borrowed exclusive storage and readers.
pub(crate) trait Source {
    fn length(&self) -> io::Result<u64>;
    fn identity(&self) -> Option<SourceIdentity> {
        None
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()>;
}
pub(crate) struct ReadSource<'a>(pub(crate) &'a dyn ReadAt);
impl Source for ReadSource<'_> {
    fn identity(&self) -> Option<SourceIdentity> {
        self.0.source_identity()
    }
    fn length(&self) -> io::Result<u64> {
        Ok(self.0.len())
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, out)
    }
}
#[cfg(feature = "bitlocker-write")]
pub(crate) struct StorageSource<'a, S: crate::storage::Storage>(pub(crate) &'a S);
#[cfg(feature = "bitlocker-write")]
impl<S: crate::storage::Storage> Source for StorageSource<'_, S> {
    fn length(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, out)
    }
}

pub(crate) struct Inspection {
    pub(crate) policy: Arc<Policy>,
    pub(crate) metadata: Metadata,
    pub(crate) info: VolumeInfo,
    pub(crate) _reservation: Reservation,
}
impl Inspection {
    pub(crate) fn inspect(
        source: &dyn Source,
        selection: MetadataSelection,
        limits: Limits,
        resources: &Resources,
    ) -> Result<Self> {
        resources.cancellation.check().map_err(resource)?;
        if limits.max_metadata_bytes > 65_536
            || limits.max_metadata_bytes < 120
            || limits.max_entries == 0
            || limits.max_entries > 65_536
            || limits.max_depth == 0
            || limits.max_depth > 8
        {
            return Err(Error::new(
                ErrorKind::ResourceLimit,
                "invalid BitLocker parser limits",
            ));
        }
        if matches!(selection, MetadataSelection::Copy(i) if i >= 3) {
            return Err(invalid("metadata copy index"));
        }
        let policy = Arc::new(Policy {
            source_identity: source.identity(),
            source_length: source
                .length()
                .map_err(|e| Error::backend("BitLocker backing length", e))?,
            limits,
            resources: resources.clone(),
            read_bytes: AtomicU64::new(0),
        });
        Self::inspect_with_policy(source, selection, policy)
    }
    pub(crate) fn inspect_with_policy(
        source: &dyn Source,
        selection: MetadataSelection,
        policy: Arc<Policy>,
    ) -> Result<Self> {
        policy.check(source)?;
        if matches!(selection, MetadataSelection::Copy(i) if i >= 3) {
            return Err(invalid("metadata copy index"));
        }
        let reservation = policy.resources.memory.reserve(1024).map_err(resource)?;
        let mut boot = [0; 512];
        policy.read(source, 0, &mut boot)?;
        let header = disk::Header::parse(&boot, policy.source_length)?;
        let mut copies: [Option<Metadata>; 3] = [None, None, None];
        let mut statuses = [CopyStatus::Rejected(ErrorKind::InvalidData); 3];
        for (i, &offset) in header.offsets.iter().enumerate() {
            match disk::read_metadata(source, offset, &header, &policy) {
                Ok(metadata) => {
                    statuses[i] = CopyStatus::Valid;
                    copies[i] = Some(metadata);
                }
                Err(error)
                    if matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported) =>
                {
                    statuses[i] = CopyStatus::Rejected(error.kind);
                }
                Err(error) => return Err(error),
            }
        }
        let index = match selection {
            MetadataSelection::Copy(i) => i,
            MetadataSelection::RequireAgreement => {
                let i = copies
                    .iter()
                    .position(Option::is_some)
                    .ok_or_else(|| invalid("no usable BitLocker metadata copy"))?;
                let selected = copies[i]
                    .as_ref()
                    .ok_or_else(|| invalid("metadata selection"))?;
                if copies.iter().flatten().any(|copy| !selected.agrees(copy)) {
                    return Err(Error::new(
                        ErrorKind::AmbiguousMetadata,
                        "metadata copies disagree",
                    ));
                }
                i
            }
        };
        let metadata = copies[index].take().ok_or_else(|| {
            let kind = match statuses[index] {
                CopyStatus::Rejected(kind) => kind,
                _ => ErrorKind::InvalidData,
            };
            Error::new(kind, "selected metadata copy is unusable")
        })?;
        let info = VolumeInfo {
            identifier: metadata.identifier,
            sector_size: header.sector_size,
            encrypted_length: metadata.encrypted_length,
            encryption_method: metadata.method,
            current_state: metadata.current_state,
            target_state: metadata.target_state,
            used_space_only: header.used_space_only,
            selected_copy: index,
            copies: statuses,
        };
        policy.check(source)?;
        Ok(Self {
            policy,
            metadata,
            info,
            _reservation: reservation,
        })
    }
    #[cfg(feature = "bitlocker-write")]
    pub(crate) fn readable(&self, source: &dyn Source) -> Result<()> {
        self.policy.check(source)?;
        validate_readable(&self.info, &self.metadata, self.policy.source_length)
    }
    #[cfg(feature = "bitlocker-write")]
    pub(crate) fn recovery_key(
        &self,
        identifier: Identifier,
        password: &RecoveryPassword,
    ) -> Result<crypto::SecretBytes> {
        recovery_key(&self.metadata, &self.policy, identifier, password)
    }
    #[cfg(feature = "bitlocker-write")]
    pub(crate) fn vmk_key(&self, vmk: &[u8]) -> Result<crypto::SecretBytes> {
        vmk_key(&self.metadata, &self.policy, vmk)
    }
    #[cfg(feature = "bitlocker-write")]
    pub(crate) fn clear_key(&self, identifier: Identifier) -> Result<crypto::SecretBytes> {
        clear_key(&self.metadata, &self.policy, identifier)
    }
}

pub(crate) struct Policy {
    source_identity: Option<SourceIdentity>,
    pub(crate) source_length: u64,
    pub(crate) limits: Limits,
    pub(crate) resources: Resources,
    read_bytes: AtomicU64,
}
impl Policy {
    pub(crate) fn check(&self, source: &dyn Source) -> Result<()> {
        self.resources.cancellation.check().map_err(resource)?;
        if source
            .length()
            .map_err(|e| Error::backend("BitLocker backing length", e))?
            != self.source_length
            || source.identity() != self.source_identity
        {
            return Err(Error::new(
                ErrorKind::SourceChanged,
                "BitLocker backing identity or length changed",
            ));
        }
        Ok(())
    }
    pub(crate) fn read(&self, source: &dyn Source, at: u64, out: &mut [u8]) -> Result<()> {
        self.check(source)?;
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.source_length)
        {
            return Err(invalid("BitLocker backing range"));
        }
        self.read_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(out.len() as u64)
                    .filter(|n| *n <= self.limits.max_read_bytes)
            })
            .map_err(|_| Error::new(ErrorKind::ResourceLimit, "BitLocker cumulative read limit"))?;
        source
            .read_exact_at(at, out)
            .map_err(|e| Error::backend("BitLocker backing read", e))?;
        self.check(source)
    }
}

/// Inspected volume retaining selected metadata and its memory reservations.
/// No filesystem cleanliness or source snapshot is inferred by construction.
pub struct BitLockerVolume {
    source: Arc<dyn ReadAt>,
    policy: Arc<Policy>,
    metadata: Metadata,
    info: VolumeInfo,
    _reservation: Reservation,
}
impl BitLockerVolume {
    /// Inspect a caller-stabilized bounded volume and explicitly select metadata.
    pub fn inspect(
        source: Arc<dyn ReadAt>,
        selection: MetadataSelection,
        limits: Limits,
        resources: &Resources,
    ) -> Result<Self> {
        let inspection =
            Inspection::inspect(&ReadSource(source.as_ref()), selection, limits, resources)?;
        Ok(Self {
            source,
            policy: inspection.policy,
            metadata: inspection.metadata,
            info: inspection.info,
            _reservation: inspection._reservation,
        })
    }
    /// Inspect non-secret selected volume information and copy diagnostics.
    pub fn info(&self) -> &VolumeInfo {
        &self.info
    }

    /// Inspect logical-read support without deriving or unwrapping any key.
    ///
    /// Structural mapping failures, cancellation and source changes remain
    /// errors. Supported does not qualify a protector, authenticate a key,
    /// validate the inner filesystem or imply native Windows qualification.
    pub fn read_support(&self) -> Result<ReadSupport> {
        self.policy.check(&ReadSource(self.source.as_ref()))?;
        let limitation = if self.info.used_space_only {
            Some(ReadLimitation::UsedSpaceOnly)
        } else if self.info.current_state != 4 || self.info.target_state != 4 {
            Some(ReadLimitation::ConversionState)
        } else if !matches!(self.info.encryption_method, 0x8004 | 0x8005) {
            Some(ReadLimitation::EncryptionMethod)
        } else {
            match self
                .metadata
                .validate_mapping(self.info.sector_size, self.policy.source_length)
            {
                Ok(()) => None,
                Err(error) if error.kind == ErrorKind::Unsupported => Some(ReadLimitation::Mapping),
                Err(error) => return Err(error),
            }
        };
        Ok(limitation.map_or(ReadSupport::Supported, ReadSupport::Unsupported))
    }

    /// Iterate protector summaries without copying secret-bearing metadata.
    pub fn protectors(&self) -> impl Iterator<Item = Protector> + '_ {
        self.metadata.protectors()
    }

    /// Decode the selected experimental Windows TPM-only protector without
    /// issuing commands. Parsing does not establish matching TPM or PCR state.
    #[cfg(feature = "bitlocker-tpm")]
    pub fn tpm_protector(
        &self,
        identifier: Identifier,
    ) -> Result<crate::bitlocker_tpm::Tpm2Protector<'_>> {
        self.policy.check(&ReadSource(self.source.as_ref()))?;
        self.metadata.protector(identifier)?.tpm2()
    }

    /// Unseal the selected TPM protector and authenticate its wrapped FVEK.
    /// This establishes key authentication independently of sector-read support;
    /// it returns no key and does not qualify used-space-only reading or boot.
    /// Supply an explicit persistent parent and a fresh cryptographic nonce for
    /// every invocation. The provider requires a trusted exclusive transport.
    #[cfg(feature = "bitlocker-tpm")]
    pub fn authenticate_tpm<T: crate::bitlocker_tpm_host::CommandTransport>(
        &self,
        identifier: Identifier,
        provider: &mut crate::bitlocker_tpm_host::Tpm2Provider<T>,
        parent_handle: u32,
        nonce_caller: &[u8; 32],
    ) -> core::result::Result<KeyEvidence, TpmUnlockError> {
        let _key = self.tpm_key(identifier, provider, parent_handle, nonce_caller)?;
        Ok(KeyEvidence::AuthenticatedKeyRecord)
    }

    /// Authenticate a TPM-only protector and open the supported full-volume XTS
    /// reader. Unsupported mappings are rejected before any TPM command.
    /// Parent selection and a fresh cryptographic nonce are explicit inputs.
    #[cfg(feature = "bitlocker-tpm")]
    pub fn unlock_tpm<T: crate::bitlocker_tpm_host::CommandTransport>(
        &self,
        identifier: Identifier,
        provider: &mut crate::bitlocker_tpm_host::Tpm2Provider<T>,
        parent_handle: u32,
        nonce_caller: &[u8; 32],
    ) -> core::result::Result<UnlockedVolume, TpmUnlockError> {
        self.readable()?;
        let key = self.tpm_key(identifier, provider, parent_handle, nonce_caller)?;
        Ok(self.reader_with_key(&key, KeyEvidence::AuthenticatedKeyRecord)?)
    }

    #[cfg(feature = "bitlocker-tpm")]
    fn tpm_key<T: crate::bitlocker_tpm_host::CommandTransport>(
        &self,
        identifier: Identifier,
        provider: &mut crate::bitlocker_tpm_host::Tpm2Provider<T>,
        parent_handle: u32,
        nonce_caller: &[u8; 32],
    ) -> core::result::Result<crypto::SecretBytes, TpmUnlockError> {
        let protector = self.tpm_protector(identifier)?;
        let secret = provider.unseal(
            &crate::bitlocker_tpm_host::UnsealRequest {
                private: protector.private_blob(),
                public: protector.public_blob(),
                parent_handle,
                nonce_caller,
                pcr_selection: protector.pcr_selection(),
                pcr_digest: Some(protector.pcr_digest()),
                policy_or: &[],
                policy_auth_value: true,
            },
            &self.policy.resources,
        )?;
        self.policy.check(&ReadSource(self.source.as_ref()))?;
        let vmk = crate::bitlocker_tpm::UnsealedVmk::parse(secret.as_bytes())?;
        Ok(vmk_key(&self.metadata, &self.policy, vmk.as_bytes())?)
    }

    /// Authenticate the selected recovery protector, then unwrap the volume key.
    pub fn unlock_recovery(
        &self,
        identifier: Identifier,
        password: &RecoveryPassword,
    ) -> Result<UnlockedVolume> {
        self.readable()?;
        let key = recovery_key(&self.metadata, &self.policy, identifier, password)?;
        self.reader_with_key(&key, KeyEvidence::AuthenticatedKeyRecord)
    }

    /// Explicitly use a clear-key protector, as found on suspended volumes.
    pub fn unlock_clear(&self, identifier: Identifier) -> Result<UnlockedVolume> {
        self.readable()?;
        let key = clear_key(&self.metadata, &self.policy, identifier)?;
        self.reader_with_key(&key, KeyEvidence::AuthenticatedKeyRecord)
    }

    /// Use a caller-supplied 32-byte VMK and authenticate the wrapped FVEK.
    /// This allows externally acquired keys without implying native TPM support.
    pub fn unlock_vmk(&self, vmk: &[u8]) -> Result<UnlockedVolume> {
        self.readable()?;
        let key = vmk_key(&self.metadata, &self.policy, vmk)?;
        self.reader_with_key(&key, KeyEvidence::AuthenticatedKeyRecord)
    }

    /// Diagnostic FVEK path. A supplied key is length-checked, not authenticated.
    /// The first half is the data key and the second half is the XTS tweak key.
    pub fn unlock_fvek(&self, fvek: &[u8]) -> Result<UnlockedVolume> {
        self.readable()?;
        self.reader_with_key(fvek, KeyEvidence::CallerSupplied)
    }

    /// Open a diagnostic reader using a key explicitly bound to the selected
    /// cipher. Authentication is not inferred from the typed key or a match.
    pub fn unlock_with_fvek(&self, fvek: &FullVolumeKey) -> Result<UnlockedVolume> {
        self.readable()?;
        if fvek.method != self.info.encryption_method {
            return Err(Error::new(
                ErrorKind::InvalidCredential,
                "supplied FVEK method mismatch",
            ));
        }
        self.reader_with_key(&fvek.bytes[..fvek.length], KeyEvidence::CallerSupplied)
    }

    fn readable(&self) -> Result<()> {
        self.policy.check(&ReadSource(self.source.as_ref()))?;
        validate_readable(&self.info, &self.metadata, self.policy.source_length)
    }

    fn reader_with_key(&self, key: &[u8], evidence: KeyEvidence) -> Result<UnlockedVolume> {
        let reservation = self
            .policy
            .resources
            .memory
            .reserve((core::mem::size_of::<UnlockedVolume>() + 128) as u64)
            .map_err(resource)?;
        let cipher = SectorCipher::new(self.info.encryption_method, key)?;
        let token = NEXT_VIEW_ID
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                Error::new(
                    ErrorKind::ResourceLimit,
                    "decrypted view identity exhausted",
                )
            })?;
        let provenance = DecryptionProvenance {
            encrypted_source: self.source.source_identity(),
            plaintext_view: SourceIdentity::new(
                VIEW_NAMESPACE,
                u128::from(token),
                self.info.encrypted_length,
            ),
            volume: self.info,
            relocated_boot_offset: self.metadata.boot_offset,
            relocated_boot_length: self.metadata.boot_length(self.info.sector_size)?,
            metadata_offsets: self.metadata.offsets,
            additional_reserved_region: self
                .metadata
                .additional_reserved_region(self.info.sector_size)?,
            key_evidence: evidence,
        };
        Ok(UnlockedVolume {
            source: self.source.clone(),
            policy: self.policy.clone(),
            cipher,
            info: self.info,
            boot_offset: self.metadata.boot_offset,
            boot_length: self.metadata.boot_length(self.info.sector_size)?,
            offsets: self.metadata.offsets,
            additional_reserved_region: provenance.additional_reserved_region,
            evidence,
            provenance,
            _reservation: reservation,
        })
    }
}

/// Evidence for accepting an unlocked volume key, independent of data integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyEvidence {
    /// AES-CCM authenticated the wrapped FVEK; data sectors remain unauthenticated.
    AuthenticatedKeyRecord,
    /// Caller supplied an unauthenticated FVEK through the diagnostic API.
    CallerSupplied,
}

// Provider-issued, process-local identities belong to retained reader instances;
// neither key bytes nor hashes of secret-bearing metadata enter public tokens.
const VIEW_NAMESPACE: u128 = 0x504152544d47524249544c4f434b4552;
static NEXT_VIEW_ID: AtomicU64 = AtomicU64::new(1);

/// Non-secret binding for a retained logical plaintext view.
///
/// The opaque view identity binds this reader's source, selected metadata and
/// mapping. Independent unlocks receive distinct tokens, even with equal keys.
/// Tokens are process-local and are not persistent content hashes. This report
/// establishes neither acquisition stability nor inner filesystem validity;
/// callers must record those independently in capture receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecryptionProvenance {
    /// Identity supplied by the ciphertext acquisition, when available.
    pub encrypted_source: Option<SourceIdentity>,
    /// Distinct provider-issued identity of the logical plaintext view.
    pub plaintext_view: SourceIdentity,
    /// Selected volume profile and redundant-copy diagnostics.
    pub volume: VolumeInfo,
    /// Physical volume-relative location of relocated boot sectors.
    pub relocated_boot_offset: u64,
    /// Length of the relocated boot region.
    pub relocated_boot_length: u64,
    /// Physical volume-relative metadata regions, each 65,536 bytes long.
    pub metadata_offsets: [u64; 3],
    /// Additional reserved offset and length in the qualified descriptor profile.
    pub additional_reserved_region: Option<(u64, u64)>,
    /// Evidence for key acceptance, not sector authentication.
    pub key_evidence: KeyEvidence,
}

/// Immutable decrypted logical volume implementing the existing positional reader.
/// Does not implement mutable storage or establish filesystem/source consistency.
pub struct UnlockedVolume {
    source: Arc<dyn ReadAt>,
    policy: Arc<Policy>,
    cipher: SectorCipher,
    info: VolumeInfo,
    boot_offset: u64,
    boot_length: u64,
    offsets: [u64; 3],
    additional_reserved_region: Option<(u64, u64)>,
    evidence: KeyEvidence,
    provenance: DecryptionProvenance,
    _reservation: Reservation,
}
impl UnlockedVolume {
    /// Selected volume information without secrets.
    pub fn info(&self) -> &VolumeInfo {
        &self.info
    }
    /// Report the actual key acceptance evidence.
    pub fn key_evidence(&self) -> KeyEvidence {
        self.evidence
    }

    /// Describe the ciphertext acquisition and this distinct plaintext view.
    pub fn provenance(&self) -> &DecryptionProvenance {
        &self.provenance
    }

    fn read(&self, at: u64, out: &mut [u8]) -> Result<()> {
        self.policy.check(&ReadSource(self.source.as_ref()))?;
        if out.is_empty() {
            return Ok(());
        }
        let size = u64::from(self.info.sector_size);
        let _scratch = self
            .policy
            .resources
            .memory
            .reserve(4096)
            .map_err(resource)?;
        let mut sector = Zeroizing::new([0u8; 4096]);
        let mut done = 0;
        while done < out.len() {
            let position = at + done as u64;
            let logical = position / size * size;
            let within = (position % size) as usize;
            let n = (size as usize - within).min(out.len() - done);
            let hidden = self
                .offsets
                .iter()
                .any(|offset| logical >= *offset && logical - *offset < 65_536)
                || (logical >= self.boot_offset && logical - self.boot_offset < self.boot_length)
                || self
                    .additional_reserved_region
                    .is_some_and(|(offset, length)| logical >= offset && logical - offset < length);
            let bytes = &mut sector[..size as usize];
            if hidden {
                self.policy.check(&ReadSource(self.source.as_ref()))?;
                bytes.fill(0);
            } else {
                let physical = if logical < self.boot_length {
                    self.boot_offset + logical
                } else {
                    logical
                };
                self.policy
                    .read(&ReadSource(self.source.as_ref()), physical, bytes)?;
                self.cipher.decrypt(bytes, physical / size);
            }
            self.policy.check(&ReadSource(self.source.as_ref()))?;
            out[done..done + n].copy_from_slice(&bytes[within..within + n]);
            done += n;
        }
        Ok(())
    }
}
impl ReadAt for UnlockedVolume {
    fn len(&self) -> u64 {
        self.info.encrypted_length
    }
    fn context(&self) -> ReadContext {
        self.source.context()
    }
    fn budget(&self) -> Option<ReadBudget> {
        self.source.budget()
    }
    fn source_identity(&self) -> Option<SourceIdentity> {
        Some(self.provenance.plaintext_view)
    }
    fn ancestor_identities(&self) -> Vec<SourceIdentity> {
        let mut ancestors = self.source.ancestor_identities();
        if let Some(identity) = self.provenance.encrypted_source
            && !ancestors.contains(&identity)
        {
            ancestors.push(identity);
        }
        ancestors
    }
    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(destination.len() as u64)
            .is_none_or(|end| end > self.len())
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.read(offset, destination).map_err(|error| {
            let kind = match error.kind {
                ErrorKind::InvalidData => io::ErrorKind::InvalidData,
                ErrorKind::Unsupported => io::ErrorKind::Unsupported,
                _ => io::ErrorKind::Other,
            };
            io::Error::new(kind, error)
        })
    }
}

fn recovery_key(
    metadata: &Metadata,
    policy: &Policy,
    identifier: Identifier,
    password: &RecoveryPassword,
) -> Result<crypto::SecretBytes> {
    let protector = metadata.protector(identifier)?;
    if protector.protection_type != 0x0800 {
        return Err(unsupported("selected protector is not a recovery password"));
    }
    let salt = protector.salt()?;
    let key = crypto::derive_recovery(
        &password.0,
        &salt,
        policy.limits.max_kdf_iterations,
        &policy.resources,
    )?;
    let vmk = crypto::unwrap_key(
        protector.encrypted_key()?,
        &key[..],
        None,
        &policy.resources,
    )?;
    if vmk.len() != 32 {
        return Err(invalid("VMK key length"));
    }
    vmk_key(metadata, policy, &vmk)
}

fn clear_key(
    metadata: &Metadata,
    policy: &Policy,
    identifier: Identifier,
) -> Result<crypto::SecretBytes> {
    let protector = metadata.protector(identifier)?;
    if protector.protection_type != 0 {
        return Err(unsupported("selected protector is not clear-key"));
    }
    let key = protector.clear_key()?;
    let vmk = crypto::unwrap_key(protector.encrypted_key()?, key, None, &policy.resources)?;
    if vmk.len() != 32 {
        return Err(invalid("VMK key length"));
    }
    vmk_key(metadata, policy, &vmk)
}

fn vmk_key(metadata: &Metadata, policy: &Policy, vmk: &[u8]) -> Result<crypto::SecretBytes> {
    if vmk.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidCredential,
            "supplied VMK length",
        ));
    }
    let key = crypto::unwrap_key(
        metadata.fvek()?,
        vmk,
        Some(metadata.method),
        &policy.resources,
    )?;
    Ok(key)
}

fn validate_readable(info: &VolumeInfo, metadata: &Metadata, source_length: u64) -> Result<()> {
    if info.used_space_only || info.current_state != 4 || info.target_state != 4 {
        return Err(unsupported("requires completed full-volume encryption"));
    }
    if !matches!(info.encryption_method, 0x8004 | 0x8005) {
        return Err(unsupported("requires XTS-AES software encryption"));
    }
    metadata.validate_mapping(info.sector_size, source_length)
}
