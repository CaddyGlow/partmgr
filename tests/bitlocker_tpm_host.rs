#![cfg(feature = "bitlocker-tpm")]
use hmac::{Hmac, Mac};
use partmgr::{
    bitlocker_tpm_host::{CommandTransport, ErrorKind, Tpm2Provider, UnsealRequest},
    fs_core::{Budget, Cancellation, Resources},
};
use sha2::{Digest, Sha256};
use std::io;

const LOAD: u32 = 0x157;
const START: u32 = 0x176;
const AUTH_VALUE: u32 = 0x16b;
const PCR: u32 = 0x17f;
const OR: u32 = 0x171;
const UNSEAL: u32 = 0x15e;
const FLUSH: u32 = 0x165;
const OBJECT: u32 = 0x8000_0042;
const SESSION: u32 = 0x0300_0012;
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn hmac(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Hmac::<Sha256>::new_from_slice(&[]).unwrap();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into_bytes().to_vec()
}
fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u16).to_be_bytes().to_vec();
    result.extend_from_slice(bytes);
    result
}
fn frame(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut result = tag.to_be_bytes().to_vec();
    result.extend_from_slice(&(10 + body.len() as u32).to_be_bytes());
    result.extend_from_slice(&code.to_be_bytes());
    result.extend_from_slice(body);
    result
}
struct Fixture {
    public: Vec<u8>,
    selection: [u8; 10],
    pcr_digest: [u8; 32],
    branches: Vec<[u8; 32]>,
    auth: bool,
}
impl Fixture {
    fn new(auth: bool, use_or: bool) -> Self {
        let selection = [0, 0, 0, 1, 0, 0x0b, 3, 0x80, 8, 0];
        let pcr_digest = [0x25; 32];
        let mut policy = [0; 32];
        if auth {
            policy = digest(&[&policy, &AUTH_VALUE.to_be_bytes()]);
        }
        policy = digest(&[&policy, &PCR.to_be_bytes(), &selection, &pcr_digest]);
        let branches = if use_or {
            vec![policy, [0x77; 32]]
        } else {
            vec![]
        };
        if use_or {
            policy = digest(&[&[0; 32], &OR.to_be_bytes(), &branches[0], &branches[1]]);
        }
        let mut public = vec![0, 8, 0, 0x0b, 0, 0, 4, 0x12];
        public.extend(sized(&policy));
        public.extend_from_slice(&[0, 0x10]);
        public.extend(sized(&[0x61; 32]));
        Self {
            public,
            selection,
            pcr_digest,
            branches,
            auth,
        }
    }
    fn request(&self) -> UnsealRequest<'_> {
        UnsealRequest {
            private: &[0x42; 170],
            public: &self.public,
            parent_handle: 0x8100_0001,
            nonce_caller: &[0x33; 32],
            pcr_selection: &self.selection,
            pcr_digest: Some(&self.pcr_digest),
            policy_or: &self.branches,
            policy_auth_value: self.auth,
        }
    }
    fn transport(&self) -> Fake {
        Fake {
            public: self.public.clone(),
            auth: self.auth,
            calls: vec![],
            failure: None,
            malformed: None,
            transport_failure: None,
            bad_hmac: false,
            cancel: None,
        }
    }
}
struct Fake {
    public: Vec<u8>,
    auth: bool,
    calls: Vec<Vec<u8>>,
    failure: Option<(u32, u32)>,
    malformed: Option<u32>,
    transport_failure: Option<u32>,
    bad_hmac: bool,
    cancel: Option<(u32, Cancellation)>,
}
impl Fake {
    fn codes(&self) -> Vec<u32> {
        self.calls
            .iter()
            .map(|c| u32::from_be_bytes(c[6..10].try_into().unwrap()))
            .collect()
    }
}
impl CommandTransport for Fake {
    fn transact(&mut self, command: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
        assert_eq!(
            u32::from_be_bytes(command[2..6].try_into().unwrap()) as usize,
            command.len()
        );
        self.calls.push(command.to_vec());
        if self.transport_failure == Some(code) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut response =
            if let Some((failed, rc)) = self.failure.filter(|(failed, _)| *failed == code) {
                assert_eq!(failed, code);
                frame(0x8001, rc, &[])
            } else {
                match code {
                    LOAD => {
                        assert_eq!(&command[10..14], &0x8100_0001u32.to_be_bytes());
                        assert_eq!(
                            &command[14..27],
                            &[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]
                        );
                        assert_eq!(&command[27..199], &sized(&[0x42; 170]));
                        assert_eq!(&command[199..], &sized(&self.public));
                        let mut name = vec![0, 0x0b];
                        name.extend_from_slice(&digest(&[&self.public]));
                        let parameters = sized(&name);
                        let mut body = OBJECT.to_be_bytes().to_vec();
                        body.extend_from_slice(&(parameters.len() as u32).to_be_bytes());
                        body.extend(parameters);
                        body.extend_from_slice(&[0, 0, 1, 0, 0]);
                        frame(0x8002, 0, &body)
                    }
                    START => {
                        assert_eq!(&command[10..18], &[0x40, 0, 0, 7, 0x40, 0, 0, 7]);
                        assert_eq!(&command[18..52], &sized(&[0x33; 32]));
                        assert_eq!(&command[52..], &[0, 0, 1, 0, 0x10, 0, 0x0b]);
                        let mut body = SESSION.to_be_bytes().to_vec();
                        body.extend(sized(&[0x44; 32]));
                        frame(0x8001, 0, &body)
                    }
                    AUTH_VALUE | PCR | OR => {
                        assert_eq!(&command[10..14], &SESSION.to_be_bytes());
                        if code == AUTH_VALUE {
                            assert_eq!(command.len(), 14);
                        }
                        if code == PCR {
                            assert_eq!(&command[14..48], &sized(&[0x25; 32]));
                            assert_eq!(&command[48..], &[0, 0, 0, 1, 0, 0x0b, 3, 0x80, 8, 0]);
                        }
                        frame(0x8001, 0, &[])
                    }
                    UNSEAL => {
                        assert_eq!(&command[10..14], &OBJECT.to_be_bytes());
                        assert_eq!(&command[18..22], &SESSION.to_be_bytes());
                        let mut name = vec![0, 0x0b];
                        name.extend_from_slice(&digest(&[&self.public]));
                        if self.auth {
                            assert_eq!(command.len(), 91);
                            assert_eq!(&command[14..18], &73u32.to_be_bytes());
                            assert_eq!(&command[22..56], &sized(&[0x33; 32]));
                            assert_eq!(command[56], 1);
                            let cp_hash = digest(&[&UNSEAL.to_be_bytes(), &name]);
                            let expected = hmac(&[&cp_hash, &[0x33; 32], &[0x44; 32], &[1]]);
                            assert_eq!(&command[57..], &sized(&expected));
                        } else {
                            assert_eq!(&command[14..], &[0, 0, 0, 9, 3, 0, 0, 0x12, 0, 0, 1, 0, 0]);
                        }
                        let mut secret = vec![0x2c, 0, 5, 0, 1, 0, 0, 0, 3, 0x20, 0, 0];
                        secret.extend_from_slice(&[0xb2; 32]);
                        let parameters = sized(&secret);
                        let mut body = (parameters.len() as u32).to_be_bytes().to_vec();
                        body.extend_from_slice(&parameters);
                        body.extend(sized(&[0x55; 32]));
                        body.push(1);
                        if self.auth {
                            let rp_hash =
                                digest(&[&0u32.to_be_bytes(), &UNSEAL.to_be_bytes(), &parameters]);
                            let mut auth = hmac(&[&rp_hash, &[0x55; 32], &[0x33; 32], &[1]]);
                            if self.bad_hmac {
                                auth[0] ^= 1;
                            }
                            body.extend(sized(&auth));
                        } else {
                            body.extend_from_slice(&[0, 0]);
                        }
                        frame(0x8002, 0, &body)
                    }
                    FLUSH => {
                        assert_eq!(command.len(), 14);
                        let handle = u32::from_be_bytes(command[10..14].try_into().unwrap());
                        assert!([OBJECT, SESSION].contains(&handle));
                        frame(0x8001, 0, &[])
                    }
                    _ => panic!("unexpected command {code:#x}; lifecycle mutation is forbidden"),
                }
            };
        if self.malformed == Some(code) {
            response[2..6].copy_from_slice(&9999u32.to_be_bytes());
        }
        if let Some((cancel_at, token)) = &self.cancel
            && *cancel_at == code
        {
            token.cancel();
        }
        out[..response.len()].copy_from_slice(&response);
        Ok(response.len())
    }
}

#[test]
fn explicit_authvalue_pcr_policy_or_and_unseal_authentication_cleanup() {
    for auth in [false, true] {
        for use_or in [false, true] {
            let fixture = Fixture::new(auth, use_or);
            let resources = resources();
            let mut provider = Tpm2Provider::new(fixture.transport());
            let secret = provider.unseal(&fixture.request(), &resources).unwrap();
            assert_eq!(&secret.as_bytes()[12..], &[0xb2; 32]);
            assert_eq!(secret.as_bytes().len(), 44);
            assert_eq!(format!("{secret:?}"), "UnsealedSecret([REDACTED])");
            assert_eq!(resources.memory.used(), 64);
            drop(secret);
            assert_eq!(resources.memory.used(), 0);
            let transport = provider.into_transport();
            let mut expected = vec![LOAD, START];
            if auth {
                expected.push(AUTH_VALUE);
            }
            expected.push(PCR);
            if use_or {
                expected.push(OR);
            }
            expected.extend([UNSEAL, FLUSH, FLUSH]);
            assert_eq!(transport.codes(), expected);
            assert_eq!(
                &transport.calls[transport.calls.len() - 2][10..],
                &SESSION.to_be_bytes()
            );
            assert_eq!(
                &transport.calls[transport.calls.len() - 1][10..],
                &OBJECT.to_be_bytes()
            );
        }
    }
}
#[test]
fn policy_and_lockout_return_codes_preserved_without_retry_and_handles_cleaned() {
    for (rc, kind) in [
        (0x99d, ErrorKind::PolicyFailed),
        (0x921, ErrorKind::Lockout),
        (0x18b, ErrorKind::Tpm),
    ] {
        let fixture = Fixture::new(true, false);
        let mut transport = fixture.transport();
        transport.failure = Some((UNSEAL, rc));
        let r = resources();
        let mut provider = Tpm2Provider::new(transport);
        let error = provider.unseal(&fixture.request(), &r).unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.response_code, Some(rc));
        assert!(!error.cleanup_required);
        assert_eq!(r.memory.used(), 0);
        assert_eq!(
            provider.into_transport().codes(),
            [LOAD, START, AUTH_VALUE, PCR, UNSEAL, FLUSH, FLUSH]
        );
    }
}
#[test]
fn uncertain_transport_or_malformed_response_fences_all_later_traffic() {
    for malformed in [false, true] {
        let fixture = Fixture::new(true, false);
        let mut transport = fixture.transport();
        if malformed {
            transport.malformed = Some(PCR);
        } else {
            transport.transport_failure = Some(PCR);
        }
        let r = resources();
        let mut provider = Tpm2Provider::new(transport);
        let error = provider.unseal(&fixture.request(), &r).unwrap_err();
        assert_eq!(
            error.kind,
            if malformed {
                ErrorKind::MalformedResponse
            } else {
                ErrorKind::Transport
            }
        );
        assert!(error.cleanup_required);
        assert!(error.cleanup.iter().all(Option::is_some));
        assert!(provider.uncertain_completion());
        assert_eq!(
            provider.unseal(&fixture.request(), &r).unwrap_err().kind,
            ErrorKind::UncertainCompletion
        );
        assert_eq!(
            provider.into_transport().codes(),
            [LOAD, START, AUTH_VALUE, PCR]
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn wrong_response_hmac_never_releases_unsealed_bytes() {
    let fixture = Fixture::new(true, false);
    let mut transport = fixture.transport();
    transport.bad_hmac = true;
    let r = resources();
    let mut provider = Tpm2Provider::new(transport);
    let error = provider.unseal(&fixture.request(), &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::MalformedResponse);
    assert!(error.cleanup_required);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(
        provider.into_transport().codes(),
        [LOAD, START, AUTH_VALUE, PCR, UNSEAL]
    );
}
#[test]
fn cancellation_and_cleanup_failure_preserve_only_owned_handle_obligations() {
    let fixture = Fixture::new(true, false);
    let r = resources();
    let mut transport = fixture.transport();
    transport.cancel = Some((START, r.cancellation.clone()));
    let mut provider = Tpm2Provider::new(transport);
    assert_eq!(
        provider.unseal(&fixture.request(), &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        provider.into_transport().codes(),
        [LOAD, START, FLUSH, FLUSH]
    );
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let mut transport = fixture.transport();
    transport.failure = Some((FLUSH, 0x18b));
    let mut provider = Tpm2Provider::new(transport);
    let error = provider.unseal(&fixture.request(), &r).unwrap_err();
    assert_eq!(error.command, FLUSH);
    assert!(error.cleanup_required);
    assert!(provider.uncertain_completion());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn unsupported_policy_and_resource_limit_send_no_commands() {
    let mut fixture = Fixture::new(true, false);
    fixture.public[10] ^= 1;
    let mut provider = Tpm2Provider::new(fixture.transport());
    assert_eq!(
        provider
            .unseal(&fixture.request(), &resources())
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    assert!(provider.into_transport().calls.is_empty());
    let fixture = Fixture::new(true, false);
    let mut provider = Tpm2Provider::new(fixture.transport());
    let r = Resources {
        memory: Budget::new(32),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        provider.unseal(&fixture.request(), &r).unwrap_err().kind,
        ErrorKind::ResourceLimit
    );
    assert_eq!(r.memory.used(), 0);
    assert!(provider.into_transport().calls.is_empty());
}

#[cfg(unix)]
mod unix_transport {
    use super::*;
    use partmgr::bitlocker_tpm_host::UnixCommandTransport;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };
    #[test]
    fn fragmented_frames_are_reassembled_and_command_channel_has_no_handshake() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let expected = frame(0x8001, FLUSH, &OBJECT.to_be_bytes());
        let received = expected.clone();
        let thread = std::thread::spawn(move || {
            let mut bytes = vec![0; received.len()];
            server.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, received);
            for chunk in frame(0x8001, 0, &[]).chunks(2) {
                server.write_all(chunk).unwrap();
            }
        });
        let mut transport =
            UnixCommandTransport::from_stream(client, Duration::from_secs(1)).unwrap();
        let mut out = [0; 4096];
        assert_eq!(transport.transact(&expected, &mut out).unwrap(), 10);
        assert_eq!(&out[..10], &frame(0x8001, 0, &[]));
        thread.join().unwrap();
    }
    #[test]
    fn stalled_header_times_out_and_never_replays_command() {
        let (client, _server) = UnixStream::pair().unwrap();
        let mut transport =
            UnixCommandTransport::from_stream(client, Duration::from_millis(20)).unwrap();
        let command = frame(0x8001, FLUSH, &OBJECT.to_be_bytes());
        let mut out = [0; 4096];
        let start = Instant::now();
        assert!(transport.transact(&command, &mut out).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(transport.transact(&command, &mut out).is_err());
    }
    #[test]
    fn oversized_response_is_rejected_before_body_read() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let command = frame(0x8001, FLUSH, &OBJECT.to_be_bytes());
        let size = command.len();
        let thread = std::thread::spawn(move || {
            let mut command = vec![0; size];
            server.read_exact(&mut command).unwrap();
            let mut response = frame(0x8001, 0, &[]);
            response[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
            server.write_all(&response).unwrap();
        });
        let mut transport =
            UnixCommandTransport::from_stream(client, Duration::from_secs(1)).unwrap();
        assert_eq!(
            transport
                .transact(&command, &mut [0; 4096])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        thread.join().unwrap();
    }
}

#[test]
fn policy_pcr_digest_mismatch_is_classified_by_exact_command_and_parameter() {
    for (command, response_code, kind, expected_commands) in [
        (
            PCR,
            0x1c4,
            ErrorKind::PolicyFailed,
            vec![LOAD, START, AUTH_VALUE, PCR, FLUSH, FLUSH],
        ),
        (
            PCR,
            0x2c4,
            ErrorKind::Tpm,
            vec![LOAD, START, AUTH_VALUE, PCR, FLUSH, FLUSH],
        ),
        (LOAD, 0x1c4, ErrorKind::Tpm, vec![LOAD]),
    ] {
        let fixture = Fixture::new(true, false);
        let mut transport = fixture.transport();
        transport.failure = Some((command, response_code));
        let mut provider = Tpm2Provider::new(transport);
        let r = resources();
        let error = provider.unseal(&fixture.request(), &r).unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.command, command);
        assert_eq!(error.response_code, Some(response_code));
        assert!(!error.cleanup_required);
        assert!(!provider.uncertain_completion());
        assert_eq!(r.memory.used(), 0);
        assert_eq!(provider.into_transport().codes(), expected_commands);
    }
}
