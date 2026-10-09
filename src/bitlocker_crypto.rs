//! BitLocker protocol composition using AES, CCM, SHA-256, and XTS crates.
use crate::{
    bitlocker::{Error, ErrorKind, Result, invalid, resource, unsupported},
    bitlocker_disk::{u16le, u32le},
    fs_core::{Reservation, Resources},
};
use aes::{Aes128, Aes256, cipher::KeyInit};
use alloc::vec::Vec;
use ccm::{
    Ccm,
    aead::AeadInPlace,
    consts::{U12, U16},
};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn derive_recovery(
    password: &[u8; 16],
    salt: &[u8; 16],
    limit: u64,
    r: &Resources,
) -> Result<Zeroizing<[u8; 32]>> {
    const ITERATIONS: u64 = 1_048_576;
    if limit < ITERATIONS {
        return Err(Error::new(
            ErrorKind::ResourceLimit,
            "recovery derivation work limit",
        ));
    }
    let _reservation = r.memory.reserve(512).map_err(resource)?;
    let mut input = Zeroizing::new([0u8; 88]);
    let mut initial = Sha256::digest(password);
    input[32..64].copy_from_slice(&initial);
    initial.as_mut_slice().zeroize();
    input[64..80].copy_from_slice(salt);
    for count in 0..ITERATIONS {
        if count.is_multiple_of(1024) {
            r.cancellation.check().map_err(resource)?;
        }
        input[80..].copy_from_slice(&count.to_le_bytes());
        let mut digest = Sha256::digest(&input[..]);
        input[..32].copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
    }
    r.cancellation.check().map_err(resource)?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&input[..32]);
    Ok(key)
}

pub(crate) struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
    _reservation: Reservation,
}
impl core::ops::Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn unwrap_key(
    data: &[u8],
    key: &[u8],
    method: Option<u16>,
    r: &Resources,
) -> Result<SecretBytes> {
    r.cancellation.check().map_err(resource)?;
    if data.len() < 40 || data.len() > 108 {
        return Err(invalid("wrapped key size"));
    }
    let reservation = r
        .memory
        .reserve((core::mem::size_of::<Ccm<Aes256, U16, U12>>() + 256) as u64)
        .map_err(resource)?;
    let cipher = Ccm::<Aes256, U16, U12>::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::InvalidCredential, "unwrap key size"))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(data.len() - 28)
        .map_err(|_| Error::new(ErrorKind::ResourceLimit, "key allocation"))?;
    plaintext.extend_from_slice(&data[28..]);
    cipher
        .decrypt_in_place_detached(data[..12].into(), &[], &mut plaintext, data[12..28].into())
        .map_err(|_| {
            Error::new(
                ErrorKind::AuthenticationFailed,
                "BitLocker key authentication",
            )
        })?;
    r.cancellation.check().map_err(resource)?;
    if plaintext.len() < 12
        || u32le(&plaintext, 0) as usize != plaintext.len()
        || u16le(&plaintext, 4) != 1
        || u16le(&plaintext, 6) != 0
    {
        return Err(invalid("authenticated key record header"));
    }
    let algorithm = u32le(&plaintext, 8);
    if let Some(method) = method {
        if algorithm != u32::from(method) {
            return Err(invalid("FVEK encryption method mismatch"));
        }
    } else if !matches!(algorithm, 0x2000 | 0x2003) {
        return Err(unsupported("VMK key algorithm"));
    }
    // Remove the parsed record header in place, then erase its former tail.
    let length = plaintext.len() - 12;
    plaintext.copy_within(12.., 0);
    plaintext[length..].fill(0);
    plaintext.truncate(length);
    Ok(SecretBytes {
        bytes: plaintext,
        _reservation: reservation,
    })
}

#[expect(
    clippy::large_enum_variant,
    reason = "retain AES schedules inline without an extra infallible heap allocation; reader memory is charged by size_of"
)]
pub(crate) enum SectorCipher {
    Aes128(Xts128<Aes128>),
    Aes256(Xts128<Aes256>),
}
impl SectorCipher {
    pub(crate) fn new(method: u16, key: &[u8]) -> Result<Self> {
        match (method, key.len()) {
            (0x8004, 32) => Ok(Self::Aes128(Xts128::new(
                Aes128::new((&key[..16]).into()),
                Aes128::new((&key[16..]).into()),
            ))),
            (0x8005, 64) => Ok(Self::Aes256(Xts128::new(
                Aes256::new((&key[..32]).into()),
                Aes256::new((&key[32..]).into()),
            ))),
            (0x8004 | 0x8005, _) => Err(Error::new(ErrorKind::InvalidCredential, "XTS FVEK size")),
            _ => Err(unsupported("BitLocker sector cipher")),
        }
    }
    pub(crate) fn decrypt(&self, sector: &mut [u8], number: u64) {
        let tweak = u128::from(number).to_le_bytes();
        match self {
            Self::Aes128(cipher) => cipher.decrypt_sector(sector, tweak),
            Self::Aes256(cipher) => cipher.decrypt_sector(sector, tweak),
        }
    }
    #[cfg(feature = "bitlocker-write")]
    pub(crate) fn encrypt(&self, sector: &mut [u8], number: u64) {
        let tweak = u128::from(number).to_le_bytes();
        match self {
            Self::Aes128(cipher) => cipher.encrypt_sector(sector, tweak),
            Self::Aes256(cipher) => cipher.encrypt_sector(sector, tweak),
        }
    }
}
