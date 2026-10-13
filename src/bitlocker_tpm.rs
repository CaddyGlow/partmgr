//! Experimental bounded Windows TPM 2.0 protector decoding.
//!
//! This module recognizes the observed TPM-only version-5 SHA-256 keyed-hash
//! object and verifies its complete `PolicyAuthValue`, then `PolicyPCR` digest.
//! It performs no TPM commands and makes no claim about matching TPM state.
//! Parent selection is an explicit host-provider input, not a guessed handle.
use crate::bitlocker::{Error, ErrorKind, Result, invalid, unsupported};
use core::fmt;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Parsed, borrowed TPM-only sealed object. Formatting never prints sealed data.
///
/// The accepted profile requires an empty (or all-zero, TPM-trimmed) object
/// authValue and a SHA-256 policy session. The TPM must authenticate that
/// assumption; successful parsing alone cannot verify the encrypted authValue.
pub struct Tpm2Protector<'a> {
    private: &'a [u8],
    public: &'a [u8],
    pcr_digest: [u8; 32],
    pcr_selection: [u8; 10],
    auth_policy: [u8; 32],
}
impl fmt::Debug for Tpm2Protector<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tpm2Protector")
            .field("pcr_mask", &self.pcr_mask())
            .field("policy", &"SHA256 PolicyAuthValue then PolicyPCR")
            .finish_non_exhaustive()
    }
}
impl<'a> Tpm2Protector<'a> {
    /// Decode one complete FVE TPM datum, including its eight-byte entry header.
    /// Requires explicit TPM-only protection (`0x0100`); additional-factor
    /// protector types are rejected rather than silently reduced to TPM-only.
    pub fn parse(protection_type: u16, datum: &'a [u8]) -> Result<Self> {
        if protection_type != 0x0100 {
            return Err(unsupported("TPM-only protector required"));
        }
        if datum.len() != 302 {
            return Err(invalid("TPM datum size"));
        }
        if le16(datum, 0) != 302 || le16(datum, 2) != 0 || le16(datum, 4) != 6 {
            return Err(invalid("TPM datum header"));
        }
        if le16(datum, 6) != 5 {
            return Err(unsupported("TPM datum version"));
        }
        let mask = u32::from_le_bytes(
            datum[8..12]
                .try_into()
                .map_err(|_| invalid("TPM PCR mask"))?,
        );
        if mask == 0 || mask & !0x00ff_ffff != 0 {
            return Err(unsupported("TPM PCR selection"));
        }
        let mut cursor = Cursor(&datum[12..]);
        let private = cursor.sized()?;
        if private.len() != 170 || be16(private, 0) != 32 || be16(private, 34) != 16 {
            return Err(unsupported("TPM sealed private object profile"));
        }
        let public = cursor.sized()?;
        if public.len() != 78 {
            return Err(unsupported("TPM public object size"));
        }
        // TPM_ALG_KEYEDHASH, TPM_ALG_SHA256, fixedTPM|fixedParent|noDA,
        // 32-byte authPolicy, TPM_ALG_NULL scheme and 32-byte unique value.
        if be16(public, 0) != 8
            || be16(public, 2) != 11
            || public[4..8] != [0, 0, 4, 0x12]
            || be16(public, 8) != 32
            || be16(public, 42) != 0x10
            || be16(public, 44) != 32
        {
            return Err(unsupported("TPM keyed-hash public profile"));
        }
        let pcr_digest: [u8; 32] = cursor
            .sized()?
            .try_into()
            .map_err(|_| unsupported("TPM PCR digest size"))?;
        let selection = cursor.take(4)?;
        if selection[0] != 3 || selection[1..] != mask.to_le_bytes()[..3] {
            return Err(invalid("TPM PCR selection copies disagree"));
        }
        if !cursor.0.is_empty() {
            return Err(invalid("TPM datum trailing data"));
        }
        let pcr_selection = [
            0,
            0,
            0,
            1,
            0,
            11,
            3,
            selection[1],
            selection[2],
            selection[3],
        ];
        let auth_policy: [u8; 32] = public[10..42]
            .try_into()
            .map_err(|_| invalid("TPM auth policy"))?;
        let expected = policy_digest(&pcr_selection, &pcr_digest);
        if expected != auth_policy {
            return Err(unsupported(
                "TPM policy digest does not match supported sequence",
            ));
        }
        Ok(Self {
            private,
            public,
            pcr_digest,
            pcr_selection,
            auth_policy,
        })
    }
    /// TPM2B_PRIVATE payload, without the outer big-endian size prefix.
    pub fn private_blob(&self) -> &'a [u8] {
        self.private
    }
    /// Complete TPMT_PUBLIC payload, without its outer size prefix.
    pub fn public_blob(&self) -> &'a [u8] {
        self.public
    }
    /// Expected SHA-256 digest of the selected PCR values at unseal time.
    pub fn pcr_digest(&self) -> &[u8; 32] {
        &self.pcr_digest
    }
    /// Full marshalled TPML_PCR_SELECTION for the single SHA-256 bank.
    pub fn pcr_selection(&self) -> &[u8; 10] {
        &self.pcr_selection
    }
    /// Selected PCR0..23 bitmap, validated against both stored copies.
    pub fn pcr_mask(&self) -> u32 {
        u32::from_le_bytes([
            self.pcr_selection[7],
            self.pcr_selection[8],
            self.pcr_selection[9],
            0,
        ])
    }
    /// Complete checked SHA-256 authorization policy, excluding its size prefix.
    pub fn auth_policy(&self) -> &[u8; 32] {
        &self.auth_policy
    }
}

fn policy_digest(selection: &[u8; 10], pcr_digest: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([0; 32]);
    hash.update(0x0000_016bu32.to_be_bytes()); // TPM_CC_PolicyAuthValue.
    let first = hash.finalize();
    let mut hash = Sha256::new();
    hash.update(first);
    hash.update(0x0000_017fu32.to_be_bytes()); // TPM_CC_PolicyPCR.
    hash.update(selection);
    hash.update(pcr_digest);
    hash.finalize().into()
}

/// Validated zeroizing VMK returned by the TPM's unsealed BitLocker key record.
/// No key material appears in formatting; no implicit cloning is provided.
pub struct UnsealedVmk(Zeroizing<[u8; 32]>);
impl fmt::Debug for UnsealedVmk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnsealedVmk { .. }")
    }
}
impl UnsealedVmk {
    /// Validate the exact 44-byte unsealed TPM VMK record, then retain its key.
    /// The caller must erase the supplied unsealed buffer after this call.
    /// TPM response authentication and subsequent FVEK authentication are still
    /// required; a syntactically valid record is not evidence of either.
    pub fn parse(record: &[u8]) -> Result<Self> {
        if record.len() != 44 {
            return Err(Error::new(
                ErrorKind::InvalidCredential,
                "unsealed TPM VMK record length",
            ));
        }
        // Windows 26200 uses zero in the second header word; the independently
        // published Windows TPM artifact uses five. Its precise status/type
        // semantics remain uncertain. The first four bytes are not a u32 size.
        if le16(record, 0) != 44
            || !matches!(le16(record, 2), 0 | 5)
            || record[4..12] != [1, 0, 0, 0, 3, 0x20, 0, 0]
        {
            return Err(unsupported("unsealed TPM VMK record profile"));
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&record[12..]);
        Ok(Self(key))
    }
    /// Borrow the VMK only for explicit authenticated FVEK unwrapping.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let out = self
            .0
            .get(..count)
            .ok_or_else(|| invalid("truncated TPM structure"))?;
        self.0 = &self.0[count..];
        Ok(out)
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let size = self.take(2)?;
        self.take(usize::from(u16::from_be_bytes([size[0], size[1]])))
    }
}
