//! GUID values and lossless GPT names and attributes.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{fmt, str::FromStr};

/// An identifier in canonical (network) byte order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Guid([u8; 16]);
/// Invalid GUID text, identity list, or exhausted generation attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuidError;
impl fmt::Display for GuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid, nil, duplicate, or unavailable GUID")
    }
}
impl crate::platform::error::Error for GuidError {}
/// Generation failed either in the entropy source or after collision retries.
#[derive(Debug)]
pub enum GenerationError<E> {
    /// The caller's entropy source failed.
    Entropy(E),
    /// No unique identifier was produced within the requested attempt limit.
    Exhausted,
}
impl<E: fmt::Display> fmt::Display for GenerationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(e) => write!(f, "GUID entropy: {e}"),
            Self::Exhausted => f.write_str("GUID generation attempts exhausted"),
        }
    }
}
impl<E: crate::platform::error::Error + 'static> crate::platform::error::Error
    for GenerationError<E>
{
    fn source(&self) -> Option<&(dyn crate::platform::error::Error + 'static)> {
        match self {
            Self::Entropy(e) => Some(e),
            Self::Exhausted => None,
        }
    }
}
impl Guid {
    /// All-zero identifier.
    pub const NIL: Self = Self([0; 16]);
    /// Construct from canonical byte order.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// Return canonical byte order.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
    /// Decode GPT's little-endian first three fields.
    pub fn from_gpt_bytes(mut bytes: [u8; 16]) -> Self {
        bytes[..4].reverse();
        bytes[4..6].reverse();
        bytes[6..8].reverse();
        Self(bytes)
    }
    /// Encode GPT's little-endian first three fields.
    pub fn to_gpt_bytes(self) -> [u8; 16] {
        Self::from_gpt_bytes(self.0).0
    }
    /// Whether this is the all-zero identifier.
    pub fn is_nil(self) -> bool {
        self == Self::NIL
    }
    /// Reject nil and duplicate identities supplied by a caller.
    pub fn validate_unique(ids: &[Self]) -> Result<(), GuidError> {
        let mut seen = crate::platform::collections::HashSet::new();
        for id in ids {
            if id.is_nil() || !seen.insert(*id) {
                return Err(GuidError);
            }
        }
        Ok(())
    }
    /// Generate a version-4 UUID using fallible caller entropy and bounded retries.
    pub fn generate_unique<E>(
        used: &[Self],
        attempts: usize,
        mut entropy: impl FnMut(&mut [u8; 16]) -> Result<(), E>,
    ) -> Result<Self, GenerationError<E>> {
        for _ in 0..attempts {
            let mut b = [0; 16];
            entropy(&mut b).map_err(GenerationError::Entropy)?;
            b[6] = (b[6] & 15) | 0x40;
            b[8] = (b[8] & 63) | 0x80;
            let id = Self(b);
            if !used.contains(&id) {
                return Ok(id);
            }
        }
        Err(GenerationError::Exhausted)
    }
    /// Known descriptive partition type, or `None` for an unknown type.
    pub fn type_name(self) -> Option<&'static str> {
        match self {
            EFI_SYSTEM_PARTITION => Some("EFI System Partition"),
            MICROSOFT_BASIC_DATA => Some("Microsoft basic data"),
            MICROSOFT_RESERVED => Some("Microsoft reserved"),
            LINUX_FILESYSTEM => Some("Linux filesystem"),
            LINUX_SWAP => Some("Linux swap"),
            _ => None,
        }
    }
}
impl FromStr for Guid {
    type Err = GuidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
            return Err(GuidError);
        }
        let mut out = [0; 16];
        let mut index = 0;
        let mut high = None;
        for (i, &v) in b.iter().enumerate() {
            if [8, 13, 18, 23].contains(&i) {
                continue;
            }
            let n = match v {
                b'0'..=b'9' => v - b'0',
                b'a'..=b'f' => v - b'a' + 10,
                b'A'..=b'F' => v - b'A' + 10,
                _ => return Err(GuidError),
            };
            if let Some(h) = high.take() {
                out[index] = h * 16 + n;
                index += 1
            } else {
                high = Some(n)
            }
        }
        Ok(Self(out))
    }
}
impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if [4, 6, 8, 10].contains(&i) {
                f.write_str("-")?
            }
            write!(f, "{b:02x}")?
        }
        Ok(())
    }
}
/// EFI System Partition type GUID.
pub const EFI_SYSTEM_PARTITION: Guid = Guid::from_bytes([
    0xc1, 0x2a, 0x73, 0x28, 0xf8, 0x1f, 0x11, 0xd2, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
]);
/// Microsoft basic data type GUID.
pub const MICROSOFT_BASIC_DATA: Guid = Guid::from_bytes([
    0xeb, 0xd0, 0xa0, 0xa2, 0xb9, 0xe5, 0x44, 0x33, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
]);
/// Microsoft reserved type GUID.
pub const MICROSOFT_RESERVED: Guid = Guid::from_bytes([
    0xe3, 0xc9, 0xe3, 0x16, 0x0b, 0x5c, 0x4d, 0xb8, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae,
]);
/// Linux filesystem type GUID.
pub const LINUX_FILESYSTEM: Guid = Guid::from_bytes([
    0x0f, 0xc6, 0x3d, 0xaf, 0x84, 0x83, 0x47, 0x72, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
]);
/// Linux swap type GUID.
pub const LINUX_SWAP: Guid = Guid::from_bytes([
    0x06, 0x57, 0xfd, 0x6d, 0xa4, 0xab, 0x43, 0xc4, 0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f,
]);
/// Lossless fixed-width GPT UTF-16 name, including bytes following a terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GptName([u16; 36]);
impl Default for GptName {
    fn default() -> Self {
        Self([0; 36])
    }
}
/// A name contains a NUL or exceeds 36 UTF-16 code units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NameError;
impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GPT name contains NUL or exceeds 36 UTF-16 units")
    }
}
impl crate::platform::error::Error for NameError {}
impl GptName {
    /// Preserve all raw code units without attempting Unicode decoding.
    pub const fn from_raw(raw: [u16; 36]) -> Self {
        Self(raw)
    }
    /// Borrow all raw code units.
    pub const fn raw(&self) -> &[u16; 36] {
        &self.0
    }
    /// Decode the name up to its first NUL, reporting malformed UTF-16.
    pub fn to_string(&self) -> Result<String, crate::platform::string::FromUtf16Error> {
        let end = self.0.iter().position(|&c| c == 0).unwrap_or(36);
        String::from_utf16(&self.0[..end])
    }
    /// Replace a name atomically without truncation, clearing unused code units.
    pub fn set(&mut self, name: &str) -> Result<(), NameError> {
        let units: Vec<_> = name.encode_utf16().collect();
        if units.len() > 36 || units.contains(&0) {
            return Err(NameError);
        }
        let mut raw = [0; 36];
        raw[..units.len()].copy_from_slice(&units);
        self.0 = raw;
        Ok(())
    }
}
/// GPT attribute bits; unknown bits remain intact during helper mutations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GptAttributes(u64);
impl GptAttributes {
    /// Preserve raw attribute bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    /// Return every attribute bit.
    pub const fn bits(self) -> u64 {
        self.0
    }
    fn set_bit(&mut self, bit: u32, value: bool) {
        if value {
            self.0 |= 1 << bit
        } else {
            self.0 &= !(1 << bit)
        }
    }
    /// Set the platform-required partition flag.
    pub fn set_required(&mut self, value: bool) {
        self.set_bit(0, value)
    }
    /// Set the flag prohibiting firmware block-I/O exposure.
    pub fn set_no_block_io(&mut self, value: bool) {
        self.set_bit(1, value)
    }
    /// Set the legacy BIOS bootable flag.
    pub fn set_legacy_boot(&mut self, value: bool) {
        self.set_bit(2, value)
    }
    /// Set Microsoft's type-specific read-only bit for basic-data partitions.
    pub fn set_read_only(&mut self, kind: Guid, value: bool) -> Result<(), GuidError> {
        if kind != MICROSOFT_BASIC_DATA {
            return Err(GuidError);
        }
        self.set_bit(60, value);
        Ok(())
    }
    /// Set Microsoft's type-specific hidden bit for basic-data partitions.
    pub fn set_hidden(&mut self, kind: Guid, value: bool) -> Result<(), GuidError> {
        if kind != MICROSOFT_BASIC_DATA {
            return Err(GuidError);
        }
        self.set_bit(62, value);
        Ok(())
    }
    /// Set Microsoft's type-specific no-default-drive-letter bit.
    pub fn set_no_drive_letter(&mut self, kind: Guid, value: bool) -> Result<(), GuidError> {
        if kind != MICROSOFT_BASIC_DATA {
            return Err(GuidError);
        }
        self.set_bit(63, value);
        Ok(())
    }
}
