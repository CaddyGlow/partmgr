//! Bounded native Windows self-relative security descriptor inspection.
//! Structural parsing does not evaluate access, resolve accounts, or grant restore authority.
use crate::fs_core::*;
use crate::platform::ops::Range;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

/// Explicit descriptor-byte, total ACE and structural-work ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsSecurityLimits {
    /// Maximum retained descriptor bytes.
    pub bytes: usize,
    /// Maximum ACEs across SACL and DACL.
    pub aces: usize,
    /// Maximum structural visits, including SID subauthorities.
    pub work: u64,
}
/// Lossless native descriptor with a shared lease for its copied bytes.
pub struct NtfsSecurityDescriptor {
    raw: Vec<u8>,
    owner: Option<Range<usize>>,
    group: Option<Range<usize>>,
    sacl: AclRange,
    dacl: AclRange,
    _lease: Reservation,
}
enum AclRange {
    Absent,
    Null,
    Present(Range<usize>),
}
/// The three distinct native ACL states. Present includes an empty ACL.
pub enum NtfsAclPresence<'a> {
    /// Corresponding PRESENT control bit is clear; its stored offset is ignored.
    Absent,
    /// PRESENT control bit is set and the stored offset is zero.
    Null,
    /// PRESENT control bit is set and a validated ACL is stored, possibly empty.
    Present(NtfsAcl<'a>),
}
/// Borrowed native SID. Identifier authority is big endian; subauthorities are little endian.
#[derive(Clone, Copy)]
pub struct NtfsSid<'a> {
    raw: &'a [u8],
}
impl<'a> NtfsSid<'a> {
    /// Exact native SID bytes.
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    /// Native revision.
    pub fn revision(self) -> u8 {
        self.raw[0]
    }
    /// Numeric 48-bit identifier authority.
    pub fn authority(self) -> u64 {
        self.raw[2..8]
            .iter()
            .fold(0, |a, b| (a << 8) | u64::from(*b))
    }
    /// Ordered numeric native subauthorities.
    pub fn subauthorities(self) -> impl ExactSizeIterator<Item = u32> + 'a {
        self.raw[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|v| u32::from_le_bytes(*v))
    }
}
/// Borrowed ACL; ACEs retain their native order, flags, and opaque bytes.
#[derive(Clone, Copy)]
pub struct NtfsAcl<'a> {
    raw: &'a [u8],
}
impl<'a> NtfsAcl<'a> {
    /// Complete native ACL bytes, including unused trailing allocation.
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    /// Native ACL revision (2 or 4).
    pub fn revision(self) -> u8 {
        self.raw[0]
    }
    /// Native ACE count.
    pub fn ace_count(self) -> usize {
        usize::from(word(self.raw, 4))
    }
    /// ACEs in their original order. All ranges were checked by the parser.
    pub fn aces(self) -> impl Iterator<Item = NtfsAce<'a>> {
        let mut at = 8;
        (0..self.ace_count()).map(move |_| {
            let end = at + usize::from(word(self.raw, at + 2));
            let ace = NtfsAce {
                raw: &self.raw[at..end],
            };
            at = end;
            ace
        })
    }
}
/// Borrowed ACE. Unknown types remain opaque and are never silently discarded.
#[derive(Clone, Copy)]
pub struct NtfsAce<'a> {
    raw: &'a [u8],
}
impl<'a> NtfsAce<'a> {
    /// Exact native ACE header and payload.
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    /// Native type, including unknown values.
    pub fn kind(self) -> u8 {
        self.raw[0]
    }
    /// Exact native inheritance/auditing flags; no canonicalization.
    pub fn flags(self) -> u8 {
        self.raw[1]
    }
    /// Verified native access mask for supported structural layouts.
    pub fn mask(self) -> Option<u32> {
        layout(self.raw).map(|_| dword(self.raw, 4))
    }
    /// Native trustee SID for supported structural layouts.
    pub fn trustee(self) -> Option<NtfsSid<'a>> {
        layout(self.raw).map(|(at, _)| NtfsSid {
            raw: &self.raw[at..at + 8 + usize::from(self.raw[at + 1]) * 4],
        })
    }
    /// Native object flags when this is an object ACE.
    pub fn object_flags(self) -> Option<u32> {
        object(self.kind()).then(|| dword(self.raw, 8))
    }
    /// Exact native GUID bytes, without string conversion.
    pub fn object_type(self) -> Option<&'a [u8]> {
        self.object_flags()
            .filter(|f| f & 1 != 0)
            .map(|_| &self.raw[12..28])
    }
    /// Exact native inherited-object GUID bytes.
    pub fn inherited_object_type(self) -> Option<&'a [u8]> {
        self.object_flags().filter(|f| f & 2 != 0).map(|f| {
            let at = 12 + if f & 1 != 0 { 16 } else { 0 };
            &self.raw[at..at + 16]
        })
    }
    /// Uninterpreted callback/resource/filter application bytes after the trustee.
    /// Unknown ACE types return their entire opaque body after the ACE header.
    pub fn opaque_payload(self) -> &'a [u8] {
        match layout(self.raw) {
            Some((at, _)) => &self.raw[at + 8 + usize::from(self.raw[at + 1]) * 4..],
            None => &self.raw[4..],
        }
    }
}
fn word(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn dword(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn ceiling(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn object(k: u8) -> bool {
    matches!(k, 5..=8 | 11 | 12 | 15 | 16)
}
fn layout(b: &[u8]) -> Option<(usize, bool)> {
    let k = b[0];
    let trailing = matches!(k, 9..=16 | 18 | 21);
    if object(k) {
        let f = dword(b, 8);
        Some((
            12 + if f & 1 != 0 { 16 } else { 0 } + if f & 2 != 0 { 16 } else { 0 },
            trailing,
        ))
    } else if matches!(k,0..=3|9|10|13|14|17..=21) {
        Some((8, trailing))
    } else {
        None
    }
}
struct Work<'a> {
    left: u64,
    aces: usize,
    limits: NtfsSecurityLimits,
    r: &'a Resources,
}
impl Work<'_> {
    fn tick(&mut self, n: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.left = self
            .left
            .checked_sub(n)
            .ok_or_else(|| ceiling("NTFS security structural work ceiling"))?;
        Ok(())
    }
    fn sid(&mut self, b: &[u8], at: usize) -> Result<Range<usize>> {
        self.tick(1)?;
        let h = b
            .get(
                at..at
                    .checked_add(8)
                    .ok_or_else(|| invalid("SID offset overflow"))?,
            )
            .ok_or_else(|| invalid("SID header bounds"))?;
        if h[0] != 1 || h[1] > 15 {
            return Err(invalid("SID revision/subauthority count"));
        }
        self.tick(u64::from(h[1]))?;
        let end = at + 8 + usize::from(h[1]) * 4;
        if end > b.len() {
            return Err(invalid("SID subauthority bounds"));
        }
        Ok(at..end)
    }
    fn acl(&mut self, b: &[u8], offset: usize, present: bool) -> Result<AclRange> {
        if !present {
            return Ok(AclRange::Absent);
        }
        if offset == 0 {
            return Ok(AclRange::Null);
        }
        self.tick(1)?;
        let h = b
            .get(
                offset
                    ..offset
                        .checked_add(8)
                        .ok_or_else(|| invalid("ACL offset overflow"))?,
            )
            .ok_or_else(|| invalid("ACL header bounds"))?;
        if !matches!(h[0], 2 | 4) || h[1] != 0 || word(h, 6) != 0 {
            return Err(invalid("ACL revision/reserved fields"));
        }
        let size = usize::from(word(h, 2));
        if size < 8 || !size.is_multiple_of(4) {
            return Err(invalid("ACL size/alignment"));
        }
        let end = offset
            .checked_add(size)
            .filter(|x| *x <= b.len())
            .ok_or_else(|| invalid("ACL range"))?;
        let acl = &b[offset..end];
        let count = usize::from(word(h, 4));
        self.aces = self
            .aces
            .checked_add(count)
            .filter(|x| *x <= self.limits.aces)
            .ok_or_else(|| ceiling("NTFS security ACE ceiling"))?;
        let mut at = 8;
        for _ in 0..count {
            self.tick(1)?;
            let h = acl
                .get(at..at + 4)
                .ok_or_else(|| invalid("ACE header bounds"))?;
            let size = usize::from(word(h, 2));
            if size < 4 || !size.is_multiple_of(4) {
                return Err(invalid("ACE size/alignment"));
            }
            let next = at
                .checked_add(size)
                .filter(|x| *x <= acl.len())
                .ok_or_else(|| invalid("ACE range"))?;
            let ace = &acl[at..next];
            if object(ace[0]) && (ace.len() < 12 || dword(ace, 8) & !3 != 0) {
                return Err(invalid("object ACE fields"));
            }
            if let Some((sid, trailing)) = layout(ace) {
                let parsed = self.sid(ace, sid)?;
                if !trailing && parsed.end != ace.len() {
                    return Err(invalid("ACE trailing bytes"));
                }
            }
            at = next;
        }
        Ok(AclRange::Present(offset..end))
    }
}
impl NtfsSecurityDescriptor {
    /// Copy and validate a self-relative descriptor under explicit/shared ceilings.
    /// Unknown ACE bodies remain inspectable as opaque bytes, not access decisions.
    pub fn parse(bytes: &[u8], limits: NtfsSecurityLimits, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        if bytes.len() > limits.bytes {
            return Err(ceiling("NTFS security descriptor byte ceiling"));
        }
        if bytes.len() < 20 || bytes[0] != 1 || word(bytes, 2) & 0x8000 == 0 {
            return Err(invalid("self-relative security descriptor header"));
        }
        let offsets = [
            dword(bytes, 4),
            dword(bytes, 8),
            dword(bytes, 12),
            dword(bytes, 16),
        ];
        for (index, off) in offsets.into_iter().enumerate() {
            if index == 2 && word(bytes, 2) & 0x10 == 0 || index == 3 && word(bytes, 2) & 4 == 0 {
                continue;
            }
            if off != 0
                && (off < 20 || !off.is_multiple_of(4) || u64::from(off) >= bytes.len() as u64)
            {
                return Err(invalid("security descriptor component offset"));
            }
        }
        let mut w = Work {
            left: limits.work,
            aces: 0,
            limits,
            r,
        };
        w.tick(1)?;
        let owner = if offsets[0] == 0 {
            None
        } else {
            Some(w.sid(bytes, offsets[0] as usize)?)
        };
        let group = if offsets[1] == 0 {
            None
        } else {
            Some(w.sid(bytes, offsets[1] as usize)?)
        };
        let control = word(bytes, 2);
        let sacl = w.acl(bytes, offsets[2] as usize, control & 0x10 != 0)?;
        let dacl = w.acl(bytes, offsets[3] as usize, control & 4 != 0)?;
        let lease = r.memory.reserve(
            (bytes.len() as u64)
                .checked_add(256)
                .ok_or_else(|| ceiling("security descriptor reservation"))?,
        )?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(bytes.len())
            .map_err(|_| ceiling("security descriptor allocation"))?;
        raw.extend_from_slice(bytes);
        r.cancellation.check()?;
        Ok(Self {
            raw,
            owner,
            group,
            sacl,
            dacl,
            _lease: lease,
        })
    }
    /// Complete unchanged native bytes, including padding and uninterpreted fields.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Exact native descriptor control bits.
    pub fn control(&self) -> u16 {
        word(&self.raw, 2)
    }
    /// Resource-manager control byte (meaning depends on SE_RM_CONTROL_VALID).
    pub fn resource_manager_control(&self) -> u8 {
        self.raw[1]
    }
    /// Owner SID, without account-name or POSIX-ID mapping.
    pub fn owner(&self) -> Option<NtfsSid<'_>> {
        self.owner.clone().map(|r| NtfsSid { raw: &self.raw[r] })
    }
    /// Primary group SID, without account-name or POSIX-ID mapping.
    pub fn group(&self) -> Option<NtfsSid<'_>> {
        self.group.clone().map(|r| NtfsSid { raw: &self.raw[r] })
    }
    fn acl(&self, r: &AclRange) -> NtfsAclPresence<'_> {
        match r {
            AclRange::Absent => NtfsAclPresence::Absent,
            AclRange::Null => NtfsAclPresence::Null,
            AclRange::Present(r) => NtfsAclPresence::Present(NtfsAcl {
                raw: &self.raw[r.clone()],
            }),
        }
    }
    /// Audit ACL, retaining absent/null/empty distinctions.
    pub fn sacl(&self) -> NtfsAclPresence<'_> {
        self.acl(&self.sacl)
    }
    /// Discretionary ACL, retaining absent/null/empty distinctions.
    pub fn dacl(&self) -> NtfsAclPresence<'_> {
        self.acl(&self.dacl)
    }
}

#[path = "fs_ntfs_secure.rs"]
mod secure;
pub use secure::*;
