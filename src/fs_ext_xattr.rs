//! Bounded native ext4 xattr structure validation; values and ACL encodings remain opaque.
use super::{invalid, u16le, u32le, unsupported};
use crate::fs_core::Resources;
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
#[derive(Debug, PartialEq, Eq)]
pub(super) struct XattrSummary {
    pub entries: usize,
    pub reference_count: u32,
    pub security_namespaces: bool,
}
pub(super) fn validate(
    bytes: &[u8],
    header: usize,
    external: bool,
    resources: &Resources,
) -> io::Result<XattrSummary> {
    resources.cancellation.check().map_err(io::Error::other)?;
    if external && (!matches!(bytes.len(), 1024 | 2048 | 4096) || header != 0)
        || !external && (bytes.len() != 256 || header < 128 || !header.is_multiple_of(4))
    {
        return Err(unsupported("ext xattr storage profile"));
    }
    let header_size = if external { 32 } else { 4 };
    let start = header
        .checked_add(header_size)
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| invalid("ext xattr header bounds"))?;
    if u32le(bytes, header) != 0xea020000 {
        return Err(invalid("ext xattr header magic"));
    }
    let references = if external { u32le(bytes, 4) } else { 1 };
    if external
        && (references == 0
            || references > 1024
            || u32le(bytes, 8) != 1
            || bytes[20..32].iter().any(|byte| *byte != 0))
    {
        return Err(unsupported(
            "ext xattr reference count/blocks/reserved fields",
        ));
    }
    let _scratch = resources.memory.reserve(16384).map_err(io::Error::other)?;
    let base = if external { 0 } else { start };
    let mut names = [(0u8, 0usize, 0usize); 256];
    let mut values = [(0usize, 0usize); 256];
    let mut count = 0;
    let mut at = start;
    let mut security = false;
    loop {
        resources.cancellation.check().map_err(io::Error::other)?;
        if at.checked_add(4).is_none_or(|end| end > bytes.len()) {
            return Err(invalid("ext xattr entry terminator bounds"));
        }
        if u32le(bytes, at) == 0 {
            break;
        }
        if count == 256 || at.checked_add(16).is_none_or(|end| end > bytes.len()) {
            return Err(invalid("ext xattr entry bounds/count"));
        }
        let length = usize::from(bytes[at]);
        let index = bytes[at + 1];
        let end = at
            .checked_add(16 + length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid("ext xattr native name bounds"))?;
        let name = &bytes[at + 16..end];
        if (index == 0 && name.is_empty()) || name.contains(&0) {
            return Err(invalid("ext xattr native name encoding"));
        }
        if u32le(bytes, at + 4) != 0 {
            return Err(unsupported("ext xattr external value inode"));
        }
        for &(previous_index, previous_start, previous_end) in &names[..count] {
            if previous_index == index && &bytes[previous_start..previous_end] == name {
                return Err(invalid("ext xattr duplicate native key"));
            }
        }
        if external && count != 0 {
            let previous = names[count - 1];
            let previous_name = &bytes[previous.1..previous.2];
            if (previous.0, previous_name.len(), previous_name) >= (index, length, name) {
                return Err(invalid("ext external xattr key order"));
            }
        }
        names[count] = (index, at + 16, end);
        let size = u32le(bytes, at + 8) as usize;
        let offset = usize::from(u16le(bytes, at + 2));
        if size != 0 {
            if !offset.is_multiple_of(4) {
                return Err(invalid("ext xattr value alignment"));
            }
            let value_start = base
                .checked_add(offset)
                .ok_or_else(|| invalid("ext xattr value offset overflow"))?;
            let value_end = value_start
                .checked_add(size)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| invalid("ext xattr value bounds"))?;
            if value_end.next_multiple_of(4) > bytes.len() {
                return Err(invalid("ext xattr padded value bounds"));
            }
            for &(left, right) in &values[..count] {
                if left != right && value_start < right && left < value_end {
                    return Err(unsupported("ext xattr shared/overlapping value storage"));
                }
            }
            values[count] = (value_start, value_end);
        }
        security |= matches!(index, 2 | 3 | 6 | 8 | 9);
        count += 1;
        at = end.next_multiple_of(4);
    }
    for &(left, right) in &values[..count] {
        if left != right && left < at + 4 {
            return Err(invalid("ext xattr values overlap entry table"));
        }
    }
    Ok(XattrSummary {
        entries: count,
        reference_count: references,
        security_namespaces: security,
    })
}
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn r(bytes: u64) -> Resources {
        Resources {
            memory: Budget::new(bytes),
            cancellation: Cancellation::default(),
        }
    }
    fn w(b: &mut [u8], at: usize, value: u16) {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn d(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture(external: bool) -> (Vec<u8>, usize) {
        let mut b = vec![0; if external { 1024 } else { 256 }];
        let header = if external { 0 } else { 160 };
        let start = header + if external { 32 } else { 4 };
        d(&mut b, header, 0xea020000);
        if external {
            d(&mut b, 4, 2);
            d(&mut b, 8, 1);
        }
        b[start] = 4;
        b[start + 1] = 1;
        b[start + 16..start + 20].copy_from_slice(&[b'x', 255, b'a', b'b']);
        let value = b.len() - 8;
        w(
            &mut b,
            start + 2,
            (value - if external { 0 } else { start }) as u16,
        );
        d(&mut b, start + 8, 5);
        b[value..value + 5].copy_from_slice(b"value");
        (b, header)
    }
    #[cfg(feature = "std")]
    #[test]
    fn inline_and_external_native_names_values_bounds_cancel_and_refunds() {
        for external in [false, true] {
            let (image, header) = fixture(external);
            let resources = r(32768);
            assert_eq!(
                validate(&image, header, external, &resources).unwrap(),
                XattrSummary {
                    entries: 1,
                    reference_count: if external { 2 } else { 1 },
                    security_namespaces: false
                }
            );
            assert_eq!(resources.memory.used(), 0);
            let start = header + if external { 32 } else { 4 };
            for (offset, value, short) in [
                (start + 4, 77, false),
                (start + 8, u32::MAX, false),
                (start + 2, 1, true),
                (start + 2, 4, true),
            ] {
                let mut bad = image.clone();
                if short {
                    w(&mut bad, offset, value as u16)
                } else {
                    d(&mut bad, offset, value)
                }
                assert!(validate(&bad, header, external, &resources).is_err());
                assert_eq!(resources.memory.used(), 0);
            }
            let low = r(1);
            assert!(validate(&image, header, external, &low).is_err());
            assert_eq!(low.memory.used(), 0);
            resources.cancellation.cancel();
            assert!(validate(&image, header, external, &resources).is_err());
            assert_eq!(resources.memory.used(), 0);
        }
    }
}

/// Limits for read-only observations; validation remains independent of ownership admission.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(super) struct ObservationLimits {
    pub bytes: usize,
    pub entries: usize,
    pub value_bytes: usize,
    pub work: usize,
}
/// Borrowed native key/value, retaining uninterpreted namespaces byte-for-byte.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Observation<'a> {
    pub index: u8,
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub entry_hash: u32,
}
#[allow(dead_code)]
impl<'a> Observation<'a> {
    /// Only ext4-native access/default ACL keys (indices 2/3, empty name).
    pub fn acl(
        &self,
        limits: super::acl::Limits,
        r: &Resources,
    ) -> io::Result<Option<super::acl::Acl<'a>>> {
        if matches!(self.index, 2 | 3) {
            if !self.name.is_empty() {
                return Err(invalid("ext ACL xattr key must have empty name"));
            }
            return super::acl::decode(self.value, limits, r).map(Some);
        }
        Ok(None)
    }
}
#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct Observations<'a> {
    bytes: &'a [u8],
    start: usize,
    base: usize,
    count: usize,
    pub reference_count: u32,
}
#[allow(dead_code)]
impl<'a> Observations<'a> {
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn entries(&self) -> impl Iterator<Item = Observation<'a>> + '_ {
        let mut at = self.start;
        let mut left = self.count;
        core::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            let length = usize::from(self.bytes[at]);
            let size = u32le(self.bytes, at + 8) as usize;
            let offset = self.base + usize::from(u16le(self.bytes, at + 2));
            let item = Observation {
                index: self.bytes[at + 1],
                name: &self.bytes[at + 16..at + 16 + length],
                // Native empty values have no required valid offset.
                value: if size == 0 {
                    &self.bytes[0..0]
                } else {
                    &self.bytes[offset..offset + size]
                },
                entry_hash: u32le(self.bytes, at + 12),
            };
            at = (at + 16 + length).next_multiple_of(4);
            left -= 1;
            Some(item)
        })
    }
}
/// Validate bounded structure before exposing borrowed observations. Neither
/// CRC nor refcount ownership is established here; callers retain those audits.
#[allow(dead_code)]
pub(super) fn observe<'a>(
    bytes: &'a [u8],
    header: usize,
    external: bool,
    limits: ObservationLimits,
    r: &Resources,
) -> io::Result<Observations<'a>> {
    r.cancellation.check().map_err(io::Error::other)?;
    if bytes.len() > limits.bytes {
        return Err(unsupported("ext xattr observation byte ceiling"));
    }
    // Existing validator scans <=256 entries, comparing each previous native key.
    // Preflight a conservative bound before any scan/scratch reservation.
    let work = bytes
        .len()
        .checked_mul(258)
        .ok_or_else(|| unsupported("ext xattr observation work overflow"))?;
    if work > limits.work {
        return Err(unsupported("ext xattr observation work ceiling"));
    }
    let summary = validate(bytes, header, external, r)?;
    if summary.entries > limits.entries {
        return Err(unsupported("ext xattr observation entry ceiling"));
    }
    let start = header + if external { 32 } else { 4 };
    let result = Observations {
        bytes,
        start,
        base: if external { 0 } else { start },
        count: summary.entries,
        reference_count: summary.reference_count,
    };
    let mut total = 0usize;
    for item in result.entries() {
        r.cancellation.check().map_err(io::Error::other)?;
        total = total
            .checked_add(item.value.len())
            .filter(|n| *n <= limits.value_bytes)
            .ok_or_else(|| unsupported("ext xattr observation value ceiling"))?;
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(result)
}
#[cfg(all(test, feature = "std"))]
mod observation_tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn r() -> Resources {
        Resources {
            memory: Budget::new(16384),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> ObservationLimits {
        ObservationLimits {
            bytes: 4096,
            entries: 256,
            value_bytes: 4096,
            work: 4096 * 258,
        }
    }
    fn fixture(external: bool) -> (Vec<u8>, usize) {
        let mut b = vec![0; if external { 1024 } else { 256 }];
        let header = if external { 0 } else { 160 };
        let start = header + if external { 32 } else { 4 };
        b[header..header + 4].copy_from_slice(&0xea020000u32.to_le_bytes());
        if external {
            b[4..8].copy_from_slice(&2u32.to_le_bytes());
            b[8..12].copy_from_slice(&1u32.to_le_bytes());
        }
        b[start + 1] = 2;
        let value = b.len() - 16;
        b[start + 2..start + 4]
            .copy_from_slice(&((value - if external { 0 } else { start }) as u16).to_le_bytes());
        b[start + 8..start + 12].copy_from_slice(&16u32.to_le_bytes());
        b[value..value + 4].copy_from_slice(&1u32.to_le_bytes());
        for (n, (tag, perm)) in [(1u16, 7u16), (4, 5), (32, 0)].into_iter().enumerate() {
            let at = value + 4 + n * 4;
            b[at..at + 2].copy_from_slice(&tag.to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&perm.to_le_bytes());
        }
        (b, header)
    }
    #[test]
    fn inline_external_observations_decode_acl_without_mutation_or_retained_allocations() {
        for external in [false, true] {
            let (b, h) = fixture(external);
            let before = b.clone();
            let r = r();
            let obs = observe(&b, h, external, limits(), &r).unwrap();
            assert_eq!(obs.len(), 1);
            assert_eq!(obs.reference_count, if external { 2 } else { 1 });
            let item = obs.entries().next().unwrap();
            assert!(item.name.is_empty());
            let acl = item
                .acl(
                    super::super::acl::Limits {
                        bytes: 1024,
                        entries: 64,
                        work: 4096,
                    },
                    &r,
                )
                .unwrap()
                .unwrap();
            assert_eq!(acl.mode(), Some(0o750));
            assert_eq!(b, before);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn observations_enforce_work_entry_value_memory_and_cancel_ceilings() {
        let (b, h) = fixture(true);
        let r = r();
        for l in [
            ObservationLimits {
                work: 0,
                ..limits()
            },
            ObservationLimits {
                bytes: 0,
                ..limits()
            },
            ObservationLimits {
                entries: 0,
                ..limits()
            },
            ObservationLimits {
                value_bytes: 15,
                ..limits()
            },
        ] {
            assert!(observe(&b, h, true, l, &r).is_err());
            assert_eq!(r.memory.used(), 0);
        }
        let low = Resources {
            memory: Budget::new(0),
            cancellation: Cancellation::default(),
        };
        assert!(observe(&b, h, true, limits(), &low).is_err());
        r.cancellation.cancel();
        assert!(observe(&b, h, true, limits(), &r).is_err());
    }
}
