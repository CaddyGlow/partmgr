//! Bounded native ext4 xattr structure validation; values and ACL encodings remain opaque.
use super::{invalid, u16le, u32le, unsupported};
use crate::fs_core::Resources;
use std::io;
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
#[cfg(test)]
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
