//! Read-only ext4 native ACL v1 decoding. This is not the generic POSIX xattr v2 wire format.
use super::{invalid, unsupported};
use crate::fs_core::Resources;
use crate::platform::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tag {
    Owner,
    User(u32),
    GroupOwner,
    Group(u32),
    Mask,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub tag: Tag,
    pub permissions: u8,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub bytes: usize,
    pub entries: usize,
    pub work: usize,
}
/// Borrowed validated native bytes; no memory allocation or ownership authority.
#[derive(Debug)]
pub(super) struct Acl<'a> {
    raw: &'a [u8],
    count: usize,
    mode: Option<u16>,
}
impl<'a> Acl<'a> {
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    pub fn len(&self) -> usize {
        self.count
    }
    /// Permission bits derived from owner, mask (or group), and other.
    pub fn mode(&self) -> Option<u16> {
        self.mode
    }
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        let mut at = 4;
        core::iter::from_fn(move || {
            if at == self.raw.len() {
                return None;
            }
            let (entry, width) = entry(&self.raw[at..]).ok()?;
            at += width;
            Some(entry)
        })
    }
}
fn word(raw: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([raw[at], raw[at + 1]])
}
fn entry(raw: &[u8]) -> io::Result<(Entry, usize)> {
    if raw.len() < 4 {
        return Err(invalid("ext ACL short entry"));
    }
    let permissions = word(raw, 2);
    if permissions & !7 != 0 {
        return Err(invalid("ext ACL permission bits"));
    }
    let tag = word(raw, 0);
    let named = matches!(tag, 2 | 8);
    if named && raw.len() < 8 {
        return Err(invalid("ext ACL short named entry"));
    }
    let id = if named {
        u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]])
    } else {
        0
    };
    if named && id == u32::MAX {
        return Err(invalid("ext ACL undefined named identity"));
    }
    let tag = match tag {
        1 => Tag::Owner,
        2 => Tag::User(id),
        4 => Tag::GroupOwner,
        8 => Tag::Group(id),
        16 => Tag::Mask,
        32 => Tag::Other,
        _ => return Err(invalid("ext ACL unknown tag")),
    };
    Ok((
        Entry {
            tag,
            permissions: permissions as u8,
        },
        if named { 8 } else { 4 },
    ))
}
/// Validate native POSIX tag-group order, IDs and mandatory mask before exposing entries.
/// A header-only native ACL is observed as empty, independently of xattr absence.
pub(super) fn decode<'a>(raw: &'a [u8], limits: Limits, r: &Resources) -> io::Result<Acl<'a>> {
    r.cancellation.check().map_err(io::Error::other)?;
    if raw.len() > limits.bytes {
        return Err(unsupported("ext ACL byte ceiling"));
    }
    if raw.len() < 4 {
        return Err(invalid("ext ACL header bounds"));
    }
    if u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) != 1 {
        return Err(unsupported(
            "ext ACL native version (generic POSIX v2 is distinct)",
        ));
    }
    let mut at = 4usize;
    let mut count = 0usize;
    let mut work = 4usize;
    if work > limits.work {
        return Err(unsupported("ext ACL work ceiling"));
    }
    let mut phase = 0;
    let mut named = false;
    let mut owner = 0u16;
    let mut group = 0u16;
    let mut mask = None;
    let mut other = 0u16;
    while at < raw.len() {
        r.cancellation.check().map_err(io::Error::other)?;
        if count == limits.entries {
            return Err(unsupported("ext ACL entry ceiling"));
        }
        // Charge before touching the next entry, including validation/comparison.
        work = work
            .checked_add(16)
            .filter(|v| *v <= limits.work)
            .ok_or_else(|| unsupported("ext ACL work ceiling"))?;
        let (e, width) = entry(&raw[at..])?;
        match e.tag {
            Tag::Owner if phase == 0 => {
                phase = 1;
                owner = u16::from(e.permissions);
            }
            Tag::User(_) if phase == 1 => {
                named = true;
            }
            Tag::GroupOwner if phase == 1 => {
                phase = 2;
                group = u16::from(e.permissions);
            }
            Tag::Group(_) if phase == 2 => {
                named = true;
            }
            Tag::Mask if phase == 2 => {
                phase = 3;
                mask = Some(u16::from(e.permissions));
            }
            Tag::Other if phase == 2 || phase == 3 => {
                phase = 4;
                other = u16::from(e.permissions);
            }
            _ => return Err(invalid("ext ACL native tag-group order")),
        }
        at += width;
        count += 1;
    }
    if count != 0 && (phase != 4 || named && mask.is_none()) {
        return Err(invalid("ext ACL required base entries/mask"));
    }
    // ext4_acl_count uses four short entries, with every excess entry eight bytes.
    let expected = 4 + if count <= 4 {
        count * 4
    } else {
        16 + (count - 4) * 8
    };
    if expected != raw.len() {
        return Err(invalid("ext ACL native entry widths"));
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(Acl {
        raw,
        count,
        mode: (count != 0).then_some((owner << 6) | (mask.unwrap_or(group) << 3) | other),
    })
}
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(0),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> Limits {
        Limits {
            bytes: 1024,
            entries: 64,
            work: 4096,
        }
    }
    fn acl(entries: &[(u16, u16, Option<u32>)]) -> Vec<u8> {
        let mut b = 1u32.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            b.extend(tag.to_le_bytes());
            b.extend(perm.to_le_bytes());
            if let Some(id) = id {
                b.extend(id.to_le_bytes());
            }
        }
        b
    }
    #[test]
    fn native_short_and_named_widths_preserve_raw_mode_and_entries() {
        let b = acl(&[
            (1, 7, None),
            (2, 5, Some(0)),
            (4, 6, None),
            (8, 2, Some(u32::MAX - 1)),
            (16, 4, None),
            (32, 1, None),
        ]);
        let r = resources();
        let parsed = decode(&b, limits(), &r).unwrap();
        assert_eq!(parsed.raw(), b);
        assert_eq!(parsed.len(), 6);
        assert_eq!(parsed.mode(), Some(0o741));
        assert_eq!(parsed.entries().count(), 6);
        assert_eq!(r.memory.used(), 0);
        let short = acl(&[(1, 7, None), (4, 5, None), (32, 0, None)]);
        assert_eq!(decode(&short, limits(), &r).unwrap().mode(), Some(0o750));
        assert_eq!(
            decode(&1u32.to_le_bytes(), limits(), &r).unwrap().mode(),
            None
        );
    }
    #[test]
    fn generic_v2_unknown_tags_and_malformed_widths_are_rejected() {
        let r = resources();
        let mut b = acl(&[(1, 7, None), (4, 5, None), (32, 0, None)]);
        b[0] = 2;
        assert!(decode(&b, limits(), &r).is_err());
        b[0] = 1;
        for n in 0..b.len() {
            if n != 4 {
                assert!(decode(&b[..n], limits(), &r).is_err());
            }
        }
        b[4] = 3;
        assert!(decode(&b, limits(), &r).is_err());
        let b = acl(&[(1, 7, None), (2, 5, None)]);
        assert!(decode(&b, limits(), &r).is_err());
    }
    #[test]
    fn order_mask_permissions_and_undefined_ids_are_rejected() {
        for entries in [
            vec![(1, 7, None), (2, 5, Some(1)), (4, 5, None), (32, 0, None)],
            vec![(1, 8, None), (4, 5, None), (32, 0, None)],
            vec![
                (1, 7, None),
                (2, 5, Some(u32::MAX)),
                (4, 5, None),
                (16, 5, None),
                (32, 0, None),
            ],
            vec![(1, 7, None), (4, 5, None), (32, 0, None), (16, 5, None)],
        ] {
            assert!(decode(&acl(&entries), limits(), &resources()).is_err());
        }
    }
    #[test]
    fn native_valid_unsorted_duplicate_named_ids_preserve_original_order() {
        let b = acl(&[
            (1, 7, None),
            (2, 5, Some(9)),
            (2, 4, Some(1)),
            (2, 3, Some(1)),
            (4, 5, None),
            (8, 2, Some(8)),
            (8, 1, Some(8)),
            (16, 5, None),
            (32, 0, None),
        ]);
        let r = resources();
        let parsed = decode(&b, limits(), &r).unwrap();
        let ids: Vec<_> = parsed
            .entries()
            .filter_map(|e| match e.tag {
                Tag::User(id) | Tag::Group(id) => Some(id),
                _ => None,
            })
            .collect();
        assert_eq!(ids, [9, 1, 1, 8, 8]);
        assert_eq!(parsed.raw(), b);
        assert_eq!(parsed.mode(), Some(0o750));
    }
    #[test]
    fn limits_and_cancellation_refuse_without_memory() {
        let b = acl(&[(1, 7, None), (4, 5, None), (32, 0, None)]);
        let r = resources();
        for l in [
            Limits {
                bytes: b.len() - 1,
                ..limits()
            },
            Limits {
                entries: 2,
                ..limits()
            },
            Limits {
                work: 51,
                ..limits()
            },
        ] {
            assert!(decode(&b, l, &r).is_err());
        }
        assert!(
            decode(
                &b,
                Limits {
                    work: 52,
                    ..limits()
                },
                &r
            )
            .is_ok()
        );
        r.cancellation.cancel();
        assert!(decode(&b, limits(), &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
}
