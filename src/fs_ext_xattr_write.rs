//! Private deterministic external-xattr COW encoding. No publication authority.
use super::{invalid, unsupported, xattr};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use crate::platform::prelude::*;
use crate::{
    fs_core::{Reservation, Resources},
    platform::io,
};
#[derive(Clone, Copy, Debug)]
pub(super) enum SetPolicy {
    Create,
    Replace,
    Upsert,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Mutation<'a> {
    Set { value: &'a [u8], policy: SetPolicy },
    Remove,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub entries: usize,
    pub value_bytes: usize,
    pub work: usize,
}
pub(super) struct EncodedBlock {
    bytes: Vec<u8>,
    _lease: Reservation,
}
impl crate::platform::ops::Deref for EncodedBlock {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.bytes
    }
}
impl crate::platform::ops::DerefMut for EncodedBlock {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}
pub(super) struct Rewrite {
    pub changed: bool,
    pub block: Option<EncodedBlock>,
}
#[derive(Clone, Copy)]
struct Attr<'a> {
    index: u8,
    name: &'a [u8],
    value: &'a [u8],
}
struct Work<'a> {
    used: usize,
    maximum: usize,
    r: &'a Resources,
}
impl Work<'_> {
    fn charge(&mut self, n: usize) -> io::Result<()> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        self.used = self
            .used
            .checked_add(n)
            .filter(|v| *v <= self.maximum)
            .ok_or_else(|| unsupported("ext xattr encoding work ceiling"))?;
        Ok(())
    }
}
fn put32(bytes: &mut [u8], at: usize, v: u32) {
    bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put16(bytes: &mut [u8], at: usize, v: u16) {
    bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
/// Exact unsigned-name/native little-endian word hash, including zero padding.
fn entry_hash(name: &[u8], value: &[u8], work: &mut Work<'_>) -> io::Result<u32> {
    let mut hash = 0u32;
    for &b in name {
        work.charge(1)?;
        hash = hash.rotate_left(5) ^ u32::from(b);
    }
    for chunk in value.chunks(4) {
        work.charge(4)?;
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        hash = hash.rotate_left(16) ^ u32::from_le_bytes(word);
    }
    Ok(hash)
}
/// Ordinary user namespace only. ACL/security/trusted/system keys cannot enter
/// this mutation API; their existing exact values are retained opaquely in COW.
pub(super) fn rewrite<'a>(
    old: Option<&'a [u8]>,
    block_bytes: usize,
    name: &'a [u8],
    mutation: Mutation<'a>,
    limits: Limits,
    r: &Resources,
) -> io::Result<Rewrite> {
    let mut work = Work {
        used: 0,
        maximum: limits.work,
        r,
    };
    work.charge(1)?;
    if !matches!(block_bytes, 1024 | 2048 | 4096) {
        return Err(unsupported("ext xattr COW block profile"));
    }
    if name.is_empty() || name.len() > 255 || name.contains(&0) {
        return Err(invalid("ext user xattr native name"));
    }
    if limits.entries > 256 {
        return Err(unsupported("ext xattr COW entry profile ceiling"));
    }
    if let Mutation::Set { value, .. } = mutation
        && value.len() > limits.value_bytes
    {
        return Err(unsupported("ext xattr COW requested value ceiling"));
    }
    let capacity = limits.entries;
    let bytes = capacity
        .checked_mul(core::mem::size_of::<Attr<'_>>())
        .ok_or_else(|| unsupported("ext xattr COW inventory overflow"))?;
    let _inventory = r.memory.reserve(bytes as u64).map_err(io::Error::other)?;
    let mut attrs = Vec::new();
    attrs
        .try_reserve_exact(capacity)
        .map_err(io::Error::other)?;
    if attrs.capacity() > capacity {
        return Err(unsupported("ext xattr COW inventory capacity"));
    }
    if let Some(old) = old {
        if old.len() != block_bytes {
            return Err(invalid("ext xattr COW source block geometry"));
        }
        work.charge(
            block_bytes
                .checked_mul(258)
                .ok_or_else(|| unsupported("ext xattr COW validation overflow"))?,
        )?;
        let view = xattr::observe(
            old,
            0,
            true,
            xattr::ObservationLimits {
                bytes: block_bytes,
                entries: capacity,
                value_bytes: limits.value_bytes,
                work: work.maximum,
            },
            r,
        )?;
        for attr in view.entries() {
            work.charge(1)?;
            if attrs.len() == capacity {
                return Err(unsupported("ext xattr COW entry ceiling"));
            }
            attrs.push(Attr {
                index: attr.index,
                name: attr.name,
                value: attr.value,
            });
        }
    }
    let mut found = None;
    for (index, attr) in attrs.iter().enumerate() {
        work.charge(attr.name.len() + 1)?;
        if attr.index == 1 && attr.name == name {
            found = Some(index);
            break;
        }
    }
    match mutation {
        Mutation::Set { value, policy } => {
            if found.is_some() && matches!(policy, SetPolicy::Create) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "ext user xattr exists",
                ));
            }
            if found.is_none() && matches!(policy, SetPolicy::Replace) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "ext user xattr absent",
                ));
            }
            if let Some(index) = found {
                work.charge(value.len())?;
                if attrs[index].value == value {
                    return Ok(Rewrite {
                        changed: false,
                        block: None,
                    });
                }
                attrs[index].value = value;
            } else {
                if attrs.len() == capacity {
                    return Err(unsupported("ext xattr COW entry ceiling"));
                }
                attrs.push(Attr {
                    index: 1,
                    name,
                    value,
                });
            }
        }
        Mutation::Remove => {
            let index = found
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ext user xattr absent"))?;
            work.charge(attrs.len())?;
            attrs.remove(index);
        }
    }
    // Pinned native libext2fs keeps a private empty external container after
    // removing the last key. Container release requires a separate policy.
    // Bounded stable insertion order matches native index/name-length/name order.
    for i in 1..attrs.len() {
        let mut j = i;
        while j > 0 {
            work.charge(attrs[j].name.len() + attrs[j - 1].name.len() + 1)?;
            let a = attrs[j - 1];
            let b = attrs[j];
            if (a.index, a.name.len(), a.name) <= (b.index, b.name.len(), b.name) {
                break;
            }
            attrs.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut total_values = 0usize;
    let mut table_end = 36usize;
    for attr in &attrs {
        work.charge(1)?;
        total_values = total_values
            .checked_add(attr.value.len())
            .filter(|v| *v <= limits.value_bytes)
            .ok_or_else(|| unsupported("ext xattr COW total value ceiling"))?;
        table_end = table_end
            .checked_add((16 + attr.name.len()).next_multiple_of(4))
            .ok_or_else(|| unsupported("ext xattr COW table overflow"))?;
    }
    let mut packed = block_bytes;
    for attr in &attrs {
        packed = packed
            .checked_sub(attr.value.len().next_multiple_of(4))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::StorageFull,
                    "ext xattr native block capacity",
                )
            })?;
    }
    if packed < table_end {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "ext xattr native block capacity",
        ));
    }
    work.charge(block_bytes)?;
    let lease = r
        .memory
        .reserve(block_bytes as u64)
        .map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(block_bytes)
        .map_err(io::Error::other)?;
    if bytes.capacity() > block_bytes {
        return Err(unsupported("ext xattr COW output capacity"));
    }
    bytes.resize(block_bytes, 0);
    let mut output = EncodedBlock {
        bytes,
        _lease: lease,
    };
    put32(&mut output, 0, 0xea020000);
    put32(&mut output, 4, 1);
    put32(&mut output, 8, 1);
    let mut at = 32usize;
    let mut end = block_bytes;
    let mut block_hash = 0u32;
    let mut unshareable = false;
    for attr in attrs {
        work.charge(attr.name.len() + attr.value.len() + 16)?;
        end -= attr.value.len().next_multiple_of(4);
        output[at] = attr.name.len() as u8;
        output[at + 1] = attr.index;
        put16(&mut output, at + 2, end as u16);
        if !attr.value.is_empty() {
            output[end..end + attr.value.len()].copy_from_slice(attr.value);
        }
        put32(&mut output, at + 8, attr.value.len() as u32);
        output[at + 16..at + 16 + attr.name.len()].copy_from_slice(attr.name);
        let hash = entry_hash(attr.name, attr.value, &mut work)?;
        put32(&mut output, at + 12, hash);
        if hash == 0 {
            unshareable = true;
        }
        block_hash = block_hash.rotate_left(16) ^ hash;
        at += (16 + attr.name.len()).next_multiple_of(4);
    }
    put32(&mut output, 12, if unshareable { 0 } else { block_hash });
    work.charge(
        block_bytes
            .checked_mul(258)
            .ok_or_else(|| unsupported("ext xattr COW result validation overflow"))?,
    )?;
    xattr::validate(&output, 0, true, r)?;
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(Rewrite {
        changed: true,
        block: Some(output),
    })
}
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn r() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> Limits {
        Limits {
            entries: 256,
            value_bytes: 4096,
            work: 4_000_000,
        }
    }
    #[test]
    fn independently_calculated_native_hash_padding_and_empty_value() {
        let r = r();
        let out = rewrite(
            None,
            1024,
            b"x",
            Mutation::Set {
                value: &[1, 2, 3],
                policy: SetPolicy::Create,
            },
            limits(),
            &r,
        )
        .unwrap();
        let block = out.block.unwrap();
        assert_eq!(&block[44..48], &0x007b0201u32.to_le_bytes());
        assert_eq!(&block[12..16], &0x007b0201u32.to_le_bytes());
        assert_eq!(&block[1020..], &[1, 2, 3, 0]);
        assert!(block[53..1020].iter().all(|b| *b == 0));
        drop(block);
        assert_eq!(r.memory.used(), 0);
        let out = rewrite(
            None,
            1024,
            b"x",
            Mutation::Set {
                value: &[],
                policy: SetPolicy::Upsert,
            },
            limits(),
            &r,
        )
        .unwrap();
        let block = out.block.unwrap();
        assert_eq!(&block[34..36], &1024u16.to_le_bytes());
        assert_eq!(&block[44..48], &120u32.to_le_bytes());
    }
    #[test]
    fn create_replace_noop_remove_and_opaque_preservation() {
        let r = r();
        let first = rewrite(
            None,
            1024,
            b"a",
            Mutation::Set {
                value: b"old",
                policy: SetPolicy::Create,
            },
            limits(),
            &r,
        )
        .unwrap()
        .block
        .unwrap();
        let baseline = first.to_vec();
        assert!(
            rewrite(
                Some(&first),
                1024,
                b"a",
                Mutation::Set {
                    value: b"new",
                    policy: SetPolicy::Create
                },
                limits(),
                &r
            )
            .is_err()
        );
        let noop = rewrite(
            Some(&first),
            1024,
            b"a",
            Mutation::Set {
                value: b"old",
                policy: SetPolicy::Replace,
            },
            limits(),
            &r,
        )
        .unwrap();
        assert!(!noop.changed);
        let second = rewrite(
            Some(&first),
            1024,
            &[255],
            Mutation::Set {
                value: b"new",
                policy: SetPolicy::Create,
            },
            limits(),
            &r,
        )
        .unwrap()
        .block
        .unwrap();
        assert_eq!(&*first, baseline.as_slice());
        let view = xattr::observe(
            &second,
            0,
            true,
            xattr::ObservationLimits {
                bytes: 1024,
                entries: 256,
                value_bytes: 4096,
                work: 4_000_000,
            },
            &r,
        )
        .unwrap();
        let items: Vec<_> = view.entries().collect();
        assert_eq!(items[0].name, b"a");
        assert_eq!(items[0].value, b"old");
        assert_eq!(items[1].name, &[255]);
        let removed = rewrite(Some(&first), 1024, b"a", Mutation::Remove, limits(), &r).unwrap();
        assert!(removed.changed);
        let empty = removed.block.unwrap();
        assert_eq!(xattr::validate(&empty, 0, true, &r).unwrap().entries, 0);
        drop(empty);
        drop((first, second));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn capacity_work_cancel_and_reserved_namespace_are_explicit() {
        let r = r();
        assert!(rewrite(None, 1024, b"", Mutation::Remove, limits(), &r).is_err());
        assert!(
            rewrite(
                None,
                1024,
                b"x",
                Mutation::Set {
                    value: &[9; 1024],
                    policy: SetPolicy::Upsert
                },
                limits(),
                &r
            )
            .is_err()
        );
        assert!(
            rewrite(
                None,
                1024,
                b"x",
                Mutation::Set {
                    value: b"a",
                    policy: SetPolicy::Upsert
                },
                Limits {
                    work: 1,
                    ..limits()
                },
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
        r.cancellation.cancel();
        assert!(rewrite(None, 1024, b"x", Mutation::Remove, limits(), &r).is_err());
    }
}
