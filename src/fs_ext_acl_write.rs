//! Private typed ACL mutation preparation. No storage/publication authority.
//! Container COW and scoped durable replay must consume these coupled outcomes.
use super::{
    acl::{Acl, Entry, Tag},
    acl_semantics::{self, AccessStorage, ChildKind},
    invalid, unsupported,
};
#[cfg(not(feature = "std"))]
use crate::platform::prelude::*;
use crate::{
    fs_core::{Reservation, Resources},
    platform::io,
};

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub bytes: usize,
    pub entries: usize,
    pub work: usize,
}
pub(super) struct NativeAcl {
    bytes: Vec<u8>,
    _lease: Reservation,
}
impl NativeAcl {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub(super) enum Change {
    Preserve,
    Remove,
    Set(NativeAcl),
}
pub(super) struct Prepared {
    pub mode: u16,
    pub access: Change,
    pub default: Change,
}
pub(super) enum Request<'a> {
    Access(Option<&'a Acl<'a>>),
    Default(Option<&'a Acl<'a>>),
    Chmod {
        permissions: u16,
        current_access: Option<&'a Acl<'a>>,
    },
    Inherit {
        parent_default: Option<&'a Acl<'a>>,
        umask: u16,
    },
}
struct Work<'a> {
    used: usize,
    limits: Limits,
    resources: &'a Resources,
}
impl Work<'_> {
    fn charge(&mut self, count: usize) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        self.used = self
            .used
            .checked_add(count)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| unsupported("ACL writer work ceiling"))?;
        Ok(())
    }
    fn semantics(&mut self, acl: &Acl<'_>) -> io::Result<()> {
        self.charge(acl.len())
    }
}
fn encode<I: Iterator<Item = Entry>>(
    entries: impl Fn() -> I,
    work: &mut Work<'_>,
) -> io::Result<NativeAcl> {
    let mut size = 4usize;
    let mut count = 0usize;
    work.charge(4)?;
    for entry in entries() {
        work.charge(1)?;
        count = count
            .checked_add(1)
            .filter(|n| *n <= work.limits.entries)
            .ok_or_else(|| unsupported("ACL writer entry ceiling"))?;
        if entry.permissions > 7 {
            return Err(invalid("ACL writer permission bits"));
        }
        let width = match entry.tag {
            Tag::User(id) | Tag::Group(id) => {
                if id == u32::MAX {
                    return Err(invalid("ACL writer undefined identity"));
                }
                8
            }
            _ => 4,
        };
        size = size
            .checked_add(width)
            .filter(|n| *n <= work.limits.bytes)
            .ok_or_else(|| unsupported("ACL writer byte ceiling"))?;
    }
    if count == 0 || size > work.limits.bytes {
        return Err(invalid("ACL writer requires nonempty validated ACL"));
    }
    // Charge allocation initialization and serialization before allocating bytes.
    work.charge(
        size.checked_mul(2)
            .ok_or_else(|| unsupported("ACL writer byte work overflow"))?,
    )?;
    let lease = work
        .resources
        .memory
        .reserve(size as u64)
        .map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(io::Error::other)?;
    if bytes.capacity() > size {
        return Err(unsupported("ACL writer allocation capacity"));
    }
    bytes.extend_from_slice(&1u32.to_le_bytes());
    for entry in entries() {
        work.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        let tag: u16 = match entry.tag {
            Tag::Owner => 1,
            Tag::User(_) => 2,
            Tag::GroupOwner => 4,
            Tag::Group(_) => 8,
            Tag::Mask => 16,
            Tag::Other => 32,
        };
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&u16::from(entry.permissions).to_le_bytes());
        if let Tag::User(id) | Tag::Group(id) = entry.tag {
            bytes.extend_from_slice(&id.to_le_bytes());
        }
    }
    work.resources
        .cancellation
        .check()
        .map_err(io::Error::other)?;
    Ok(NativeAcl {
        bytes,
        _lease: lease,
    })
}
// Validated Acl/Projection iterator types need not expose Clone: two separate
// source-owned passes are supplied rather than accepting arbitrary entries.
fn original(acl: &Acl<'_>, work: &mut Work<'_>) -> io::Result<NativeAcl> {
    encode(|| acl.entries(), work)
}
pub(super) fn prepare<'a>(
    request: Request<'a>,
    kind: ChildKind,
    inode_mode: u16,
    limits: Limits,
    r: &Resources,
) -> io::Result<Prepared> {
    let mut work = Work {
        used: 0,
        limits,
        resources: r,
    };
    work.charge(1)?;
    let mut result = Prepared {
        mode: inode_mode,
        access: Change::Preserve,
        default: Change::Preserve,
    };
    match request {
        Request::Access(acl) => {
            if kind == ChildKind::Symlink {
                return Err(unsupported("ACL access mutation on symlink"));
            }
            result.access = if let Some(acl) = acl {
                work.semantics(acl)?;
                let p = acl_semantics::reconcile(acl, inode_mode, acl.len(), r)?;
                result.mode = p.mode;
                match p.storage {
                    AccessStorage::RemoveEquivalent => Change::Remove,
                    AccessStorage::RetainExtended => Change::Set(original(acl, &mut work)?),
                }
            } else {
                Change::Remove
            };
        }
        Request::Default(acl) => {
            if kind != ChildKind::Directory {
                if acl.is_some() {
                    return Err(unsupported("default ACL mutation requires directory"));
                }
                r.cancellation.check().map_err(io::Error::other)?;
                return Ok(result);
            }
            result.default = if let Some(acl) = acl {
                Change::Set(original(acl, &mut work)?)
            } else {
                Change::Remove
            };
        }
        Request::Chmod {
            permissions,
            current_access,
        } => {
            if kind == ChildKind::Symlink {
                return Err(unsupported("ACL chmod on symlink"));
            }
            result.mode = (inode_mode & !0o7777) | (permissions & 0o7777);
            if let Some(acl) = current_access {
                work.semantics(acl)?;
                let p = acl_semantics::chmod(acl, result.mode, acl.len(), r)?;
                result.access = match p.storage {
                    AccessStorage::RemoveEquivalent => Change::Remove,
                    AccessStorage::RetainExtended => {
                        Change::Set(encode(|| p.entries(), &mut work)?)
                    }
                };
            }
        }
        Request::Inherit {
            parent_default,
            umask,
        } => {
            if let Some(acl) = parent_default {
                work.semantics(acl)?;
            }
            let p = acl_semantics::inherit(
                parent_default,
                kind,
                inode_mode,
                umask,
                parent_default.map_or(0, Acl::len),
                r,
            )?;
            result.mode = p.mode;
            result.access = if let Some(access) = p.access {
                Change::Set(encode(|| access.entries(), &mut work)?)
            } else {
                Change::Remove
            };
            result.default = if let Some(default) = p.default {
                Change::Set(original(default, &mut work)?)
            } else {
                Change::Remove
            };
        }
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    const RAW: &[u8] = &[
        1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 42, 0, 0, 0, 4, 0, 5, 0, 16,
        0, 6, 0, 32, 0, 1, 0,
    ];
    fn limits() -> Limits {
        Limits {
            bytes: 4096,
            entries: 256,
            work: 4096,
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(8192),
            cancellation: Cancellation::default(),
        }
    }
    fn acl<'a>(raw: &'a [u8], r: &Resources) -> Acl<'a> {
        super::super::acl::decode(
            raw,
            super::super::acl::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            r,
        )
        .unwrap()
    }
    #[test]
    fn typed_access_and_chmod_native_bytes_keep_duplicate_ids() {
        let r = resources();
        let a = acl(RAW, &r);
        let p = prepare(
            Request::Access(Some(&a)),
            ChildKind::Regular,
            0o100600,
            limits(),
            &r,
        )
        .unwrap();
        assert_eq!(p.mode, 0o100761);
        let Change::Set(bytes) = p.access else {
            panic!("extended access must remain")
        };
        assert_eq!(bytes.bytes(), RAW);
        drop(bytes);
        assert_eq!(r.memory.used(), 0);
        let p = prepare(
            Request::Chmod {
                permissions: 0o640,
                current_access: Some(&a),
            },
            ChildKind::Regular,
            0o100761,
            limits(),
            &r,
        )
        .unwrap();
        let Change::Set(bytes) = p.access else {
            panic!("extended chmod must remain")
        };
        let decoded = acl(bytes.bytes(), &r);
        assert_eq!(decoded.mode(), Some(0o640));
        let entries: Vec<_> = decoded.entries().collect();
        assert_eq!(entries[1].tag, Tag::User(42));
        assert_eq!(entries[2].tag, Tag::User(42));
        assert_eq!(entries[1].permissions, 7);
        assert_eq!(entries[2].permissions, 3);
        drop(bytes);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn inheritance_default_mode_and_typed_namespace_refusals() {
        let r = resources();
        let a = acl(RAW, &r);
        let p = prepare(
            Request::Inherit {
                parent_default: Some(&a),
                umask: 0o777,
            },
            ChildKind::Directory,
            0o40750,
            limits(),
            &r,
        )
        .unwrap();
        assert_eq!(p.mode, 0o40740);
        let Change::Set(access) = p.access else {
            panic!("extended child access")
        };
        let Change::Set(default) = p.default else {
            panic!("directory default")
        };
        assert_eq!(default.bytes(), RAW);
        assert_eq!(acl(access.bytes(), &r).mode(), Some(0o740));
        drop((access, default));
        assert_eq!(r.memory.used(), 0);
        assert!(
            prepare(
                Request::Default(Some(&a)),
                ChildKind::Regular,
                0o100600,
                limits(),
                &r
            )
            .is_err()
        );
        assert!(
            prepare(
                Request::Access(Some(&a)),
                ChildKind::Symlink,
                0o120777,
                limits(),
                &r
            )
            .is_err()
        );
        let no_default = prepare(
            Request::Default(None),
            ChildKind::Regular,
            0o100600,
            limits(),
            &r,
        )
        .unwrap();
        assert!(matches!(no_default.default, Change::Preserve));
        assert_eq!(no_default.mode, 0o100600);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn finite_work_memory_and_cancellation_refund() {
        let r = resources();
        let a = acl(RAW, &r);
        let mut low = limits();
        low.work = 1;
        assert!(
            prepare(
                Request::Access(Some(&a)),
                ChildKind::Regular,
                0o100600,
                low,
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
        let tiny = Resources {
            memory: Budget::new(1),
            cancellation: Cancellation::default(),
        };
        assert!(
            prepare(
                Request::Access(Some(&a)),
                ChildKind::Regular,
                0o100600,
                limits(),
                &tiny
            )
            .is_err()
        );
        assert_eq!(tiny.memory.used(), 0);
        let canceled = resources();
        canceled.cancellation.cancel();
        assert!(
            prepare(
                Request::Access(Some(&a)),
                ChildKind::Regular,
                0o100600,
                limits(),
                &canceled
            )
            .is_err()
        );
        assert_eq!(canceled.memory.used(), 0);
        // Defaults serialize separately: failure after access allocation must refund both.
        let tiny = Resources {
            memory: Budget::new(RAW.len() as u64),
            cancellation: Cancellation::default(),
        };
        assert!(
            prepare(
                Request::Inherit {
                    parent_default: Some(&a),
                    umask: 0
                },
                ChildKind::Directory,
                0o40777,
                limits(),
                &tiny
            )
            .is_err()
        );
        assert_eq!(tiny.memory.used(), 0);
    }
}
