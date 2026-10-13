//! Borrowed semantic projections over validated ext-native ACL v1.
//! This is neither a container writer nor an effective-access decision engine.
use super::{
    acl::{Acl, Entry, Tag},
    invalid,
};
use crate::{fs_core::Resources, platform::io};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccessStorage {
    RemoveEquivalent,
    RetainExtended,
}
#[derive(Clone, Copy, Debug)]
enum Transform {
    Identity,
    Chmod(u16),
    Create(u16),
}
#[derive(Debug)]
pub(super) struct Projection<'a> {
    acl: &'a Acl<'a>,
    transform: Transform,
    mask: bool,
    pub mode: u16,
    pub storage: AccessStorage,
}
impl Projection<'_> {
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        self.acl.entries().map(move |mut e| {
            let shift = match e.tag {
                Tag::Owner => Some(6),
                Tag::Other => Some(0),
                Tag::Mask => Some(3),
                Tag::GroupOwner if !self.mask => Some(3),
                _ => None,
            };
            if let Some(shift) = shift {
                match self.transform {
                    Transform::Identity => {}
                    Transform::Chmod(mode) => e.permissions = ((mode >> shift) & 7) as u8,
                    Transform::Create(mode) => e.permissions &= ((mode >> shift) & 7) as u8,
                }
            }
            e
        })
    }
}
fn inspect(acl: &Acl<'_>, work: usize, r: &Resources) -> io::Result<(bool, bool, u16)> {
    r.cancellation.check().map_err(io::Error::other)?;
    if acl.len() == 0 {
        return Err(invalid("ACL semantic projection requires nonempty ACL"));
    }
    if acl.len() > work {
        return Err(io::Error::other(crate::fs_core::Error::new(
            crate::fs_core::ErrorKind::BudgetExhausted,
            "ACL semantic entry work",
        )));
    }
    let mut mask = false;
    let mut extended = false;
    let mut mode = 0u16;
    for e in acl.entries() {
        r.cancellation.check().map_err(io::Error::other)?;
        match e.tag {
            Tag::Owner => mode |= u16::from(e.permissions) << 6,
            Tag::GroupOwner => mode |= u16::from(e.permissions) << 3,
            Tag::Mask => mode = (mode & !0o070) | (u16::from(e.permissions) << 3),
            Tag::Other => mode |= u16::from(e.permissions),
            _ => {}
        }
        mask |= matches!(e.tag, Tag::Mask);
        extended |= matches!(e.tag, Tag::Mask | Tag::User(_) | Tag::Group(_));
    }
    r.cancellation.check().map_err(io::Error::other)?;
    Ok((mask, extended, mode))
}
/// Caller supplies non-permission inode bits; setgid privilege policy is separate.
pub(super) fn reconcile<'a>(
    acl: &'a Acl<'a>,
    inode_mode: u16,
    work: usize,
    r: &Resources,
) -> io::Result<Projection<'a>> {
    let (mask, extended, permissions) = inspect(acl, work, r)?;
    Ok(Projection {
        acl,
        transform: Transform::Identity,
        mask,
        mode: (inode_mode & !0o777) | permissions,
        storage: if extended {
            AccessStorage::RetainExtended
        } else {
            AccessStorage::RemoveEquivalent
        },
    })
}
/// Changes owner/other and mask (group owner only when mask absent); named entries stay exact.
pub(super) fn chmod<'a>(
    acl: &'a Acl<'a>,
    mode: u16,
    work: usize,
    r: &Resources,
) -> io::Result<Projection<'a>> {
    let mut p = reconcile(acl, mode, work, r)?;
    p.transform = Transform::Chmod(mode);
    p.mode = mode;
    Ok(p)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChildKind {
    Regular,
    Directory,
    Symlink,
}
#[derive(Debug)]
pub(super) struct Inheritance<'a> {
    pub mode: u16,
    pub access: Option<Projection<'a>>,
    pub default: Option<&'a Acl<'a>>,
}
/// ACL-enabled Linux creation branch. With a default ACL, umask is NOT applied again.
/// Symlink bypass matches posix_acl_create; caller must apply any outer creation policy.
pub(super) fn inherit<'a>(
    default: Option<&'a Acl<'a>>,
    kind: ChildKind,
    requested: u16,
    umask: u16,
    work: usize,
    r: &Resources,
) -> io::Result<Inheritance<'a>> {
    r.cancellation.check().map_err(io::Error::other)?;
    if kind == ChildKind::Symlink {
        return Ok(Inheritance {
            mode: requested,
            access: None,
            default: None,
        });
    }
    let Some(acl) = default else {
        return Ok(Inheritance {
            mode: requested & !(umask & 0o777),
            access: None,
            default: None,
        });
    };
    let mut p = reconcile(acl, requested, work, r)?;
    p.transform = Transform::Create(requested);
    p.mode = (requested & !0o777) | (p.mode & requested & 0o777);
    let mode = p.mode;
    let access = if p.storage == AccessStorage::RetainExtended {
        Some(p)
    } else {
        None
    };
    Ok(Inheritance {
        mode,
        access,
        default: if kind == ChildKind::Directory {
            Some(acl)
        } else {
            None
        },
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    use alloc::vec::Vec;
    fn r() -> Resources {
        Resources {
            memory: Budget::new(0),
            cancellation: Cancellation::default(),
        }
    }
    // Native v1: owner7,user(42)7,user(42)3,group5,mask6,other1.
    const RAW: &[u8] = &[
        1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 42, 0, 0, 0, 4, 0, 5, 0, 16,
        0, 6, 0, 32, 0, 1, 0,
    ];
    #[test]
    fn mode_mask_and_chmod_preserve_named_order_duplicates() {
        let r = r();
        let acl = super::super::acl::decode(
            RAW,
            super::super::acl::Limits {
                bytes: 100,
                entries: 16,
                work: 100,
            },
            &r,
        )
        .unwrap();
        let p = reconcile(&acl, 0o104000, 6, &r).unwrap();
        assert_eq!(p.mode, 0o104761);
        assert_eq!(p.storage, AccessStorage::RetainExtended);
        let p = chmod(&acl, 0o100640, 6, &r).unwrap();
        let entries: Vec<_> = p.entries().collect();
        assert_eq!(
            entries.iter().map(|e| e.permissions).collect::<Vec<_>>(),
            [6, 7, 3, 5, 4, 0]
        );
        assert_eq!(entries[1].tag, Tag::User(42));
        assert_eq!(entries[2].tag, Tag::User(42));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn inheritance_masks_class_not_named_entries_and_ignores_umask_with_default() {
        let r = r();
        let acl = super::super::acl::decode(
            RAW,
            super::super::acl::Limits {
                bytes: 100,
                entries: 16,
                work: 100,
            },
            &r,
        )
        .unwrap();
        let p = inherit(Some(&acl), ChildKind::Directory, 0o40754, 0o777, 6, &r).unwrap();
        assert_eq!(p.mode, 0o40740);
        assert!(p.default.is_some());
        assert_eq!(
            p.access
                .unwrap()
                .entries()
                .map(|e| e.permissions)
                .collect::<Vec<_>>(),
            [7, 7, 3, 5, 4, 0]
        );
        assert_eq!(
            inherit(None, ChildKind::Regular, 0o100666, 0o027, 0, &r)
                .unwrap()
                .mode,
            0o100640
        );
        assert_eq!(
            inherit(Some(&acl), ChildKind::Symlink, 0o120777, 0o777, 0, &r)
                .unwrap()
                .mode,
            0o120777
        );
    }
    #[test]
    fn finite_work_and_cancel_refuse_without_allocating() {
        let r = r();
        let acl = super::super::acl::decode(
            RAW,
            super::super::acl::Limits {
                bytes: 100,
                entries: 16,
                work: 100,
            },
            &r,
        )
        .unwrap();
        assert!(reconcile(&acl, 0, 5, &r).is_err());
        assert!(reconcile(&acl, 0, 6, &r).is_ok());
        r.cancellation.cancel();
        assert!(inherit(None, ChildKind::Regular, 0o666, 0, 0, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    // Include inside fs_ext_acl_semantics::tests after its existing helpers.
    #[test]
    fn primary_extracted_c_differential_vectors() {
        let r = r();
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 0, 64, &r).unwrap();
            assert_eq!(p.mode, 489);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 511, 64, &r).unwrap();
            assert_eq!(p.mode, 489);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 438, 64, &r).unwrap();
            assert_eq!(p.mode, 489);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 416, 64, &r).unwrap();
            assert_eq!(p.mode, 489);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 492, 64, &r).unwrap();
            assert_eq!(p.mode, 489);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 35327, 64, &r).unwrap();
            assert_eq!(p.mode, 35305);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 0, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 0);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => 0,
                            Tag::GroupOwner => 0,
                            Tag::Other => 0,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [0, 0, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 511, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 489);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((511 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((511 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (511 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 438, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((438 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((438 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (438 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [6, 4, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 416, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((416 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((416 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (416 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [6, 4, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 492, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 488);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((492 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((492 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (492 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 5, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 35327, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 35305);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((35327 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((35327 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (35327 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 5, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 0, 64, &r).unwrap();
            assert_eq!(p.mode, 0);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [0, 0, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 511, 64, &r).unwrap();
            assert_eq!(p.mode, 511);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 7]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 438, 64, &r).unwrap();
            assert_eq!(p.mode, 438);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [6, 6, 6]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 416, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [6, 4, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 492, 64, &r).unwrap();
            assert_eq!(p.mode, 492);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 4]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 35327, 64, &r).unwrap();
            assert_eq!(p.mode, 35327);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 7]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 0, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 511, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 438, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 416, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 492, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 35327, 64, &r).unwrap();
            assert_eq!(p.mode, 35313);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 0, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 0);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => 0,
                            Tag::GroupOwner => 0,
                            Tag::Other => 0,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [0, 5, 0, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 511, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((511 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((511 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (511 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 438, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 432);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((438 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((438 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (438 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [6, 5, 6, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 416, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((416 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((416 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (416 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [6, 5, 4, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 492, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 480);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((492 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((492 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (492 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 5, 4, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 35327, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 35313);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((35327 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((35327 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (35327 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 5, 6, 1]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 0, 64, &r).unwrap();
            assert_eq!(p.mode, 0);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [0, 5, 0, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 511, 64, &r).unwrap();
            assert_eq!(p.mode, 511);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 7, 7]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 438, 64, &r).unwrap();
            assert_eq!(p.mode, 438);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [6, 5, 6, 6]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 416, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [6, 5, 4, 0]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 492, 64, &r).unwrap();
            assert_eq!(p.mode, 492);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 5, 4]);
        }
        {
            let raw = &[1, 0, 0, 0, 1, 0, 7, 0, 4, 0, 5, 0, 16, 0, 6, 0, 32, 0, 1, 0];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 35327, 64, &r).unwrap();
            assert_eq!(p.mode, 35327);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 5, 7, 7]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 0, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 511, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 438, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 416, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 492, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = reconcile(&acl, 35327, 64, &r).unwrap();
            assert_eq!(p.mode, 35313);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 0, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 0);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => 0,
                            Tag::GroupOwner => 0,
                            Tag::Other => 0,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [0, 7, 3, 1, 5, 6, 2, 0, 0]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 511, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 497);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((511 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((511 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (511 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 438, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 432);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((438 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((438 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (438 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [6, 7, 3, 1, 5, 6, 2, 6, 0]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 416, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((416 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((416 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (416 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [6, 7, 3, 1, 5, 6, 2, 4, 0]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 492, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 480);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((492 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((492 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (492 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 4, 0]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = inherit(Some(&acl), ChildKind::Regular, 35327, 0o777, 64, &r).unwrap();
            assert_eq!(p.mode, 35313);
            let entries: Vec<_> = p
                .access
                .as_ref()
                .map(|a| a.entries().map(|e| e.permissions).collect())
                .unwrap_or_else(|| {
                    acl.entries()
                        .map(|e| match e.tag {
                            Tag::Owner => e.permissions & ((35327 >> 6) & 7) as u8,
                            Tag::GroupOwner => e.permissions & ((35327 >> 3) & 7) as u8,
                            Tag::Other => e.permissions & (35327 & 7) as u8,
                            _ => e.permissions,
                        })
                        .collect()
                });
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 6, 1]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 0, 64, &r).unwrap();
            assert_eq!(p.mode, 0);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [0, 7, 3, 1, 5, 6, 2, 0, 0]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 511, 64, &r).unwrap();
            assert_eq!(p.mode, 511);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 7, 7]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 438, 64, &r).unwrap();
            assert_eq!(p.mode, 438);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [6, 7, 3, 1, 5, 6, 2, 6, 6]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 416, 64, &r).unwrap();
            assert_eq!(p.mode, 416);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [6, 7, 3, 1, 5, 6, 2, 4, 0]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 492, 64, &r).unwrap();
            assert_eq!(p.mode, 492);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 5, 4]);
        }
        {
            let raw = &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 42, 0, 0, 0, 2, 0, 3, 0, 7, 0, 0, 0, 2, 0, 1,
                0, 42, 0, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 99, 0, 0, 0, 8, 0, 2, 0, 2, 0, 0, 0, 16, 0,
                6, 0, 32, 0, 1, 0,
            ];
            let acl = super::super::acl::decode(
                raw,
                super::super::acl::Limits {
                    bytes: 1024,
                    entries: 64,
                    work: 1024,
                },
                &r,
            )
            .unwrap();
            let p = chmod(&acl, 35327, 64, &r).unwrap();
            assert_eq!(p.mode, 35327);
            let entries: Vec<_> = p.entries().map(|e| e.permissions).collect();
            assert_eq!(entries, [7, 7, 3, 1, 5, 6, 2, 7, 7]);
        }
        assert_eq!(r.memory.used(), 0);
    }
}

#[cfg(test)]
mod mounted_guest_comparison {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    use alloc::vec::Vec;
    struct Case {
        id: &'static str,
        op: &'static str,
        input: &'static [u8],
        expected: &'static [u8],
        requested: u16,
        umask: u16,
        mode: u16,
    }
    const CASES: &[Case] = &[
        Case {
            id: "ext3/observation-0/file/umask-0",
            op: "file",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            requested: 438,
            umask: 0,
            mode: 416,
        },
        Case {
            id: "ext3/observation-1/chmod/umask-0",
            op: "chmod",
            input: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 2, 0, 32, 0, 0, 0,
            ],
            requested: 400,
            umask: 0,
            mode: 400,
        },
        Case {
            id: "ext3/observation-2/directory/umask-0",
            op: "directory",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            requested: 492,
            umask: 0,
            mode: 488,
        },
        Case {
            id: "ext3/observation-3/file/umask-27",
            op: "file",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            requested: 438,
            umask: 23,
            mode: 416,
        },
        Case {
            id: "ext3/observation-4/chmod/umask-0",
            op: "chmod",
            input: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 2, 0, 32, 0, 0, 0,
            ],
            requested: 400,
            umask: 0,
            mode: 400,
        },
        Case {
            id: "ext3/observation-5/directory/umask-27",
            op: "directory",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            requested: 492,
            umask: 23,
            mode: 488,
        },
        Case {
            id: "ext3/observation-6/file/umask-777",
            op: "file",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            requested: 438,
            umask: 511,
            mode: 416,
        },
        Case {
            id: "ext3/observation-7/chmod/umask-0",
            op: "chmod",
            input: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 2, 0, 32, 0, 0, 0,
            ],
            requested: 400,
            umask: 0,
            mode: 400,
        },
        Case {
            id: "ext3/observation-8/directory/umask-777",
            op: "directory",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            requested: 492,
            umask: 511,
            mode: 488,
        },
        Case {
            id: "ext4/observation-17/file/umask-0",
            op: "file",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            requested: 438,
            umask: 0,
            mode: 416,
        },
        Case {
            id: "ext4/observation-18/chmod/umask-0",
            op: "chmod",
            input: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 2, 0, 32, 0, 0, 0,
            ],
            requested: 400,
            umask: 0,
            mode: 400,
        },
        Case {
            id: "ext4/observation-19/directory/umask-0",
            op: "directory",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            requested: 492,
            umask: 0,
            mode: 488,
        },
        Case {
            id: "ext4/observation-20/file/umask-27",
            op: "file",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            requested: 438,
            umask: 23,
            mode: 416,
        },
        Case {
            id: "ext4/observation-21/chmod/umask-0",
            op: "chmod",
            input: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 2, 0, 32, 0, 0, 0,
            ],
            requested: 400,
            umask: 0,
            mode: 400,
        },
        Case {
            id: "ext4/observation-22/directory/umask-27",
            op: "directory",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            requested: 492,
            umask: 23,
            mode: 488,
        },
        Case {
            id: "ext4/observation-23/file/umask-777",
            op: "file",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            requested: 438,
            umask: 511,
            mode: 416,
        },
        Case {
            id: "ext4/observation-24/chmod/umask-0",
            op: "chmod",
            input: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 4, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 2, 0, 32, 0, 0, 0,
            ],
            requested: 400,
            umask: 0,
            mode: 400,
        },
        Case {
            id: "ext4/observation-25/directory/umask-777",
            op: "directory",
            input: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            expected: &[
                1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 7, 0, 33, 78, 0, 0, 4, 0, 5, 0, 8, 0, 6, 0, 34, 78,
                0, 0, 16, 0, 5, 0, 32, 0, 0, 0,
            ],
            requested: 492,
            umask: 511,
            mode: 488,
        },
    ];
    fn acl<'a>(raw: &'a [u8], r: &Resources) -> Acl<'a> {
        super::super::acl::decode(
            raw,
            super::super::acl::Limits {
                bytes: 4096,
                entries: 32,
                work: 128,
            },
            r,
        )
        .unwrap()
    }
    #[test]
    fn current_semantics_match_captured_mounted_inheritance_and_chmod() {
        let r = Resources {
            memory: Budget::new(0),
            cancellation: Cancellation::default(),
        };
        assert_eq!(CASES.len(), 18);
        for c in CASES {
            let original = acl(c.input, &r);
            let expected = acl(c.expected, &r);
            let expected_entries: Vec<_> = expected.entries().collect();
            if c.op == "chmod" {
                let projection = chmod(&original, c.requested, 32, &r).unwrap();
                assert_eq!(projection.mode, c.mode, "{}", c.id);
                assert_eq!(
                    projection.entries().collect::<Vec<_>>(),
                    expected_entries,
                    "{}",
                    c.id
                );
            } else {
                let directory = c.op == "directory";
                let inheritance = inherit(
                    Some(&original),
                    if directory {
                        ChildKind::Directory
                    } else {
                        ChildKind::Regular
                    },
                    c.requested,
                    c.umask,
                    32,
                    &r,
                )
                .unwrap();
                assert_eq!(inheritance.mode, c.mode, "{}", c.id);
                assert_eq!(
                    inheritance
                        .access
                        .as_ref()
                        .unwrap()
                        .entries()
                        .collect::<Vec<_>>(),
                    expected_entries,
                    "{}",
                    c.id
                );
                assert_eq!(inheritance.default.is_some(), directory, "{}", c.id);
                if let Some(default) = inheritance.default {
                    assert_eq!(default.raw(), original.raw(), "{}", c.id);
                }
            }
            assert_eq!(r.memory.used(), 0, "{}", c.id);
        }
    }
}
