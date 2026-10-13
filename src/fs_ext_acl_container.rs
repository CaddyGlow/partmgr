//! Batched typed ACL container rewrite; final allocation/lifetime remains the planner's job.
use super::{
    acl_write::{Change, Prepared},
    invalid, unsupported, xattr,
};
use crate::{fs_core::Resources, platform::io};
#[path = "fs_ext_acl_container_codec.rs"]
mod codec;
pub(super) struct Block(codec::EncodedBlock);
impl Block {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
pub(super) struct Rewrite {
    pub changed: bool,
    pub mode: u16,
    pub block: Option<Block>,
}
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub entries: usize,
    pub value_bytes: usize,
    pub work: usize,
}
fn apply(
    old: Option<&[u8]>,
    bs: usize,
    index: u8,
    change: &Change,
    limits: codec::Limits,
    r: &Resources,
) -> io::Result<codec::Rewrite> {
    match change {
        Change::Preserve => Ok(codec::Rewrite {
            work: 0,
            changed: false,
            block: None,
        }),
        Change::Remove => codec::rewrite(old, bs, index, b"", codec::Mutation::Remove, limits, r),
        Change::Set(value) => codec::rewrite(
            old,
            bs,
            index,
            b"",
            codec::Mutation::Set {
                value: value.bytes(),
                policy: codec::SetPolicy::Upsert,
            },
            limits,
            r,
        ),
    }
}
/// One final block result for both ACL keys; no intermediate physical allocation.
pub(super) fn rewrite(
    old: Option<&[u8]>,
    bs: usize,
    prepared: &Prepared,
    limits: Limits,
    r: &Resources,
) -> io::Result<Rewrite> {
    r.cancellation.check().map_err(io::Error::other)?;
    let count = usize::from(!matches!(&prepared.access, Change::Preserve))
        + usize::from(!matches!(&prepared.default, Change::Preserve));
    if count == 0 {
        return Ok(Rewrite {
            changed: false,
            mode: prepared.mode,
            block: None,
        });
    }
    let encoding = codec::Limits {
        entries: limits.entries,
        value_bytes: limits.value_bytes,
        work: limits.work,
    };
    let access = apply(old, bs, 2, &prepared.access, encoding, r)?;
    let intermediate = access.block.as_ref().map(|b| &b[..]).or(old);
    // Both passes consume one finite aggregate. A small first pass must not
    // strand budget needed to observe the intermediate block in the second.
    let remaining = codec::Limits {
        work: limits
            .work
            .checked_sub(access.work)
            .ok_or_else(|| unsupported("ACL container aggregate work ceiling"))?,
        ..encoding
    };
    let default = apply(intermediate, bs, 3, &prepared.default, remaining, r)?;
    let block = if default.changed {
        default.block
    } else {
        access.block
    };
    // Kernel ext4_xattr_block_set uses no new_bh for an empty entry list.
    // The planner must release/decref the old owner and update inode sectors.
    let block = block.filter(|bytes| bytes[32..36] != [0, 0, 0, 0]);
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(Rewrite {
        changed: access.changed || default.changed,
        mode: prepared.mode,
        block: block.map(Block),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    const ACL: &[u8] = &[
        1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 5, 0, 42, 0, 0, 0, 4, 0, 5, 0, 16, 0, 5, 0, 32, 0, 1, 0,
    ];
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
            work: 8_000_000,
        }
    }
    #[test]
    fn batched_inherited_acl_keeps_opaque_user_value_and_one_final_container() {
        let r = r();
        let opaque = super::super::xattr_write::rewrite(
            None,
            1024,
            b"opaque",
            super::super::xattr_write::Mutation::Set {
                value: b"\0opaque\xff",
                policy: super::super::xattr_write::SetPolicy::Upsert,
            },
            super::super::xattr_write::Limits {
                entries: 256,
                value_bytes: 4096,
                work: 8_000_000,
            },
            &r,
        )
        .unwrap()
        .block
        .unwrap();
        let a = super::super::acl::decode(
            ACL,
            super::super::acl::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let p = super::super::acl_write::prepare(
            super::super::acl_write::Request::Inherit {
                parent_default: Some(&a),
                umask: 0o777,
            },
            super::super::acl_semantics::ChildKind::Directory,
            0o40750,
            super::super::acl_write::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let result = rewrite(Some(&opaque), 1024, &p, limits(), &r).unwrap();
        assert!(result.changed);
        assert_eq!(result.mode, 0o40750);
        let block = result.block.unwrap();
        let view = xattr::observe(
            block.bytes(),
            0,
            true,
            xattr::ObservationLimits {
                bytes: 1024,
                entries: 256,
                value_bytes: 4096,
                work: 8_000_000,
            },
            &r,
        )
        .unwrap();
        let entries: Vec<_> = view.entries().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].index, 1);
        assert_eq!(entries[0].value, b"\0opaque\xff");
        assert_eq!(entries[1].index, 2);
        assert_eq!(entries[2].index, 3);
        assert_eq!(entries[2].value, ACL);
        assert!(entries[1].name.is_empty() && entries[2].name.is_empty());
        drop((block, p, opaque));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn absent_removal_no_container_and_finite_total_work() {
        let r = r();
        let p = Prepared {
            mode: 0o100600,
            access: Change::Remove,
            default: Change::Preserve,
        };
        let result = rewrite(None, 1024, &p, limits(), &r).unwrap();
        assert!(!result.changed && result.block.is_none());
        let mut low = limits();
        low.work = 0;
        assert!(rewrite(None, 1024, &p, low, &r).is_err());
        assert_eq!(r.memory.used(), 0);
        r.cancellation.cancel();
        assert!(rewrite(None, 1024, &p, limits(), &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn removing_last_acl_requests_container_release_not_empty_allocation() {
        let r = r();
        let a = super::super::acl::decode(
            ACL,
            super::super::acl::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let p = super::super::acl_write::prepare(
            super::super::acl_write::Request::Access(Some(&a)),
            super::super::acl_semantics::ChildKind::Regular,
            0o100600,
            super::super::acl_write::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let first = rewrite(None, 1024, &p, limits(), &r).unwrap();
        let original = first.block.unwrap();
        let remove = Prepared {
            mode: p.mode,
            access: Change::Remove,
            default: Change::Preserve,
        };
        let result = rewrite(Some(original.bytes()), 1024, &remove, limits(), &r).unwrap();
        assert!(result.changed && result.block.is_none());
        drop((original, p));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn inherited_pair_shares_exact_aggregate_work_and_refuses_one_below() {
        let r = r();
        let decoded = super::super::acl::decode(
            ACL,
            super::super::acl::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        let prepared = super::super::acl_write::prepare(
            super::super::acl_write::Request::Inherit {
                parent_default: Some(&decoded),
                umask: 0o777,
            },
            super::super::acl_semantics::ChildKind::Directory,
            0o40750,
            super::super::acl_write::Limits {
                bytes: 4096,
                entries: 256,
                work: 4096,
            },
            &r,
        )
        .unwrap();
        // 1024-byte initialization, one/two 28-byte values, exact table/hash
        // work, and three conservative 1024*258 validation charges.
        let first = 1 + 1 + 1024 + (28 + 16) + 28 + 1024 * 258;
        let second = 1 + 1024 * 258 + 1 + 1 + 1 + 2 + 1024 + 2 * (28 + 16) + 2 * 28 + 1024 * 258;
        let mut exact = limits();
        exact.work = first + second;
        let result = rewrite(None, 1024, &prepared, exact, &r).unwrap();
        assert!(result.changed && result.block.is_some());
        drop(result);
        exact.work -= 1;
        assert!(rewrite(None, 1024, &prepared, exact, &r).is_err());
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
    }
}
