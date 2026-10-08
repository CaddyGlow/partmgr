//! Explicit checkpoint descriptor retirement, separately durable before any allocation reuse.
use super::*;
use crate::fs_apfs_audit::{ApfsRetentionProof, prove_apfs_retention};

/// Source-bound explicit authorization to forget complete checkpoints below a native XID horizon.
/// This plan cannot free or reuse any allocation and always retains a complete predecessor.
pub struct ApfsCheckpointRetirementPlan {
    scope: u128,
    generation: u64,
    xid: u64,
    resources: Resources,
    proof: ApfsRetentionProof,
}
impl ApfsCheckpointRetirementPlan {
    /// Descriptor addresses and XIDs that this explicit operation will forget.
    pub fn checkpoints(&self) -> &[(u64, u64)] {
        self.proof.retirement_candidates()
    }
}
/// Durable descriptor retirement followed by a complete fresh ownership audit.
#[derive(Clone, Debug)]
pub struct ApfsCheckpointRetirementReceipt {
    /// Number of complete older descriptors deliberately retired.
    pub retired_checkpoints: usize,
    /// Unchanged selected native transaction ID.
    pub checkpoint_xid: u64,
    /// No native allocation or queue entry was released by this operation.
    pub released_blocks: u64,
}
impl<S: Storage> ApfsEditor<S> {
    /// Explicitly plan forgetting older complete checkpoints while preserving the selected one
    /// and a named complete predecessor. All payload, bitmap and retirement allocations remain.
    /// The initial operation accepts one supported-profile volume, without snapshots/encryption.
    pub fn plan_checkpoint_retirement(
        &self,
        minimum_retained_xid: u64,
        r: &Resources,
    ) -> Result<ApfsCheckpointRetirementPlan> {
        self.revalidate(r)?;
        if self.volume.container().checkpoint().volumes.len() != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "APFS writable retention single-volume profile",
            ));
        }
        self.snapshot.work.charge(self.limits.audit.work)?;
        let proof = prove_apfs_retention(&self.volume, minimum_retained_xid, self.limits.audit, r)?;
        // Every candidate must belong solely to the old descriptor area. In particular it must
        // not overlap a retained checkpoint's mapping blocks or its terminal superblock.
        let c = self.volume.container();
        let h = &c.inner.header;
        let base = crate::fs_apfs::u64le(h, 112);
        let count = crate::fs_apfs::u32le(h, 104) as u64;
        for (address, _) in proof.retirement_candidates() {
            if *address < base || *address >= base + count {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "APFS retirement descriptor bounds",
                ));
            }
            for (retained, header) in &c.inner.retained_headers {
                if crate::fs_apfs::u64le(header, 16) < minimum_retained_xid {
                    continue;
                }
                let start = crate::fs_apfs::u32le(header, 136) as u64;
                let length = crate::fs_apfs::u32le(header, 140) as u64;
                if address == retained
                    || (0..length).any(|i| base + ((start + i) % count) == *address)
                {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "APFS retirement aliases retained descriptor",
                    ));
                }
            }
        }
        self.revalidate(r)?;
        Ok(ApfsCheckpointRetirementPlan {
            scope: self.scope,
            generation: self.generation,
            xid: self.checkpoint_xid(),
            resources: r.clone(),
            proof,
        })
    }

    /// Retire only authorized old superblock descriptors, flush, read back and completely re-audit.
    /// Caller must retain the geometry recovery anchor before calling. Cuts can leave a subset of
    /// old descriptors forgotten; selected checkpoint/payload and every allocation remain intact.
    /// Any attempted write failure requires consuming the owner through `recover`.
    pub fn commit_checkpoint_retirement(
        &mut self,
        plan: ApfsCheckpointRetirementPlan,
        anchor: &ApfsRecoveryAnchor,
        r: &Resources,
    ) -> Result<ApfsCheckpointRetirementReceipt> {
        plan.resources.cancellation.check()?;
        self.revalidate(r)?;
        if plan.scope != self.scope
            || plan.generation != self.generation
            || plan.xid != self.checkpoint_xid()
            || anchor != &self.recovery_anchor()
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS checkpoint retirement binding",
            ));
        }
        let count = plan.checkpoints().len();
        if count == 0 {
            return Ok(ApfsCheckpointRetirementReceipt {
                retired_checkpoints: 0,
                checkpoint_xid: plan.xid,
                released_blocks: 0,
            });
        }
        self.snapshot.work.charge(
            (count as u64)
                .checked_mul(3 * BLOCK as u64)
                .ok_or_else(|| Error::new(ErrorKind::BudgetExhausted, "APFS retirement work"))?,
        )?;
        self.generation
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::BudgetExhausted, "APFS retirement generation"))?;
        self.recovery_required = true;
        let result = (|| {
            let unused = [0; BLOCK];
            for (address, _) in plan.checkpoints() {
                plan.resources.cancellation.check()?;
                self.write_block(*address, &unused, r)?;
            }
            self.target
                .flush()
                .map_err(|e| Error::io("APFS descriptor retirement flush", e))?;
            for (address, _) in plan.checkpoints() {
                r.cancellation.check()?;
                plan.resources.cancellation.check()?;
                let mut observed = [0; BLOCK];
                self.target
                    .read_exact_at(*address * BLOCK as u64, &mut observed)
                    .map_err(|e| Error::io("APFS descriptor retirement readback", e))?;
                if observed != unused {
                    return Err(Error::new(
                        ErrorKind::UncertainDurability,
                        "APFS descriptor retirement readback mismatch",
                    ));
                }
            }
            self.refresh_owned(plan.xid, r)?;
            Ok(ApfsCheckpointRetirementReceipt {
                retired_checkpoints: count,
                checkpoint_xid: plan.xid,
                released_blocks: 0,
            })
        })();
        result.map_err(|mut error| {
            if error.kind != ErrorKind::UncertainDurability {
                error.kind = ErrorKind::InterruptedWrite;
            }
            error
        })
    }
}
