//! Native retirement queue reclamation after independently proved checkpoint pruning.
use super::*;
use crate::fs_apfs_audit::{ApfsRetentionProof, prove_apfs_retention};

pub(super) struct Reclamation {
    pub(super) main: Vec<u64>,
    pub(super) internal: Vec<u64>,
}
/// Source-bound native reclamation checkpoint. No storage is released during planning.
pub struct ApfsReclamationPlan {
    cow: ApfsRangePlan,
    main: usize,
    internal: usize,
    _retention: ApfsRetentionProof,
}
impl ApfsReclamationPlan {
    /// Retirement reservations removed from the current main-device queue.
    pub fn main_blocks(&self) -> usize {
        self.main
    }
    /// Retirement reservations removed from the current internal-pool queue.
    pub fn internal_blocks(&self) -> usize {
        self.internal
    }
    /// Planned physical volume superblock for independent post-publication oracle selection.
    pub fn planned_volume_block(&self) -> u64 {
        self.cow.planned_volume_block()
    }
}
/// Durable native COW publication and exact removed retirement-reservation counts.
#[derive(Debug)]
pub struct ApfsReclamationReceipt {
    /// Reopened and completely audited checkpoint publication.
    pub publication: ApfsEditReceipt,
    /// Removed main-device retirement reservations; fresh metadata can reuse these blocks.
    pub main_blocks: usize,
    /// Removed internal-pool reservations; fresh allocation metadata can reuse these blocks.
    pub internal_blocks: usize,
}
struct EmptyInput(ObjectId);
impl FileRead for EmptyInput {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        0
    }
    fn read_at(&self, _: u64, _: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        Ok(0)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()
    }
}
impl<S: Storage> ApfsEditor<S> {
    /// Plan a native metadata-only checkpoint releasing old queue entries proved absent from
    /// every retained live owner. Retirement XIDs must strictly predate the retained horizon.
    /// Caller must first explicitly retire obsolete descriptors; this method never prunes history.
    pub fn plan_reclamation(&self, r: &Resources) -> Result<ApfsReclamationPlan> {
        self.revalidate(r)?;
        let c = self.volume.container();
        if c.checkpoint().volumes.len() != 1 || c.checkpoint().blocks > 127 * 32768 {
            return Err(unavailable(
                "APFS reclamation single-volume/leaf/CIB profile",
            ));
        }
        self.generation
            .checked_add(2)
            .ok_or_else(|| budget("APFS reclamation generation exhausted"))?;
        for node in self.volume.inner.nodes.values() {
            if u32le(&node.raw, 68) != 0 {
                return Err(unavailable("APFS reclamation BSD write/security flags"));
            }
            for stream in &node.streams {
                if (stream.kind != StreamKind::Data && stream.inline.is_none())
                    || (stream.kind == StreamKind::Data && stream.id != node.id)
                {
                    return Err(unavailable(
                        "APFS reclamation external/shared stream profile",
                    ));
                }
            }
        }
        let horizon = c
            .inner
            .retained_headers
            .iter()
            .map(|(_, h)| u64le(h, 16))
            .min()
            .ok_or_else(|| invalid("APFS reclamation retained horizon"))?;
        self.snapshot.work.charge(self.limits.audit.work)?;
        let proof = prove_apfs_retention(&self.volume, horizon, self.limits.audit, r)?;
        if !proof.retirement_candidates().is_empty() {
            return Err(invalid(
                "APFS reclamation requires durable prior descriptor retirement",
            ));
        }
        let blocks = c.checkpoint().blocks;
        let charge = blocks
            .checked_mul(1024)
            .and_then(|n| n.checked_add((self.limits.read.records as u64).checked_mul(32)?))
            .ok_or_else(|| budget("APFS reclamation plan reservation"))?;
        let lease = r.memory.reserve(charge)?;
        self.snapshot.work.charge(
            self.limits
                .read
                .work
                .checked_add(
                    blocks
                        .checked_mul(64)
                        .ok_or_else(|| budget("APFS reclamation planning work"))?,
                )
                .ok_or_else(|| budget("APFS reclamation planning work overflow"))?,
        )?;
        let sm_address = c
            .inner
            .mappings
            .iter()
            .find(|m| m.oid == c.checkpoint().space_manager)
            .ok_or_else(|| invalid("APFS reclamation spaceman"))?
            .address;
        let sm = self.copied(sm_address)?;
        let main_pending = self.pending_blocks(u64le(&sm, 248), r)?;
        let internal_pending = self.pending_blocks(u64le(&sm, 208), r)?;
        let mut main = Vec::new();
        main.try_reserve_exact(main_pending.len())
            .map_err(|_| budget("APFS reclaim main index"))?;
        for (block, xid) in main_pending {
            r.cancellation.check()?;
            let state = proof
                .block(block)
                .ok_or_else(|| invalid("APFS reclamation main block"))?;
            if xid < horizon && !state.live {
                main.push(block);
            }
        }
        let mut internal = Vec::new();
        internal
            .try_reserve_exact(internal_pending.len())
            .map_err(|_| budget("APFS reclaim internal index"))?;
        for (block, xid) in internal_pending {
            r.cancellation.check()?;
            let state = proof
                .block(block)
                .ok_or_else(|| invalid("APFS reclamation internal block"))?;
            if xid < horizon && !state.internal_live {
                internal.push(block);
            }
        }
        if main.is_empty() && internal.is_empty() {
            return Err(unavailable(
                "APFS no safely reclaimable native retirement reservations",
            ));
        }
        let mut work = Work {
            limits: self.limits.read,
            used: 0,
        };
        let (vmap, _) = index::omap(c, u64le(&self.volume.inner.header, 128), &mut work, r)?;
        let catalog = records(
            c,
            u64le(&self.volume.inner.header, 136),
            0,
            TreeKind::Filesystem,
            Some(&vmap),
            &mut work,
            r,
        )?;
        self.snapshot.work.charge(work.used)?;
        let counts = (main.len(), internal.len());
        let cow = self.assemble(
            Projection {
                binding: None,
                catalog,
                payload: Vec::new(),
                input: Arc::new(EmptyInput(ObjectId {
                    source: self.scope,
                    generation: self.generation,
                    native: b"native retirement reclamation".to_vec(),
                })),
                offset: 0,
                eof: 0,
                zero_from: None,
                lease,
                resources: r.clone(),
                counters: None,
                reclamation: Some(Reclamation { main, internal }),
            },
            r,
        )?;
        self.revalidate(r)?;
        Ok(ApfsReclamationPlan {
            cow,
            main: counts.0,
            internal: counts.1,
            _retention: proof,
        })
    }
    /// Publish the prepared native bitmap/CIB/queue roots and checkpoint through the normal COW
    /// barriers. Every retained predecessor remains recoverable; the external anchor is geometry
    /// only. Removed queue entries are never treated as a substitute for the live-reference proof.
    pub fn commit_reclamation(
        &mut self,
        plan: ApfsReclamationPlan,
        anchor: &ApfsRecoveryAnchor,
        r: &Resources,
    ) -> Result<ApfsReclamationReceipt> {
        let publication = self.commit_range(plan.cow, anchor, r)?;
        Ok(ApfsReclamationReceipt {
            publication,
            main_blocks: plan.main,
            internal_blocks: plan.internal,
        })
    }
}
