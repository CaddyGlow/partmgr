//! Independently retained live-reference and pending-reservation classifications.
use super::*;

/// Native block classification under an explicitly selected retention horizon.
/// A pending reservation is not a live reference and neither grants mutation authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApfsRetainedBlock {
    /// A retained checkpoint has a live native reference to this block.
    pub live: bool,
    /// A retained checkpoint lists this block in a main-device retirement queue.
    pub pending: bool,
    /// A retained checkpoint owns this internal-pool block.
    pub internal_live: bool,
    /// A retained checkpoint reserves this internal-pool block only through a retirement queue.
    pub internal_pending: bool,
    /// A checkpoint below the requested horizon has a live reference.
    pub older_live: bool,
    /// A checkpoint below the requested horizon has a retirement reservation.
    pub older_pending: bool,
    /// A checkpoint below the requested horizon owns this internal-pool block.
    pub older_internal_live: bool,
    /// An older checkpoint reserves this internal-pool block through a retirement queue.
    pub older_internal_pending: bool,
}
/// Complete clean-source retention classification. No block is freed or reusable by this proof.
pub struct ApfsRetentionProof {
    states: Vec<u8>,
    retained: Vec<(u64, u64)>,
    retirement_candidates: Vec<(u64, u64)>,
    _lease: Reservation,
}
impl ApfsRetentionProof {
    /// Checked classification of one native physical block; out-of-volume is unavailable.
    pub fn block(&self, block: u64) -> Option<ApfsRetainedBlock> {
        let f = *self.states.get(usize::try_from(block).ok()?)?;
        Some(ApfsRetainedBlock {
            live: f & 1 != 0,
            pending: f & 2 != 0,
            internal_live: f & 4 != 0,
            internal_pending: f & 8 != 0,
            older_live: f & 16 != 0,
            older_pending: f & 32 != 0,
            older_internal_live: f & 64 != 0,
            older_internal_pending: f & 128 != 0,
        })
    }
    /// Physical checkpoint descriptor addresses and XIDs that must remain retained.
    pub fn retained_checkpoints(&self) -> &[(u64, u64)] {
        &self.retained
    }
    /// Checked complete older descriptors eligible for a separately authorized retirement protocol.
    /// These remain allocated and fully retained on disk until that protocol succeeds.
    pub fn retirement_candidates(&self) -> &[(u64, u64)] {
        &self.retirement_candidates
    }
}

/// Classify all complete native checkpoints without merging retirement reservations into live refs.
/// The requested XID must name an existing checkpoint and retain at least one predecessor.
/// The source must pass the existing complete all-volume/history audit first. This function makes
/// no changes, authorizes no discard, and reserves bounded maps before allocation.
pub fn prove_apfs_retention(
    volume: &ApfsVolume,
    minimum_retained_xid: u64,
    limits: ApfsAuditLimits,
    r: &Resources,
) -> Result<ApfsRetentionProof> {
    r.cancellation.check()?;
    let c = volume.container();
    let selected = c.checkpoint().xid;
    if minimum_retained_xid == 0 || minimum_retained_xid >= selected {
        return Err(bad("APFS retention must preserve a complete predecessor"));
    }
    if !c
        .inner
        .retained_headers
        .iter()
        .any(|(_, h)| u64le(h, 16) == minimum_retained_xid)
    {
        return Err(bad("APFS retention horizon does not name a checkpoint"));
    }
    let blocks = usize::try_from(c.checkpoint().blocks)
        .map_err(|_| budget("APFS retention block address space"))?;
    if c.checkpoint().blocks > limits.blocks {
        return Err(budget("APFS retention block ceiling"));
    }
    let count = c.inner.retained_headers.len();
    let charge = (blocks as u64)
        .checked_add(
            (count as u64)
                .checked_mul(32)
                .ok_or_else(|| budget("APFS retention checkpoint reservation"))?,
        )
        .ok_or_else(|| budget("APFS retention reservation"))?;
    let lease = r.memory.reserve(charge)?;
    let mut states = vector(blocks)?;
    states.resize(blocks, 0u8);
    let mut retained = vector(count)?;
    let mut retirement_candidates = vector(count)?;
    let complete = audit_apfs(volume, limits, r)?;
    if !complete.is_clean() {
        return Err(bad("APFS retention requires complete clean ownership"));
    }
    let mut remaining = limits
        .work
        .checked_sub(complete.work)
        .ok_or_else(|| budget("APFS retention complete audit work"))?;
    let mut objects = complete.objects;
    drop(complete);
    for (address, header) in &c.inner.retained_headers {
        r.cancellation.check()?;
        let xid = u64le(header, 16);
        let checkpoint = if *address == c.checkpoint().superblock {
            c.clone()
        } else {
            c.historical(*address, header, remaining, r)?
                .ok_or_else(|| unsupported("APFS incomplete checkpoint retirement profile"))?
        };
        remaining = remaining
            .checked_sub(checkpoint.inner.discovery_work)
            .ok_or_else(|| budget("APFS retention checkpoint discovery work"))?;
        let oid = *checkpoint
            .checkpoint()
            .volumes
            .first()
            .ok_or_else(|| bad("APFS retention checkpoint has no volumes"))?;
        let v = ApfsVolume::open_bounded(checkpoint, oid, remaining, r)?;
        remaining = remaining
            .checked_sub(v.inner.decode_work)
            .ok_or_else(|| budget("APFS retention volume work"))?;
        let proof = audit_checkpoint(
            &v,
            ApfsAuditLimits {
                work: remaining,
                objects: limits.objects.saturating_sub(objects),
                ..limits
            },
            r,
        )?;
        remaining = remaining
            .checked_sub(proof.work)
            .ok_or_else(|| budget("APFS retention checkpoint work"))?;
        objects = objects
            .checked_add(proof.objects)
            .ok_or_else(|| budget("APFS retention object accounting"))?;
        if !proof.is_clean() {
            return Err(bad("APFS retention checkpoint reference defect"));
        }
        let shift = if xid >= minimum_retained_xid { 0 } else { 4 };
        for (block, state) in states.iter_mut().enumerate() {
            r.cancellation.check()?;
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| budget("APFS retention classification work"))?;
            *state |= (u8::from(proof.owners[block].kind != 0)
                | (u8::from(proof.pending[block]) << 1)
                | (u8::from(proof.internal_live[block]) << 2)
                | (u8::from(proof.internal_owners[block] && !proof.internal_live[block]) << 3))
                << shift;
        }
        if shift == 0 {
            retained.push((*address, xid));
        } else {
            retirement_candidates.push((*address, xid));
        }
    }
    retained.sort_unstable_by_key(|entry| entry.1);
    retirement_candidates.sort_unstable_by_key(|entry| entry.1);
    if !retained.iter().any(|(_, xid)| *xid < selected) {
        return Err(bad("APFS retention has no complete predecessor"));
    }
    volume.revalidate(&volume.root_identity(), r)?;
    Ok(ApfsRetentionProof {
        states,
        retained,
        retirement_candidates,
        _lease: lease,
    })
}
