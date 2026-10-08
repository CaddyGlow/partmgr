//! Owned APFS sessions. Copied metadata is immutable; mutable storage is never a `ReadAt`.
use crate::{
    fs_apfs::{ApfsContainer, ApfsReadLimits, ApfsVolume},
    fs_apfs_audit::{ApfsAuditLimits, ApfsAuditReport, audit_apfs},
    fs_core::*,
    storage::Storage,
};
use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
const BLOCK: usize = 4096;
static SCOPES: AtomicU64 = AtomicU64::new(1);
#[path = "fs_apfs_edit_cow.rs"]
mod cow;
pub use cow::{
    ApfsCreateMetadata, ApfsEditReceipt, ApfsMutationPlan, ApfsRangePlan, ApfsRecoveryAnchor,
};
/// Independent metadata snapshot and restart ceilings, in addition to decoder/audit limits.
#[derive(Clone, Copy, Debug)]
pub struct ApfsEditLimits {
    /// Maximum copied native metadata blocks. Payload blocks are not prefetched.
    pub metadata_blocks: usize,
    /// Maximum decoder attempts, including the successful attempt.
    pub attempts: usize,
    /// Aggregate conservative decoder/audit reservations plus actual positional bytes.
    pub work: u64,
    /// Immutable decoder limits for each attempt.
    pub read: ApfsReadLimits,
    /// Complete all-volume/history ownership proof limits for each attempt.
    pub audit: ApfsAuditLimits,
}
#[derive(Debug)]
struct MissingBlock(u64);
impl fmt::Display for MissingBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uncopied APFS metadata block {}", self.0)
    }
}
impl std::error::Error for MissingBlock {}
struct WorkCounter {
    used: AtomicU64,
    ceiling: AtomicU64,
    resources: Resources,
}
impl WorkCounter {
    fn charge(&self, n: u64) -> Result<()> {
        self.resources.cancellation.check()?;
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(n)
                    .filter(|next| *next <= self.ceiling.load(Ordering::Acquire))
            })
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "APFS owned snapshot work"))?;
        Ok(())
    }
}
struct Snapshot {
    length: u64,
    blocks: Vec<(u64, Arc<[u8; BLOCK]>)>,
    work: Arc<WorkCounter>,
    // One reservation covers every retained block and both simultaneously live index tables.
    _lease: Arc<Reservation>,
}
impl ReadAt for Snapshot {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.work
            .charge(out.len() as u64)
            .map_err(io::Error::other)?;
        if !at.is_multiple_of(BLOCK as u64)
            || out.len() != BLOCK
            || at
                .checked_add(BLOCK as u64)
                .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APFS metadata-only snapshot range",
            ));
        }
        let block = at / BLOCK as u64;
        let index = self
            .blocks
            .binary_search_by_key(&block, |entry| entry.0)
            .map_err(|_| io::Error::other(MissingBlock(block)))?;
        out.copy_from_slice(self.blocks[index].1.as_ref());
        Ok(())
    }
}
/// Exclusive owned container. This checkpoint exposes preparation/proof only; COW publication follows separately.
pub struct ApfsEditor<S: Storage> {
    target: S,
    scope: u128,
    recovery_required: bool,
    generation: u64,
    snapshot: Arc<Snapshot>,
    volume: ApfsVolume,
    proof: ApfsAuditReport,
    limits: ApfsEditLimits,
}
impl<S: Storage> ApfsEditor<S> {
    /// Decode immutable copies of precisely requested metadata, requiring a complete clean container proof.
    /// Caller supplies exclusive storage and an explicit volume; no host devices are discovered.
    pub fn open(target: S, volume_oid: u64, limits: ApfsEditLimits, r: &Resources) -> Result<Self> {
        Self::open_seeded(target, volume_oid, limits, r, None)
    }
    fn open_seeded(
        target: S,
        volume_oid: u64,
        limits: ApfsEditLimits,
        r: &Resources,
        seed: Option<(u64, [u8; BLOCK])>,
    ) -> Result<Self> {
        r.cancellation.check()?;
        let seeded = seed.is_some();
        let length = target
            .len()
            .map_err(|e| Error::io("APFS owned length", e))?;
        if limits.metadata_blocks == 0 || limits.attempts == 0 {
            return Err(Error::new(
                ErrorKind::BudgetExhausted,
                "APFS zero snapshot ceilings",
            ));
        }
        if length < 1048576 || !length.is_multiple_of(BLOCK as u64) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "APFS owned bare-container geometry",
            ));
        }
        if length / BLOCK as u64 > limits.read.blocks || length / BLOCK as u64 > limits.audit.blocks
        {
            return Err(Error::new(
                ErrorKind::BudgetExhausted,
                "APFS owned geometry ceiling",
            ));
        }
        let charge = u64::try_from(limits.metadata_blocks)
            .ok()
            .and_then(|n| n.checked_mul(BLOCK as u64 + 256))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::BudgetExhausted,
                    "APFS snapshot reservation overflow",
                )
            })?;
        let lease = Arc::new(r.memory.reserve(charge)?);
        let work = Arc::new(WorkCounter {
            used: AtomicU64::new(seed.as_ref().map_or(0, |s| s.0)),
            ceiling: AtomicU64::new(limits.work),
            resources: r.clone(),
        });
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(limits.metadata_blocks)
            .map_err(|_| {
                Error::new(ErrorKind::BudgetExhausted, "APFS snapshot index allocation")
            })?;
        if let Some((_, bytes)) = seed {
            blocks.push((0, Arc::new(bytes)));
        }
        let attempt_charge = limits
            .read
            .work
            .checked_add(limits.audit.work)
            .ok_or_else(|| {
                Error::new(ErrorKind::BudgetExhausted, "APFS restart ceiling overflow")
            })?;
        for _ in 0..limits.attempts {
            work.charge(attempt_charge)?;
            let mut copied = Vec::new();
            copied.try_reserve_exact(blocks.len()).map_err(|_| {
                Error::new(ErrorKind::BudgetExhausted, "APFS immutable snapshot index")
            })?;
            copied.extend(blocks.iter().cloned());
            let snapshot = Arc::new(Snapshot {
                length,
                blocks: copied,
                work: work.clone(),
                _lease: lease.clone(),
            });
            let decoded = (|| {
                let c = ApfsContainer::open(snapshot.clone(), limits.read, r)?;
                let volume = ApfsVolume::open(c, volume_oid, r)?;
                let proof = audit_apfs(&volume, limits.audit, r)?;
                if !proof.is_complete() || !proof.is_clean() {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "APFS owned session requires complete clean proof",
                    ));
                }
                Ok((volume, proof))
            })();
            match decoded {
                Ok((volume, proof)) => {
                    let sequence = SCOPES
                        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                        .map_err(|_| {
                            Error::new(ErrorKind::BudgetExhausted, "APFS owned scope exhausted")
                        })?;
                    let editor = Self {
                        target,
                        scope: (17u128 << 64) | u128::from(sequence),
                        recovery_required: false,
                        generation: 0,
                        snapshot,
                        volume,
                        proof,
                        limits,
                    };
                    editor.revalidate_subset(r, !seeded)?;
                    return Ok(editor);
                }
                Err(error) => {
                    // Only our exact typed sentinel authorizes another Storage read.
                    let missing = error
                        .source
                        .as_ref()
                        .and_then(io::Error::get_ref)
                        .and_then(|cause| cause.downcast_ref::<MissingBlock>())
                        .map(|m| m.0);
                    let Some(block) = missing else {
                        return Err(error);
                    };
                    if blocks.len() == limits.metadata_blocks {
                        return Err(Error::new(
                            ErrorKind::BudgetExhausted,
                            "APFS metadata block ceiling",
                        ));
                    }
                    if target
                        .len()
                        .map_err(|e| Error::io("APFS snapshot length", e))?
                        != length
                    {
                        return Err(Error::new(
                            ErrorKind::StalePlan,
                            "APFS owned length changed",
                        ));
                    }
                    work.charge(BLOCK as u64)?;
                    let mut bytes = [0u8; BLOCK];
                    target
                        .read_exact_at(block * BLOCK as u64, &mut bytes)
                        .map_err(|e| Error::io("APFS owned metadata copy", e))?;
                    let at = blocks
                        .binary_search_by_key(&block, |entry| entry.0)
                        .unwrap_err();
                    blocks.insert(at, (block, Arc::new(bytes)));
                }
            }
        }
        Err(Error::new(
            ErrorKind::BudgetExhausted,
            "APFS metadata restart ceiling",
        ))
    }
    /// Rebind length and every retained metadata byte to the exclusive owned storage.
    pub fn revalidate(&self, r: &Resources) -> Result<()> {
        if self.recovery_required {
            return Err(Error::new(
                ErrorKind::InterruptedWrite,
                "APFS native recovery required",
            ));
        }
        self.revalidate_subset(r, true)
    }
    fn revalidate_subset(&self, r: &Resources, boot: bool) -> Result<()> {
        r.cancellation.check()?;
        self.snapshot.work.resources.cancellation.check()?;
        if self
            .target
            .len()
            .map_err(|e| Error::io("APFS owned revalidate length", e))?
            != self.snapshot.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS owned length changed",
            ));
        }
        let mut bytes = [0u8; BLOCK];
        for (block, expected) in &self.snapshot.blocks {
            if !boot && *block == 0 {
                continue;
            }
            r.cancellation.check()?;
            self.snapshot.work.charge(BLOCK as u64)?;
            self.target
                .read_exact_at(block * BLOCK as u64, &mut bytes)
                .map_err(|e| Error::io("APFS owned binding read", e))?;
            if &bytes != expected.as_ref() {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS owned metadata changed",
                ));
            }
        }
        if self
            .target
            .len()
            .map_err(|e| Error::io("APFS owned final length", e))?
            != self.snapshot.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS owned final length changed",
            ));
        }
        Ok(())
    }
    /// Native selected checkpoint transaction, bound to this session's metadata snapshot.
    pub fn checkpoint_xid(&self) -> u64 {
        self.volume.container().checkpoint().xid
    }
    /// Complete all-volume/history allocation proof. It confers no standalone mutation authority.
    pub fn allocation_proof(&self) -> &ApfsAuditReport {
        &self.proof
    }
    /// Actual metadata copies retained; payload contents are not prefetched.
    pub fn copied_metadata_blocks(&self) -> usize {
        self.snapshot.blocks.len()
    }
    /// Conservative charged restart work plus exact copied/readback positional bytes.
    pub fn work_used(&self) -> u64 {
        self.snapshot.work.used.load(Ordering::Acquire)
    }
    /// Configured preparation ceilings.
    pub fn limits(&self) -> ApfsEditLimits {
        self.limits
    }
    /// Return exclusive storage without exposing an immutable alias.
    pub fn into_storage(self) -> S {
        self.target
    }
}
