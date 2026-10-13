//! Audited classic bitmap and direct/indirect allocation planning.
#[cfg(feature = "std")]
use super::transaction::OverwriteEvidence;
use super::transaction::{OrderedDataEvidence, OrderedDataPatch, OrderedOperation, OrderedOrigin};
use super::*;
use crate::platform::collections::BTreeMap;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{fs_core::FileRead, fs_file::ExtentKind, storage::WriteRange};
use core::cell::Cell;
fn budget(message: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, message)
}
fn bad(message: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message)
}
fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn sort_tick(work: &mut usize, limit: usize, r: &Resources) -> Result<()> {
    r.cancellation.check()?;
    *work = work
        .checked_add(1)
        .filter(|n| *n <= limit)
        .ok_or_else(|| budget("ext2 bounded sort work"))?;
    Ok(())
}
// In-place heapsort charges each comparison and swap before doing it.
pub(crate) fn bounded_sort<T, K: Ord>(
    values: &mut [T],
    key: impl Fn(&T) -> K,
    work: &mut usize,
    limit: usize,
    r: &Resources,
) -> Result<()> {
    fn sift<T, K: Ord>(
        values: &mut [T],
        mut root: usize,
        end: usize,
        key: &impl Fn(&T) -> K,
        work: &mut usize,
        limit: usize,
        r: &Resources,
    ) -> Result<()> {
        loop {
            let Some(mut child) = root
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .filter(|n| *n < end)
            else {
                return Ok(());
            };
            if child + 1 < end {
                sort_tick(work, limit, r)?;
                if key(&values[child]) < key(&values[child + 1]) {
                    child += 1;
                }
            }
            sort_tick(work, limit, r)?;
            if key(&values[root]) >= key(&values[child]) {
                return Ok(());
            }
            sort_tick(work, limit, r)?;
            values.swap(root, child);
            root = child;
        }
    }
    r.cancellation.check()?;
    let length = values.len();
    for root in (0..length / 2).rev() {
        sift(values, root, length, &key, work, limit, r)?;
    }
    for end in (1..length).rev() {
        sort_tick(work, limit, r)?;
        values.swap(0, end);
        sift(values, 0, end, &key, work, limit, r)?;
    }
    Ok(())
}
fn zeros(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("ext2 bounded allocation"))?;
    v.resize(n, 0);
    Ok(v)
}
/// Native allocation and metadata effects of a file resize.
#[derive(Clone, Debug)]
pub struct ExtResizeReport {
    /// Previous logical size.
    pub old_length: u64,
    /// Resulting logical size.
    pub new_length: u64,
    /// Newly allocated payload blocks.
    pub allocated_data_blocks: usize,
    /// Newly allocated classic indirect blocks.
    pub allocated_indirect_blocks: usize,
    /// Payload blocks released from the verified owned map.
    pub freed_data_blocks: usize,
    /// Indirect blocks released after their references are removed.
    pub freed_indirect_blocks: usize,
    /// The resulting final partial allocated block has an explicitly zeroed tail.
    pub retained_tail_zeroed: bool,
    /// Native inode fields remain exact except size, sector count and classic pointers.
    pub native_metadata_preserved: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Phase {
    Initialize,
    Allocate,
    Publish,
    Release,
    Clean,
}
pub(crate) struct PlanningContext<'a> {
    pub(super) target: &'a dyn Storage,
    pub(super) geometry: &'a ExtGeometry,
    pub(super) limits: ExtEditLimits,
    audit: &'a ExtAuditReport,
    decoder_open:
        for<'b> fn(&'b dyn Storage, u128, &Resources) -> io::Result<ExtStorageDecoder<'b>>,
    pub(super) scope: u128,
    pub(super) generation: u64,
}
impl<S: Storage, J: Storage> ExtEditor<S, J> {
    pub(super) fn planning_context<'a>(&'a self, r: &Resources) -> Result<PlanningContext<'a>> {
        self.ready(r)?;
        Ok(PlanningContext {
            target: &self.target,
            geometry: &self.geometry,
            limits: self.limits,
            scope: self.scope,
            generation: self.generation,
            decoder_open: |target, scope, r| ExtStorageDecoder::open_storage(target, scope, r),
            audit: self
                .audit
                .as_ref()
                .ok_or_else(|| bad("ext2 audit authorization absent"))?,
        })
    }
}
static NEXT_ORDERED_PLANNER: AtomicU64 = AtomicU64::new(1);
pub(super) struct FreshRegularBlock {
    source: u128,
    generation: u64,
    operation: OrderedOperation,
    serial: u64,
    block: u32,
    logical_block: u64,
}
pub(super) struct Planner<'a> {
    pub(super) target: &'a dyn Storage,
    pub(super) g: &'a ExtGeometry,
    pub(super) limits: ExtEditLimits,
    pub(super) r: &'a Resources,
    free: &'a [crate::fs_ext_audit::ExtFreeRange],
    free_index: usize,
    free_used: u64,
    edits: BTreeMap<u64, (u8, Phase)>,
    patches: Vec<(Phase, WriteRange)>,
    bytes: u64,
    work: usize,
    scope: u128,
    generation: u64,
    ordered: Option<OrderedDataEvidence>,
    symlink: Vec<super::transaction::SymlinkEvidence>,
    symlink_metadata: bool,
    ordered_serial: u64,
    lease: Reservation,
    decoder_open:
        for<'b> fn(&'b dyn Storage, u128, &Resources) -> io::Result<ExtStorageDecoder<'b>>,
}
impl<'a> Planner<'a> {
    pub(super) fn new(editor: &PlanningContext<'a>, r: &'a Resources) -> Result<Self> {
        editor.ready(r)?;
        let charge = editor
            .limits
            .affected_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add((editor.limits.work as u64).checked_mul(64)?))
            .and_then(|n| {
                n.checked_add(
                    u64::from(editor.limits.undo.patches)
                        * (4 * crate::platform::mem::size_of::<WriteRange>() as u64
                            + 96
                            + crate::platform::mem::size_of::<OrderedDataPatch>() as u64),
                )
            })
            .and_then(|n| n.checked_add(2048))
            .ok_or_else(|| budget("ext2 allocation planning accounting"))?;
        let lease = r.memory.reserve(charge)?;
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(editor.limits.undo.patches as usize)
            .map_err(|_| budget("ext2 allocation patch vector"))?;
        Ok(Self {
            target: editor.target,
            g: editor.geometry,
            limits: editor.limits,
            r,
            free: editor.audit.free_ranges(),
            free_index: 0,
            free_used: 0,
            edits: BTreeMap::new(),
            patches,
            bytes: 0,
            work: 0,
            lease,
            scope: editor.scope,
            generation: editor.generation,
            ordered: None,
            symlink: Vec::new(),
            symlink_metadata: false,
            ordered_serial: 0,
            decoder_open: editor.decoder_open,
        })
    }
    pub(super) fn begin_symlink_metadata(&mut self) -> Result<()> {
        self.tick(1)?;
        if self.ordered.is_some() || self.symlink_metadata {
            return Err(bad("symlink planner purpose conflict"));
        }
        self.symlink_metadata = true;
        Ok(())
    }
    pub(super) fn scope_for_symlink(&self) -> u128 {
        self.scope
    }
    pub(super) fn generation_for_symlink(&self) -> u64 {
        self.generation
    }
    pub(super) fn set_symlink_evidence(
        &mut self,
        e: super::transaction::SymlinkEvidence,
    ) -> Result<()> {
        self.tick(1)?;
        if !self.symlink_metadata
            || !self.symlink.is_empty()
            || e.source != self.scope
            || e.generation != self.generation
        {
            return Err(bad("symlink purpose/evidence mismatch"));
        }
        // Both construction paths retain a proof lease that includes exactly
        // size_of::<SymlinkEvidence>() for this sole vector element, separately
        // from target/body capacities. Check actual capacity before publication.
        self.symlink
            .try_reserve_exact(1)
            .map_err(|_| budget("symlink evidence owner"))?;
        if self.symlink.capacity() > 1 {
            return Err(budget("symlink evidence capacity"));
        }
        self.symlink.push(e);
        Ok(())
    }
    pub(super) fn begin_ordered(&mut self, operation: OrderedOperation) -> Result<()> {
        self.tick(1)?;
        if self.ordered.is_some() || self.symlink_metadata {
            return Err(bad("ext2 ordered evidence already initialized"));
        }
        let capacity = self
            .limits
            .file_blocks
            .min(self.limits.undo.patches as usize);
        let mut data = Vec::new();
        data.try_reserve_exact(capacity)
            .map_err(|_| budget("ext2 ordered evidence allocation"))?;
        if data.capacity() > capacity {
            return Err(budget("ext2 ordered evidence capacity"));
        }
        self.ordered_serial = NEXT_ORDERED_PLANNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| budget("ext2 ordered planner identity exhausted"))?;
        self.ordered = Some(OrderedDataEvidence {
            source: self.scope,
            generation: self.generation,
            operation,
            data,
            source_guard: None,
            overwrite: None,
        });
        Ok(())
    }
    pub(super) fn allocate_regular(&mut self, logical_block: u64) -> Result<FreshRegularBlock> {
        let operation = self
            .ordered
            .as_ref()
            .ok_or_else(|| bad("ext2 regular allocation lacks operation evidence"))?
            .operation;
        Ok(FreshRegularBlock {
            block: self.allocate()?,
            logical_block,
            source: self.scope,
            generation: self.generation,
            operation,
            serial: self.ordered_serial,
        })
    }
    pub(super) fn regular_block(token: &FreshRegularBlock) -> u32 {
        token.block
    }
    fn record_regular(&mut self, role: OrderedDataPatch) -> Result<()> {
        self.tick(1)?;
        let evidence = self
            .ordered
            .as_mut()
            .ok_or_else(|| bad("ext2 regular patch lacks operation evidence"))?;
        if evidence.data.len() == evidence.data.capacity() {
            return Err(budget("ext2 ordered evidence ceiling"));
        }
        evidence.data.push(role);
        Ok(())
    }
    pub(super) fn patch_regular_fresh(
        &mut self,
        token: FreshRegularBlock,
        body: Vec<u8>,
    ) -> Result<()> {
        if token.source != self.scope
            || token.generation != self.generation
            || token.serial != self.ordered_serial
            || self
                .ordered
                .as_ref()
                .is_none_or(|e| e.operation != token.operation)
        {
            return Err(bad("ext2 regular allocation belongs to another planner"));
        }
        if body.len() != self.g.block_size as usize {
            return Err(bad("ext2 ordered fresh data must fill one block"));
        }
        let offset = u64::from(token.block) * u64::from(self.g.block_size);
        let bytes = body.len();
        self.patch(offset, body, Phase::Initialize)?;
        self.record_regular(OrderedDataPatch {
            offset,
            bytes,
            logical_block: token.logical_block,
            origin: OrderedOrigin::AuditedFree,
        })
    }
    fn patch_regular_tail(
        &mut self,
        file: &ExtEditFile,
        logical: u64,
        block: u32,
        body: Vec<u8>,
    ) -> Result<()> {
        let bs = u64::from(self.g.block_size);
        let within = (file.len() % bs) as usize;
        if within == 0
            || logical != file.len() / bs
            || body.len() != self.g.block_size as usize - within
        {
            return Err(bad("ext2 ordered tail exceeds original EOF suffix"));
        }
        let valid_operation = self.ordered.as_ref().is_some_and(|e| matches!(e.operation,
            OrderedOperation::Extend { inode, inode_generation, old_length, .. }
                if inode == file.inode.number() && inode_generation == file.inode.generation() && old_length == file.len()));
        if file.identity.source != self.scope
            || file.identity.generation != self.generation
            || !valid_operation
        {
            return Err(bad("ext2 ordered tail belongs to another operation"));
        }
        let position = logical * bs;
        let mut found = None;
        for extent in &file.map.extents {
            self.tick(1)?;
            if extent.offset <= position
                && extent
                    .offset
                    .checked_add(extent.length)
                    .is_some_and(|end| position < end)
            {
                found = Some(extent);
                break;
            }
        }
        let extent = found.ok_or_else(|| bad("ext2 ordered tail missing original mapping"))?;
        if !matches!(extent.kind, ExtentKind::Data(at) if at.checked_add(position - extent.offset) == Some(u64::from(block) * bs))
        {
            return Err(bad("ext2 ordered tail differs from original data mapping"));
        }
        let offset = u64::from(block) * bs + within as u64;
        let bytes = body.len();
        self.patch(offset, body, Phase::Initialize)?;
        self.record_regular(OrderedDataPatch {
            offset,
            bytes,
            logical_block: logical,
            origin: OrderedOrigin::ExistingAppendTail {
                visible_prefix_bytes: within,
            },
        })
    }
    fn validate_ordered(&mut self, source: u128, generation: u64) -> Result<()> {
        let Some(evidence) = self.ordered.take() else {
            return Ok(());
        };
        if evidence.source != source || evidence.generation != generation {
            return Err(bad("ext2 ordered evidence binding differs"));
        }
        let bs = u64::from(self.g.block_size);
        let truncating = matches!(evidence.operation, OrderedOperation::Truncate { .. });
        let overwriting = matches!(evidence.operation, OrderedOperation::Overwrite { .. });
        let sparse_extending = matches!(evidence.operation, OrderedOperation::SparseExtend { .. });
        let (inode, inode_generation, old, length, creating) = match evidence.operation {
            OrderedOperation::SparseExtend {
                inode,
                inode_generation,
                old_length,
                new_length,
            } if new_length > old_length => {
                (inode, inode_generation, old_length, new_length, false)
            }
            OrderedOperation::Extend {
                inode,
                inode_generation,
                old_length,
                new_length,
            } if new_length > old_length => {
                (inode, inode_generation, old_length, new_length, false)
            }
            OrderedOperation::Truncate {
                inode,
                inode_generation,
                old_length,
                new_length,
            } if new_length < old_length => {
                (inode, inode_generation, old_length, new_length, false)
            }
            OrderedOperation::Overwrite {
                inode,
                inode_generation,
                length,
                offset,
                bytes,
            } if bytes != 0 && offset.checked_add(bytes).is_some_and(|end| end <= length) => {
                (inode, inode_generation, length, length, false)
            }
            OrderedOperation::Create {
                inode,
                inode_generation,
                length,
            } => (inode, inode_generation, 0, length, true),
            _ => return Err(bad("ext2 ordered operation lengths")),
        };
        if evidence.overwrite.is_some() != overwriting {
            return Err(bad("overwrite evidence operation mismatch"));
        }
        if inode == 0 || inode > self.g.inodes {
            return Err(bad("ext2 ordered operation inode"));
        }
        let generation_at = self
            .inode_offset(inode)?
            .checked_add(100)
            .ok_or_else(|| bad("ext2 ordered inode generation offset"))?;
        let mut raw_generation = [0; 4];
        if creating {
            let mut found = false;
            for index in 0..self.patches.len() {
                self.tick(1)?;
                let patch = &self.patches[index].1;
                if generation_at >= patch.offset()
                    && generation_at
                        .checked_add(4)
                        .is_some_and(|end| end <= patch.offset() + patch.replacement().len() as u64)
                {
                    let at = (generation_at - patch.offset()) as usize;
                    raw_generation.copy_from_slice(&patch.replacement()[at..at + 4]);
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(bad("ext2 ordered birth lacks inode generation patch"));
            }
        } else {
            self.tick(1)?;
            self.target
                .read_exact_at(generation_at, &mut raw_generation)
                .map_err(native)?;
        }
        if u32::from_le_bytes(raw_generation) != inode_generation {
            return Err(bad("ext2 ordered inode generation changed"));
        }
        let first_logical = if let OrderedOperation::Overwrite { offset, .. } = evidence.operation {
            offset / bs
        } else if truncating {
            length / bs
        } else {
            old / bs
        };
        let expected_roles =
            if let OrderedOperation::Overwrite { offset, bytes, .. } = evidence.operation {
                (offset + bytes).div_ceil(bs) - offset / bs
            } else if truncating || sparse_extending {
                u64::from(evidence.source_guard.is_some())
            } else {
                length
                    .div_ceil(bs)
                    .checked_sub(first_logical)
                    .ok_or_else(|| bad("ext2 ordered role count overflow"))?
            };
        if evidence.data.len() as u64 != expected_roles {
            return Err(bad("ext2 ordered data coverage incomplete"));
        }
        for (index, role) in evidence.data.iter().enumerate() {
            self.tick(1)?;
            if role.logical_block != first_logical + index as u64 {
                return Err(bad("ext2 ordered logical coverage differs"));
            }
            let end = role
                .offset
                .checked_add(role.bytes as u64)
                .ok_or_else(|| bad("ext2 ordered data range overflow"))?;
            if role.bytes == 0
                || end > u64::from(self.g.blocks) * bs
                || role.logical_block >= length.div_ceil(bs)
            {
                return Err(bad("ext2 ordered data outside geometry or file"));
            }
            match role.origin {
                OrderedOrigin::AuditedFree
                    if role.offset.is_multiple_of(bs) && role.bytes as u64 == bs => {}
                OrderedOrigin::ExistingAppendTail {
                    visible_prefix_bytes,
                } if !truncating
                    && !overwriting
                    && !sparse_extending
                    && !old.is_multiple_of(bs)
                    && role.logical_block == old / bs
                    && visible_prefix_bytes as u64 == old % bs
                    && role.offset % bs == old % bs
                    && role.bytes as u64 == bs - old % bs => {}
                _ => return Err(bad("ext2 ordered data origin bounds")),
            }
            let mut matched = false;
            for patch_index in 0..self.patches.len() {
                self.tick(1)?;
                let patch = &self.patches[patch_index].1;
                let patch_end = patch
                    .offset()
                    .checked_add(patch.expected().len() as u64)
                    .ok_or_else(|| bad("ext2 ordered patch overflow"))?;
                if patch_end <= patch.offset() {
                    return Err(bad("ext2 ordered empty patch"));
                }
                if patch.offset() == role.offset && patch.expected().len() == role.bytes {
                    if matched {
                        return Err(bad("ext2 duplicate ordered patch"));
                    }
                    matched = true;
                } else if patch.offset() / bs <= (end - 1) / bs
                    && (patch_end - 1) / bs >= role.offset / bs
                {
                    return Err(bad("ext2 ordered data shares metadata block"));
                }
            }
            if !matched {
                return Err(bad("ext2 ordered data has no exact patch"));
            }
            for previous in &evidence.data[..index] {
                self.tick(1)?;
                if previous.offset / bs == role.offset / bs
                    || previous.logical_block == role.logical_block
                {
                    return Err(bad("ext2 ordered data block collision"));
                }
            }
        }
        self.ordered = Some(evidence);
        Ok(())
    }
    pub(super) fn tick(&mut self, n: usize) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("ext2 allocation work ceiling"))?;
        Ok(())
    }
    pub(super) fn current(&mut self, at: u64, out: &mut [u8]) -> Result<()> {
        self.tick(1)?;
        self.target.read_exact_at(at, out).map_err(native)?;
        for (i, b) in out.iter_mut().enumerate() {
            self.tick(1)?;
            if let Some((new, _)) = self.edits.get(&(at + i as u64)) {
                *b = *new;
            }
        }
        Ok(())
    }
    pub(super) fn edit(&mut self, at: u64, bytes: &[u8], phase: Phase) -> Result<()> {
        self.tick(bytes.len())?;
        for (i, &b) in bytes.iter().enumerate() {
            let at = at + i as u64;
            if let Some((old, old_phase)) = self.edits.get_mut(&at) {
                if *old_phase != phase {
                    return Err(bad("ext2 metadata phases overlap"));
                }
                *old = b;
            } else {
                self.edits.insert(at, (b, phase));
            }
        }
        Ok(())
    }
    pub(super) fn patch(&mut self, at: u64, after: Vec<u8>, phase: Phase) -> Result<()> {
        self.tick(1)?;
        self.bytes = self
            .bytes
            .checked_add(after.len() as u64)
            .filter(|n| *n <= self.limits.affected_bytes)
            .ok_or_else(|| budget("ext2 allocation affected bytes"))?;
        if self.patches.len() >= self.limits.undo.patches as usize {
            return Err(budget("ext2 allocation patch ceiling"));
        }
        let mut before = zeros(after.len())?;
        self.target.read_exact_at(at, &mut before).map_err(native)?;
        self.patches
            .push((phase, WriteRange::new(at, before, after).map_err(native)?));
        Ok(())
    }
    fn descriptor(&mut self, group: u32) -> Result<[u32; 3]> {
        self.tick(1)?;
        if group >= self.g.groups {
            return Err(bad("ext2 descriptor group outside geometry"));
        }
        let mut bytes = [0; 12];
        self.target
            .read_exact_at(
                (u64::from(self.g.first) + 1) * u64::from(self.g.block_size)
                    + u64::from(group) * 32,
                &mut bytes,
            )
            .map_err(native)?;
        Ok([u32le(&bytes, 0), u32le(&bytes, 4), u32le(&bytes, 8)])
    }
    pub(super) fn inode_offset(&mut self, number: u32) -> Result<u64> {
        if number == 0 || number > self.g.inodes {
            return Err(bad("ext2 inode outside geometry"));
        }
        let d = self.descriptor((number - 1) / self.g.inodes_per_group)?;
        Ok(u64::from(d[2]) * u64::from(self.g.block_size)
            + u64::from((number - 1) % self.g.inodes_per_group) * u64::from(self.g.inode_size))
    }
    pub(super) fn counter(
        &mut self,
        at: u64,
        delta: i64,
        width: usize,
        phase: Phase,
    ) -> Result<()> {
        let mut b = [0; 4];
        self.current(at, &mut b[..width])?;
        let old = if width == 2 {
            u16le(&b, 0) as i64
        } else {
            u32le(&b, 0) as i64
        };
        let next = old
            .checked_add(delta)
            .filter(|n| {
                *n >= 0
                    && (*n as u64)
                        <= if width == 2 {
                            u16::MAX as u64
                        } else {
                            u32::MAX as u64
                        }
            })
            .ok_or_else(|| bad("ext2 native counter overflow"))?;
        self.edit(at, &(next as u32).to_le_bytes()[..width], phase)
    }
    pub(super) fn bitmap(&mut self, number: u32, inode: bool, allocate: bool) -> Result<()> {
        let (index, per) = if inode {
            (
                number
                    .checked_sub(1)
                    .ok_or_else(|| bad("ext2 inode bitmap zero"))?,
                self.g.inodes_per_group,
            )
        } else {
            (
                number
                    .checked_sub(self.g.first)
                    .ok_or_else(|| bad("ext2 block bitmap geometry"))?,
                self.g.blocks_per_group,
            )
        };
        let group = index / per;
        let within = index % per;
        let d = self.descriptor(group)?;
        let at =
            u64::from(d[usize::from(inode)]) * u64::from(self.g.block_size) + u64::from(within / 8);
        let mut b = [0];
        self.current(at, &mut b)?;
        let mask = 1u8 << (within % 8);
        if (b[0] & mask != 0) == allocate {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ext2 allocation bitmap disagrees with audited plan",
            ));
        }
        b[0] = if allocate { b[0] | mask } else { b[0] & !mask };
        // Ordered truncate publishes allocation and release together in one
        // metadata transaction; external-undo phase ordering stays unchanged.
        let phase = if self.symlink_metadata
            || self.ordered.as_ref().is_some_and(|e| {
                matches!(
                    e.operation,
                    OrderedOperation::Truncate { .. }
                        | OrderedOperation::Overwrite { .. }
                        | OrderedOperation::SparseExtend { .. }
                )
            }) {
            Phase::Publish
        } else if allocate {
            Phase::Allocate
        } else {
            Phase::Release
        };
        self.edit(at, &b, phase)?;
        let delta = if allocate { -1 } else { 1 };
        self.counter(
            (u64::from(self.g.first) + 1) * u64::from(self.g.block_size)
                + u64::from(group) * 32
                + if inode { 14 } else { 12 },
            delta,
            2,
            phase,
        )?;
        self.counter(1024 + if inode { 16 } else { 12 }, delta, 4, phase)
    }
    pub(super) fn allocate(&mut self) -> Result<u32> {
        loop {
            self.tick(1)?;
            let range = self
                .free
                .get(self.free_index)
                .ok_or_else(|| bad("ext2 no audited free blocks available"))?;
            if self.free_used == range.length {
                self.free_index += 1;
                self.free_used = 0;
                continue;
            }
            let at = range.offset + self.free_used;
            self.free_used += u64::from(self.g.block_size);
            let block = u32::try_from(at / u64::from(self.g.block_size))
                .map_err(|_| bad("ext2 free block geometry"))?;
            self.bitmap(block, false, true)?;
            return Ok(block);
        }
    }
    pub(super) fn free_block(&mut self, block: u32) -> Result<()> {
        self.tick(1)?;
        self.bitmap(block, false, false)
    }
    pub(super) fn finish(
        mut self,
        source: u128,
        generation: u64,
        report: Option<ExtResizeReport>,
    ) -> Result<ExtEditBatch> {
        let edits = crate::platform::mem::take(&mut self.edits);
        let mut run = Vec::new();
        let mut at = 0;
        let mut phase = Phase::Publish;
        for (position, (byte, next_phase)) in edits {
            self.tick(1)?;
            if !run.is_empty() && (position != at + run.len() as u64 || next_phase != phase) {
                let data = crate::platform::mem::take(&mut run);
                self.patch(at, data, phase)?;
            }
            if run.is_empty() {
                at = position;
                phase = next_phase;
            }
            run.try_reserve(1)
                .map_err(|_| budget("ext2 metadata run allocation"))?;
            run.push(byte);
        }
        if !run.is_empty() {
            self.patch(at, run, phase)?;
        }
        self.patch(1024 + 58, vec![1, 0], Phase::Clean)?;
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(self.patches.len())
            .map_err(|_| budget("ext2 patch overlap index"))?;
        for index in 0..self.patches.len() {
            self.tick(1)?;
            let patch = &self.patches[index].1;
            offsets.push((patch.offset(), patch.expected().len() as u64));
        }
        bounded_sort(
            &mut offsets,
            |entry| *entry,
            &mut self.work,
            self.limits.work,
            self.r,
        )?;
        for pair in offsets.windows(2) {
            self.tick(1)?;
            if pair[0].0 + pair[0].1 > pair[1].0 {
                return Err(bad("ext2 allocation patches overlap"));
            }
        }
        self.validate_ordered(source, generation)?;
        bounded_sort(
            &mut self.patches,
            |(phase, patch)| (*phase, patch.offset()),
            &mut self.work,
            self.limits.work,
            self.r,
        )?;
        let mut stages = Vec::new();
        let mut patches = Vec::new();
        patches
            .try_reserve_exact(self.patches.len())
            .map_err(|_| budget("ext2 final patch vector"))?;
        let mut current = None;
        for (phase, patch) in self.patches {
            if current != Some(phase) {
                stages.push(0);
                current = Some(phase);
            }
            *stages.last_mut().unwrap() += 1;
            patches.push(patch);
        }
        // The prospective audit uses only this owner's source and proposed exact patches.
        offsets.clear();
        for (index, patch) in patches.iter().enumerate() {
            sort_tick(&mut self.work, self.limits.work, self.r)?;
            offsets.push((patch.offset(), index as u64));
        }
        bounded_sort(
            &mut offsets,
            |entry| *entry,
            &mut self.work,
            self.limits.work,
            self.r,
        )?;
        let projection_work = Cell::new(self.work);
        let projected = Projected {
            target: self.target,
            patches: &patches,
            offsets: &offsets,
            work: &projection_work,
            limit: self.limits.work,
            r: self.r,
        };
        projected.tick(1).map_err(native)?;
        let decoder = (self.decoder_open)(&projected, self.scope, self.r).map_err(native)?;
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, self.limits.audit, self.r)?;
        if !audit.is_clean() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "ext2 prospective ownership audit rejected: {:?}",
                    audit.findings()
                ),
            ));
        }
        drop(audit);
        if let Some(evidence) = &self.ordered {
            let tick = |count: usize| -> Result<()> { projected.tick(count).map_err(native) };
            tick(1)?;
            let (number, generation, length) = match evidence.operation {
                OrderedOperation::Extend {
                    inode,
                    inode_generation,
                    new_length,
                    ..
                }
                | OrderedOperation::SparseExtend {
                    inode,
                    inode_generation,
                    new_length,
                    ..
                }
                | OrderedOperation::Truncate {
                    inode,
                    inode_generation,
                    new_length,
                    ..
                } => (inode, inode_generation, new_length),
                OrderedOperation::Overwrite {
                    inode,
                    inode_generation,
                    length,
                    ..
                } => (inode, inode_generation, length),
                OrderedOperation::Create {
                    inode,
                    inode_generation,
                    length,
                } => (inode, inode_generation, length),
            };
            tick(1)?;
            let inode = decoder.inode(number, self.r).map_err(native)?;
            if inode.mode() & 0xf000 != 0x8000
                || inode.generation() != generation
                || inode.len() != length
            {
                return Err(bad(
                    "ext2 ordered projected inode differs from regular operation",
                ));
            }
            let blocks = usize::try_from(length.div_ceil(u64::from(self.g.block_size)))
                .map_err(|_| budget("ext2 ordered projected map size"))?;
            tick(blocks)?;
            let map = decoder
                .file_map(number, self.limits.file_blocks, self.r, false)
                .map_err(native)?;
            if let OrderedOperation::SparseExtend { old_length, .. } = evidence.operation {
                let bs = u64::from(self.g.block_size);
                let original =
                    (self.decoder_open)(self.target, self.scope, self.r).map_err(native)?;
                let old_inode = original.inode(number, self.r).map_err(native)?;
                if old_inode.len() != old_length
                    || old_inode.generation() != generation
                    || old_inode.mode() & 0xf000 != 0x8000
                {
                    return Err(bad("sparse extension original inode changed"));
                }
                tick(128)?;
                for at in 0..128 {
                    if !(4..8).contains(&at)
                        && !(28..32).contains(&at)
                        && !(40..100).contains(&at)
                        && old_inode.raw_metadata()[at] != inode.raw_metadata()[at]
                    {
                        return Err(bad("sparse extension changed unrelated inode metadata"));
                    }
                }
                let old_count = usize::try_from(old_length.div_ceil(bs))
                    .map_err(|_| budget("sparse old map size"))?;
                tick(old_count)?;
                let old_map = original
                    .file_map(number, self.limits.file_blocks, self.r, false)
                    .map_err(native)?;
                let (old_data, _old_lease) = data_blocks(&old_map, self.g.block_size, self.r)?;
                let (new_data, _new_lease) = data_blocks(&map, self.g.block_size, self.r)?;
                if old_data.len() != old_count || new_data.len() != blocks {
                    return Err(bad("sparse extension map length"));
                }
                let cow = old_length % bs != 0 && old_data.last().is_some_and(|block| *block != 0);
                if evidence.source_guard.is_some() != cow
                    || evidence.data.len() != usize::from(cow)
                    || evidence.overwrite.is_some()
                {
                    return Err(bad("sparse extension tail coverage"));
                }
                for (index, block) in new_data.iter().enumerate() {
                    tick(1)?;
                    let expected = if cow && index == old_count - 1 {
                        (evidence.data[0].offset / bs) as u32
                    } else {
                        old_data.get(index).copied().unwrap_or(0)
                    };
                    if *block != expected {
                        return Err(bad("sparse extension mapping differs"));
                    }
                }
                let cow_mapping = cow.then(|| {
                    (
                        (old_count - 1) as u64,
                        (evidence.data[0].offset / bs) as u32,
                    )
                });
                for slot in 0..15 {
                    tick(1)?;
                    if cow && slot < 12 && slot == old_count - 1 {
                        continue;
                    }
                    if old_inode.raw_metadata()[40 + slot * 4..44 + slot * 4]
                        != inode.raw_metadata()[40 + slot * 4..44 + slot * 4]
                    {
                        return Err(bad("sparse extension pointer root changed"));
                    }
                }
                let n = bs / 4;
                let mut base = 12;
                for depth in 1..=3 {
                    let block = u32le(old_inode.raw_metadata(), 40 + (11 + depth as usize) * 4);
                    validate_sparse_nodes(
                        self.target,
                        &projected,
                        block,
                        depth,
                        base,
                        cow_mapping,
                        self.g.block_size,
                        self.r,
                        &tick,
                    )?;
                    base += n.pow(depth);
                }
                if let Some((at, bytes, _)) = &evidence.source_guard {
                    if *at != u64::from(old_data[old_count - 1]) * bs || bytes.len() != bs as usize
                    {
                        return Err(bad("sparse extension guard mapping"));
                    }
                    let role = &evidence.data[0];
                    let mut free = false;
                    for range in self.free {
                        tick(1)?;
                        if range.offset <= role.offset
                            && role.offset.checked_add(bs).is_some_and(|end| {
                                range
                                    .offset
                                    .checked_add(range.length)
                                    .is_some_and(|limit| end <= limit)
                            })
                        {
                            free = true;
                            break;
                        }
                    }
                    if !free || !matches!(role.origin, OrderedOrigin::AuditedFree) {
                        return Err(bad("sparse extension COW not originally free"));
                    }
                    let _scratch = self.r.memory.reserve(bs)?;
                    tick(bs as usize)?;
                    let mut current = zeros(bs as usize)?;
                    if current.capacity() > bs as usize {
                        return Err(budget("sparse guard scratch capacity"));
                    }
                    tick(bs as usize)?;
                    self.target
                        .read_exact_at(*at, &mut current)
                        .map_err(native)?;
                    tick(bs as usize)?;
                    if current != *bytes {
                        return Err(Error::new(
                            ErrorKind::StalePlan,
                            "sparse extension source changed",
                        ));
                    }
                    tick(patches.len())?;
                    let patch = patches
                        .iter()
                        .find(|patch| patch.offset() == role.offset)
                        .ok_or_else(|| bad("sparse COW patch absent"))?;
                    let prefix = (old_length % bs) as usize;
                    tick(bs as usize)?;
                    if patch.replacement().len() != bs as usize
                        || patch.replacement()[..prefix] != bytes[..prefix]
                        || patch.replacement()[prefix..].iter().any(|byte| *byte != 0)
                    {
                        return Err(bad("sparse COW bytes differ"));
                    }
                }
            }
            if let OrderedOperation::Overwrite {
                offset,
                bytes: count,
                ..
            } = evidence.operation
            {
                let overwrite = evidence
                    .overwrite
                    .as_ref()
                    .ok_or_else(|| bad("overwrite semantics absent"))?;
                if evidence.source_guard.is_some() || overwrite.input.len() as u64 != count {
                    return Err(bad("overwrite input or legacy guard differs"));
                }
                let original =
                    (self.decoder_open)(self.target, self.scope, self.r).map_err(native)?;
                let old_inode = original.inode(number, self.r).map_err(native)?;
                if old_inode.len() != length
                    || old_inode.generation() != generation
                    || old_inode.mode() & 0xf000 != 0x8000
                {
                    return Err(bad("overwrite original inode changed"));
                }
                // Only sector count and mapping pointers may differ in native inode.
                tick(128)?;
                for at in 0..128 {
                    if !(28..32).contains(&at)
                        && !(40..100).contains(&at)
                        && old_inode.raw_metadata()[at] != inode.raw_metadata()[at]
                    {
                        return Err(bad("overwrite changed unrelated inode metadata"));
                    }
                }
                tick(blocks)?;
                let old_map = original
                    .file_map(number, self.limits.file_blocks, self.r, false)
                    .map_err(native)?;
                let (old_data, _old_lease) = data_blocks(&old_map, self.g.block_size, self.r)?;
                let (new_data, _new_lease) = data_blocks(&map, self.g.block_size, self.r)?;
                if old_data.len() != blocks || new_data.len() != blocks {
                    return Err(bad("overwrite map length differs"));
                }
                let bs = u64::from(self.g.block_size);
                let first = offset / bs;
                let last = (offset + count).div_ceil(bs);
                let mut guard_index = 0usize;
                for index in 0..blocks {
                    tick(1)?;
                    let logical = index as u64;
                    if logical < first || logical >= last {
                        if old_data[index] != new_data[index] {
                            return Err(bad("overwrite changed untouched mapping"));
                        }
                        continue;
                    }
                    let role = &evidence.data[(logical - first) as usize];
                    let mut audited_free = false;
                    for range in self.free {
                        tick(1)?;
                        if range.offset <= role.offset
                            && role.offset.checked_add(bs).is_some_and(|end| {
                                range
                                    .offset
                                    .checked_add(range.length)
                                    .is_some_and(|limit| end <= limit)
                            })
                        {
                            audited_free = true;
                            break;
                        }
                    }
                    if !audited_free || !matches!(role.origin, OrderedOrigin::AuditedFree) {
                        return Err(bad("overwrite destination was not originally audited free"));
                    }
                    if new_data[index] != (role.offset / bs) as u32
                        || old_data[index] == new_data[index]
                    {
                        return Err(bad("overwrite lacks fresh final mapping"));
                    }
                    tick(patches.len())?;
                    let patch = patches
                        .iter()
                        .find(|patch| patch.offset() == role.offset)
                        .ok_or_else(|| bad("overwrite fresh patch absent"))?;
                    if patch.replacement().len() != bs as usize {
                        return Err(bad("overwrite replacement length"));
                    }
                    let original_bytes = if old_data[index] != 0 {
                        let guard = overwrite
                            .guards
                            .get(guard_index)
                            .ok_or_else(|| bad("overwrite mapped source guard absent"))?;
                        guard_index += 1;
                        if guard.0 != u64::from(old_data[index]) * bs
                            || guard.1.len() != bs as usize
                        {
                            return Err(bad("overwrite source guard mapping"));
                        }
                        let _scratch = self.r.memory.reserve(bs)?;
                        let mut current = zeros(bs as usize)?;
                        if current.capacity() > bs as usize {
                            return Err(budget("overwrite guard scratch capacity"));
                        }
                        tick(bs as usize)?;
                        self.target
                            .read_exact_at(guard.0, &mut current)
                            .map_err(native)?;
                        tick(bs as usize)?;
                        if current != guard.1 {
                            return Err(Error::new(
                                ErrorKind::StalePlan,
                                "overwrite source changed",
                            ));
                        }
                        Some(guard.1.as_slice())
                    } else {
                        None
                    };
                    let start = logical * bs;
                    let within = offset.saturating_sub(start) as usize;
                    let until = ((offset + count - start).min(bs)) as usize;
                    tick(bs as usize)?;
                    for at in 0..bs as usize {
                        let expected = if (within..until).contains(&at) {
                            overwrite.input[(start + at as u64 - offset) as usize]
                        } else {
                            original_bytes.map_or(0, |source| source[at])
                        };
                        if patch.replacement()[at] != expected {
                            return Err(bad("overwrite replacement bytes differ"));
                        }
                    }
                }
                if guard_index != overwrite.guards.len() {
                    return Err(bad("overwrite extra source guard"));
                }
            }
            if let OrderedOperation::Truncate { old_length, .. } = evidence.operation {
                let original =
                    (self.decoder_open)(self.target, self.scope, self.r).map_err(native)?;
                let original_inode = original.inode(number, self.r).map_err(native)?;
                if original_inode.len() != old_length || original_inode.generation() != generation {
                    return Err(bad("ordered truncate original inode changed"));
                }
                let original_blocks =
                    usize::try_from(old_length.div_ceil(u64::from(self.g.block_size)))
                        .map_err(|_| budget("ordered truncate original map size"))?;
                tick(original_blocks)?;
                let original_map = original
                    .file_map(number, self.limits.file_blocks, self.r, false)
                    .map_err(native)?;
                let (old_data, _old_lease) = data_blocks(&original_map, self.g.block_size, self.r)?;
                let (new_data, _new_lease) = data_blocks(&map, self.g.block_size, self.r)?;
                if old_data.len() < blocks || new_data.len() != blocks {
                    return Err(bad("ordered truncate projected map length"));
                }
                for (index, block) in new_data.iter().enumerate() {
                    tick(1)?;
                    let cow = evidence
                        .data
                        .first()
                        .filter(|role| role.logical_block == index as u64);
                    let expected = cow.map_or(old_data[index], |role| {
                        (role.offset / u64::from(self.g.block_size)) as u32
                    });
                    if *block != expected {
                        return Err(bad("ordered truncate retained mapping differs"));
                    }
                }
                let tail = length % u64::from(self.g.block_size);
                let expected_cow = tail != 0
                    && old_data
                        .get(blocks.saturating_sub(1))
                        .is_some_and(|b| *b != 0);
                if evidence.source_guard.is_some() != expected_cow
                    || evidence.data.len() != usize::from(expected_cow)
                {
                    return Err(bad("ordered truncate COW coverage differs"));
                }
                if let Some((at, bytes, _)) = &evidence.source_guard {
                    tick(bytes.len())?;
                    if *at != u64::from(old_data[blocks - 1]) * u64::from(self.g.block_size)
                        || bytes.len() != self.g.block_size as usize
                    {
                        return Err(bad("ordered truncate source guard mapping"));
                    }
                    let _scratch = self.r.memory.reserve(bytes.len() as u64)?;
                    let mut found = zeros(bytes.len())?;
                    self.target.read_exact_at(*at, &mut found).map_err(native)?;
                    if found != *bytes {
                        return Err(Error::new(
                            ErrorKind::StalePlan,
                            "ordered truncate source changed",
                        ));
                    }
                    let role = &evidence.data[0];
                    tick(patches.len())?;
                    let patch = patches
                        .iter()
                        .find(|p| p.offset() == role.offset)
                        .ok_or_else(|| bad("ordered truncate COW patch absent"))?;
                    if patch.replacement()[..tail as usize] != bytes[..tail as usize]
                        || patch.replacement()[tail as usize..].iter().any(|b| *b != 0)
                    {
                        return Err(bad("ordered truncate COW bytes differ"));
                    }
                }
            }
            for role in &evidence.data {
                let position = role.logical_block * u64::from(self.g.block_size);
                let mut matched = false;
                for extent in &map.extents {
                    tick(1)?;
                    if extent.offset <= position
                        && extent
                            .offset
                            .checked_add(extent.length)
                            .is_some_and(|end| position < end)
                    {
                        matched = matches!(extent.kind, ExtentKind::Data(at) if at.checked_add(position - extent.offset) == Some(role.offset / u64::from(self.g.block_size) * u64::from(self.g.block_size)));
                        break;
                    }
                }
                if !matched {
                    return Err(bad("ext2 ordered role is not projected regular-file data"));
                }
            }
        }
        // Inserted in Planner::finish after full prospective audit, using SAME decoder.
        if let Some(e) = self.symlink.first() {
            let tick = |n: usize| -> Result<()> { projected.tick(n).map_err(native) };
            tick(512)?;
            if self.symlink.len() != 1
                || self.ordered.is_some()
                || e.source != source
                || e.generation != generation
                || e.inode < 11
                || e.inode > self.g.inodes
            {
                return Err(bad("symlink evidence source/owner mismatch"));
            }
            let mut before = [0; 128];
            let mut after = [0; 128];
            self.target
                .read_exact_at(e.inode_offset, &mut before)
                .map_err(native)?;
            projected
                .read_exact_at(e.inode_offset, &mut after)
                .map_err(native)?;
            if before != e.original_inode || after != e.final_inode {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "symlink inode guard changed",
                ));
            }
            let group = (e.inode - 1) / self.g.inodes_per_group;
            let bit = ((e.inode - 1) % self.g.inodes_per_group) as usize;
            let descriptors = decoder.group(group).map_err(native)?;
            let expected_inode_at = u64::from(descriptors[2]) * u64::from(self.g.block_size)
                + u64::from((e.inode - 1) % self.g.inodes_per_group) * u64::from(self.g.inode_size);
            if e.inode_offset != expected_inode_at {
                return Err(bad("symlink inode physical association"));
            }
            let mut original_descriptor = [0; 12];
            self.target
                .read_exact_at(
                    (u64::from(self.g.first) + 1) * u64::from(self.g.block_size)
                        + u64::from(group) * 32,
                    &mut original_descriptor,
                )
                .map_err(native)?;
            for index in 0..3 {
                if u32::from_le_bytes(
                    original_descriptor[index * 4..index * 4 + 4]
                        .try_into()
                        .unwrap(),
                ) != descriptors[index]
                {
                    return Err(bad("symlink descriptor pointer changed"));
                }
            }

            let bitmap_at =
                u64::from(descriptors[1]) * u64::from(self.g.block_size) + bit as u64 / 8;
            let mut old_bit = [0];
            let mut new_bit = [0];
            self.target
                .read_exact_at(bitmap_at, &mut old_bit)
                .map_err(native)?;
            projected
                .read_exact_at(bitmap_at, &mut new_bit)
                .map_err(native)?;
            if (old_bit[0] & (1 << (bit % 8)) != 0)
                != (e.action != super::transaction::SymlinkAction::Create)
                || (new_bit[0] & (1 << (bit % 8)) != 0) != e.final_allocated
            {
                return Err(bad("symlink inode allocation differs"));
            }
            let old_links = u16::from_le_bytes(before[26..28].try_into().unwrap());
            let new_links = u16::from_le_bytes(after[26..28].try_into().unwrap());
            let old_gen = u32::from_le_bytes(before[100..104].try_into().unwrap());
            let new_gen = u32::from_le_bytes(after[100..104].try_into().unwrap());
            use super::transaction::SymlinkAction;
            match e.action {
                SymlinkAction::Create
                    if new_links == 1
                        && old_gen.checked_add(1) == Some(new_gen)
                        && e.final_allocated => {}
                SymlinkAction::Replace | SymlinkAction::Rename
                    if old_links != 0
                        && new_links == old_links
                        && new_gen == old_gen
                        && e.final_allocated => {}
                SymlinkAction::Unlink
                    if old_links.checked_sub(1) == Some(new_links)
                        && e.final_allocated == (new_links != 0)
                        && new_gen == old_gen => {}
                _ => return Err(bad("symlink lifecycle proof differs")),
            }
            if e.action == SymlinkAction::Create && e.original_slow.is_some() {
                return Err(bad("symlink creation carries original target guard"));
            }
            if !e.final_allocated && e.fresh_slow.is_some() {
                return Err(bad("symlink final unlink carries fresh target"));
            }
            if e.action != SymlinkAction::Create {
                // Account separately for the original target framing scan. Raw inode
                // comparisons are covered by the fixed envelope above.
                tick(e.original_slow.as_ref().map_or(60, |(_, body)| body.len()))?;
                super::namespace::symlink_source_shape(
                    &before,
                    e.original_slow.as_ref().map(|(_, b)| b.as_slice()),
                    self.g.block_size,
                )?;
                for index in 0..128 {
                    let managed = match e.action {
                        SymlinkAction::Replace => {
                            (4..8).contains(&index)
                                || (28..32).contains(&index)
                                || (40..100).contains(&index)
                        }
                        SymlinkAction::Unlink => {
                            (26..28).contains(&index)
                                || (!e.final_allocated
                                    && ((4..8).contains(&index)
                                        || (20..24).contains(&index)
                                        || (28..32).contains(&index)
                                        || (40..100).contains(&index)))
                        }
                        _ => false,
                    };
                    if !managed && before[index] != after[index] {
                        return Err(bad("symlink changed unrelated inode field"));
                    }
                }
            }
            if let Some((at, body)) = &e.original_slow {
                tick(body.len())?;
                let _scratch = self.r.memory.reserve(body.len() as u64)?;
                let mut found = super::namespace::zeros(body.len())?;
                if found.capacity() > body.len() {
                    return Err(budget("symlink scratch capacity"));
                }
                self.target.read_exact_at(*at, &mut found).map_err(native)?;
                if found != *body {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "symlink target source changed",
                    ));
                }
                if *at
                    != u64::from(u32::from_le_bytes(before[40..44].try_into().unwrap()))
                        * u64::from(self.g.block_size)
                {
                    return Err(bad("symlink guard physical association"));
                }
            }
            if e.final_allocated {
                let inode = decoder.inode(e.inode, self.r).map_err(native)?;
                if inode.mode() & 0xf000 != 0xa000 || inode.len() != e.target.len() as u64 {
                    return Err(bad("symlink projected kind/length"));
                }
                let slow = u32::from_le_bytes(after[28..32].try_into().unwrap()) != 0;
                if slow {
                    let block = u32::from_le_bytes(after[40..44].try_into().unwrap());
                    let bs = self.g.block_size as usize;
                    // Read, framing/NUL scan, exact target comparison and suffix or
                    // unchanged-body comparison each inspect at most one full block.
                    tick(
                        bs.checked_mul(4)
                            .ok_or_else(|| budget("symlink final scan work overflow"))?,
                    )?;
                    let _scratch = self.r.memory.reserve(bs as u64)?;
                    let mut body = super::namespace::zeros(bs)?;
                    if body.capacity() > bs {
                        return Err(budget("symlink projected body capacity"));
                    }
                    projected
                        .read_exact_at(u64::from(block) * bs as u64, &mut body)
                        .map_err(native)?;
                    super::namespace::symlink_source_shape(&after, Some(&body), self.g.block_size)?;
                    if body[..e.target.len()] != e.target {
                        return Err(bad("symlink target bytes differ"));
                    }
                    if matches!(e.action, SymlinkAction::Create | SymlinkAction::Replace) {
                        if e.fresh_slow != Some(block)
                            || body[e.target.len()..].iter().any(|b| *b != 0)
                        {
                            return Err(bad("symlink fresh target proof"));
                        }
                        let mut free = false;
                        for range in self.free {
                            tick(1)?;
                            if u64::from(block) * u64::from(self.g.block_size) >= range.offset
                                && (u64::from(block) + 1) * u64::from(self.g.block_size)
                                    <= range.offset + range.length
                            {
                                free = true;
                                break;
                            }
                        }
                        if !free {
                            return Err(bad("symlink target not originally audited free"));
                        }
                        let mut matched = 0;
                        for patch in &patches {
                            tick(1)?;
                            if patch.offset() == u64::from(block) * bs as u64 {
                                tick(bs)?;
                                if patch.replacement() == body {
                                    matched += 1;
                                }
                            }
                        }
                        if matched != 1 {
                            return Err(bad("symlink target lacks unique full metadata patch"));
                        }
                    } else if e
                        .original_slow
                        .as_ref()
                        .is_none_or(|(at, old)| *at != u64::from(block) * bs as u64 || *old != body)
                    {
                        return Err(bad("symlink unchanged target differs"));
                    }
                } else {
                    tick(
                        e.target
                            .len()
                            .checked_mul(2)
                            .and_then(|n| n.checked_add(60))
                            .ok_or_else(|| budget("symlink inline scan work overflow"))?,
                    )?;
                    super::namespace::symlink_source_shape(&after, None, self.g.block_size)?;
                    if after[40..40 + e.target.len()] != e.target || e.fresh_slow.is_some() {
                        return Err(bad("symlink inline target proof"));
                    }
                    if matches!(e.action, SymlinkAction::Create | SymlinkAction::Replace)
                        && after[40 + e.target.len()..100].iter().any(|b| *b != 0)
                    {
                        return Err(bad("symlink noncanonical inline suffix"));
                    }
                }
            } else if !e.target.is_empty()
                || after[4..8] != [0; 4]
                || after[28..32] != [0; 4]
                || after[40..100] != [0; 60]
                || u32::from_le_bytes(after[20..24].try_into().unwrap()) < self.g.inodes
            {
                return Err(bad("symlink final unlink fields differ"));
            }
        }

        if self.symlink_metadata == self.symlink.is_empty() {
            return Err(bad("symlink purpose lacks checked evidence"));
        }
        drop(decoder);
        Ok(ExtEditBatch {
            source,
            generation,
            patches,
            stages,
            bytes: self.bytes,
            _lease: self.lease,
            resize: report,
            namespace: None,
            range_allocation: None,
            ordered: self.ordered,
            symlink: self.symlink,
        })
    }
}
// Compare the physical indirect topology itself, not only decoded file bytes.
#[expect(
    clippy::too_many_arguments,
    reason = "Bounded private topology proof carries both read-only views and explicit work authority"
)]
fn validate_sparse_nodes(
    original: &dyn Storage,
    projected: &dyn Storage,
    block: u32,
    depth: u32,
    base: u64,
    cow: Option<(u64, u32)>,
    block_size: u32,
    r: &Resources,
    tick: &dyn Fn(usize) -> Result<()>,
) -> Result<()> {
    if block == 0 {
        return Ok(());
    }
    let bs = block_size as usize;
    let _scratch = r.memory.reserve(
        (bs as u64)
            .checked_mul(2)
            .ok_or_else(|| budget("sparse topology scratch overflow"))?,
    )?;
    let mut before = zeros(bs)?;
    let mut after = zeros(bs)?;
    if before.capacity() > bs || after.capacity() > bs {
        return Err(budget("sparse topology scratch capacity"));
    }
    tick(
        bs.checked_mul(4)
            .ok_or_else(|| budget("sparse topology work overflow"))?,
    )?;
    original
        .read_exact_at(u64::from(block) * block_size as u64, &mut before)
        .map_err(native)?;
    projected
        .read_exact_at(u64::from(block) * block_size as u64, &mut after)
        .map_err(native)?;
    let n = bs as u64 / 4;
    let span = n.pow(depth - 1);
    for slot in 0..bs / 4 {
        tick(4)?;
        let child = u32le(&before, slot * 4);
        let logical = base + slot as u64 * span;
        let expected = if depth == 1 {
            cow.filter(|(at, _)| *at == logical)
                .map_or(child, |(_, fresh)| fresh)
        } else {
            child
        };
        if u32le(&after, slot * 4) != expected {
            return Err(bad("sparse extension indirect topology changed"));
        }
        if depth > 1 {
            validate_sparse_nodes(
                original,
                projected,
                child,
                depth - 1,
                logical,
                cow,
                block_size,
                r,
                tick,
            )?;
        }
    }
    Ok(())
}
struct Projected<'a> {
    target: &'a dyn Storage,
    patches: &'a [WriteRange],
    offsets: &'a [(u64, u64)],
    work: &'a Cell<usize>,
    limit: usize,
    r: &'a Resources,
}
impl Projected<'_> {
    fn tick(&self, count: usize) -> io::Result<()> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        let work = self
            .work
            .get()
            .checked_add(count)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other(budget("ext2 projected lookup work")))?;
        self.work.set(work);
        Ok(())
    }
}
impl Storage for Projected<'_> {
    fn len(&self) -> io::Result<u64> {
        self.tick(1)?;
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.tick(1)?;
        self.target.read_exact_at(at, out)?;
        let end = at
            .checked_add(out.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut low = 0;
        let mut high = self.offsets.len();
        while low < high {
            self.tick(1)?;
            let middle = low + (high - low) / 2;
            if self.offsets[middle].0 < at {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut index = low.saturating_sub(1);
        while let Some(&(offset, patch_index)) = self.offsets.get(index) {
            self.tick(1)?;
            if offset >= end {
                break;
            }
            let patch = &self.patches[patch_index as usize];
            let start = at.max(patch.offset());
            let stop = end.min(patch.offset() + patch.replacement().len() as u64);
            if start < stop {
                out[(start - at) as usize..(stop - at) as usize].copy_from_slice(
                    &patch.replacement()
                        [(start - patch.offset()) as usize..(stop - patch.offset()) as usize],
                );
            }
            index += 1;
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
struct Nodes {
    old: BTreeMap<(u32, u64), u32>,
    _leases: Vec<Reservation>,
}
fn collect_nodes(
    p: &mut Planner<'_>,
    block: u32,
    depth: u32,
    base: u64,
    nodes: &mut Nodes,
) -> Result<()> {
    if block == 0 {
        return Ok(());
    }
    p.tick(1)?;
    let lease = p.r.memory.reserve(128)?;
    nodes
        ._leases
        .try_reserve(1)
        .map_err(|_| budget("ext2 indirect index lease vector"))?;
    nodes._leases.push(lease);
    if nodes.old.insert((depth, base), block).is_some() {
        return Err(bad("ext2 repeated indirect path"));
    }
    if depth > 1 {
        let bs = p.g.block_size as usize;
        let _scratch = p.r.memory.reserve(bs as u64)?;
        let mut page = zeros(bs)?;
        p.target
            .read_exact_at(u64::from(block) * bs as u64, &mut page)
            .map_err(native)?;
        let n = bs as u64 / 4;
        let span = n.pow(depth - 1);
        for i in 0..n {
            p.tick(1)?;
            let child = u32le(&page, i as usize * 4);
            if child != 0 {
                collect_nodes(p, child, depth - 1, base + i * span, nodes)?;
            }
        }
    }
    Ok(())
}
fn old_nodes(p: &mut Planner<'_>, inode: &ExtInode) -> Result<Nodes> {
    let mut nodes = Nodes {
        old: BTreeMap::new(),
        _leases: Vec::new(),
    };
    let n = u64::from(p.g.block_size) / 4;
    let mut base = 12;
    for depth in 1..=3 {
        collect_nodes(
            p,
            u32le(inode.raw_metadata(), 40 + (11 + depth as usize) * 4),
            depth,
            base,
            &mut nodes,
        )?;
        base += n.pow(depth);
    }
    Ok(nodes)
}
fn build_node(
    p: &mut Planner<'_>,
    data: &[u32],
    depth: u32,
    base: u64,
    nodes: &mut Nodes,
    new_nodes: &mut usize,
    total_nodes: &mut usize,
) -> Result<u32> {
    p.tick(1)?;
    let n = u64::from(p.g.block_size) / 4;
    let end = (base + n.pow(depth)).min(data.len() as u64);
    let start = base.min(data.len() as u64);
    p.tick((end - start) as usize)?;
    // Retain owned empty metadata nodes still within logical EOF. Besides preserving
    // native allocation, this prevents an append from mixing allocation and release.
    if start == end
        || (!data[start as usize..end as usize].iter().any(|b| *b != 0)
            && !nodes.old.contains_key(&(depth, base)))
    {
        return Ok(0);
    }
    *total_nodes = total_nodes
        .checked_add(1)
        .ok_or_else(|| budget("ext2 indirect count overflow"))?;
    let old = nodes.old.remove(&(depth, base));
    let block = if let Some(block) = old {
        block
    } else {
        *new_nodes += 1;
        p.allocate()?
    };
    let bs = p.g.block_size as usize;
    let _scratch = p.r.memory.reserve((bs * 2) as u64)?;
    let mut page = zeros(bs)?;
    let span = n.pow(depth - 1);
    for i in 0..n {
        p.tick(1)?;
        let at = base + i * span;
        if at >= data.len() as u64 {
            break;
        }
        let pointer = if depth == 1 {
            data[at as usize]
        } else {
            build_node(p, data, depth - 1, at, nodes, new_nodes, total_nodes)?
        };
        page[i as usize * 4..i as usize * 4 + 4].copy_from_slice(&pointer.to_le_bytes());
    }
    if old.is_some() {
        let mut original = zeros(bs)?;
        p.target
            .read_exact_at(u64::from(block) * bs as u64, &mut original)
            .map_err(native)?;
        for i in (0..bs).step_by(4) {
            if original[i..i + 4] != page[i..i + 4] {
                p.edit(
                    u64::from(block) * bs as u64 + i as u64,
                    &page[i..i + 4],
                    Phase::Publish,
                )?;
            }
        }
    } else {
        p.patch(u64::from(block) * bs as u64, page, Phase::Initialize)?;
    }
    Ok(block)
}
pub(super) fn data_blocks(
    map: &ExtDecodedFileMap,
    bs: u32,
    r: &Resources,
) -> Result<(Vec<u32>, Reservation)> {
    let count = map.length.div_ceil(u64::from(bs)) as usize;
    let lease = r.memory.reserve(count as u64 * 4)?;
    let mut data = Vec::new();
    data.try_reserve_exact(count)
        .map_err(|_| budget("ext2 data map allocation"))?;
    for extent in &map.extents {
        r.cancellation.check()?;
        data.push(match extent.kind {
            ExtentKind::Hole => 0,
            ExtentKind::Data(at) => u32::try_from(at / u64::from(bs))
                .map_err(|_| bad("ext2 physical block overflow"))?,
            ExtentKind::Unwritten => return Err(bad("ext2 unexpected unwritten extent")),
        });
    }
    if data.len() != count {
        return Err(bad("ext2 uncoalesced native map required"));
    }
    Ok((data, lease))
}
pub(super) fn mapped_inode(
    p: &mut Planner<'_>,
    inode: &ExtInode,
    data: &[u32],
    length: u64,
) -> Result<([u8; 128], usize, usize)> {
    let mut nodes = old_nodes(p, inode)?;
    let n = u64::from(p.g.block_size) / 4;
    let mut roots = [0u32; 15];
    for (i, &block) in data.iter().take(12).enumerate() {
        roots[i] = block;
    }
    let mut base = 12;
    let mut allocated = 0;
    let mut total = 0;
    for depth in 1..=3 {
        roots[11 + depth as usize] =
            build_node(p, data, depth, base, &mut nodes, &mut allocated, &mut total)?;
        base += n.pow(depth);
    }
    let freed = nodes.old.len();
    for &block in nodes.old.values() {
        p.free_block(block)?;
    }
    let mut raw = *inode.raw_metadata();
    raw[4..8].copy_from_slice(
        &u32::try_from(length)
            .map_err(|_| bad("ext2 classic file size exceeds native u32"))?
            .to_le_bytes(),
    );
    p.tick(data.len())?;
    let sectors = (data.iter().filter(|b| **b != 0).count() as u64 + total as u64)
        * (u64::from(p.g.block_size) / 512);
    raw[28..32].copy_from_slice(
        &u32::try_from(sectors)
            .map_err(|_| bad("ext2 native i_blocks overflow"))?
            .to_le_bytes(),
    );
    for (i, &pointer) in roots.iter().enumerate() {
        raw[40 + i * 4..44 + i * 4].copy_from_slice(&pointer.to_le_bytes());
    }
    Ok((raw, allocated, freed))
}
pub(super) fn publish_map(
    p: &mut Planner<'_>,
    inode: &ExtInode,
    data: &[u32],
    length: u64,
) -> Result<(usize, usize)> {
    let (raw, allocated, freed) = mapped_inode(p, inode, data, length)?;
    let inode_at = p.inode_offset(inode.number())?;
    for (start, end) in [(4, 8), (28, 32), (40, 100)] {
        for at in (start..end).step_by(4) {
            if raw[at..at + 4] != inode.raw_metadata()[at..at + 4] {
                p.edit(inode_at + at as u64, &raw[at..at + 4], Phase::Publish)?;
            }
        }
    }
    Ok((allocated, freed))
}

impl PlanningContext<'_> {
    /// Append exactly the source's declared length, using bounded positional reads.
    /// Native owner, permissions, times and generation are preserved explicitly.
    pub fn plan_extend(
        &self,
        file: &ExtEditFile,
        input: &dyn FileRead,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_file(file, r)?;
        let append = input.len();
        if append == 0 {
            return Err(bad("ext2 append requires nonempty source"));
        }
        let length = file
            .len()
            .checked_add(append)
            .filter(|n| *n <= u64::from(u32::MAX))
            .ok_or_else(|| bad("ext2 native file size overflow"))?;
        if length > i32::MAX as u64 {
            let mut features = [0; 4];
            self.target
                .read_exact_at(1024 + 100, &mut features)
                .map_err(native)?;
            if u32le(&features, 0) & 2 == 0 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "ext2 large file feature must already be enabled",
                ));
            }
        }
        let bs = u64::from(self.geometry.block_size);
        let count = length.div_ceil(bs) as usize;
        if count > self.limits.file_blocks {
            return Err(budget("ext2 extended logical block ceiling"));
        }
        if input.identity().native.len() > self.limits.work {
            return Err(budget("ext2 input identity ceiling"));
        }
        let _identity_lease = r
            .memory
            .reserve(input.identity().native.len() as u64 + 64)?;
        let identity = input.identity().clone();
        let mut p = Planner::new(self, r)?;
        p.begin_ordered(OrderedOperation::Extend {
            inode: file.inode.number(),
            inode_generation: file.inode.generation(),
            old_length: file.len(),
            new_length: length,
        })?;
        let (mut data, _old_map) = data_blocks(&file.map, self.geometry.block_size, r)?;
        let _map = r.memory.reserve(count as u64 * 4)?;
        data.try_reserve_exact(count - data.len())
            .map_err(|_| budget("ext2 extended block map"))?;
        data.resize(count, 0);
        let mut allocated = 0;
        let mut source_offset = 0u64;
        for logical in file.len() / bs..length.div_ceil(bs) {
            p.tick(1)?;
            let start = logical * bs;
            let within = file.len().saturating_sub(start) as usize;
            let end = (length - start).min(bs) as usize;
            let old = data[logical as usize];
            let fresh = if old == 0 {
                Some(p.allocate_regular(logical)?)
            } else {
                None
            };
            let block = if let Some(token) = &fresh {
                allocated += 1;
                Planner::regular_block(token)
            } else {
                old
            };
            data[logical as usize] = block;
            let written = if old == 0 { bs } else { bs - within as u64 };
            if p.bytes
                .checked_add(written)
                .is_none_or(|n| n > self.limits.affected_bytes)
            {
                return Err(budget("ext2 append initialization byte ceiling"));
            }
            let _scratch = r.memory.reserve(bs)?;
            let mut body = zeros(bs as usize)?;
            if old != 0 {
                p.target
                    .read_exact_at(u64::from(old) * bs, &mut body)
                    .map_err(native)?;
            }
            body[end..].fill(0);
            let mut filled = within;
            while filled < end {
                p.tick(1)?;
                if input.identity() != &identity || input.len() != append {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "ext2 deferred source identity or length changed",
                    ));
                }
                let n = input.read_at(source_offset, &mut body[filled..end], r)?;
                if n == 0 || n > end - filled {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "ext2 deferred append short or oversized read",
                    ));
                }
                filled += n;
                source_offset += n as u64;
                if input.identity() != &identity || input.len() != append {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "ext2 deferred source changed during read",
                    ));
                }
            }
            if let Some(token) = fresh {
                p.patch_regular_fresh(token, body)?;
            } else {
                p.patch_regular_tail(file, logical, block, body.split_off(within))?;
            }
        }
        if source_offset != append {
            return Err(bad("ext2 append length mismatch"));
        }
        let (allocated_indirect, freed_indirect) = publish_map(&mut p, &file.inode, &data, length)?;
        p.finish(
            self.scope,
            self.generation,
            Some(ExtResizeReport {
                old_length: file.len(),
                new_length: length,
                allocated_data_blocks: allocated,
                allocated_indirect_blocks: allocated_indirect,
                freed_data_blocks: 0,
                freed_indirect_blocks: freed_indirect,
                retained_tail_zeroed: !length.is_multiple_of(bs),
                native_metadata_preserved: true,
            }),
        )
    }
    /// Grow logical length with holes; mapped partial EOF uses original-free COW.
    #[cfg(feature = "std")]
    pub(crate) fn plan_extend_sparse_ordered(
        &self,
        file: &ExtEditFile,
        length: u64,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_file(file, r)?;
        if length <= file.len() || length > u64::from(u32::MAX) {
            return Err(bad("sparse extension requires a larger native u32 length"));
        }
        let bs = u64::from(self.geometry.block_size);
        let count = usize::try_from(length.div_ceil(bs))
            .map_err(|_| budget("sparse extension map size"))?;
        let n = bs / 4;
        let pointer_capacity = 12 + n + n * n + n * n * n;
        if count > self.limits.file_blocks || count as u64 > pointer_capacity {
            return Err(budget("sparse extension logical pointer ceiling"));
        }
        let mut p = Planner::new(self, r)?;
        if length > i32::MAX as u64 {
            let mut features = [0; 4];
            p.tick(1)?;
            p.target
                .read_exact_at(1124, &mut features)
                .map_err(native)?;
            if u32le(&features, 0) & 2 == 0 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "sparse extension requires existing large-file feature",
                ));
            }
        }
        p.begin_ordered(OrderedOperation::SparseExtend {
            inode: file.inode.number(),
            inode_generation: file.inode.generation(),
            old_length: file.len(),
            new_length: length,
        })?;
        p.tick(
            usize::try_from(file.len().div_ceil(bs)).map_err(|_| budget("sparse old map work"))?,
        )?;
        let (old_data, _old_lease) = data_blocks(&file.map, self.geometry.block_size, r)?;
        let _map_lease = r.memory.reserve(
            (count as u64)
                .checked_mul(4)
                .ok_or_else(|| budget("sparse map reservation overflow"))?,
        )?;
        let mut data = Vec::new();
        data.try_reserve_exact(count)
            .map_err(|_| budget("sparse extension map allocation"))?;
        if data.capacity() > count {
            return Err(budget("sparse extension map capacity"));
        }
        p.tick(count)?;
        data.extend_from_slice(&old_data);
        data.resize(count, 0);
        if !file.len().is_multiple_of(bs) && old_data.last().is_some_and(|block| *block != 0) {
            let index = old_data.len() - 1;
            let old = old_data[index];
            let lease = r.memory.reserve(bs)?;
            p.tick(bs as usize)?;
            let mut original = zeros(bs as usize)?;
            if original.capacity() > bs as usize {
                return Err(budget("sparse source capacity"));
            }
            p.tick(bs as usize)?;
            p.target
                .read_exact_at(u64::from(old) * bs, &mut original)
                .map_err(native)?;
            let _scratch = r.memory.reserve(bs)?;
            p.tick(bs as usize)?;
            let mut body = zeros(bs as usize)?;
            if body.capacity() > bs as usize {
                return Err(budget("sparse body capacity"));
            }
            let prefix = (file.len() % bs) as usize;
            p.tick(prefix)?;
            body[..prefix].copy_from_slice(&original[..prefix]);
            let token = p.allocate_regular(index as u64)?;
            data[index] = Planner::regular_block(&token);
            p.patch_regular_fresh(token, body)?;
            p.ordered
                .as_mut()
                .ok_or_else(|| bad("sparse evidence absent"))?
                .source_guard = Some((u64::from(old) * bs, original, lease));
            p.free_block(old)?;
        }
        let (allocated_metadata, freed_metadata) = publish_map(&mut p, &file.inode, &data, length)?;
        if allocated_metadata != 0 || freed_metadata != 0 {
            return Err(bad(
                "sparse extension unexpectedly changed indirect allocation",
            ));
        }
        p.finish(self.scope, self.generation, None)
    }

    /// Plan COW replacement of an arbitrary nonempty range within existing EOF.
    /// All source blocks retain their physical bytes; hardlinks share the inode.
    #[cfg(feature = "std")]
    pub(crate) fn plan_overwrite_ordered(
        &self,
        file: &ExtEditFile,
        offset: u64,
        input: &dyn FileRead,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_file(file, r)?;
        let length = input.len();
        let end = offset
            .checked_add(length)
            .filter(|end| length != 0 && *end <= file.len())
            .ok_or_else(|| bad("ordered overwrite requires a nonempty range within EOF"))?;
        let bs = u64::from(self.geometry.block_size);
        let first = offset / bs;
        let last = end.div_ceil(bs);
        let touched =
            usize::try_from(last - first).map_err(|_| budget("overwrite touched count"))?;
        let count = usize::try_from(length).map_err(|_| budget("overwrite input size"))?;
        let identity_ref = input.identity();
        let identity_bytes = identity_ref.native.len();
        if touched > self.limits.file_blocks
            || length > self.limits.affected_bytes
            || identity_bytes > self.limits.work
        {
            return Err(budget("overwrite source or block ceiling"));
        }
        let _identity_lease = r.memory.reserve(
            (identity_bytes as u64)
                .checked_add(64)
                .ok_or_else(|| budget("overwrite identity overflow"))?,
        )?;
        let mut native_identity = Vec::new();
        native_identity
            .try_reserve_exact(identity_bytes)
            .map_err(|_| budget("overwrite identity allocation"))?;
        if native_identity.capacity() > identity_bytes {
            return Err(budget("overwrite identity capacity"));
        }
        native_identity.extend_from_slice(&identity_ref.native);
        let identity = crate::fs_core::ObjectId {
            source: identity_ref.source,
            generation: identity_ref.generation,
            native: native_identity,
        };
        let bytes_charge = (touched as u64)
            .checked_mul(core::mem::size_of::<(u64, Vec<u8>, Reservation)>() as u64)
            .and_then(|n| n.checked_add(length))
            .ok_or_else(|| budget("overwrite evidence reservation"))?;
        let evidence_lease = r.memory.reserve(bytes_charge)?;
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(touched)
            .map_err(|_| budget("overwrite guard allocation"))?;
        let mut captured = zeros(count)?;
        if guards.capacity() > touched || captured.capacity() > count {
            return Err(budget("overwrite evidence capacity"));
        }
        let mut p = Planner::new(self, r)?;
        p.tick(identity_bytes)?;
        p.begin_ordered(OrderedOperation::Overwrite {
            inode: file.inode.number(),
            inode_generation: file.inode.generation(),
            length: file.len(),
            offset,
            bytes: length,
        })?;
        let mut filled = 0;
        while filled < count {
            p.tick(
                identity_bytes
                    .checked_add(1)
                    .ok_or_else(|| budget("overwrite identity work overflow"))?,
            )?;
            if input.identity() != &identity || input.len() != length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "overwrite source identity changed",
                ));
            }
            let n = input.read_at(filled as u64, &mut captured[filled..], r)?;
            if n == 0 || n > count - filled {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "overwrite source short or oversized read",
                ));
            }
            p.tick(n)?;
            filled += n;
            p.tick(identity_bytes)?;
            if input.identity() != &identity || input.len() != length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "overwrite source changed during read",
                ));
            }
        }
        let (mut data, _map_lease) = data_blocks(&file.map, self.geometry.block_size, r)?;
        for logical in first..last {
            p.tick(1)?;
            let index = usize::try_from(logical).map_err(|_| budget("overwrite map index"))?;
            let old = data[index];
            let _scratch = r.memory.reserve(bs)?;
            let mut body = zeros(bs as usize)?;
            if body.capacity() > bs as usize {
                return Err(budget("overwrite body capacity"));
            }
            if old != 0 {
                let lease = r.memory.reserve(bs)?;
                let mut original = zeros(bs as usize)?;
                if original.capacity() > bs as usize {
                    return Err(budget("overwrite source capacity"));
                }
                p.tick(bs as usize)?;
                p.target
                    .read_exact_at(u64::from(old) * bs, &mut original)
                    .map_err(native)?;
                p.tick(bs as usize)?;
                body.copy_from_slice(&original);
                guards.push((u64::from(old) * bs, original, lease));
            }
            let start = logical * bs;
            let within = offset.saturating_sub(start) as usize;
            let until = (end - start).min(bs) as usize;
            p.tick(until - within)?;
            body[within..until].copy_from_slice(
                &captured[(start + within as u64 - offset) as usize
                    ..(start + until as u64 - offset) as usize],
            );
            let token = p.allocate_regular(logical)?;
            data[index] = Planner::regular_block(&token);
            p.patch_regular_fresh(token, body)?;
        }
        // allocate() walks immutable audited free ranges, never released blocks.
        // All regular allocation finishes before release; metadata allocation
        // in publish_map has the same original-free eligibility.
        for (at, _, _) in &guards {
            p.free_block((*at / bs) as u32)?;
        }
        p.ordered
            .as_mut()
            .ok_or_else(|| bad("overwrite evidence absent"))?
            .overwrite = Some(OverwriteEvidence {
            guards,
            input: captured,
            _lease: evidence_lease,
        });
        publish_map(&mut p, &file.inode, &data, file.len())?;
        p.finish(self.scope, self.generation, None)
    }

    /// Plan native ordered truncation without modifying originally reachable data.
    #[cfg(feature = "std")]
    pub(crate) fn plan_truncate_ordered(
        &self,
        file: &ExtEditFile,
        length: u64,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_file(file, r)?;
        if length >= file.len() {
            return Err(bad("ordered truncate requires a smaller size"));
        }
        let mut p = Planner::new(self, r)?;
        p.begin_ordered(OrderedOperation::Truncate {
            inode: file.inode.number(),
            inode_generation: file.inode.generation(),
            old_length: file.len(),
            new_length: length,
        })?;
        let bs = u64::from(self.geometry.block_size);
        let (mut data, _map) = data_blocks(&file.map, self.geometry.block_size, r)?;
        let count = usize::try_from(length.div_ceil(bs))
            .map_err(|_| budget("ordered truncate map size"))?;
        let mut allocated = 0;
        let mut freed = 0;
        if !length.is_multiple_of(bs) && data[count - 1] != 0 {
            let original = data[count - 1];
            let lease = r.memory.reserve(bs)?;
            let mut bytes = zeros(bs as usize)?;
            p.tick(bs as usize)?;
            p.target
                .read_exact_at(u64::from(original) * bs, &mut bytes)
                .map_err(native)?;
            let _scratch = r.memory.reserve(bs)?;
            let mut body = zeros(bs as usize)?;
            let prefix = (length % bs) as usize;
            body[..prefix].copy_from_slice(&bytes[..prefix]);
            let token = p.allocate_regular((count - 1) as u64)?;
            data[count - 1] = Planner::regular_block(&token);
            p.patch_regular_fresh(token, body)?;
            p.ordered
                .as_mut()
                .ok_or_else(|| bad("ordered truncate evidence absent"))?
                .source_guard = Some((u64::from(original) * bs, bytes, lease));
            p.free_block(original)?;
            allocated = 1;
            freed = 1;
        }
        for &block in &data[count..] {
            p.tick(1)?;
            if block != 0 {
                p.free_block(block)?;
                freed += 1;
            }
        }
        data.truncate(count);
        let (allocated_indirect, freed_indirect) = publish_map(&mut p, &file.inode, &data, length)?;
        p.finish(
            self.scope,
            self.generation,
            Some(ExtResizeReport {
                old_length: file.len(),
                new_length: length,
                allocated_data_blocks: allocated,
                allocated_indirect_blocks: allocated_indirect,
                freed_data_blocks: freed,
                freed_indirect_blocks: freed_indirect,
                retained_tail_zeroed: allocated != 0,
                native_metadata_preserved: true,
            }),
        )
    }
    /// Truncate to a smaller logical size; detach pointers before freeing verified owned blocks.
    pub fn plan_truncate(
        &self,
        file: &ExtEditFile,
        length: u64,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.check_file(file, r)?;
        if length >= file.len() {
            return Err(bad("ext2 truncate requires a smaller logical size"));
        }
        let mut p = Planner::new(self, r)?;
        let bs = u64::from(self.geometry.block_size);
        let (mut data, _map) = data_blocks(&file.map, self.geometry.block_size, r)?;
        let count = length.div_ceil(bs) as usize;
        let mut freed = 0;
        for &block in &data[count..] {
            if block != 0 {
                p.free_block(block)?;
                freed += 1;
            }
        }
        data.truncate(count);
        if !length.is_multiple_of(bs)
            && let Some(&block) = data.last().filter(|b| **b != 0)
        {
            p.patch(
                u64::from(block) * bs + length % bs,
                zeros((bs - length % bs) as usize)?,
                Phase::Initialize,
            )?;
        }
        let (allocated_indirect, freed_indirect) = publish_map(&mut p, &file.inode, &data, length)?;
        p.finish(
            self.scope,
            self.generation,
            Some(ExtResizeReport {
                old_length: file.len(),
                new_length: length,
                allocated_data_blocks: 0,
                allocated_indirect_blocks: allocated_indirect,
                freed_data_blocks: freed,
                freed_indirect_blocks: freed_indirect,
                retained_tail_zeroed: !length.is_multiple_of(bs)
                    && data.last().is_some_and(|b| *b != 0),
                native_metadata_preserved: true,
            }),
        )
    }
}
/// Explicit allocation effects when replacing bytes in existing sparse holes.
#[derive(Clone, Debug)]
pub struct ExtRangeAllocationReport {
    /// Newly initialized payload blocks replacing holes.
    pub allocated_data_blocks: usize,
    /// Newly initialized classic indirect blocks.
    pub allocated_indirect_blocks: usize,
    /// Logical size, native times, owner, permissions and generation remain exact.
    /// Only classic pointers and the native sector count change.
    pub native_metadata_preserved_except_allocation: bool,
}
impl PlanningContext<'_> {
    pub(super) fn plan_replace_allocating(
        &self,
        ranges: &[ExtReplacement<'_>],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        let mut p = Planner::new(self, r)?;
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(ranges.len())
            .map_err(|_| budget("ext2 sparse range index"))?;
        for item in ranges {
            p.tick(1)?;
            self.check_file(item.file, r)?;
            sorted.push(item);
        }
        sorted.sort_unstable_by_key(|item| (item.file.inode.number(), item.offset));
        for pair in sorted.windows(2) {
            if pair[0].file.inode.number() == pair[1].file.inode.number()
                && pair[0].offset + pair[0].bytes.len() as u64 > pair[1].offset
            {
                return Err(bad("ext2 sparse replacements overlap through hardlinks"));
            }
        }
        let bs = u64::from(self.geometry.block_size);
        let mut index = 0;
        let mut allocated_data = 0;
        let mut allocated_indirect = 0;
        while index < sorted.len() {
            let file = sorted[index].file;
            let mut end = index + 1;
            while end < sorted.len() && sorted[end].file.inode.number() == file.inode.number() {
                p.tick(1)?;
                end += 1;
            }
            let (mut data, _map) = data_blocks(&file.map, self.geometry.block_size, r)?;
            let mut holes: BTreeMap<usize, (u32, Vec<u8>, Reservation)> = BTreeMap::new();
            for item in &sorted[index..end] {
                let mut done = 0usize;
                while done < item.bytes.len() {
                    p.tick(1)?;
                    let at = item.offset + done as u64;
                    let logical = (at / bs) as usize;
                    let within = (at % bs) as usize;
                    let n = (bs as usize - within).min(item.bytes.len() - done);
                    if data[logical] != 0 && !holes.contains_key(&logical) {
                        let bytes = item.bytes[done..done + n].to_vec();
                        p.patch(
                            u64::from(data[logical]) * bs + within as u64,
                            bytes,
                            Phase::Initialize,
                        )?;
                    } else {
                        if !holes.contains_key(&logical) {
                            if (holes.len() as u64 + 1)
                                .checked_mul(bs)
                                .and_then(|n| n.checked_add(p.bytes))
                                .is_none_or(|n| n > p.limits.affected_bytes)
                            {
                                return Err(budget("ext2 sparse initialization byte ceiling"));
                            }
                            let lease = r.memory.reserve(bs + 128)?;
                            let block = p.allocate()?;
                            holes.insert(logical, (block, zeros(bs as usize)?, lease));
                            data[logical] = block;
                            allocated_data += 1;
                        }
                        holes.get_mut(&logical).unwrap().1[within..within + n]
                            .copy_from_slice(&item.bytes[done..done + n]);
                    }
                    done += n;
                }
            }
            let changed = !holes.is_empty();
            for (_, (block, body, _lease)) in holes {
                p.patch(u64::from(block) * bs, body, Phase::Initialize)?;
            }
            if changed {
                let (allocated, freed) = publish_map(&mut p, &file.inode, &data, file.len())?;
                if freed != 0 {
                    return Err(invalid_sparse_release());
                }
                allocated_indirect += allocated;
            }
            index = end;
        }
        let mut batch = p.finish(self.scope, self.generation, None)?;
        batch.range_allocation = Some(ExtRangeAllocationReport {
            allocated_data_blocks: allocated_data,
            allocated_indirect_blocks: allocated_indirect,
            native_metadata_preserved_except_allocation: true,
        });
        Ok(batch)
    }
}
fn invalid_sparse_release() -> Error {
    Error::new(
        ErrorKind::InvalidData,
        "ext2 sparse replacement unexpectedly released original metadata",
    )
}

impl<S: Storage, J: Storage> ExtEditor<S, J> {
    /// Append exactly the source's declared length using bounded positional reads.
    pub fn plan_extend(
        &self,
        file: &ExtEditFile,
        input: &dyn FileRead,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?.plan_extend(file, input, r)
    }
    /// Truncate a verified file and release its exclusively owned allocations.
    pub fn plan_truncate(
        &self,
        file: &ExtEditFile,
        length: u64,
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?.plan_truncate(file, length, r)
    }
    pub(super) fn plan_replace_allocating(
        &self,
        ranges: &[ExtReplacement<'_>],
        r: &Resources,
    ) -> Result<ExtEditBatch> {
        self.planning_context(r)?.plan_replace_allocating(ranges, r)
    }
}
impl PlanningContext<'_> {
    pub(super) fn ready(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.target.len().map_err(native)?;
        Ok(())
    }
    fn check_file(&self, file: &ExtEditFile, r: &Resources) -> Result<()> {
        self.ready(r)?;
        if file.identity.source != self.scope || file.identity.generation != self.generation {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated ext2 file handle",
            ));
        }
        Ok(())
    }
    #[cfg(feature = "std")]
    pub(crate) fn file_handle(&self, number: u32, r: &Resources) -> Result<ExtEditFile> {
        self.ready(r)?;
        let metadata = r.memory.reserve(512)?;
        let decoder = self.decoder(r)?;
        let inode = decoder.inode(number, r).map_err(native)?;
        if number < 11 || inode.mode() & 0xf000 != 0x8000 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "native planning requires ordinary regular file",
            ));
        }
        let map = decoder
            .file_map(number, self.limits.file_blocks, r, false)
            .map_err(native)?;
        let mut identity = decoder.identity(number, r).map_err(native)?;
        identity.generation = self.generation;
        Ok(ExtEditFile {
            identity,
            inode,
            map,
            _metadata: metadata,
        })
    }
    pub(super) fn decoder<'a>(&'a self, r: &Resources) -> Result<ExtStorageDecoder<'a>> {
        (self.decoder_open)(self.target, self.scope, r).map_err(native)
    }
}

#[cfg(feature = "std")]
impl<'a> PlanningContext<'a> {
    // The native owner supplies its current borrowed decoder geometry and complete audit.
    // This context has no write authority, owns no source, and cannot outlive either proof.
    pub(crate) fn native(
        target: &'a dyn Storage,
        geometry: &'a ExtGeometry,
        audit: &'a ExtAuditReport,
        owner: (u128, u64),
        limits: ExtEditLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if !geometry.has_journal
            || !matches!(geometry.inode_size, 128 | 256)
            || geometry.extent_profile
            || geometry.modern.is_some()
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "native borrowed allocation planner requires checked classic-map 128/256-byte journaled inodes",
            ));
        }
        if !audit.is_clean() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "native borrowed allocation planner requires complete same-owner clean audit",
            ));
        }
        target.len().map_err(native)?;
        Ok(Self {
            target,
            geometry,
            audit,
            limits,
            scope: owner.0,
            generation: owner.1,
            decoder_open: |target, scope, r| {
                let (decoder, proof) = ExtStorageDecoder::open_native_clean(target, scope, r)?;
                drop(proof);
                Ok(decoder)
            },
        })
    }
}

#[cfg(all(test, feature = "std"))]
#[path = "fs_ext_edit_allocation_overwrite_tests.rs"]
mod overwrite_tests;

#[cfg(all(test, feature = "std"))]
#[path = "fs_ext_edit_allocation_sparse_tests.rs"]
mod sparse_tests;

#[cfg(all(test, feature = "std"))]
#[path = "fs_ext_edit_allocation_symlink_tests.rs"]
mod symlink_tests;
