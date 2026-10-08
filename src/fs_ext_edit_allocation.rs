//! Audited classic bitmap and direct/indirect allocation planning.
use super::*;
use crate::{fs_core::FileRead, fs_file::ExtentKind, storage::WriteRange};
use std::collections::BTreeMap;
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
    audit_projected: fn(&dyn Storage, u128, ExtAuditLimits, &Resources) -> Result<ExtAuditReport>,
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
            audit_projected: |target, _, limits, r| audit_ext_storage(target, limits, r),
            audit: self
                .audit
                .as_ref()
                .ok_or_else(|| bad("ext2 audit authorization absent"))?,
        })
    }
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
    lease: Reservation,
    scope: u128,
    audit_projected: fn(&dyn Storage, u128, ExtAuditLimits, &Resources) -> Result<ExtAuditReport>,
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
                        * (4 * std::mem::size_of::<WriteRange>() as u64 + 96),
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
            audit_projected: editor.audit_projected,
        })
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
        let phase = if allocate {
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
        let edits = std::mem::take(&mut self.edits);
        let mut run = Vec::new();
        let mut at = 0;
        let mut phase = Phase::Publish;
        for (position, (byte, next_phase)) in edits {
            self.tick(1)?;
            if !run.is_empty() && (position != at + run.len() as u64 || next_phase != phase) {
                let data = std::mem::take(&mut run);
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
        for (_, patch) in &self.patches {
            offsets.push((patch.offset(), patch.expected().len() as u64));
        }
        offsets.sort_unstable();
        for pair in offsets.windows(2) {
            if pair[0].0 + pair[0].1 > pair[1].0 {
                return Err(bad("ext2 allocation patches overlap"));
            }
        }
        self.patches
            .sort_by_key(|(phase, patch)| (*phase, patch.offset()));
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
        let projected = Projected {
            target: self.target,
            patches: &patches,
        };
        let audit = (self.audit_projected)(&projected, self.scope, self.limits.audit, self.r)?;
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
        })
    }
}
struct Projected<'a> {
    target: &'a dyn Storage,
    patches: &'a [WriteRange],
}
impl Storage for Projected<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)?;
        let end = at
            .checked_add(out.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        for patch in self.patches {
            let start = at.max(patch.offset());
            let stop = end.min(patch.offset() + patch.replacement().len() as u64);
            if start < stop {
                out[(start - at) as usize..(stop - at) as usize].copy_from_slice(
                    &patch.replacement()
                        [(start - patch.offset()) as usize..(stop - patch.offset()) as usize],
                );
            }
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
            let block = if old == 0 {
                allocated += 1;
                p.allocate()?
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
            if old == 0 {
                p.patch(u64::from(block) * bs, body, Phase::Initialize)?;
            } else {
                p.patch(
                    u64::from(block) * bs + within as u64,
                    body.split_off(within),
                    Phase::Initialize,
                )?;
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
    #[cfg(test)]
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

#[cfg(test)]
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
            audit_projected: |target, scope, limits, r| {
                let (decoder, proof) =
                    ExtStorageDecoder::open_native_clean(target, scope, r).map_err(native)?;
                let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, r)?;
                drop(proof);
                Ok(audit)
            },
        })
    }
}
