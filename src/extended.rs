//! Bounded extended-MBR traversal with exact preservation of EBR sectors.
//!
//! Publication writes and flushes chain sectors from tail to head, then the MBR.
//! A partial sector write can make an EBR invalid; strict inspection reports this
//! rather than guessing. Rollback requires the caller to retain the previous
//! trusted metadata snapshot outside the sectors being overwritten. The table
//! has no redundant copy and publication is not atomic. To recover, the caller
//! explicitly selects that retained snapshot and builds its `plan_against` the
//! interrupted storage; damaged on-disk EBRs alone do not establish a source.
//! Old obsolete EBR sectors remain untouched and unreachable. Durability remains
//! uncertain after a failed flush; payload bytes are never part of these plans.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{collections::HashSet, io};
use crate::{
    layout::{Geometry, LbaRange},
    storage::{Barrier, WritePlan, WriteRange},
};
fn invalid(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("checked sector"))
}
fn extended(k: u8) -> bool {
    matches!(k, 5 | 15 | 0x85)
}
fn range(e: &[u8], base: u64) -> io::Result<LbaRange> {
    let start = base
        .checked_add(u64::from(u32le(e, 8)))
        .ok_or_else(|| invalid("LBA overflow"))?;
    LbaRange::new(
        start,
        start
            .checked_add(u64::from(u32le(e, 12)))
            .ok_or_else(|| invalid("LBA overflow"))?,
    )
}
/// Exact logical partition and its owning EBR.
#[derive(Clone, Debug)]
pub struct LogicalPartition {
    ebr: u64,
    range: LbaRange,
    sector: Vec<u8>,
}
impl LogicalPartition {
    /// Absolute location of the owning EBR.
    pub fn ebr_lba(&self) -> u64 {
        self.ebr
    }
    /// Payload range in absolute sectors.
    pub fn range(&self) -> LbaRange {
        self.range
    }
    /// MBR type byte.
    pub fn kind(&self) -> u8 {
        self.sector[450]
    }
    /// Complete EBR logical sector, preserving boot code and CHS.
    pub fn sector(&self) -> &[u8] {
        &self.sector
    }
}
/// Validated basic primary partitions and a single extended chain.
#[derive(Clone)]
pub struct ExtendedLayout {
    geometry: Geometry,
    mbr: Vec<u8>,
    container: LbaRange,
    container_slot: u32,
    logical: Vec<LogicalPartition>,
    empty_ebr: Option<Vec<u8>>,
    primary: Vec<LbaRange>,
}
impl ExtendedLayout {
    /// Read a bounded EBR chain. Both link-relative and EBR-relative LBA bases
    /// are interpreted explicitly. Hybrid and dynamic tables are rejected.
    pub fn inspect(source: &dyn ReadAt, sector: u32, max_chain: usize) -> io::Result<Self> {
        if max_chain == 0 || max_chain > 4096 {
            return Err(invalid("invalid EBR chain limit"));
        }
        let geometry = Geometry::new(source.len(), sector)?;
        let mut mbr = vec![0; sector as usize];
        source.read_exact_at(0, &mut mbr)?;
        if mbr[510..512] != [0x55, 0xaa] {
            return Err(invalid("missing MBR signature"));
        }
        let mut container = None;
        let mut primary = Vec::new();
        for (i, e) in mbr[446..510].chunks_exact(16).enumerate() {
            if e[4] == 0 {
                if e.iter().any(|b| *b != 0) {
                    return Err(invalid("nonzero unused MBR slot"));
                }
                continue;
            }
            if !matches!(e[0], 0 | 0x80) || matches!(e[4], 0xee | 0x42) {
                return Err(invalid("unsupported MBR flags or type"));
            }
            let r = range(e, 0)?;
            if r.start() == 0 || r.end() > geometry.sectors() || r.end() > u64::from(u32::MAX) + 1 {
                return Err(invalid("MBR outside geometry"));
            }
            if extended(e[4]) {
                if container.replace((r, i as u32 + 1)).is_some() {
                    return Err(invalid("multiple extended containers"));
                }
            } else {
                primary.push(r);
            }
        }
        let (container, container_slot) =
            container.ok_or_else(|| invalid("missing extended container"))?;
        let mut occupied = primary.clone();
        occupied.push(container);
        validate_overlap(&occupied)?;
        let mut logical = Vec::new();
        let mut empty_ebr = None;
        let mut seen = HashSet::new();
        let mut current = container.start();
        let mut linked_limit = None;
        loop {
            if logical.len() >= max_chain || !seen.insert(current) {
                return Err(invalid("EBR chain limit or cycle"));
            }
            if current < container.start() || current >= container.end() {
                return Err(invalid("EBR outside container"));
            }
            let mut raw = vec![0; sector as usize];
            source.read_exact_at(current * u64::from(sector), &mut raw)?;
            if raw[510..512] != [0x55, 0xaa] || raw[478..510].iter().any(|b| *b != 0) {
                return Err(invalid("invalid EBR signature or unused entries"));
            }
            if raw[446..478].iter().all(|b| *b == 0)
                && current == container.start()
                && logical.is_empty()
            {
                empty_ebr = Some(raw);
                break;
            }
            let e = &raw[446..462];
            if e[4] == 0
                || extended(e[4])
                || matches!(e[4], 0xee | 0x42)
                || !matches!(e[0], 0 | 0x80)
            {
                return Err(invalid("invalid logical entry"));
            }
            let r = range(e, current)?;
            if r.start() <= current || r.start() < container.start() || r.end() > container.end() {
                return Err(invalid("logical partition outside container or over EBR"));
            }
            if linked_limit.is_some_and(|limit| r.end() > limit) {
                return Err(invalid("logical partition exceeds incoming link length"));
            }
            let link = &raw[462..478];
            let next = if link.iter().all(|b| *b == 0) {
                None
            } else {
                if !extended(link[4]) || link[0] != 0 {
                    return Err(invalid("invalid EBR link"));
                }
                let r = range(link, container.start())?;
                if r.start() < container.start() || r.end() > container.end() {
                    return Err(invalid("EBR link outside container"));
                }
                linked_limit = Some(r.end());
                Some(r.start())
            };
            logical.push(LogicalPartition {
                ebr: current,
                range: r,
                sector: raw,
            });
            if let Some(next) = next {
                current = next;
            } else {
                break;
            }
        }
        let mut ranges: Vec<_> = logical.iter().map(|p| p.range).collect();
        for p in &logical {
            ranges.push(LbaRange::new(p.ebr, p.ebr + 1)?);
        }
        validate_overlap(&ranges)?;
        Ok(Self {
            geometry,
            mbr,
            container,
            container_slot,
            logical,
            empty_ebr,
            primary,
        })
    }
    /// Logical disk geometry.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// Exact MBR sector.
    pub fn mbr_sector(&self) -> &[u8] {
        &self.mbr
    }
    /// Extended container range.
    pub fn container(&self) -> LbaRange {
        self.container
    }
    /// One-based primary container slot.
    pub fn container_slot(&self) -> u32 {
        self.container_slot
    }
    /// Logical partitions in chain order.
    pub fn logical(&self) -> &[LogicalPartition] {
        &self.logical
    }
    /// Primary data ranges excluding the extended container.
    pub fn primary_ranges(&self) -> &[LbaRange] {
        &self.primary
    }
    /// Change logical boundaries only, preserving all other EBR bytes.
    pub fn set_range(&mut self, index: usize, new: LbaRange) -> io::Result<()> {
        let mut proposed = self.clone();
        let p = proposed
            .logical
            .get_mut(index)
            .ok_or_else(|| invalid("invalid logical index"))?;
        if new.start() <= p.ebr
            || new.start() < self.container.start()
            || new.end() > self.container.end()
        {
            return Err(invalid("logical range outside container"));
        }
        let relative = u32::try_from(new.start() - p.ebr)
            .map_err(|_| invalid("relative LBA exceeds MBR limit"))?;
        let count =
            u32::try_from(new.sectors()).map_err(|_| invalid("length exceeds MBR limit"))?;
        p.sector[454..458].copy_from_slice(&relative.to_le_bytes());
        p.sector[458..462].copy_from_slice(&count.to_le_bytes());
        p.range = new;
        proposed.relink()?;
        proposed.validate()?;
        *self = proposed;
        Ok(())
    }
    fn validate(&self) -> io::Result<()> {
        let mut ranges: Vec<_> = self.logical.iter().map(|p| p.range).collect();
        for p in &self.logical {
            ranges.push(LbaRange::new(p.ebr, p.ebr + 1)?);
        }
        validate_overlap(&ranges)
    }
    /// Build ordered EBR writes from tail to head, flushing each stage.
    /// Publication is not atomic and EBRs have no redundant copy. Rollback after
    /// interruption requires a caller-retained trusted previous metadata snapshot
    /// outside overwritten storage; write ordering alone cannot recover it.
    pub fn write_plan(&self, old: &Self) -> io::Result<WritePlan> {
        if self.geometry != old.geometry
            || self.container != old.container
            || self.mbr != old.mbr
            || self.logical.len() != old.logical.len()
        {
            return Err(invalid(
                "chain topology changes require an initialization plan",
            ));
        }
        let mut barriers = Vec::new();
        for (new, previous) in self.logical.iter().zip(&old.logical).rev() {
            if new.ebr != previous.ebr {
                return Err(invalid("EBR location changed"));
            }
            if new.sector != previous.sector {
                let write = WriteRange::new(
                    new.ebr * u64::from(self.geometry.sector_size()),
                    previous.sector.clone(),
                    new.sector.clone(),
                )?;
                barriers.push(Barrier::new("EBR durable", vec![write])?);
            }
        }
        let mut conditions = vec![crate::storage::ReadCondition::new(0, old.mbr.clone())?];
        for p in &old.logical {
            conditions.push(crate::storage::ReadCondition::new(
                p.ebr * u64::from(self.geometry.sector_size()),
                p.sector.clone(),
            )?);
        }
        if let Some(raw) = &old.empty_ebr {
            conditions.push(crate::storage::ReadCondition::new(
                old.container.start() * u64::from(self.geometry.sector_size()),
                raw.clone(),
            )?);
        }
        WritePlan::new(self.geometry.bytes(), barriers)?.with_preconditions(conditions)
    }
}
fn validate_overlap(ranges: &[LbaRange]) -> io::Result<()> {
    let mut ranges = ranges.to_vec();
    ranges.sort_by_key(|r| r.start());
    if ranges.windows(2).any(|p| p[0].end() > p[1].start()) {
        return Err(invalid("overlapping MBR ranges or EBR metadata"));
    }
    Ok(())
}
impl ExtendedLayout {
    /// Initialize an extended container and explicitly positioned EBRs in memory.
    /// Each tuple supplies an absolute EBR LBA, type, and unchanged payload range.
    pub fn initialize(
        geometry: Geometry,
        signature: u32,
        container_slot: u32,
        container: LbaRange,
        partitions: &[(u64, u8, LbaRange)],
    ) -> io::Result<Self> {
        if !(1..=4).contains(&container_slot)
            || container.start() == 0
            || container.end() > geometry.sectors()
            || container.end() > u64::from(u32::MAX) + 1
            || partitions.len() > 4096
            || partitions.first().is_some_and(|p| p.0 != container.start())
        {
            return Err(invalid("invalid extended initialization"));
        }
        let mut mbr = vec![0; geometry.sector_size() as usize];
        mbr[440..444].copy_from_slice(&signature.to_le_bytes());
        mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
        set_entry(
            &mut mbr,
            container_slot as usize - 1,
            0x0f,
            container.start(),
            container.sectors(),
        )?;
        let mut logical = Vec::new();
        let mut seen = HashSet::new();
        for &(ebr, kind, range) in partitions {
            if !seen.insert(ebr)
                || ebr < container.start()
                || ebr >= container.end()
                || range.start() <= ebr
                || range.end() > container.end()
                || kind == 0
                || extended(kind)
                || matches!(kind, 0xee | 0x42)
            {
                return Err(invalid("invalid logical partition"));
            }
            let mut sector = vec![0; geometry.sector_size() as usize];
            sector[510..512].copy_from_slice(&[0x55, 0xaa]);
            set_entry(&mut sector, 0, kind, range.start() - ebr, range.sectors())?;
            logical.push(LogicalPartition { ebr, range, sector });
        }
        let mut layout = Self {
            geometry,
            mbr,
            container,
            container_slot,
            empty_ebr: if logical.is_empty() {
                let mut b = vec![0; geometry.sector_size() as usize];
                b[510..512].copy_from_slice(&[0x55, 0xaa]);
                Some(b)
            } else {
                None
            },
            logical,
            primary: Vec::new(),
        };
        layout.relink()?;
        layout.validate()?;
        Ok(layout)
    }
    fn relink(&mut self) -> io::Result<()> {
        for i in 0..self.logical.len() {
            if let Some(next) = self.logical.get(i + 1) {
                let start = u32::try_from(next.ebr - self.container.start())
                    .map_err(|_| invalid("link LBA limit"))?;
                let count = u32::try_from(self.container.end() - next.ebr)
                    .map_err(|_| invalid("link size limit"))?;
                let next_end = next.range.end();
                let link = &mut self.logical[i].sector[462..478];
                if link[4] != 0
                    && u32le(link, 8) == start
                    && self.container.start() + u64::from(start) + u64::from(u32le(link, 12))
                        >= next_end
                {
                    continue;
                }
                if link[4] == 0 {
                    link[1..4].fill(0xff);
                    link[4] = 0x0f;
                    link[5..8].fill(0xff);
                }
                link[8..12].copy_from_slice(&start.to_le_bytes());
                link[12..16].copy_from_slice(&count.to_le_bytes());
            } else {
                self.logical[i].sector[462..478].fill(0);
            }
        }
        Ok(())
    }
    /// Insert a logical entry using an explicit free EBR sector.
    pub fn create(&mut self, ebr: u64, kind: u8, range: LbaRange) -> io::Result<()> {
        if self.logical.len() >= 4096
            || ebr < self.container.start()
            || (self.logical.is_empty() && ebr != self.container.start())
            || (!self.logical.is_empty() && ebr == self.container.start())
            || ebr >= self.container.end()
            || self.logical.iter().any(|p| p.ebr == ebr)
            || range.start() <= ebr
            || range.end() > self.container.end()
            || kind == 0
            || extended(kind)
            || matches!(kind, 0xee | 0x42)
        {
            return Err(invalid("invalid logical partition"));
        }
        let mut proposed = self.clone();
        let mut sector = proposed
            .empty_ebr
            .take()
            .unwrap_or_else(|| vec![0; self.geometry.sector_size() as usize]);
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        set_entry(&mut sector, 0, kind, range.start() - ebr, range.sectors())?;
        proposed
            .logical
            .push(LogicalPartition { ebr, range, sector });
        proposed.relink()?;
        proposed.validate()?;
        *self = proposed;
        Ok(())
    }
    /// Delete a logical entry, retaining an empty signed EBR for an empty container.
    /// Removing the first entry moves its successor entry into the original first
    /// EBR while preserving that sector's boot code and opaque bytes.
    pub fn delete(&mut self, index: usize) -> io::Result<()> {
        if index >= self.logical.len() {
            return Err(invalid("invalid logical index"));
        }
        let mut proposed = self.clone();
        let first_sector = proposed.logical[0].sector.clone();
        proposed.logical.remove(index);
        if proposed.logical.is_empty() {
            let mut raw = first_sector;
            raw[446..510].fill(0);
            proposed.empty_ebr = Some(raw);
        } else if index == 0 {
            let p = &mut proposed.logical[0];
            let raw_entry = p.sector[446..462].to_vec();
            p.sector = first_sector;
            p.sector[446..462].copy_from_slice(&raw_entry);
            p.ebr = self.container.start();
            let start = u32::try_from(p.range.start() - p.ebr)
                .map_err(|_| invalid("relative LBA limit"))?;
            p.sector[454..458].copy_from_slice(&start.to_le_bytes());
        }
        proposed.relink()?;
        proposed.validate()?;
        *self = proposed;
        Ok(())
    }
    /// Add a primary partition outside the container, preserving payload positions.
    pub fn create_primary(&mut self, slot: u32, kind: u8, range: LbaRange) -> io::Result<()> {
        if !(1..=4).contains(&slot)
            || slot == self.container_slot
            || kind == 0
            || extended(kind)
            || matches!(kind, 0xee | 0x42)
            || range.start() == 0
            || range.end() > self.geometry.sectors()
        {
            return Err(invalid("invalid primary partition"));
        }
        let offset = 446 + (slot as usize - 1) * 16;
        if self.mbr[offset + 4] != 0 {
            return Err(invalid("occupied primary slot"));
        }
        let mut ranges = self.primary.clone();
        ranges.push(range);
        ranges.push(self.container);
        validate_overlap(&ranges)?;
        set_entry(
            &mut self.mbr,
            slot as usize - 1,
            kind,
            range.start(),
            range.sectors(),
        )?;
        self.primary.push(range);
        Ok(())
    }
    /// Plan initialization or topology edits, reading exact expected metadata.
    /// EBRs become durable from tail to head before publishing the MBR container.
    /// The caller must ensure exclusive access and review new EBR sectors because
    /// initialization may replace bytes outside existing partition payloads.
    /// For rollback, retain the trusted previous metadata snapshot outside the
    /// overwritten sectors before committing. This method does not persist that
    /// snapshot and does not provide atomicity or on-disk metadata redundancy.
    pub fn plan_against(&self, source: &dyn ReadAt) -> io::Result<WritePlan> {
        if source.len() != self.geometry.bytes() {
            return Err(invalid("geometry changed"));
        }
        let mut stages = Vec::new();
        if let Some(raw) = &self.empty_ebr {
            let offset = self.container.start() * u64::from(self.geometry.sector_size());
            let mut expected = vec![0; raw.len()];
            source.read_exact_at(offset, &mut expected)?;
            stages.push(Barrier::new(
                "empty extended container",
                vec![WriteRange::new(offset, expected, raw.clone())?],
            )?);
        }
        for p in self.logical.iter().rev() {
            let offset = p.ebr * u64::from(self.geometry.sector_size());
            let mut expected = vec![0; p.sector.len()];
            source.read_exact_at(offset, &mut expected)?;
            if expected != p.sector {
                stages.push(Barrier::new(
                    "publish EBR",
                    vec![WriteRange::new(offset, expected, p.sector.clone())?],
                )?);
            }
        }
        let mut expected = vec![0; self.mbr.len()];
        source.read_exact_at(0, &mut expected)?;
        stages.push(Barrier::new(
            "publish extended MBR",
            vec![WriteRange::new(0, expected, self.mbr.clone())?],
        )?);
        WritePlan::new(self.geometry.bytes(), stages)
    }
}
fn set_entry(sector: &mut [u8], slot: usize, kind: u8, start: u64, count: u64) -> io::Result<()> {
    let start = u32::try_from(start).map_err(|_| invalid("MBR LBA limit"))?;
    let count = u32::try_from(count).map_err(|_| invalid("MBR count limit"))?;
    if count == 0 {
        return Err(invalid("zero MBR length"));
    }
    let offset = 446 + slot * 16;
    sector[offset..offset + 16].fill(0);
    sector[offset + 1..offset + 4].fill(0xff);
    sector[offset + 4] = kind;
    sector[offset + 5..offset + 8].fill(0xff);
    sector[offset + 8..offset + 12].copy_from_slice(&start.to_le_bytes());
    sector[offset + 12..offset + 16].copy_from_slice(&count.to_le_bytes());
    Ok(())
}
impl ExtendedLayout {
    /// Plan edits against an inspected source snapshot, including unchanged
    /// original metadata in stale-plan preconditions.
    pub fn edit_plan(&self, old: &Self, source: &dyn ReadAt) -> io::Result<WritePlan> {
        if self.geometry != old.geometry || self.container != old.container {
            return Err(invalid("extended geometry changed"));
        }
        for p in &self.logical {
            if old
                .logical
                .iter()
                .any(|previous| p.ebr >= previous.range.start() && p.ebr < previous.range.end())
                || old
                    .primary
                    .iter()
                    .any(|range| p.ebr >= range.start() && p.ebr < range.end())
            {
                return Err(invalid(
                    "new EBR would overwrite an original partition payload",
                ));
            }
        }
        let mut conditions = vec![crate::storage::ReadCondition::new(0, old.mbr.clone())?];
        if let Some(raw) = &old.empty_ebr {
            conditions.push(crate::storage::ReadCondition::new(
                old.container.start() * u64::from(self.geometry.sector_size()),
                raw.clone(),
            )?);
        }
        for p in &old.logical {
            conditions.push(crate::storage::ReadCondition::new(
                p.ebr * u64::from(self.geometry.sector_size()),
                p.sector.clone(),
            )?);
        }
        self.plan_against(source)?.with_preconditions(conditions)
    }
}
impl ExtendedLayout {
    /// Set explicit boot code and preserve sector bytes beyond the MBR prefix.
    pub fn with_mbr_preservation(mut self, source: &[u8], boot: &[u8; 440]) -> io::Result<Self> {
        if source.len() != self.mbr.len() {
            return Err(invalid("MBR logical sector length mismatch"));
        }
        self.mbr[..440].copy_from_slice(boot);
        self.mbr[512..].copy_from_slice(&source[512..]);
        Ok(self)
    }
    /// Inspect with domain error categorization.
    pub fn inspect_checked(
        source: &dyn ReadAt,
        sector: u32,
        max_chain: usize,
    ) -> Result<Self, crate::error::Error> {
        Self::inspect(source, sector, max_chain).map_err(crate::error::Error::inspection)
    }
}
impl ExtendedLayout {
    /// Enumerate free container ranges excluding logical payloads and live EBRs.
    pub fn free_space(&self) -> Vec<LbaRange> {
        let mut used: Vec<_> = self
            .logical
            .iter()
            .flat_map(|p| {
                [
                    p.range,
                    LbaRange::new(p.ebr, p.ebr + 1).expect("checked EBR"),
                ]
            })
            .collect();
        if self.empty_ebr.is_some() {
            used.push(
                LbaRange::new(self.container.start(), self.container.start() + 1)
                    .expect("checked container"),
            );
        }
        used.sort_by_key(|r| r.start());
        let mut next = self.container.start();
        let mut gaps = Vec::new();
        for r in used {
            if next < r.start() {
                gaps.push(LbaRange::new(next, r.start()).expect("nonempty gap"));
            }
            next = r.end();
        }
        if next < self.container.end() {
            gaps.push(LbaRange::new(next, self.container.end()).expect("nonempty gap"));
        }
        gaps
    }
    /// Find aligned logical payload space and an adjacent safe EBR sector.
    /// Empty containers retain their first signed EBR rather than relocating it.
    pub fn place(&self, sectors: u64, alignment: u64) -> io::Result<(u64, LbaRange)> {
        if sectors == 0 || alignment == 0 {
            return Err(invalid("zero size or alignment"));
        }
        for gap in self.free_space() {
            let minimum = if self.logical.is_empty() {
                gap.start()
            } else {
                gap.start()
                    .checked_add(1)
                    .ok_or_else(|| invalid("placement overflow"))?
            };
            let rem = minimum % alignment;
            let start = minimum
                .checked_add(if rem == 0 { 0 } else { alignment - rem })
                .ok_or_else(|| invalid("alignment overflow"))?;
            if let Some(end) = start.checked_add(sectors)
                && end <= gap.end()
            {
                return Ok((
                    if self.logical.is_empty() {
                        self.container.start()
                    } else {
                        start - 1
                    },
                    LbaRange::new(start, end)?,
                ));
            }
        }
        Err(invalid("no aligned logical space"))
    }
}
