//! Explicit GPT source selection and bounded repair/geometry planning.
use crate::gpt::crc32 as crc;
use crate::io::ReadAt;
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    layout::{DiskLayout, Geometry, GptLayout},
    storage::{Barrier, ReadCondition, WritePlan, WriteRange},
};
fn invalid(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("header field"))
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("header field"))
}

fn header(
    mut b: Vec<u8>,
    current: u64,
    alternate: u64,
    table: u64,
    first: u64,
    last: u64,
) -> Vec<u8> {
    for (o, v) in [
        (24, current),
        (32, alternate),
        (40, first),
        (48, last),
        (72, table),
    ] {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    b[16..20].fill(0);
    let n = u32le(&b, 12) as usize;
    let c = crc(&b[..n]);
    b[16..20].copy_from_slice(&c.to_le_bytes());
    b
}
struct Overlay<'a> {
    source: &'a dyn ReadAt,
    length: u64,
    regions: Vec<(u64, Vec<u8>)>,
}
impl ReadAt for Overlay<'_> {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, o: u64, out: &mut [u8]) -> io::Result<()> {
        if o.checked_add(out.len() as u64)
            .is_none_or(|e| e > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        out.fill(0);
        if o < self.source.len() {
            let n = out.len().min((self.source.len() - o) as usize);
            self.source.read_exact_at(o, &mut out[..n])?;
        }
        let end = o + out.len() as u64;
        for (start, b) in &self.regions {
            let lo = o.max(*start);
            let hi = end.min(*start + b.len() as u64);
            if lo < hi {
                out[(lo - o) as usize..(hi - o) as usize]
                    .copy_from_slice(&b[(lo - start) as usize..(hi - start) as usize]);
            }
        }
        Ok(())
    }
}
fn candidate(source: &dyn ReadAt, sector: u32, lba: u64) -> io::Result<GptLayout> {
    let g = Geometry::new(source.len(), sector)?;
    if lba >= g.sectors() {
        return Err(invalid("candidate outside geometry"));
    }
    let mut b = vec![0; sector as usize];
    source.read_exact_at(lba * u64::from(sector), &mut b)?;
    if &b[..8] != b"EFI PART" || u64le(&b, 24) != lba {
        return Err(invalid("invalid candidate header"));
    }
    let n = u32le(&b, 12) as usize;
    if !(92..=b.len()).contains(&n) {
        return Err(invalid("invalid candidate header size"));
    }
    let expected = u32le(&b, 16);
    let mut check = b.clone();
    check[16..20].fill(0);
    if crc(&check[..n]) != expected {
        return Err(invalid("candidate header CRC"));
    }
    let count = u32le(&b, 80);
    let size = u32le(&b, 84);
    let bytes = u64::from(count) * u64::from(size);
    if count == 0
        || count > 131072
        || !(128..=4096).contains(&size)
        || !size.is_power_of_two()
        || !(16384..=16777216).contains(&bytes)
    {
        return Err(invalid("candidate allocation limits"));
    }
    let table_lba = u64le(&b, 72);
    let table_end = table_lba
        .checked_mul(u64::from(sector))
        .and_then(|o| o.checked_add(bytes))
        .ok_or_else(|| invalid("candidate table overflow"))?;
    if table_end > source.len() {
        return Err(invalid("candidate array outside geometry"));
    }
    let mut table = vec![0; bytes as usize];
    source.read_exact_at(table_lba * u64::from(sector), &mut table)?;
    if crc(&table) != u32le(&b, 88) {
        return Err(invalid("candidate array CRC"));
    }
    let old_total = if lba == 1 {
        u64le(&b, 32)
            .checked_add(1)
            .ok_or_else(|| invalid("candidate geometry overflow"))?
    } else {
        if u64le(&b, 32) != 1 {
            return Err(invalid("candidate backup does not refer to primary"));
        }
        lba + 1
    };
    if old_total > g.sectors() {
        return Err(invalid("candidate exceeds actual geometry"));
    }
    let blocks = bytes.div_ceil(u64::from(sector));
    if old_total <= blocks + 2 {
        return Err(invalid("candidate geometry too small"));
    }
    let first = u64le(&b, 40);
    let last = u64le(&b, 48);
    let table_blocks = bytes.div_ceil(u64::from(sector));
    let table_end_lba = table_lba
        .checked_add(table_blocks)
        .ok_or_else(|| invalid("candidate table LBA overflow"))?;
    if (lba == 1 && (table_lba < 2 || table_end_lba > first))
        || (lba != 1 && (table_lba <= last || table_end_lba > lba))
    {
        return Err(invalid("candidate metadata intersects usable range"));
    }
    let primary_lba = if lba == 1 { table_lba } else { 2 };
    let backup_lba = if lba == 1 {
        old_total - 1 - blocks
    } else {
        table_lba
    };
    let primary = header(b.clone(), 1, old_total - 1, primary_lba, first, last);
    let backup = header(b, old_total - 1, 1, backup_lba, first, last);
    let mut mbr = vec![0; sector as usize];
    source.read_exact_at(0, &mut mbr)?;
    mbr[446..510].fill(0);
    mbr[450] = 0xee;
    mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
    mbr[458..462].copy_from_slice(&((old_total - 1).min(u64::from(u32::MAX)) as u32).to_le_bytes());
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
    let overlay = Overlay {
        source,
        length: old_total * u64::from(sector),
        regions: vec![
            (0, mbr),
            (u64::from(sector), primary),
            (primary_lba * u64::from(sector), table.clone()),
            (backup_lba * u64::from(sector), table),
            ((old_total - 1) * u64::from(sector), backup),
        ],
    };
    match DiskLayout::inspect(&overlay, sector)? {
        DiskLayout::Gpt(g) => Ok(g),
        _ => Err(invalid("candidate did not form GPT")),
    }
}
/// Explicit valid metadata source selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverySource {
    /// Header at LBA 1.
    Primary,
    /// Header at the current final LBA.
    Backup,
    /// A caller-specified displaced backup header.
    Displaced(u64),
}
/// Independent source results. No source is silently preferred over another.
pub struct RecoveryReport {
    primary: io::Result<GptLayout>,
    backup: io::Result<GptLayout>,
    displaced: Vec<(u64, io::Result<GptLayout>)>,
    sector: u32,
    length: u64,
    snapshots: Vec<(u64, Vec<u8>)>,
}
impl RecoveryReport {
    /// Inspect primary, final backup, and at most 64 explicit candidate LBAs.
    /// This never scans attacker-selected or disk-sized ranges.
    pub fn inspect(source: &dyn ReadAt, sector: u32, candidates: &[u64]) -> io::Result<Self> {
        let g = Geometry::new(source.len(), sector)?;
        if candidates.len() > 64 {
            return Err(invalid("too many recovery candidates"));
        }
        let mut snapshots = Vec::new();
        let mut lbas = vec![1, g.sectors() - 1];
        lbas.extend_from_slice(candidates);
        lbas.sort_unstable();
        lbas.dedup();
        let mut mbr = vec![0; sector as usize];
        source.read_exact_at(0, &mut mbr)?;
        snapshots.push((0, mbr));
        for lba in lbas {
            if lba >= g.sectors() {
                continue;
            }
            let mut raw = vec![0; sector as usize];
            source.read_exact_at(lba * u64::from(sector), &mut raw)?;
            snapshots.push((lba * u64::from(sector), raw.clone()));
            if let Ok(layout) = candidate(source, sector, lba) {
                let mut array = vec![0; layout.array().len()];
                let offset = u64le(&raw, 72) * u64::from(sector);
                source.read_exact_at(offset, &mut array)?;
                snapshots.push((offset, array));
            }
        }
        Ok(Self {
            length: source.len(),
            snapshots,
            primary: candidate(source, sector, 1),
            backup: candidate(source, sector, g.sectors() - 1),
            displaced: candidates
                .iter()
                .map(|&l| (l, candidate(source, sector, l)))
                .collect(),
            sector,
        })
    }
    /// Independently validated primary copy or its exact failure.
    pub fn primary(&self) -> Result<&GptLayout, &io::Error> {
        self.primary.as_ref()
    }
    /// Independently validated final-LBA backup copy or its exact failure.
    pub fn backup(&self) -> Result<&GptLayout, &io::Error> {
        self.backup.as_ref()
    }
    /// Explicit candidate LBAs and independent validation outcomes.
    pub fn displaced(&self) -> &[(u64, io::Result<GptLayout>)] {
        &self.displaced
    }
    /// Whether both valid copies describe different identities, bounds, or arrays.
    pub fn divergent(&self) -> bool {
        match (&self.primary, &self.backup) {
            (Ok(a), Ok(b)) => {
                a.disk_guid() != b.disk_guid() || a.usable() != b.usable() || a.array() != b.array()
            }
            _ => false,
        }
    }
    fn selected(&self, s: RecoverySource) -> io::Result<&GptLayout> {
        let r = match s {
            RecoverySource::Primary => &self.primary,
            RecoverySource::Backup => &self.backup,
            RecoverySource::Displaced(l) => {
                &self
                    .displaced
                    .iter()
                    .find(|(p, _)| *p == l)
                    .ok_or_else(|| invalid("candidate was not inspected"))?
                    .1
            }
        };
        r.as_ref()
            .map_err(|_| invalid("selected source is invalid"))
    }
    /// Repair the unselected copy, or relocate both copies after image growth.
    pub fn repair_plan(
        &self,
        source: &dyn ReadAt,
        selected: RecoverySource,
    ) -> io::Result<WritePlan> {
        self.geometry_plan(source, selected, source.len())
    }
    /// Plan metadata against a target geometry before a caller resizes storage.
    /// Shrink targets that intersect partitions or GPT metadata are rejected.
    /// The returned plan commits on the current geometry; resize only after success.
    pub fn geometry_plan(
        &self,
        source: &dyn ReadAt,
        selected: RecoverySource,
        target_bytes: u64,
    ) -> io::Result<WritePlan> {
        if source.len() != self.length {
            return Err(invalid("recovery report geometry changed"));
        }
        for (offset, expected) in &self.snapshots {
            let mut current = vec![0; expected.len()];
            source.read_exact_at(*offset, &mut current)?;
            if &current != expected {
                return Err(invalid("recovery report metadata changed"));
            }
        }
        let original_mbr = &self
            .snapshots
            .iter()
            .find(|(o, _)| *o == 0)
            .expect("captured MBR")
            .1;
        if original_mbr[446..510]
            .chunks_exact(16)
            .any(|e| e[4] != 0 && e[4] != 0xee)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hybrid or ordinary MBR cannot be overwritten by GPT recovery",
            ));
        }
        let layout = self.selected(selected)?;
        if !layout.mutation_supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unknown GPT metadata extension cannot be repaired",
            ));
        }
        let g = Geometry::new(target_bytes, self.sector)?;
        if target_bytes > source.len() {
            return Err(invalid("grow storage before planning GPT relocation"));
        }
        let sector = u64::from(self.sector);
        let blocks = (layout.array().len() as u64).div_ceil(sector);
        let total = g.sectors();
        let last = total
            .checked_sub(blocks + 2)
            .ok_or_else(|| invalid("target too small"))?;
        let last = if layout.geometry().bytes() == target_bytes {
            layout.usable().end() - 1
        } else {
            last
        };
        let first = layout.usable().start();
        if first > last
            || layout
                .entries()
                .iter()
                .filter_map(|e| e.range())
                .any(|r| r.end() > last + 1)
        {
            return Err(invalid("target intersects partitions or metadata"));
        }
        let same = layout.geometry().bytes() == target_bytes;
        let primary_lba = if same { layout.primary_array_lba() } else { 2 };
        let backup_lba = if same {
            layout.backup_array_lba()
        } else {
            total - 1 - blocks
        };
        let primary = header(
            layout.primary_header().to_vec(),
            1,
            total - 1,
            primary_lba,
            first,
            last,
        );
        let backup = header(
            layout.backup_header().to_vec(),
            total - 1,
            1,
            backup_lba,
            first,
            last,
        );
        let mut mbr = layout.mbr_sector().to_vec();
        mbr[458..462].copy_from_slice(&((total - 1).min(u64::from(u32::MAX)) as u32).to_le_bytes());
        let same = layout.geometry().bytes() == target_bytes;
        let mut regions = Vec::new();
        let mut stage = |name: &str, writes: Vec<(u64, Vec<u8>)>| -> io::Result<Barrier> {
            let mut ranges = Vec::new();
            for (o, b) in writes {
                let mut old = vec![0; b.len()];
                source.read_exact_at(o, &mut old)?;
                regions.push((o, b.clone()));
                ranges.push(WriteRange::new(o, old, b)?);
            }
            Barrier::new(name, ranges)
        };
        let mut stages = Vec::new();
        if !same || selected != RecoverySource::Backup {
            stages.push(stage(
                "repair-backup",
                vec![
                    (backup_lba * sector, layout.array().to_vec()),
                    ((total - 1) * sector, backup),
                ],
            )?);
        }
        if !same || selected != RecoverySource::Primary {
            stages.push(stage(
                "repair-primary",
                vec![
                    (primary_lba * sector, layout.array().to_vec()),
                    (sector, primary),
                ],
            )?);
        }
        let mut actual_mbr = vec![0; mbr.len()];
        source.read_exact_at(0, &mut actual_mbr)?;
        if actual_mbr != mbr {
            stages.push(stage("repair-protective-mbr", vec![(0, mbr)])?);
        }
        let overlay = Overlay {
            source,
            length: target_bytes,
            regions,
        };
        DiskLayout::inspect(&overlay, self.sector)?;
        WritePlan::new(source.len(), stages)?.with_preconditions(
            self.snapshots
                .iter()
                .map(|(o, b)| ReadCondition::new(*o, b.clone()))
                .collect::<io::Result<Vec<_>>>()?,
        )
    }
}
/// Failure during coordinated resizing, preserving stage and uncertain geometry.
#[derive(Debug)]
pub enum ResizeError {
    /// Inspection or planning failed before mutation.
    Preflight(io::Error),
    /// Storage resize failed; actual geometry must be inspected before retrying.
    StorageResize(io::Error),
    /// Metadata commit failed; the commit error describes completed barriers.
    Commit(crate::storage::CommitError),
    /// Final storage geometry or strict GPT readback failed after mutation.
    Verification(io::Error),
}
impl crate::platform::fmt::Display for ResizeError {
    fn fmt(&self, f: &mut crate::platform::fmt::Formatter<'_>) -> crate::platform::fmt::Result {
        match self {
            Self::Preflight(e) => write!(f, "resize preflight: {e}"),
            Self::StorageResize(e) => write!(f, "storage resize uncertain: {e}"),
            Self::Commit(e) => write!(f, "resize metadata: {e}"),
            Self::Verification(e) => write!(f, "resized GPT verification: {e}"),
        }
    }
}
impl crate::platform::error::Error for ResizeError {
    fn source(&self) -> Option<&(dyn crate::platform::error::Error + 'static)> {
        Some(match self {
            Self::Preflight(e) | Self::StorageResize(e) | Self::Verification(e) => e,
            Self::Commit(e) => e,
        })
    }
}
struct StorageReader<'a, S> {
    storage: &'a S,
    length: u64,
}
impl<S: crate::storage::Storage + Send + Sync> ReadAt for StorageReader<'_, S> {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.storage.read_exact_at(o, b)
    }
}
/// Coordinate physical image geometry with explicit GPT metadata source choice.
/// Growth validates a safe source, grows storage, then relocates metadata. Shrink
/// validates and commits target metadata before reducing storage. Failed resize
/// or commit can leave geometry or copies changed; inspect before retrying.
/// This changes partition-table geometry only and never resizes a filesystem.
pub fn resize_gpt<S: crate::storage::ResizableStorage + Send + Sync>(
    storage: &mut S,
    sector: u32,
    target_bytes: u64,
    selected: RecoverySource,
    candidates: &[u64],
) -> Result<GptLayout, ResizeError> {
    let old_length = storage.len().map_err(ResizeError::Preflight)?;
    Geometry::new(target_bytes, sector).map_err(ResizeError::Preflight)?;
    let report = RecoveryReport::inspect(
        &StorageReader {
            storage,
            length: old_length,
        },
        sector,
        candidates,
    )
    .map_err(ResizeError::Preflight)?;
    if report
        .snapshots
        .iter()
        .find(|(o, _)| *o == 0)
        .expect("captured MBR")
        .1[446..510]
        .chunks_exact(16)
        .any(|e| e[4] != 0 && e[4] != 0xee)
    {
        return Err(ResizeError::Preflight(io::Error::new(
            io::ErrorKind::Unsupported,
            "hybrid MBR cannot be resized through GPT recovery",
        )));
    }
    let chosen = report.selected(selected).map_err(ResizeError::Preflight)?;
    if !chosen.mutation_supported() {
        return Err(ResizeError::Preflight(io::Error::new(
            io::ErrorKind::Unsupported,
            "unknown GPT metadata extensions cannot be resized",
        )));
    }
    if target_bytes > old_length {
        storage
            .resize(target_bytes)
            .map_err(ResizeError::StorageResize)?;
        if storage.len().map_err(ResizeError::Verification)? != target_bytes {
            return Err(ResizeError::Verification(invalid(
                "resize adapter geometry mismatch",
            )));
        }
        let mut discovery = candidates.to_vec();
        let old_final = old_length / u64::from(sector) - 1;
        if !discovery.contains(&old_final) {
            discovery.push(old_final)
        }
        let selected = if selected == RecoverySource::Backup {
            RecoverySource::Displaced(old_final)
        } else {
            selected
        };
        let reader = StorageReader {
            storage,
            length: target_bytes,
        };
        let report = RecoveryReport::inspect(&reader, sector, &discovery)
            .map_err(ResizeError::Verification)?;
        let plan = report
            .repair_plan(&reader, selected)
            .map_err(ResizeError::Verification)?;
        plan.commit(storage).map_err(ResizeError::Commit)?;
    } else {
        let plan = report
            .geometry_plan(
                &StorageReader {
                    storage,
                    length: old_length,
                },
                selected,
                target_bytes,
            )
            .map_err(ResizeError::Preflight)?;
        plan.commit(storage).map_err(ResizeError::Commit)?;
        if target_bytes < old_length {
            storage
                .resize(target_bytes)
                .map_err(ResizeError::StorageResize)?;
        }
    }
    let length = storage.len().map_err(ResizeError::Verification)?;
    if length != target_bytes {
        return Err(ResizeError::Verification(invalid(
            "resize adapter geometry mismatch",
        )));
    }
    match DiskLayout::inspect(&StorageReader { storage, length }, sector)
        .map_err(ResizeError::Verification)?
    {
        DiskLayout::Gpt(g) => Ok(g),
        _ => Err(ResizeError::Verification(invalid(
            "resized image is not GPT",
        ))),
    }
}
