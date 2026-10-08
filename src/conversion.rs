//! Explicit scheme conversion preserving every payload's sector positions.
//!
//! Conversion changes scheme discovery at the final MBR publication barrier.
//! GPT-to-MBR/extended writes publish the new MBR before clearing obsolete GPT
//! copies; MBR/extended-to-GPT writes backup then primary GPT before publishing
//! the protective MBR, then remove obsolete EBRs. A failed flush can leave bytes
//! visible without confirmed durability. A newly published scheme can be readable
//! even while obsolete metadata remains. Before publication new GPT copies can
//! already be inspected explicitly. If GPT metadata replaces an old EBR sector,
//! the old chain may stop being readable before publication; keep a saved source
//! snapshot when restoration is required.
//!
//! Preserve the reviewed source metadata (including EBR sectors) independently
//! when rollback is required. `WritePlan` exposes exact original bytes; an
//! explicitly chosen saved-source restoration must capture current preconditions
//! and use appropriate ordering. GPT recovery never silently overwrites a current
//! ordinary or hybrid MBR with an old GPT copy. Payload hashes remain independent
//! of scheme metadata, and conversion never moves partition contents.
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    codec,
    guid::Guid,
    layout::{DiskLayout, GptLayout, MbrLayout},
    storage::{Barrier, ReadCondition, WritePlan, WriteRange},
};
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn boot_bytes(source: &[u8], policy: &ConversionPolicy) -> [u8; 440] {
    let mut boot = [0; 440];
    match &policy.boot_code {
        BootCodePolicy::Clear => {}
        BootCodePolicy::Preserve => boot.copy_from_slice(&source[..440]),
        BootCodePolicy::Replace(b) => boot.copy_from_slice(b.as_ref()),
    }
    boot
}
fn is_ldm(id: Guid) -> bool {
    let b = id.to_gpt_bytes();
    b == [
        0xaa, 0xc8, 0x08, 0x58, 0x8f, 0x7e, 0xe0, 0x42, 0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34, 0xcf,
        0xb3,
    ] || b
        == [
            0xa0, 0x60, 0x9b, 0xaf, 0x31, 0x14, 0x62, 0x4f, 0xbc, 0x68, 0x33, 0x11, 0x71, 0x4a,
            0x69, 0xad,
        ]
}
fn validate_mappings(mappings: &[TypeMapping]) -> io::Result<()> {
    if mappings.iter().enumerate().any(|(i, a)| {
        mappings[i + 1..]
            .iter()
            .any(|b| a.mbr == b.mbr || a.gpt == b.gpt)
    }) {
        return Err(invalid("ambiguous conversion mappings"));
    }
    Ok(())
}
fn snapshots(layout: &DiskLayout) -> Vec<(u64, Vec<u8>)> {
    match layout {
        DiskLayout::Mbr(m) => vec![(0, m.sector().to_vec())],
        DiskLayout::Gpt(g) => {
            let sector = u64::from(g.geometry().sector_size());
            vec![
                (0, g.mbr_sector().to_vec()),
                (sector, g.primary_header().to_vec()),
                (g.primary_array_lba() * sector, g.array().to_vec()),
                (g.backup_array_lba() * sector, g.array().to_vec()),
                (
                    (g.geometry().sectors() - 1) * sector,
                    g.backup_header().to_vec(),
                ),
            ]
        }
    }
}
/// Explicit bidirectional type mapping; unknown types are never guessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeMapping {
    mbr: u8,
    gpt: Guid,
}
impl TypeMapping {
    /// Construct a mapping for ordinary static partitions (excluding LDM/hybrid).
    pub fn new(mbr: u8, gpt: Guid) -> io::Result<Self> {
        if matches!(mbr, 0 | 5 | 15 | 0x85 | 0x42 | 0xee) || gpt.is_nil() || is_ldm(gpt) {
            return Err(invalid("unsupported conversion type"));
        }
        Ok(Self { mbr, gpt })
    }
}
/// Explicit policy for executable MBR boot code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootCodePolicy {
    /// Replace boot code with zeros.
    Clear,
    /// Preserve source boot code verbatim without promising compatibility.
    Preserve,
    /// Install exactly 440 caller-provided boot-code bytes.
    Replace(Box<[u8; 440]>),
}
/// New identities and boot policy must be reviewed because conversion changes them.
#[derive(Clone, Debug)]
pub struct ConversionPolicy {
    disk_guid: Guid,
    disk_signature: u32,
    boot_code: BootCodePolicy,
}
impl ConversionPolicy {
    /// Specify target GPT identity, target MBR signature, and boot code treatment.
    pub fn new(disk_guid: Guid, disk_signature: u32, boot_code: BootCodePolicy) -> Self {
        Self {
            disk_guid,
            disk_signature,
            boot_code,
        }
    }
}
/// Convert an owned proposal without storage writes or payload movement.
/// MBR-to-GPT requires one explicit nonnil unique ID per used partition.
/// GPT-to-MBR accepts up to four partitions; extended layouts use dedicated APIs.
pub fn convert(
    source: &DiskLayout,
    mappings: &[TypeMapping],
    policy: &ConversionPolicy,
    partition_ids: &[Guid],
) -> io::Result<DiskLayout> {
    validate_mappings(mappings)?;
    let old_mbr = match source {
        DiskLayout::Gpt(g) => g.mbr_sector(),
        DiskLayout::Mbr(m) => m.sector(),
    };
    let boot = boot_bytes(old_mbr, policy);
    match source {
        DiskLayout::Mbr(m) => {
            if partition_ids.len() != m.entries().len() {
                return Err(invalid("explicit partition IDs required"));
            }
            Guid::validate_unique(partition_ids)
                .map_err(|_| invalid("nil or duplicate conversion ID"))?;
            let mut g = GptLayout::initialize(m.geometry(), policy.disk_guid, 128, 128)?;
            for (index, e) in m.entries().iter().enumerate() {
                if !e.standalone_volume() {
                    return Err(invalid("dynamic-volume conversion unsupported"));
                }
                let kind = mappings
                    .iter()
                    .find(|x| x.mbr == e.raw()[4])
                    .ok_or_else(|| invalid("missing MBR type mapping"))?
                    .gpt;
                g.create(index as u32 + 1, kind, partition_ids[index], e.range())?;
            }
            Ok(DiskLayout::Gpt(g.with_mbr_preservation(old_mbr, &boot)?))
        }
        DiskLayout::Gpt(g) => {
            if !g.mutation_supported() {
                return Err(invalid(
                    "unknown GPT metadata extensions cannot be converted",
                ));
            }
            let entries: Vec<_> = g.entries().iter().filter(|e| e.range().is_some()).collect();
            if entries.len() > 4 {
                return Err(invalid("conversion needs an explicit extended-MBR layout"));
            }
            let mut m = MbrLayout::initialize(g.geometry(), policy.disk_signature);
            for (index, e) in entries.iter().enumerate() {
                if !e.standalone_volume() {
                    return Err(invalid("dynamic-volume conversion unsupported"));
                }
                let guid = Guid::from_gpt_bytes(e.raw()[..16].try_into().expect("GPT prefix"));
                let kind = mappings
                    .iter()
                    .find(|x| x.gpt == guid)
                    .ok_or_else(|| invalid("missing GPT type mapping"))?
                    .mbr;
                m.create(
                    index as u32 + 1,
                    kind,
                    e.range().expect("used entry"),
                    false,
                )?;
            }
            Ok(DiskLayout::Mbr(m.with_mbr_preservation(old_mbr, &boot)?))
        }
    }
}
/// Produce ordered conversion writes with explicit obsolete-GPT removal.
/// Boot code is applied at the final scheme-selection MBR barrier. Source payload
/// ranges are unchanged and never included in the plan. In-place conversion is
/// not atomic; inspect/recover after interruption rather than blindly retrying.
pub fn conversion_plan(
    source: &dyn crate::io::ReadAt,
    old: &DiskLayout,
    mappings: &[TypeMapping],
    policy: &ConversionPolicy,
    partition_ids: &[Guid],
) -> io::Result<(DiskLayout, WritePlan)> {
    let saved = snapshots(old);
    for (offset, expected) in &saved {
        let mut current = vec![0; expected.len()];
        source.read_exact_at(*offset, &mut current)?;
        if &current != expected {
            return Err(invalid("conversion source metadata changed"));
        }
    }
    let proposed = convert(old, mappings, policy, partition_ids)?;
    let base = codec::initialize_plan(source, &proposed)?;
    let mut stages = base.stages().to_vec();
    let old_mbr = match old {
        DiskLayout::Gpt(g) => g.mbr_sector(),
        DiskLayout::Mbr(m) => m.sector(),
    };
    let new_mbr = match &proposed {
        DiskLayout::Gpt(g) => g.mbr_sector(),
        DiskLayout::Mbr(m) => m.sector(),
    };
    let mut final_mbr = new_mbr.to_vec();
    final_mbr[512..].copy_from_slice(&old_mbr[512..]);
    match &policy.boot_code {
        BootCodePolicy::Clear => final_mbr[..440].fill(0),
        BootCodePolicy::Preserve => final_mbr[..440].copy_from_slice(&old_mbr[..440]),
        BootCodePolicy::Replace(b) => final_mbr[..440].copy_from_slice(b.as_ref()),
    }
    let last = stages
        .pop()
        .ok_or_else(|| invalid("missing scheme selection barrier"))?;
    let mut expected = vec![0; final_mbr.len()];
    source.read_exact_at(0, &mut expected)?;
    let final_stage = Barrier::new(last.name(), vec![WriteRange::new(0, expected, final_mbr)?])?;
    if let DiskLayout::Gpt(g) = old {
        let sector = u64::from(g.geometry().sector_size());
        let mut obsolete = Vec::new();
        for (offset, length) in [
            (sector, g.primary_header().len()),
            (g.primary_array_lba() * sector, g.array().len()),
            (g.backup_array_lba() * sector, g.array().len()),
            (
                (g.geometry().sectors() - 1) * sector,
                g.backup_header().len(),
            ),
        ] {
            let end = offset + length as u64;
            if g.entries()
                .iter()
                .filter_map(|e| e.range())
                .any(|r| offset < r.end() * sector && r.start() * sector < end)
            {
                return Err(invalid("obsolete metadata overlaps payload"));
            }
            let mut expected = vec![0; length];
            source.read_exact_at(offset, &mut expected)?;
            obsolete.push(WriteRange::new(offset, expected, vec![0; length])?);
        }
        stages.push(final_stage);
        stages.push(Barrier::new("remove obsolete GPT", obsolete)?);
    } else {
        stages.push(final_stage)
    }
    Ok((
        proposed,
        WritePlan::new(source.len(), stages)?.with_preconditions(
            saved
                .into_iter()
                .map(|(o, b)| ReadCondition::new(o, b))
                .collect::<io::Result<Vec<_>>>()?,
        )?,
    ))
}
/// Convert primary and logical MBR payloads to GPT without changing their ranges.
/// Every used payload requires a caller-provided unique ID. The extended
/// container and EBR sectors cease to be partition metadata after conversion.
pub fn extended_to_gpt(
    source: &crate::extended::ExtendedLayout,
    mappings: &[TypeMapping],
    policy: &ConversionPolicy,
    partition_ids: &[Guid],
) -> io::Result<GptLayout> {
    validate_mappings(mappings)?;
    let mut entries = Vec::new();
    for (slot, raw) in source.mbr_sector()[446..510].chunks_exact(16).enumerate() {
        if slot as u32 + 1 == source.container_slot() || raw[4] == 0 {
            continue;
        }
        let start = u64::from(u32::from_le_bytes(
            raw[8..12].try_into().expect("MBR field"),
        ));
        let count = u64::from(u32::from_le_bytes(
            raw[12..16].try_into().expect("MBR field"),
        ));
        entries.push((raw[4], crate::layout::LbaRange::new(start, start + count)?));
    }
    entries.extend(source.logical().iter().map(|e| (e.kind(), e.range())));
    if entries.len() != partition_ids.len() {
        return Err(invalid(
            "explicit IDs required for primary and logical payloads",
        ));
    }
    Guid::validate_unique(partition_ids).map_err(|_| invalid("nil or duplicate conversion IDs"))?;
    let mut layout = GptLayout::initialize(source.geometry(), policy.disk_guid, 128, 128)?;
    for (index, (kind, range)) in entries.iter().enumerate() {
        if *kind == 0x42 {
            return Err(invalid("dynamic-volume conversion unsupported"));
        }
        let mapped = mappings
            .iter()
            .find(|m| m.mbr == *kind)
            .ok_or_else(|| invalid("missing logical/primary type mapping"))?;
        layout.create(index as u32 + 1, mapped.gpt, partition_ids[index], *range)?;
    }
    layout.with_mbr_preservation(
        source.mbr_sector(),
        &boot_bytes(source.mbr_sector(), policy),
    )
}
/// Convert all GPT partitions into logical MBR partitions at explicit EBR LBAs.
/// EBR placement and container geometry must fit without moving any payload.
/// Boot code policy is applied by the conversion write plan, not this pure model.
pub fn gpt_to_extended(
    source: &GptLayout,
    mappings: &[TypeMapping],
    policy: &ConversionPolicy,
    container_slot: u32,
    container: crate::layout::LbaRange,
    ebr_lbas: &[u64],
) -> io::Result<crate::extended::ExtendedLayout> {
    validate_mappings(mappings)?;
    if !source.mutation_supported() {
        return Err(invalid(
            "unknown GPT metadata extensions cannot be converted",
        ));
    }
    let entries: Vec<_> = source
        .entries()
        .iter()
        .filter(|e| e.range().is_some())
        .collect();
    if entries.len() != ebr_lbas.len() {
        return Err(invalid("one explicit EBR LBA required per partition"));
    }
    let mut partitions = Vec::new();
    for (index, e) in entries.iter().enumerate() {
        if !e.standalone_volume() {
            return Err(invalid("dynamic-volume conversion unsupported"));
        }
        let id = Guid::from_gpt_bytes(e.raw()[..16].try_into().expect("GPT prefix"));
        let kind = mappings
            .iter()
            .find(|m| m.gpt == id)
            .ok_or_else(|| invalid("missing GPT type mapping"))?
            .mbr;
        partitions.push((ebr_lbas[index], kind, e.range().expect("used partition")));
    }
    crate::extended::ExtendedLayout::initialize(
        source.geometry(),
        policy.disk_signature,
        container_slot,
        container,
        &partitions,
    )?
    .with_mbr_preservation(
        source.mbr_sector(),
        &boot_bytes(source.mbr_sector(), policy),
    )
}
/// Plan GPT-to-extended conversion, installing EBRs before the final MBR and
/// clearing obsolete GPT metadata afterward. Selected EBR locations must not
/// overlap the old GPT metadata; payload positions remain unchanged.
pub fn gpt_to_extended_plan(
    source: &dyn crate::io::ReadAt,
    old: &GptLayout,
    mappings: &[TypeMapping],
    policy: &ConversionPolicy,
    container_slot: u32,
    container: crate::layout::LbaRange,
    ebr_lbas: &[u64],
) -> io::Result<(crate::extended::ExtendedLayout, WritePlan)> {
    let layout = gpt_to_extended(old, mappings, policy, container_slot, container, ebr_lbas)?;
    let saved = snapshots(&DiskLayout::Gpt(old.clone()));
    verify_snapshots(source, &saved)?;
    let base = layout.plan_against(source)?;
    let mut stages = base.stages().to_vec();
    let sector = u64::from(old.geometry().sector_size());
    let metadata: Vec<_> = saved.iter().filter(|(o, _)| *o != 0).cloned().collect();
    for logical in layout.logical() {
        let start = logical.ebr_lba() * sector;
        let end = start + sector;
        if metadata
            .iter()
            .any(|(o, b)| start < *o + b.len() as u64 && *o < end)
        {
            return Err(invalid(
                "EBR overlaps old GPT metadata; choose a safe EBR location",
            ));
        }
    }
    stages.push(Barrier::new(
        "remove obsolete GPT",
        metadata
            .into_iter()
            .map(|(o, b)| WriteRange::new(o, b.clone(), vec![0; b.len()]))
            .collect::<io::Result<Vec<_>>>()?,
    )?);
    let plan = WritePlan::new(source.len(), stages)?.with_preconditions(conditions(saved)?)?;
    Ok((layout, plan))
}
/// Plan extended-to-GPT conversion, selecting GPT via its protective MBR last
/// and clearing obsolete EBRs afterward. EBR bytes covered by new GPT metadata
/// are replaced by that metadata instead of receiving a second write.
pub fn extended_to_gpt_plan(
    source: &dyn crate::io::ReadAt,
    old: &crate::extended::ExtendedLayout,
    mappings: &[TypeMapping],
    policy: &ConversionPolicy,
    partition_ids: &[Guid],
) -> io::Result<(GptLayout, WritePlan)> {
    let layout = extended_to_gpt(old, mappings, policy, partition_ids)?;
    let sector = u64::from(old.geometry().sector_size());
    let mut saved = vec![(0, old.mbr_sector().to_vec())];
    saved.extend(
        old.logical()
            .iter()
            .map(|e| (e.ebr_lba() * sector, e.sector().to_vec())),
    );
    verify_snapshots(source, &saved)?;
    let base = codec::initialize_plan(source, &DiskLayout::Gpt(layout.clone()))?;
    let mut stages = base.stages().to_vec();
    let planned: Vec<_> = stages
        .iter()
        .flat_map(|s| s.writes())
        .map(|w| (w.offset(), w.offset() + w.replacement().len() as u64))
        .collect();
    let mut obsolete = Vec::new();
    for (offset, bytes) in saved.iter().skip(1) {
        let mut segments = vec![(*offset, *offset + bytes.len() as u64)];
        for (lo, hi) in &planned {
            let mut next = Vec::new();
            for (a, b) in segments {
                if a < *hi && *lo < b {
                    if a < *lo {
                        next.push((a, *lo))
                    }
                    if *hi < b {
                        next.push((*hi, b))
                    }
                } else {
                    next.push((a, b))
                }
            }
            segments = next;
        }
        for (a, b) in segments {
            let expected = bytes[(a - offset) as usize..(b - offset) as usize].to_vec();
            obsolete.push(WriteRange::new(a, expected, vec![0; (b - a) as usize])?);
        }
    }
    if !obsolete.is_empty() {
        stages.push(Barrier::new("remove obsolete EBRs", obsolete)?)
    }
    let plan = WritePlan::new(source.len(), stages)?.with_preconditions(conditions(saved)?)?;
    Ok((layout, plan))
}
fn verify_snapshots(source: &dyn crate::io::ReadAt, saved: &[(u64, Vec<u8>)]) -> io::Result<()> {
    for (offset, expected) in saved {
        let mut current = vec![0; expected.len()];
        source.read_exact_at(*offset, &mut current)?;
        if &current != expected {
            return Err(invalid("conversion source metadata changed"));
        }
    }
    Ok(())
}
fn conditions(saved: Vec<(u64, Vec<u8>)>) -> io::Result<Vec<ReadCondition>> {
    saved
        .into_iter()
        .map(|(o, b)| ReadCondition::new(o, b))
        .collect()
}
