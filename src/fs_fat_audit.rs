//! Read-only FAT ownership audit. Sources must remain immutable throughout.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{io, sync::Arc};
use crate::{
    fs_core::{Reservation, Resources},
    fs_fat::{
        FatDecodeRead, FatDecoder, FatEntry, FatFamily, FatGeometry, FatStorageDecoder, FatVolume,
    },
};

/// Explicit whole-volume work bounds, independent of memory accounting.
#[derive(Clone, Copy, Debug)]
pub struct FatAuditLimits {
    /// Maximum data clusters inventoried.
    pub clusters: usize,
    /// Maximum namespace entries, including directories.
    pub entries: usize,
    /// Maximum slots scanned in each directory.
    pub directory_slots: usize,
    /// Maximum retained diagnostic records.
    pub findings: usize,
}
/// Allocation or volume-state defect, with volume-relative cluster identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FatAuditFinding {
    /// A reserved entry violates media/profile encoding, independently of status bits.
    InvalidReservedEntry {
        /// Zero-based selected FAT copy.
        copy: u8,
        /// Reserved entry index, zero or one.
        entry: u8,
        /// Decoded value, masking FAT32 reserved high bits.
        value: u32,
        /// Bits governed by this encoding rule; dirty/status bits are excluded.
        mask: u32,
        /// Required value after applying mask.
        expected: u32,
    },
    /// Mirrored FAT entries differ (disabled inactive copies are not compared).
    MirrorDisagreement {
        /// FAT entry index.
        cluster: u32,
        /// Differing zero-based FAT copy.
        copy: u8,
    },
    /// Dirty or hardware-error flag is set in FAT entry one.
    Unclean {
        /// Zero-based FAT copy.
        copy: u8,
        /// Clean-shutdown bit value.
        clean: bool,
        /// No-hardware-error bit value.
        no_error: bool,
    },
    /// Two namespace objects claim one cluster.
    CrossLink {
        /// Shared data cluster.
        cluster: u32,
    },
    /// An object's chain revisits one of its own clusters.
    Cycle {
        /// Revisited cluster.
        cluster: u32,
    },
    /// Chain references a free, bad, reserved, or out-of-range entry.
    InvalidChain {
        /// Cluster whose transition failed, or invalid start.
        cluster: u32,
        /// Invalid transition value.
        value: u32,
    },
    /// File allocation does not match its declared byte length.
    LengthMismatch {
        /// First data cluster from directory slot.
        first_cluster: u32,
    },
    /// Nonfree, nonbad data cluster has no namespace owner.
    LostAllocation {
        /// Unowned nonfree data cluster.
        cluster: u32,
    },
}
/// Data-only free range. Never includes FATs, fixed root, or volume tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatFreeRange {
    /// Volume-relative byte offset.
    pub offset: u64,
    /// Byte length of consecutive unallocated data clusters.
    pub length: u64,
}
/// Complete bounded inventory retaining its memory reservation.
/// This report grants no write authority, durable commit, or exclusive access.
pub struct FatAuditReport {
    findings: Vec<FatAuditFinding>,
    free: Vec<FatFreeRange>,
    objects: usize,
    namespace_complete: bool,
    _reservation: Reservation,
}
impl FatAuditReport {
    /// Ownership and dirty-state defects; empty means this audit passed.
    pub fn findings(&self) -> &[FatAuditFinding] {
        &self.findings
    }
    /// Unallocated data ranges according to the selected FAT.
    pub fn free_ranges(&self) -> &[FatFreeRange] {
        &self.free
    }
    /// False when a malformed directory chain prevented descendant traversal.
    pub fn namespace_complete(&self) -> bool {
        self.namespace_complete
    }
    /// Namespace object count, including the root.
    pub fn objects(&self) -> usize {
        self.objects
    }
}
fn failure(s: &'static str) -> io::Error {
    io::Error::other(crate::fs_core::Error::new(
        crate::fs_core::ErrorKind::BudgetExhausted,
        s,
    ))
}
fn check(r: &Resources) -> io::Result<()> {
    r.cancellation.check().map_err(io::Error::other)
}
fn first(e: &FatEntry, g: &FatGeometry) -> u32 {
    let b = e.raw_metadata();
    let lo = u32::from(u16::from_le_bytes([b[26], b[27]]));
    if g.family() == FatFamily::Fat32 {
        lo | (u32::from(u16::from_le_bytes([b[20], b[21]])) << 16)
    } else {
        lo
    }
}
fn push(v: &mut Vec<FatAuditFinding>, f: FatAuditFinding, limit: usize) -> io::Result<()> {
    if v.len() == limit {
        return Err(failure("FAT audit finding limit exhausted"));
    }
    v.push(f);
    Ok(())
}
/// Audit every selected FAT entry and every reachable namespace object.
///
/// Strict directory decoding errors and exhausted bounds fail the operation;
/// no partial report is returned. Allocation graph defects are diagnostics.
/// Validated names alone never establish ownership. FAT32 inactive copies with
/// mirroring disabled are intentionally outside the comparison scope. FSInfo,
/// boot backups, dot-link semantics, payload correctness and durable/exclusive
/// mutation authorization are outside this read-only audit.
pub fn audit_fat(
    source: Arc<dyn ReadAt>,
    limits: FatAuditLimits,
    resources: &Resources,
) -> io::Result<FatAuditReport> {
    let volume = FatVolume::open(source)?;
    audit_decoder(&volume.decoder, limits, resources)
}

pub(crate) fn audit_fat_storage(
    source: &dyn crate::storage::Storage,
    limits: FatAuditLimits,
    resources: &Resources,
) -> io::Result<FatAuditReport> {
    let volume = FatStorageDecoder::open_storage(source, 0)?;
    audit_decoder(&volume, limits, resources)
}
fn audit_decoder<R: FatDecodeRead>(
    volume: &FatDecoder<R>,
    limits: FatAuditLimits,
    resources: &Resources,
) -> io::Result<FatAuditReport> {
    check(resources)?;
    let g = volume.geometry();
    let n = g.cluster_count() as usize;
    if n > limits.clusters || limits.entries == 0 {
        return Err(failure("FAT audit inventory limit exhausted"));
    }
    let charge = (n as u64)
        .checked_mul(64)
        .and_then(|v| v.checked_add((limits.entries as u64).checked_mul(800)?))
        .and_then(|v| v.checked_add((limits.findings as u64).checked_mul(64)?))
        .ok_or_else(|| failure("FAT audit memory overflow"))?;
    let reservation = resources.memory.reserve(charge).map_err(io::Error::other)?;
    let mut values = Vec::new();
    values.try_reserve_exact(n + 2).map_err(io::Error::other)?;
    let mut owners = Vec::new();
    owners.try_reserve_exact(n + 2).map_err(io::Error::other)?;
    owners.resize(n + 2, 0usize);
    let mut findings = Vec::new();
    findings
        .try_reserve_exact(limits.findings)
        .map_err(io::Error::other)?;
    let selected = g.active_fat().unwrap_or(0);
    for c in 0..=g.cluster_count() + 1 {
        check(resources)?;
        let value = volume.read_fat_entry(selected, c)?;
        values.push(value);
        if g.active_fat().is_none() {
            for copy in 1..g.fat_count() {
                if volume.read_fat_entry(copy, c)? != value {
                    push(
                        &mut findings,
                        FatAuditFinding::MirrorDisagreement { cluster: c, copy },
                        limits.findings,
                    )?;
                }
            }
        }
    }
    let (full_mask, entry_one_mask) = match g.family() {
        FatFamily::Fat12 => (0xfff, 0xff8),
        FatFamily::Fat16 => (0xffff, 0x3fff),
        FatFamily::Fat32 => (0x0fff_ffff, 0x03ff_ffff),
    };
    for copy in 0..g.fat_count() {
        if g.active_fat().is_some() && copy != selected {
            continue;
        }
        for (index, mask, expected) in [
            (
                0,
                full_mask,
                (full_mask & !0xff) | u32::from(g.media_descriptor()),
            ),
            (1, entry_one_mask, entry_one_mask),
        ] {
            let value = volume.read_fat_entry(copy, index)?;
            if value & mask != expected {
                push(
                    &mut findings,
                    FatAuditFinding::InvalidReservedEntry {
                        copy,
                        entry: index as u8,
                        value,
                        mask,
                        expected,
                    },
                    limits.findings,
                )?;
            }
        }
    }
    if g.family() != FatFamily::Fat12 {
        let (clean, error) = if g.family() == FatFamily::Fat16 {
            (0x8000, 0x4000)
        } else {
            (0x0800_0000, 0x0400_0000)
        };
        for copy in 0..g.fat_count() {
            if g.active_fat().is_some() && copy != selected {
                continue;
            }
            let value = volume.read_fat_entry(copy, 1)?;
            if value & clean == 0 || value & error == 0 {
                push(
                    &mut findings,
                    FatAuditFinding::Unclean {
                        copy,
                        clean: value & clean != 0,
                        no_error: value & error != 0,
                    },
                    limits.findings,
                )?;
            }
        }
    }
    let reserved = match g.family() {
        FatFamily::Fat12 => 0xff0,
        FatFamily::Fat16 => 0xfff0,
        FatFamily::Fat32 => 0x0fff_fff0,
    };
    let mut queue: Vec<Option<FatEntry>> = Vec::new();
    queue
        .try_reserve_exact(limits.entries)
        .map_err(io::Error::other)?;
    queue.push(None);
    let mut objects = 0;
    let mut namespace_complete = true;
    while let Some(object) = queue.pop() {
        check(resources)?;
        objects += 1;
        if objects > limits.entries {
            return Err(failure("FAT audit object limit exhausted"));
        }
        let directory = object.as_ref().is_none_or(FatEntry::is_directory);
        let start = object
            .as_ref()
            .map(|e| first(e, g))
            .or(g.root_cluster())
            .unwrap_or(0);
        let mut c = start;
        let mut count = 0u64;
        let mut valid = true;
        while c != 0 {
            check(resources)?;
            if c < 2 || c >= reserved || c > g.cluster_count() + 1 {
                push(
                    &mut findings,
                    FatAuditFinding::InvalidChain {
                        cluster: c,
                        value: c,
                    },
                    limits.findings,
                )?;
                valid = false;
                break;
            }
            let old = owners[c as usize];
            if old != 0 {
                push(
                    &mut findings,
                    if old == objects {
                        FatAuditFinding::Cycle { cluster: c }
                    } else {
                        FatAuditFinding::CrossLink { cluster: c }
                    },
                    limits.findings,
                )?;
                valid = false;
                break;
            }
            owners[c as usize] = objects;
            count += 1;
            let next = values[c as usize];
            if next >= reserved + 8 {
                break;
            }
            if next < 2 || next >= reserved {
                push(
                    &mut findings,
                    FatAuditFinding::InvalidChain {
                        cluster: c,
                        value: next,
                    },
                    limits.findings,
                )?;
                valid = false;
                break;
            }
            c = next;
        }
        if let Some(e) = object.as_ref()
            && !directory
            && count != u64::from(e.len()).div_ceil(g.cluster_bytes())
        {
            push(
                &mut findings,
                FatAuditFinding::LengthMismatch {
                    first_cluster: start,
                },
                limits.findings,
            )?;
        }
        if directory && !valid {
            namespace_complete = false;
        }
        if directory && valid {
            let inventory = match object.as_ref() {
                None => {
                    volume.root_directory(limits.clusters, limits.directory_slots, resources)?
                }
                Some(e) => {
                    volume.read_directory(e, limits.clusters, limits.directory_slots, resources)?
                }
            };
            if objects
                .checked_add(queue.len())
                .and_then(|v| v.checked_add(inventory.entries().len()))
                .is_none_or(|v| v > limits.entries)
            {
                return Err(failure("FAT audit object limit exhausted"));
            }
            queue.extend(inventory.entries().iter().cloned().map(Some));
        }
    }
    let mut free: Vec<FatFreeRange> = Vec::new();
    free.try_reserve_exact(n).map_err(io::Error::other)?;
    for c in 2..=g.cluster_count() + 1 {
        check(resources)?;
        let value = values[c as usize];
        if value == 0 && owners[c as usize] == 0 {
            let offset = g.data_offset() + u64::from(c - 2) * g.cluster_bytes();
            if let Some(last) = free
                .last_mut()
                .filter(|last| last.offset + last.length == offset)
            {
                last.length += g.cluster_bytes();
            } else {
                free.push(FatFreeRange {
                    offset,
                    length: g.cluster_bytes(),
                });
            }
        } else if value != 0 && value != reserved + 7 && owners[c as usize] == 0 {
            push(
                &mut findings,
                FatAuditFinding::LostAllocation { cluster: c },
                limits.findings,
            )?;
        }
    }
    Ok(FatAuditReport {
        findings,
        free,
        objects,
        namespace_complete,
        _reservation: reservation,
    })
}
