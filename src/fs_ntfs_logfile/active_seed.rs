//! Source-owned restart discovery arithmetic, before tail/fast-copy discovery.
use super::*;

/// Aggregate ceilings for restart selection and declared-span arithmetic.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogDiscoverySeedLimits {
    /// Existing restart-copy inspection ceilings (work also capped by `work`).
    pub restart: NtfsLogFileLimits,
    /// Maximum physical pages traversed by declared endpoint arithmetic.
    pub pages: usize,
    /// Combined actual restart/selection work and arithmetic steps.
    pub work: usize,
}
/// LSN address classification only; no record/page byte has been read here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogSeedAddress {
    /// Zero LSN, retained independently of reserved-region pseudo addresses.
    Zero,
    /// Nonzero LSN addresses the restart/tail/fast-copy reserved region.
    Pseudo {
        /// Byte offset within the recorded log stream; not validated record evidence.
        byte_offset: u64,
        /// Sequence generation extracted from the native LSN encoding.
        generation: u64,
    },
    /// Ordinary region address; does not itself prove a record exists there.
    Ordinary {
        /// Byte offset within the recorded log stream; not validated record evidence.
        byte_offset: u64,
        /// Sequence generation extracted from the native LSN encoding.
        generation: u64,
    },
}
/// Declared inclusive physical endpoint, without ordinary-page validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogDeclaredEndpoint {
    final_byte_offset: u64,
    final_page_offset: u64,
    physical_wraps: usize,
    pages: usize,
}
impl NtfsLogDeclaredEndpoint {
    /// Inclusive last header/payload byte, skipping continuation-page headers.
    pub fn final_byte_offset(&self) -> u64 {
        self.final_byte_offset
    }
    /// Physical page containing the inclusive endpoint.
    pub fn final_page_offset(&self) -> u64 {
        self.final_page_offset
    }
    /// End-to-ordinary-start transitions actually traversed by arithmetic.
    pub fn physical_wraps(&self) -> usize {
        self.physical_wraps
    }
    /// Physical visits; a near-full-ring span can revisit its initial page.
    pub fn pages(&self) -> usize {
        self.pages
    }
}
/// Immutable derived observations, available only after final source guards.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogDiscoverySeed {
    ordinary_start: u64,
    current: NtfsLogSeedAddress,
    endpoint: Option<NtfsLogDeclaredEndpoint>,
    numeric_oldest_lsn: u64,
    oldest: NtfsLogSeedAddress,
}
impl NtfsLogDiscoverySeed {
    /// Version-specific first ordinary page (4P for1.1,34P for2.0).
    pub fn ordinary_start(&self) -> u64 {
        self.ordinary_start
    }
    /// Selected native current-LSN address classification, not record evidence.
    pub fn current_address(&self) -> NtfsLogSeedAddress {
        self.current
    }
    /// None for zero/pseudo current LSN; otherwise declared-span arithmetic only.
    pub fn declared_endpoint(&self) -> Option<&NtfsLogDeclaredEndpoint> {
        self.endpoint.as_ref()
    }
    /// Minimum nonzero in-use-client oldest LSN seeded by selected current LSN.
    /// Numeric order uses caller's explicit exclusion of sequence rollover.
    pub fn numeric_oldest_lsn(&self) -> u64 {
        self.numeric_oldest_lsn
    }
    /// Address classification of that numeric lower-bound observation.
    pub fn oldest_address(&self) -> NtfsLogSeedAddress {
        self.oldest
    }
}
/// Retains both original restart copies and caller-qualified selection evidence.
pub struct NtfsLogDiscoverySeedReport {
    selection: NtfsLogRestartSelectionReport,
    seed: Option<NtfsLogDiscoverySeed>,
    error: Option<Error>,
    source_error: Option<Error>,
    work: usize,
}
impl NtfsLogDiscoverySeedReport {
    /// Original selected and rejected restart context; never merged.
    pub fn selection(&self) -> &NtfsLogRestartSelectionReport {
        &self.selection
    }
    /// Derived observations withheld after arithmetic or final source failure.
    pub fn seed(&self) -> Option<&NtfsLogDiscoverySeed> {
        self.stopping_error()
            .is_none()
            .then_some(self.seed.as_ref())
            .flatten()
    }
    /// Original failure; rejected format-only copies remain diagnostic in selection.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.selection
            .stopping_error()
            .or(self.error.as_ref())
            .or(self.source_error.as_ref())
    }
    /// Independent final stream/volume cancellation/source failure.
    pub fn source_error(&self) -> Option<&Error> {
        self.source_error.as_ref().or(self.selection.source_error())
    }
    /// Actual combined restart selection and endpoint arithmetic work.
    pub fn work(&self) -> usize {
        self.work
    }
    /// Always false: this seed neither examines nor installs tail/fast copies.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// Always false: no transaction analysis or replay authority supplied.
    pub fn recovery_complete(&self) -> bool {
        false
    }
    /// Fail explicitly if a consumer requests authoritative active-window use.
    pub fn require_active_window(&self) -> Result<()> {
        Err(unsupported(
            "NTFS active-window tail/fast-copy discovery not established",
        ))
    }
}
fn seed_address(area: &NtfsRestartArea, first: u64, lsn: u64) -> Result<NtfsLogSeedAddress> {
    if lsn == 0 {
        return Ok(NtfsLogSeedAddress::Zero);
    }
    let bits = 64u32
        .checked_sub(area.sequence_bits)
        .ok_or_else(|| invalid("NTFS seed sequence bits"))?;
    let mask = 1u64
        .checked_shl(bits)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| invalid("NTFS seed LSN mask"))?;
    let offset = (lsn & mask)
        .checked_mul(8)
        .ok_or_else(|| invalid("NTFS seed LSN address overflow"))?;
    if offset >= area.file_bytes {
        return Err(invalid("NTFS seed LSN outside recorded stream"));
    }
    let generation = lsn
        .checked_shr(bits)
        .ok_or_else(|| invalid("NTFS seed generation shift"))?;
    Ok(if offset < first {
        NtfsLogSeedAddress::Pseudo {
            byte_offset: offset,
            generation,
        }
    } else {
        NtfsLogSeedAddress::Ordinary {
            byte_offset: offset,
            generation,
        }
    })
}
fn derive(
    area: &NtfsRestartArea,
    limits: NtfsLogDiscoverySeedLimits,
    work: &mut Work,
    r: &Resources,
) -> Result<NtfsLogDiscoverySeed> {
    work.tick(r)?;
    let first = match area.version {
        (1, 1) => 4 * PAGE as u64,
        (2, 0) => 34 * PAGE as u64,
        _ => return Err(unsupported("NTFS seed version profile")),
    };
    let current = seed_address(area, first, area.current_lsn)?;
    let mut oldest = area.current_lsn;
    // Parser already validated the historical single-client linked-list shape.
    // An existing FREE slot contributes no client oldest LSN.
    if area.in_use_head != NO_CLIENT {
        if area.client_count != 1 || area.in_use_head != 0 {
            return Err(unsupported("NTFS seed active client profile"));
        }
        if let Some(client) = area.client_oldest_lsn
            && client != 0
            && client < oldest
        {
            oldest = client;
        }
    }
    work.tick(r)?;
    let oldest_address = seed_address(area, first, oldest)?;
    let endpoint = if let NtfsLogSeedAddress::Ordinary { byte_offset, .. } = current {
        let position = byte_offset % PAGE as u64;
        if position < u64::from(area.page_data_offset)
            || position + u64::from(area.record_header_bytes) > PAGE as u64
        {
            return Err(invalid("NTFS seed current header address"));
        }
        let ordinary_pages = area
            .file_bytes
            .checked_sub(first)
            .ok_or_else(|| invalid("NTFS seed ordinary geometry"))?
            / PAGE as u64;
        let per_page = PAGE as u64 - u64::from(area.page_data_offset);
        let capacity = ordinary_pages
            .checked_mul(per_page)
            .ok_or_else(|| invalid("NTFS seed ring capacity overflow"))?;
        let mut remaining = u64::from(area.record_header_bytes)
            .checked_add(u64::from(area.last_lsn_data_bytes))
            .ok_or_else(|| invalid("NTFS seed span overflow"))?;
        // Strict full-ring bound prevents any overlap of the starting LFS header.
        if remaining >= capacity {
            return Err(invalid("NTFS seed declared span overlaps complete ring"));
        }
        let mut page = byte_offset - position;
        let mut start = position;
        let mut wraps = 0usize;
        let mut pages = 0usize;
        loop {
            if pages == limits.pages {
                return Err(exhausted("NTFS seed declared page ceiling"));
            }
            work.tick(r)?;
            pages = pages
                .checked_add(1)
                .ok_or_else(|| exhausted("NTFS seed visit overflow"))?;
            let available = PAGE as u64 - start;
            if remaining <= available {
                let final_byte = page
                    .checked_add(start)
                    .and_then(|n| n.checked_add(remaining))
                    .and_then(|n| n.checked_sub(1))
                    .ok_or_else(|| invalid("NTFS seed endpoint overflow"))?;
                break Some(NtfsLogDeclaredEndpoint {
                    final_byte_offset: final_byte,
                    final_page_offset: page,
                    physical_wraps: wraps,
                    pages,
                });
            }
            remaining -= available;
            page = page
                .checked_add(PAGE as u64)
                .ok_or_else(|| invalid("NTFS seed page advance overflow"))?;
            if page == area.file_bytes {
                page = first;
                wraps = wraps
                    .checked_add(1)
                    .ok_or_else(|| exhausted("NTFS seed wrap count"))?;
            }
            if page >= area.file_bytes || wraps > 1 {
                return Err(invalid("NTFS seed declared ring traversal"));
            }
            start = u64::from(area.page_data_offset);
        }
    } else {
        None
    };
    Ok(NtfsLogDiscoverySeed {
        ordinary_start: first,
        current,
        endpoint,
        numeric_oldest_lsn: oldest,
        oldest: oldest_address,
    })
}
/// Inspect only both restart pages, retain selected context, and compute bounded
/// declared endpoint/lower-bound observations without reading ordinary pages.
/// Caller must keep source immutable; length guards do not detect same-length writes.
/// No next-page reuse, successor LSN, overlay or active record selection is inferred.
pub fn inspect_logfile_discovery_seed(
    source: Arc<dyn ReadAt>,
    limits: NtfsLogDiscoverySeedLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsLogDiscoverySeedReport> {
    let mut restart_limits = limits.restart;
    restart_limits.work = restart_limits.work.min(limits.work);
    let selection = inspect_logfile_restart_candidate(source.clone(), restart_limits, ordering, r)?;
    let length = selection.restart().source_bytes();
    let mut work = Work {
        used: selection.work(),
        maximum: limits.work,
    };
    let mut report = NtfsLogDiscoverySeedReport {
        selection,
        seed: None,
        error: None,
        source_error: None,
        work: 0,
    };
    if let Some(area) = report.selection.selected_context() {
        match derive(area, limits, &mut work, r) {
            Ok(seed) => report.seed = Some(seed),
            Err(error) => report.error = Some(error),
        }
    }
    report.work = work.used;
    report.source_error = r.cancellation.check().err().or_else(|| {
        if source.len() != length {
            Some(Error::new(
                ErrorKind::StalePlan,
                "NTFS discovery seed source length changed",
            ))
        } else {
            r.cancellation.check().err()
        }
    });
    Ok(report)
}
/// Source-scoped resolved native record-2 seed observations, not recovery authority.
pub struct NtfsVolumeLogDiscoverySeedReport {
    /// Native record-2 identity from the same resolved volume.
    pub owner: crate::fs_core::ObjectId,
    /// Independently observed native volume flags.
    pub volume_flags: u16,
    /// Complete original restart selection and optional derived seed.
    pub report: NtfsLogDiscoverySeedReport,
}
/// Resolve native record-2 DATA and suppress seed observations on final volume
/// source/cancellation failure. Never reads or repairs an ordinary/tail page.
pub fn inspect_ntfs_logfile_discovery_seed(
    source: Arc<dyn ReadAt>,
    read_limits: crate::fs_ntfs::NtfsReadLimits,
    stream_limits: crate::fs_ntfs::NtfsStreamLimits,
    limits: NtfsLogDiscoverySeedLimits,
    ordering: NtfsLogRestartOrdering,
    r: &Resources,
) -> Result<NtfsVolumeLogDiscoverySeedReport> {
    r.cancellation.check()?;
    if limits.restart.restart_page_bytes < PAGE {
        return Err(exhausted("NTFS restart page ceiling"));
    }
    let (volume, owner, file) = select_native_logfile(source, read_limits, stream_limits, r)?;
    let native = NativeLogFile {
        file,
        resources: r.clone(),
    };
    let mut report = inspect_logfile_discovery_seed(Arc::new(native), limits, ordering, r)?;
    if let Err(error) = volume
        .audit_check_source(r)
        .and_then(|()| r.cancellation.check())
    {
        report.source_error = Some(error);
    }
    Ok(NtfsVolumeLogDiscoverySeedReport {
        owner,
        volume_flags: volume.audit_flags(),
        report,
    })
}
