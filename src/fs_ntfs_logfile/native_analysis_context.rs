//! Exact physical evidence for source-owned native-volume log analysis.
use super::*;
use crate::fs_ntfs::{NtfsGeometry, NtfsReadLimits, NtfsStreamLimits, NtfsVolume};
use crate::platform::sync::Mutex;
mod target_query;
pub use target_query::*;

/// Independent physical capture ceilings; native parsing retains its own limits.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogNativeContextLimits {
    /// Maximum actual native opening/resolution reads, including overlapping reads.
    pub reads: usize,
    /// Maximum aggregate returned physical bytes retained without deduplication.
    pub bytes: usize,
    /// Maximum physical read/comparison work for capture and one repeat pass.
    pub work: usize,
}
struct Guard {
    offset: u64,
    bytes: Vec<u8>,
    _lease: Reservation,
}
struct Capture {
    resources: Resources,
    guards: Vec<Guard>,
    bytes: usize,
    work: usize,
    limits: NtfsLogNativeContextLimits,
    _lease: Reservation,
}
pub(crate) struct NativeReadCapture {
    capture: Capture,
}
impl NativeReadCapture {
    pub(crate) fn ranges(&self) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.capture
            .guards
            .iter()
            .map(|g| (g.offset, g.bytes.len()))
    }
    pub(crate) fn work(&self) -> Result<usize> {
        self.capture
            .bytes
            .checked_mul(3)
            .and_then(|n| n.checked_add(self.capture.guards.len()))
            .and_then(|n| n.checked_add(2))
            .filter(|n| *n <= self.capture.limits.work)
            .ok_or_else(|| exhausted("NTFS native scoped read guard work"))
    }
    pub(crate) fn check(
        &self,
        context: &NtfsLogNativeAnalysisContext,
        r: &Resources,
    ) -> Result<()> {
        self.check_bytes(context.source.as_ref(), context.source_len, r)
    }
    fn check_bytes(&self, source: &dyn ReadAt, source_len: u64, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.work()?;
        let initial = source.len();
        r.cancellation.check()?;
        if initial != source_len {
            return Err(stale());
        }
        repeat_capture(&self.capture, source, r)?;
        let final_length = source.len();
        r.cancellation.check()?;
        if final_length != source_len {
            return Err(stale());
        }
        Ok(())
    }
}
struct CapturingSource {
    source: Arc<dyn ReadAt>,
    resources: Resources,
    capture: Mutex<Option<Capture>>,
}
impl ReadAt for CapturingSource {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
        let mut state = self.capture.lock().map_err(|_| {
            crate::io::Error::other(invalid("native context capture lock poisoned"))
        })?;
        let Some(capture) = state.as_mut() else {
            self.resources
                .cancellation
                .check()
                .map_err(crate::io::Error::other)?;
            self.source.read_exact_at(offset, out)?;
            self.resources
                .cancellation
                .check()
                .map_err(crate::io::Error::other)?;
            return Ok(());
        };
        let attempt = (|| -> Result<()> {
            capture.resources.cancellation.check()?;
            let bytes = capture
                .bytes
                .checked_add(out.len())
                .filter(|n| *n <= capture.limits.bytes)
                .ok_or_else(|| exhausted("NTFS native physical capture bytes"))?;
            let charge = out
                .len()
                .checked_mul(3)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| capture.work.checked_add(n))
                .filter(|n| *n <= capture.limits.work)
                .ok_or_else(|| exhausted("NTFS native physical capture work"))?;
            if capture.guards.len() >= capture.limits.reads {
                return Err(exhausted("NTFS native physical capture reads"));
            }
            offset
                .checked_add(out.len() as u64)
                .filter(|end| *end <= self.source.len())
                .ok_or_else(|| invalid("NTFS native physical capture range"))?;
            capture.resources.cancellation.check()?;
            let lease = capture.resources.memory.reserve(out.len() as u64)?;
            let mut raw = Vec::new();
            raw.try_reserve_exact(out.len())
                .map_err(|_| exhausted("NTFS native physical capture allocation"))?;
            if raw.capacity() > out.len() {
                return Err(exhausted("NTFS native physical capture capacity"));
            }
            capture.resources.cancellation.check()?;
            self.source
                .read_exact_at(offset, out)
                .map_err(|e| Error::io("NTFS native physical capture", e))?;
            capture.resources.cancellation.check()?;
            raw.extend_from_slice(out);
            capture.guards.push(Guard {
                offset,
                bytes: raw,
                _lease: lease,
            });
            capture.bytes = bytes;
            capture.work = charge;
            Ok(())
        })();
        attempt.map_err(crate::io::Error::other)
    }
}
/// Source-owned volume geometry, record-2 stream and exact consumed metadata.
///
/// Every successful physical read consumed during native opening and logfile
/// resolution is retained at its original source offset. This includes actual
/// boot, MFT bootstrap/extension, attribute-list and volume-info observations.
/// Repeated overlapping reads remain separate, so inconsistent ephemeral source
/// observations cannot silently become one reconstructed metadata view.
/// The caller must keep source contents immutable throughout this read-only use.
/// This context supplies no recovery or mutation authority.
pub struct NtfsLogNativeAnalysisContext {
    source: Arc<dyn ReadAt>,
    source_len: u64,
    volume: NtfsVolume,
    streams: NtfsStreamLimits,
    owner: crate::fs_core::ObjectId,
    logfile: Arc<dyn ReadAt>,
    capture: Capture,
    recorder: Arc<CapturingSource>,
}
impl NtfsLogNativeAnalysisContext {
    /// Geometry decoded from the exact retained native volume observations.
    pub fn geometry(&self) -> &NtfsGeometry {
        self.volume.geometry()
    }
    /// Source-owned native record-2 owner, never a caller-supplied identity.
    pub fn owner(&self) -> &crate::fs_core::ObjectId {
        &self.owner
    }
    /// Exact ordinary initialized native logfile stream selected from record 2.
    pub fn logfile_source(&self) -> Arc<dyn ReadAt> {
        self.logfile.clone()
    }
    /// Exact observed volume flags without clearing dirty/recovery state.
    pub fn volume_flags(&self) -> u16 {
        self.volume.audit_flags()
    }
    /// Count of retained actual physical metadata observations.
    pub fn source_observations(&self) -> usize {
        self.capture.guards.len()
    }
    /// This context alone does not qualify a complete active window.
    pub fn active_window_complete(&self) -> bool {
        false
    }
    /// This context alone does not qualify recovery.
    pub fn recovery_complete(&self) -> bool {
        false
    }
    pub(crate) fn native_mft_map(&self) -> (&[crate::fs_file::FileExtent], u64) {
        self.volume.native_mft_map()
    }
    // Source decoding limits are retained from native context construction.
    pub(crate) fn native_stream_limits(&self) -> NtfsStreamLimits {
        self.streams
    }
    pub(crate) fn native_mirror_physical(&self) -> Result<(u64, u64)> {
        let cluster = self.geometry().cluster_bytes();
        let primary = self
            .geometry()
            .mft_cluster()
            .checked_mul(cluster)
            .ok_or_else(|| invalid("NTFS native primary MFT physical overflow"))?;
        let mirror = self
            .volume
            .audit_mirror_cluster()
            .checked_mul(cluster)
            .ok_or_else(|| invalid("NTFS native MFTMirr physical overflow"))?;
        Ok((primary, mirror))
    }
    // Retains the physical provenance consumed by a source-owned exact log query.
    pub(crate) fn capture_native_reads<T>(
        &self,
        limits: NtfsLogNativeContextLimits,
        r: &Resources,
        query: impl FnOnce() -> Result<T>,
    ) -> Result<(Result<T>, NativeReadCapture)> {
        r.cancellation.check()?;
        let inventory = limits
            .reads
            .checked_mul(core::mem::size_of::<Guard>())
            .ok_or_else(|| exhausted("NTFS scoped native guard storage"))?;
        let lease = r.memory.reserve(inventory as u64)?;
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(limits.reads)
            .map_err(|_| exhausted("NTFS scoped native guard allocation"))?;
        if guards.capacity() > limits.reads {
            return Err(exhausted("NTFS scoped native guard capacity"));
        }
        {
            let mut state = self
                .recorder
                .capture
                .lock()
                .map_err(|_| invalid("NTFS scoped native capture poisoned"))?;
            if state.is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "NTFS scoped native capture already active",
                ));
            }
            *state = Some(Capture {
                resources: r.clone(),
                guards,
                bytes: 0,
                work: 0,
                limits,
                _lease: lease,
            });
        }
        let result = query();
        let capture = self
            .recorder
            .capture
            .lock()
            .map_err(|_| invalid("NTFS scoped native capture poisoned"))?
            .take()
            .ok_or_else(|| invalid("NTFS scoped native capture vanished"))?;
        Ok((result, NativeReadCapture { capture }))
    }
    // Callers prepay their combined bytes/read work and retain exact raw guards.
    // Geometry and source identity remain sealed in this context, never supplied.
    pub(crate) fn read_native_physical(
        &self,
        offset: u64,
        raw: &mut [u8],
        r: &Resources,
    ) -> Result<()> {
        self.read_native_physical_observed(offset, raw, r, &mut false)
    }
    // Records successful full raw I/O before post-read length/cancellation decisions.
    pub(crate) fn read_native_physical_observed(
        &self,
        offset: u64,
        raw: &mut [u8],
        r: &Resources,
        read_complete: &mut bool,
    ) -> Result<()> {
        *read_complete = false;
        r.cancellation.check()?;
        let length = self.source.len();
        r.cancellation.check()?;
        if length != self.source_len {
            return Err(stale());
        }
        offset
            .checked_add(raw.len() as u64)
            .filter(|end| *end <= self.geometry().volume_bytes() && *end <= length)
            .ok_or_else(|| invalid("NTFS native physical effect range"))?;
        self.source
            .read_exact_at(offset, raw)
            .map_err(|e| Error::io("NTFS native physical effect read", e))?;
        *read_complete = true;
        r.cancellation.check()?;
        let final_length = self.source.len();
        r.cancellation.check()?;
        if final_length != self.source_len {
            return Err(stale());
        }
        Ok(())
    }
    pub(crate) fn source_guard_work(&self) -> Result<usize> {
        self.capture
            .bytes
            .checked_mul(3)
            .and_then(|n| n.checked_add(self.capture.guards.len()))
            .ok_or_else(|| exhausted("NTFS native combined physical guard work"))
    }
    /// Compare every consumed physical observation against the original source.
    ///
    /// Each call has an independent finite work ceiling and leased scratch;
    /// downstream analysis must additionally account calls in its combined work.
    pub fn check_source(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.volume.audit_check_source(r)?;
        if self.source.len() != self.source_len {
            return Err(stale());
        }
        repeat_capture(&self.capture, self.source.as_ref(), r)?;
        r.cancellation.check()?;
        let final_len = self.source.len();
        r.cancellation.check()?;
        if final_len != self.source_len {
            return Err(stale());
        }
        Ok(())
    }
}
fn repeat_capture(capture: &Capture, source: &dyn ReadAt, r: &Resources) -> Result<()> {
    let required = capture
        .bytes
        .checked_mul(3)
        .and_then(|n| n.checked_add(capture.guards.len()))
        .filter(|n| *n <= capture.limits.work)
        .ok_or_else(|| exhausted("NTFS native physical repeat work"))?;
    let _ = required;
    for guard in &capture.guards {
        r.cancellation.check()?;
        let _scratch = r.memory.reserve(guard.bytes.len() as u64)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(guard.bytes.len())
            .map_err(|_| exhausted("NTFS native physical repeat allocation"))?;
        if raw.capacity() > guard.bytes.len() {
            return Err(exhausted("NTFS native physical repeat capacity"));
        }
        raw.resize(guard.bytes.len(), 0);
        source
            .read_exact_at(guard.offset, &mut raw)
            .map_err(|e| Error::io("NTFS native physical repeat", e))?;
        r.cancellation.check()?;
        if raw != guard.bytes {
            return Err(stale());
        }
    }
    Ok(())
}
fn stale() -> Error {
    Error::new(
        ErrorKind::StalePlan,
        "NTFS consumed native metadata changed",
    )
}
/// Capture the actual native reads that establish volume geometry and record 2.
///
/// Native parser and stream-resolution limits apply independently of physical
/// capture limits. No caller geometry or preselected object supplies authority.
pub fn inspect_ntfs_log_native_analysis_context(
    source: Arc<dyn ReadAt>,
    read_limits: NtfsReadLimits,
    stream_limits: NtfsStreamLimits,
    limits: NtfsLogNativeContextLimits,
    r: &Resources,
) -> Result<NtfsLogNativeAnalysisContext> {
    r.cancellation.check()?;
    let count_bytes = limits
        .reads
        .checked_mul(core::mem::size_of::<Guard>())
        .ok_or_else(|| exhausted("NTFS native physical guard vector"))?;
    let lease = r.memory.reserve(count_bytes as u64)?;
    let mut guards = Vec::new();
    guards
        .try_reserve_exact(limits.reads)
        .map_err(|_| exhausted("NTFS native physical guard allocation"))?;
    if guards.capacity() > limits.reads {
        return Err(exhausted("NTFS native physical guard capacity"));
    }
    let source_len = source.len();
    let recorded = Arc::new(CapturingSource {
        source: source.clone(),
        resources: r.clone(),
        capture: Mutex::new(Some(Capture {
            resources: r.clone(),
            guards,
            bytes: 0,
            work: 0,
            limits,
            _lease: lease,
        })),
    });
    let (volume, owner, file) =
        select_native_logfile(recorded.clone(), read_limits, stream_limits, r)?;
    r.cancellation.check()?;
    let capture = recorded
        .capture
        .lock()
        .map_err(|_| invalid("NTFS native physical capture lock"))?
        .take()
        .ok_or_else(|| invalid("NTFS native physical capture already sealed"))?;
    let context = NtfsLogNativeAnalysisContext {
        source,
        source_len,
        volume,
        streams: stream_limits,
        owner,
        logfile: Arc::new(NativeLogFile {
            file,
            resources: r.clone(),
        }),
        capture,
        recorder: recorded,
    };
    context.check_source(r)?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    use crate::platform::sync::atomic::{AtomicUsize, Ordering};
    struct ChangingSource {
        reads: AtomicUsize,
    }
    impl ReadAt for ChangingSource {
        fn len(&self) -> u64 {
            512
        }
        fn read_exact_at(&self, _offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
            let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            out.fill(read as u8);
            Ok(())
        }
    }
    fn recorder(
        source: Arc<ChangingSource>,
        r: &Resources,
        reads: usize,
        bytes: usize,
        work: usize,
    ) -> CapturingSource {
        let lease = r
            .memory
            .reserve((reads * core::mem::size_of::<Guard>()) as u64)
            .unwrap();
        let mut guards = Vec::new();
        guards.try_reserve_exact(reads).unwrap();
        assert!(guards.capacity() <= reads);
        CapturingSource {
            source,
            resources: r.clone(),
            capture: Mutex::new(Some(Capture {
                resources: r.clone(),
                guards,
                bytes: 0,
                work: 0,
                limits: NtfsLogNativeContextLimits { reads, bytes, work },
                _lease: lease,
            })),
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    #[test]
    fn overlapping_consumed_versions_are_both_retained_and_leased() {
        let r = resources();
        let source = Arc::new(ChangingSource {
            reads: AtomicUsize::new(0),
        });
        let recorded = recorder(source, &r, 2, 16, 50);
        let before = r.memory.used();
        let mut bytes = [0; 8];
        recorded.read_exact_at(32, &mut bytes).unwrap();
        recorded.read_exact_at(32, &mut bytes).unwrap();
        let state = recorded.capture.lock().unwrap();
        let capture = state.as_ref().unwrap();
        assert_eq!(capture.guards.len(), 2);
        assert_eq!(capture.guards[0].offset, capture.guards[1].offset);
        assert_eq!(capture.guards[0].bytes, [1; 8]);
        assert_eq!(capture.guards[1].bytes, [2; 8]);
        assert_eq!(r.memory.used(), before + 16);
        drop(state);
        drop(recorded);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn finite_capture_refuses_before_unretained_physical_read() {
        for (reads, bytes, work) in [(0, 8, 25), (1, 7, 25), (1, 8, 24)] {
            let r = resources();
            let source = Arc::new(ChangingSource {
                reads: AtomicUsize::new(0),
            });
            let recorded = recorder(source.clone(), &r, reads, bytes, work);
            assert!(recorded.read_exact_at(0, &mut [0; 8]).is_err());
            assert_eq!(source.reads.load(Ordering::SeqCst), 0);
            drop(recorded);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn cancellation_refuses_before_source_observation() {
        let r = resources();
        let source = Arc::new(ChangingSource {
            reads: AtomicUsize::new(0),
        });
        let recorded = recorder(source.clone(), &r, 1, 8, 25);
        r.cancellation.cancel();
        assert!(recorded.read_exact_at(0, &mut [0; 8]).is_err());
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        drop(recorded);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn repeat_work_accounts_zeroing_before_any_repeat_read() {
        let r = resources();
        let source = Arc::new(ChangingSource {
            reads: AtomicUsize::new(0),
        });
        let recorded = recorder(source.clone(), &r, 1, 8, 25);
        recorded.read_exact_at(0, &mut [0; 8]).unwrap();
        let mut capture = recorded.capture.lock().unwrap().take().unwrap();
        capture.limits.work = 24; // 8 zeroed + 8 read + 8 compared + one observation.
        assert_eq!(
            repeat_capture(&capture, source.as_ref(), &r)
                .unwrap_err()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(source.reads.load(Ordering::SeqCst), 1);
        capture.limits.work = 25;
        assert_eq!(
            repeat_capture(&capture, source.as_ref(), &r)
                .unwrap_err()
                .kind,
            ErrorKind::StalePlan
        );
        assert_eq!(source.reads.load(Ordering::SeqCst), 2);
        drop(capture);
        drop(recorded);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn scoped_read_guard_checks_late_same_length_cancel_and_length_drift() {
        struct LengthCallback {
            calls: AtomicUsize,
            cancellation: crate::fs_core::Cancellation,
            cancel: bool,
        }
        impl ReadAt for LengthCallback {
            fn len(&self) -> u64 {
                let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                if call == 2 && self.cancel {
                    self.cancellation.cancel();
                }
                if call == 2 && !self.cancel { 513 } else { 512 }
            }
            fn read_exact_at(&self, _offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
                out.fill(0);
                Ok(())
            }
        }
        for cancel in [true, false] {
            let r = resources();
            let source = LengthCallback {
                calls: AtomicUsize::new(0),
                cancellation: r.cancellation.clone(),
                cancel,
            };
            let lease = r
                .memory
                .reserve(core::mem::size_of::<Guard>() as u64)
                .unwrap();
            let rawlease = r.memory.reserve(8).unwrap();
            let mut capture = NativeReadCapture {
                capture: Capture {
                    resources: r.clone(),
                    guards: vec![Guard {
                        offset: 0,
                        bytes: vec![0; 8],
                        _lease: rawlease,
                    }],
                    bytes: 8,
                    work: 25,
                    limits: NtfsLogNativeContextLimits {
                        reads: 1,
                        bytes: 8,
                        work: 27,
                    },
                    _lease: lease,
                },
            };
            capture.capture.limits.work = 26;
            assert_eq!(
                capture.check_bytes(&source, 512, &r).unwrap_err().kind,
                ErrorKind::BudgetExhausted
            );
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            capture.capture.limits.work = 27;
            assert_eq!(capture.work().unwrap(), 27);
            let error = capture.check_bytes(&source, 512, &r).unwrap_err();
            assert_eq!(
                error.kind,
                if cancel {
                    ErrorKind::Cancelled
                } else {
                    ErrorKind::StalePlan
                }
            );
            assert_eq!(source.calls.load(Ordering::SeqCst), 2);
            drop(capture);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
