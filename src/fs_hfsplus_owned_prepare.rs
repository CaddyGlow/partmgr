//! Same-owner metadata preparation for future recoverable HFS+ operations.
//! Mutable storage is never exposed as an immutable ReadAt source.
use crate::{
    fs_core::*,
    fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume, bad, budget, vector},
    fs_hfsplus_audit::{HfsPlusAuditLimits, HfsPlusAuditReport, audit_hfsplus},
    storage::{Storage, WriteRange},
};
use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
const PAGE: usize = 512;
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) pages: usize,
    pub(crate) attempts: usize,
    pub(crate) work: u64,
    pub(crate) range_bytes: u64,
    pub(crate) read: HfsPlusReadLimits,
    pub(crate) audit: HfsPlusAuditLimits,
}
#[derive(Debug)]
struct MissingPage(u64);
impl fmt::Display for MissingPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uncopied HFS+ metadata page {}", self.0)
    }
}
impl std::error::Error for MissingPage {}
struct Work {
    used: AtomicU64,
    ceiling: u64,
    resources: Resources,
}
impl Work {
    fn charge(&self, bytes: u64) -> Result<()> {
        self.resources.cancellation.check()?;
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes).filter(|n| *n <= self.ceiling)
            })
            .map_err(|_| budget("HFS+ owned metadata work ceiling"))?;
        Ok(())
    }
}
struct Snapshot {
    length: u64,
    pages: Vec<(u64, Arc<[u8; PAGE]>)>,
    work: Arc<Work>,
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
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut done = 0;
        while done < out.len() {
            let position = at + done as u64;
            let page = position / PAGE as u64;
            let index = self
                .pages
                .binary_search_by_key(&page, |entry| entry.0)
                .map_err(|_| io::Error::other(MissingPage(page)))?;
            let within = (position % PAGE as u64) as usize;
            let count = (PAGE - within).min(out.len() - done);
            out[done..done + count].copy_from_slice(&self.pages[index].1[within..within + count]);
            done += count;
        }
        Ok(())
    }
}
pub(crate) struct Prepared<S: Storage> {
    target: S,
    snapshot: Arc<Snapshot>,
    volume: HfsPlusVolume,
    proof: HfsPlusAuditReport,
    range_bytes: u64,
    limits: Limits,
    generation: u64,
    uncertain: bool,
}
pub(crate) struct RangePlan {
    source: u128,
    generation: u64,
    patches: Vec<WriteRange>,
    _lease: Reservation,
}
impl<S: Storage> Prepared<S> {
    pub(crate) fn needs_recovery(&self) -> bool {
        self.uncertain
    }
    pub(crate) fn into_storage(self) -> S {
        self.target
    }
    pub(crate) fn open(target: S, limits: Limits, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        let length = target
            .len()
            .map_err(|e| Error::io("HFS+ owned length", e))?;
        if length < 4096 || !length.is_multiple_of(PAGE as u64) {
            return Err(bad("HFS+ owned bare volume geometry"));
        }
        if limits.pages == 0 || limits.attempts == 0 {
            return Err(budget("HFS+ zero owned snapshot ceilings"));
        }
        let charge = (limits.pages as u64)
            .checked_mul(PAGE as u64 + 128)
            .ok_or_else(|| budget("HFS+ owned snapshot reservation overflow"))?;
        let lease = Arc::new(r.memory.reserve(charge)?);
        let work = Arc::new(Work {
            used: AtomicU64::new(0),
            ceiling: limits.work,
            resources: r.clone(),
        });
        let decoder_charge = limits
            .read
            .work
            .checked_add(limits.audit.work)
            .ok_or_else(|| budget("HFS+ owned decoder work overflow"))?;
        work.charge(decoder_charge)?;
        let discovery_work = work.clone();
        let resources = r.clone();
        let pages = crate::fs_discovery::discover::<PAGE>(
            &target,
            length,
            vector(limits.pages)?,
            (limits.pages, limits.attempts),
            r,
            Arc::new(move |bytes| discovery_work.charge(bytes)),
            move |source| {
                let volume = HfsPlusVolume::open(source, limits.read, &resources)?;
                if volume.geometry().volume_bytes() != length {
                    return Err(bad("HFS+ owned source contains undeclared tail"));
                }
                let proof = audit_hfsplus(&volume, limits.audit, &resources)?;
                if !proof.is_complete() || !proof.is_clean() {
                    return Err(bad("HFS+ owned preparation requires complete clean proof"));
                }
                Ok(())
            },
        )?;
        // Only immutable copied pages escape discovery. Decode them once to bind
        // retained file maps to the sealed snapshot, then compare with the owner.
        work.charge(decoder_charge)?;
        let snapshot = Arc::new(Snapshot {
            length,
            pages,
            work,
            _lease: lease,
        });
        let volume = HfsPlusVolume::open(snapshot.clone(), limits.read, r)?;
        let proof = audit_hfsplus(&volume, limits.audit, r)?;
        if !proof.is_complete() || !proof.is_clean() {
            return Err(bad("HFS+ sealed preparation requires complete clean proof"));
        }
        let prepared = Self {
            target,
            snapshot,
            volume,
            proof,
            range_bytes: limits.range_bytes,
            limits,
            generation: 0,
            uncertain: false,
        };
        prepared.revalidate(r)?;
        Ok(prepared)
    }

    fn revalidate(&self, r: &Resources) -> Result<()> {
        if self
            .target
            .len()
            .map_err(|e| Error::io("HFS+ owned revalidation length", e))?
            != self.snapshot.length
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "HFS+ owned length changed",
            ));
        }
        let mut actual = [0; PAGE];
        for (page, expected) in &self.snapshot.pages {
            r.cancellation.check()?;
            self.snapshot.work.charge(PAGE as u64)?;
            self.target
                .read_exact_at(page * PAGE as u64, &mut actual)
                .map_err(|e| Error::io("HFS+ owned metadata revalidation", e))?;
            if actual != **expected {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "HFS+ owned metadata changed",
                ));
            }
        }
        Ok(())
    }
    // No write authority: these exact existing-fork patches will be consumed only
    // by a dirty-fenced, same-owner recovery transaction.
    pub(crate) fn plan_range(
        &self,
        path: &[NativeName],
        kind: &StreamKind,
        offset: u64,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<RangePlan> {
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "HFS+ owned session requires recovery",
            ));
        }
        if bytes.is_empty() || bytes.len() as u64 > self.range_bytes {
            return Err(budget("HFS+ owned replacement byte ceiling"));
        }
        self.revalidate(r)?;
        let id = self.volume.lookup(path, r)?;
        self.volume.verify_catalog_record(&id, r)?;
        let fork = self.volume.open_fork(&id, kind, r)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= fork.len())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    "HFS+ replacement exceeds existing fork EOF",
                )
            })?;
        let extents = fork.file.extents();
        let charge = (bytes.len() as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add((extents.len() as u64).checked_mul(128)?))
            .ok_or_else(|| budget("HFS+ range reservation overflow"))?;
        let lease = r.memory.reserve(charge)?;
        let mut patches = vector(extents.len())?;
        let mut mapped = 0;
        for extent in extents {
            r.cancellation.check()?;
            let first = offset.max(extent.offset);
            let last = end.min(extent.offset + extent.length);
            if first >= last {
                continue;
            }
            let crate::fs_file::ExtentKind::Data(physical) = extent.kind else {
                return Err(bad("HFS+ owned replacement requires allocated data"));
            };
            let at = physical
                .checked_add(first - extent.offset)
                .ok_or_else(|| bad("HFS+ owned physical replacement overflow"))?;
            let count = usize::try_from(last - first).map_err(|_| budget("HFS+ range length"))?;
            let mut before = vector(count)?;
            before.resize(count, 0);
            self.snapshot.work.charge(count as u64)?;
            self.target
                .read_exact_at(at, &mut before)
                .map_err(|e| Error::io("HFS+ owned range preimage", e))?;
            let mut after = vector(count)?;
            let start = (first - offset) as usize;
            after.extend_from_slice(&bytes[start..start + count]);
            patches.push(
                WriteRange::new(at, before, after)
                    .map_err(|e| Error::io("HFS+ owned range patch", e))?,
            );
            mapped += count;
        }
        if mapped != bytes.len() {
            return Err(bad("HFS+ owned range incomplete mapping"));
        }
        self.revalidate(r)?;
        Ok(RangePlan {
            source: self.volume.root_identity().source,
            generation: self.generation,
            patches,
            _lease: lease,
        })
    }
}
#[path = "fs_hfsplus_owned_transaction.rs"]
pub(crate) mod transaction;

#[test]
fn same_owner_complete_metadata_snapshot_no_payload_prefetch_and_refunds() {
    use super::independent as fixture;
    struct Owned {
        bytes: Vec<u8>,
        reads: std::sync::Mutex<Vec<(u64, usize)>>,
        fail_io: bool,
    }
    impl Storage for Owned {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.reads.lock().unwrap().push((at, out.len()));
            if self.fail_io {
                return Err(io::Error::from_raw_os_error(5));
            }
            let at = at as usize;
            out.copy_from_slice(
                self.bytes
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("preparation grants no writes")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("preparation grants no barriers")
        }
    }
    let limits = Limits {
        pages: 256,
        attempts: 257,
        // Two decoder passes plus actual bytes fit; per-page decoder restarts do not.
        work: 5 << 20,
        range_bytes: 1 << 16,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    for binary in [false, true] {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let target = Owned {
            bytes: fixture::hfsplus_seed(binary),
            reads: std::sync::Mutex::new(Vec::new()),
            fail_io: false,
        };
        let mut prepared = Prepared::open(target, limits, &r).unwrap();
        assert!(prepared.proof.is_complete() && prepared.proof.is_clean());
        let id = prepared
            .volume
            .lookup(&[NativeName::Utf16(fixture::native_name(binary))], &r)
            .unwrap();
        let fork = prepared
            .volume
            .open_fork(&id, &StreamKind::Data, &r)
            .unwrap();
        assert_eq!(fork.len(), 9 * 4096 - 7);
        assert!(
            prepared
                .target
                .reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, len)| { *len == PAGE && !((12 * 4096)..(35 * 4096)).contains(at) })
        );
        let path = [NativeName::Utf16(fixture::native_name(binary))];
        prepared.target.reads.lock().unwrap().clear();
        let replacement = [0x5a; 31];
        let plan = prepared
            .plan_range(&path, &StreamKind::Data, 8 * 4096 - 8, &replacement, &r)
            .unwrap();
        assert_eq!(plan.patches.len(), 2);
        assert_eq!(
            (plan.patches[0].offset(), plan.patches[1].offset()),
            (26 * 4096 + 4088, 28 * 4096)
        );
        let before: Vec<_> = plan
            .patches
            .iter()
            .flat_map(|p| p.expected().iter().copied())
            .collect();
        let expected: Vec<_> = (8 * 4096 - 8..8 * 4096 + 23)
            .map(|i| (i * 17 % 251) as u8)
            .collect();
        assert_eq!(before, expected);
        assert_eq!(
            plan.patches
                .iter()
                .flat_map(|p| p.replacement().iter().copied())
                .collect::<Vec<_>>(),
            replacement
        );
        let payload_reads: Vec<_> = prepared
            .target
            .reads
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|(at, _)| ((12 * 4096)..(35 * 4096)).contains(at))
            .collect();
        assert_eq!(payload_reads, vec![(26 * 4096 + 4088, 8), (28 * 4096, 23)]);
        drop(plan);
        let resource = prepared
            .plan_range(&path, &StreamKind::ResourceFork, 1, b"abc", &r)
            .unwrap();
        assert_eq!(resource.patches[0].offset(), 32 * 4096 + 1);
        assert_eq!(resource.patches[0].expected(), b"SRC");
        drop(resource);
        assert!(
            prepared
                .plan_range(&path, &StreamKind::Data, fork.len() - 1, b"xx", &r)
                .is_err()
        );
        prepared.target.bytes[1024 + 68] ^= 1;
        assert!(matches!(prepared.revalidate(&r), Err(e) if e.kind == ErrorKind::StalePlan));
        drop((fork, prepared));
        assert_eq!(r.memory.used(), 0);
        let target = Owned {
            bytes: fixture::hfsplus_seed(binary),
            reads: std::sync::Mutex::new(Vec::new()),
            fail_io: false,
        };
        assert!(Prepared::open(target, Limits { pages: 1, ..limits }, &r).is_err());
        assert_eq!(r.memory.used(), 0);
        for failed_limits in [
            Limits {
                attempts: 1,
                ..limits
            },
            Limits { work: 0, ..limits },
        ] {
            let target = Owned {
                bytes: fixture::hfsplus_seed(binary),
                reads: std::sync::Mutex::new(Vec::new()),
                fail_io: false,
            };
            assert!(Prepared::open(target, failed_limits, &r).is_err());
            assert_eq!(r.memory.used(), 0);
        }
        let mut damaged = fixture::hfsplus_seed(binary);
        let bitmap_block = u32::from_be_bytes(damaged[1152..1156].try_into().unwrap()) as usize;
        let block_bytes = u32::from_be_bytes(damaged[1064..1068].try_into().unwrap()) as usize;
        let bitmap_byte = bitmap_block * block_bytes + 12 / 8;
        assert_ne!(damaged[bitmap_byte] & (0x80 >> (12 % 8)), 0);
        damaged[bitmap_byte] &= !(0x80 >> (12 % 8));
        let target = Owned {
            bytes: damaged,
            reads: std::sync::Mutex::new(Vec::new()),
            fail_io: false,
        };
        assert!(Prepared::open(target, limits, &r).is_err());
        assert_eq!(r.memory.used(), 0);
        let target = Owned {
            bytes: fixture::hfsplus_seed(binary),
            reads: std::sync::Mutex::new(Vec::new()),
            fail_io: true,
        };
        let error = match Prepared::open(target, limits, &r) {
            Ok(_) => panic!("I/O failure must be causal"),
            Err(e) => e,
        };
        assert_eq!(error.source.unwrap().raw_os_error(), Some(5));
        assert_eq!(r.memory.used(), 0);
        r.cancellation.cancel();
        let target = Owned {
            bytes: fixture::hfsplus_seed(binary),
            reads: std::sync::Mutex::new(Vec::new()),
            fail_io: false,
        };
        assert!(Prepared::open(target, limits, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fs_hfsplus_owned_resize.rs"]
pub(crate) mod resize;

#[path = "fs_hfsplus_owned_namespace.rs"]
pub(crate) mod namespace;
