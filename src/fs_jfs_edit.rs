//! Staged exclusive native-journal editor bootstrap; no public mutation API yet.
use super::*;
use crate::{
    fs_jfs_audit::{JfsAuditLimits, audit_decoded},
    storage::Storage,
};

struct Borrowed<'a> {
    storage: &'a dyn Storage,
    length: u64,
    resources: &'a Resources,
}
impl DecodeRead for Borrowed<'_> {
    fn length(&self) -> Result<u64> {
        self.resources.cancellation.check()?;
        let length = self
            .storage
            .len()
            .map_err(|e| Error::io("JFS exclusive length", e))?;
        if length != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS exclusive geometry changed",
            ));
        }
        Ok(length)
    }
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let length = self.length()?;
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > length)
        {
            return Err(bad("JFS exclusive read bounds"));
        }
        self.storage
            .read_exact_at(at, out)
            .map_err(|e| Error::io("JFS exclusive metadata", e))?;
        self.length()?;
        Ok(())
    }
}
fn inspect(
    storage: &dyn Storage,
    limits: JfsReadLimits,
    audit: JfsAuditLimits,
    r: &Resources,
) -> Result<Decoded> {
    inspect_with(storage, limits, audit, r, r)
}
fn inspect_with(
    storage: &dyn Storage,
    limits: JfsReadLimits,
    audit: JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<Decoded> {
    let source = Borrowed {
        storage,
        length: storage
            .len()
            .map_err(|e| Error::io("JFS exclusive open", e))?,
        resources: original,
    };
    let decoded = decode(&source, limits, r)?;
    let proof = audit_decoded(&decoded, audit, r)?;
    if !proof.is_clean() {
        return Err(bad("JFS exclusive baseline not allocation/reference clean"));
    }
    source.length()?;
    Ok(decoded)
}

struct Overlay<'a> {
    source: Borrowed<'a>,
    patches: &'a [(u64, Vec<u8>)],
}
impl DecodeRead for Overlay<'_> {
    fn length(&self) -> Result<u64> {
        self.source.length()
    }
    fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
        self.source.exact(at, out)?;
        let end = at + out.len() as u64;
        for (start, bytes) in self.patches {
            let left = at.max(*start);
            let right = end.min(*start + bytes.len() as u64);
            if left < right {
                out[(left - at) as usize..(right - at) as usize]
                    .copy_from_slice(&bytes[(left - *start) as usize..(right - *start) as usize]);
            }
        }
        self.source.length()?;
        Ok(())
    }
}
struct NativeSession<'a> {
    storage: &'a mut dyn Storage,
    resources: Resources,
    read: JfsReadLimits,
    audit: JfsAuditLimits,
    uncertain: bool,
    binding: [u8; 16],
}
impl<'a> NativeSession<'a> {
    fn open(
        storage: &'a mut dyn Storage,
        read: JfsReadLimits,
        audit: JfsAuditLimits,
        r: &Resources,
    ) -> Result<Self> {
        let decoded = inspect(storage, read, audit, r)?;
        let mut binding = [0u8; 16];
        binding.copy_from_slice(&decoded.header[136..152]);
        drop(decoded);
        Ok(Self {
            storage,
            resources: r.clone(),
            read,
            audit,
            uncertain: false,
            binding,
        })
    }
    fn write_uid(&mut self, inode: u32, uid: u32, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::UncertainDurability,
                "JFS staged native session requires explicit recovery",
            ));
        }
        let prepared = journal::prepare_uid(
            self.storage,
            inode,
            uid,
            self.read,
            self.audit,
            &self.resources,
            r,
        )?;
        let result = journal::publish_uid(self.storage, prepared, &self.resources, r);
        if result
            .as_ref()
            .is_err_and(|error| error.kind == ErrorKind::UncertainDurability)
        {
            self.uncertain = true;
        }
        result
    }
    fn recover(&mut self, r: &Resources) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        journal::recover_uid(
            self.storage,
            self.binding,
            self.read,
            self.audit,
            &self.resources,
            r,
        )?;
        self.uncertain = false;
        Ok(())
    }
}

#[path = "../tests/fixtures/jfs_clean.rs"]
mod fixture;
#[test]
fn borrowed_storage_bootstrap_never_reads_payload_or_writes_and_refunds() {
    use std::cell::RefCell;
    struct Backend {
        bytes: Vec<u8>,
        reads: RefCell<Vec<(u64, usize)>>,
        writes: usize,
        fail: bool,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.reads.borrow_mut().push((at, out.len()));
            if self.fail {
                return Err(io::Error::other("independent exclusive failure"));
            }
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            Err(io::Error::other("must not write"))
        }
        fn flush(&mut self) -> io::Result<()> {
            self.writes += 1;
            Err(io::Error::other("must not flush"))
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: fixture::jfs_seed(),
        reads: RefCell::new(Vec::new()),
        writes: 0,
        fail: false,
    };
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    for inode in decoded.nodes.values().filter(|i| !i.directory) {
        for run in &inode.runs {
            let start = run.physical.start * 4096;
            let end = start + run.physical.count * 4096;
            assert!(
                !storage
                    .reads
                    .borrow()
                    .iter()
                    .any(|(at, n)| *at < end && start < *at + *n as u64)
            );
        }
    }
    drop(decoded);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(storage.writes, 0);
    let mut inserted = fixture::jfs_seed();
    let block_map = 16 * 4096;
    for block in [90usize, 91, 100, 102, 110, 112] {
        let word = block / 32;
        let bit = 0x80000000u32 >> (block % 32);
        for map in [2048, 3072] {
            let at = block_map + 4 * 4096 + map + word * 4;
            let value = le32(&inserted, at) & !bit;
            fixture::p32(&mut inserted, at, value);
        }
    }
    fixture::insert_native(&mut inserted);
    let expanded = Backend {
        bytes: inserted,
        reads: RefCell::new(Vec::new()),
        writes: 0,
        fail: false,
    };
    drop(inspect(&expanded, limits, audit, &r).unwrap());
    assert_eq!(expanded.writes, 0);
    assert_eq!(r.memory.used(), 0);
    storage.fail = true;
    assert!(inspect(&storage, limits, audit, &r).is_err());
    assert_eq!(r.memory.used(), 0);
    assert_eq!(storage.writes, 0);
    storage.fail = false;
    fixture::p32(&mut storage.bytes, 32768 + 40, 1);
    assert!(inspect(&storage, limits, audit, &r).is_err());
    assert_eq!(storage.writes, 0);
    assert_eq!(r.memory.used(), 0);
}
#[path = "fs_jfs_edit_allocation.rs"]
mod allocation;
#[path = "fs_jfs_edit_journal.rs"]
mod journal;

fn journal_seed() -> Vec<u8> {
    let mut b = fixture::jfs_seed();
    for at in [32768 + 136, 61440 + 136] {
        b[at..at + 16].fill(0xa5);
    }
    for page in 2usize..30 {
        let at = (482 + page) * 4096;
        let seq = if page == 2 { 27 } else { page as u32 - 3 };
        fixture::p32(&mut b, at, seq);
        fixture::p32(&mut b, at + 4088, seq);
        let end = if page == 2 { 44 } else { 8 };
        fixture::p16(&mut b, at + 6, end);
        fixture::p16(&mut b, at + 4094, end);
    }
    fixture::p16(&mut b, 484 * 4096 + 16, 0x4000);
    fixture::p32(&mut b, 483 * 4096 + 32, 2 * 4096 + 44);
    b
}

#[test]
fn staged_native_uid_lifecycle_preserves_all_other_inode_bytes_and_is_sticky_after_write_failure() {
    struct Backend {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
        fail: bool,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let n = if self.fail {
                16.min(bytes.len())
            } else {
                37.min(bytes.len())
            };
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if self.fail {
                return Err(io::Error::other("modeled partial native program"));
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: journal_seed(),
        writes: 0,
        flushes: 0,
        fail: false,
    };
    let before = storage.bytes.clone();
    let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
    session.write_uid(2, 777, &r).unwrap();
    assert!(!session.uncertain);
    drop(session);
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(le32(&decoded.nodes[&2].raw, 44), 777);
    drop(decoded);
    assert!(storage.writes > 0 && storage.flushes >= 8);
    assert_eq!(r.memory.used(), 0);
    for (at, (old, new)) in before.iter().zip(&storage.bytes).enumerate() {
        let allowed = [
            (32768 + 40, 4),
            (32768 + 68, 4),
            (61440 + 40, 4),
            (61440 + 68, 4),
            (483 * 4096, 4096),
            (484 * 4096, 4096),
            (29 * 4096 + 1024 + 44, 4),
        ]
        .iter()
        .any(|(start, n)| *start <= at && at < *start + *n);
        if !allowed {
            assert_eq!(old, new, "unexpected native mutation at {at}");
        }
    }
    let mut broken = Backend {
        bytes: journal_seed(),
        writes: 0,
        flushes: 0,
        fail: true,
    };
    let mut session = NativeSession::open(&mut broken, limits, audit, &r).unwrap();
    assert_eq!(
        session.write_uid(2, 777, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    assert!(session.uncertain);
    assert_eq!(
        session.write_uid(2, 888, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    drop(session);
    assert_eq!(broken.writes, 1);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn staged_native_committed_uid_recovery_validates_first_restarts_and_complete_does_not_write() {
    struct Backend {
        bytes: Vec<u8>,
        writes: usize,
        home_fail: bool,
        flushes: usize,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let n = 37.min(bytes.len());
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if self.home_fail && (29 * 4096 + 1024..29 * 4096 + 1152).contains(&(at as usize)) {
                return Err(io::Error::other("partial committed native home"));
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut storage = Backend {
        bytes: journal_seed(),
        writes: 0,
        home_fail: true,
        flushes: 0,
    };
    let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
    assert_eq!(
        session.write_uid(2, 777, &r).unwrap_err().kind,
        ErrorKind::UncertainDurability
    );
    assert!(session.uncertain);
    drop(session);
    let writes = storage.writes;
    let before = storage.bytes.clone();
    assert!(journal::recover_uid(&mut storage, [0xb6; 16], limits, audit, &r, &r).is_err());
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.bytes, before);
    for at in [
        32768 + 68,
        483 * 4096 + 68,
        484 * 4096 + 80,
        484 * 4096 + 228,
        484 * 4096 + 240,
    ] {
        let old = storage.bytes[at];
        storage.bytes[at] ^= 1;
        let malformed = storage.bytes.clone();
        assert!(journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).is_err());
        assert_eq!(storage.writes, writes);
        assert_eq!(storage.bytes, malformed);
        assert_eq!(r.memory.used(), 0);
        storage.bytes[at] = old;
    }
    assert_eq!(
        journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r)
            .unwrap_err()
            .kind,
        ErrorKind::UncertainDurability
    );
    assert_eq!(r.memory.used(), 0);
    storage.home_fail = false;
    journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    assert_eq!(le32(&decoded.nodes[&2].raw, 44), 777);
    drop(decoded);
    let writes = storage.writes;
    let completed = storage.bytes.clone();
    journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.bytes, completed);
    assert_eq!(r.memory.used(), 0);
    let end_at = 483 * 4096 + 32;
    let original_end = storage.bytes[end_at..end_at + 4].to_vec();
    storage.bytes[end_at..end_at + 4].copy_from_slice(&44u32.to_le_bytes());
    let malformed = storage.bytes.clone();
    assert!(journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).is_err());
    assert_eq!(storage.writes, writes);
    assert_eq!(storage.bytes, malformed);
    assert_eq!(r.memory.used(), 0);
    storage.bytes[end_at..end_at + 4].copy_from_slice(&original_end);
    for at in [484 * 4096, 484 * 4096 + 6, 485 * 4096 + 6] {
        let old = storage.bytes[at];
        storage.bytes[at] ^= 1;
        let malformed = storage.bytes.clone();
        assert!(journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).is_err());
        assert_eq!(storage.writes, writes);
        assert_eq!(storage.bytes, malformed);
        assert_eq!(r.memory.used(), 0);
        storage.bytes[at] = old;
    }
    let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
    session.recover(&r).unwrap();
    assert!(!session.uncertain);
    drop(session);
    assert_eq!(storage.writes, writes);
}

#[test]
fn staged_native_committed_barrier_restart_retains_or_discards_volatile_bytes() {
    #[derive(Clone)]
    struct Durable {
        bytes: Vec<u8>,
        durable: Vec<u8>,
        flushes: usize,
        fail: usize,
        writes: usize,
        fail_page: usize,
        page_writes: usize,
        stop_at: Option<u64>,
    }
    impl Storage for Durable {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            let mut n = 37.min(bytes.len());
            let interrupted = self
                .stop_at
                .is_some_and(|stop| at <= stop && stop < at + n as u64);
            if interrupted {
                n = (self.stop_at.unwrap() - at) as usize;
            }
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if interrupted {
                self.stop_at = None;
                return Err(io::Error::other("modeled partial native activation"));
            }
            if at == 484 * 4096 {
                self.page_writes += 1;
                if self.page_writes == self.fail_page {
                    return Err(io::Error::other("modeled ordered partial page"));
                }
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes == self.fail {
                return Err(io::Error::other("modeled native barrier interruption"));
            }
            self.durable.copy_from_slice(&self.bytes);
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    // Barrier 3 is the native COMMIT barrier. Dropping that unsuccessful
    // barrier leaves an uncommitted REDO; the current recovery profile aborts it.
    for cut in 3..=8 {
        for retain in [false, true] {
            let bytes = journal_seed();
            let mut storage = Durable {
                durable: bytes.clone(),
                bytes,
                flushes: 0,
                fail: cut,
                writes: 0,
                fail_page: usize::MAX,
                page_writes: 0,
                stop_at: None,
            };
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            assert_eq!(
                session.write_uid(2, 777, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            drop(session);
            if !retain {
                storage.bytes.copy_from_slice(&storage.durable);
            }
            // The selected bytes survived the modeled restart and form the
            // next boot's durable baseline; later cuts affect new writes.
            storage.durable.copy_from_slice(&storage.bytes);
            for recovery_retain in [false, true] {
                let mut retry = storage.clone();
                retry.fail = retry.flushes + 1;
                let outcome = journal::recover_uid(&mut retry, [0xa5; 16], limits, audit, &r, &r);
                // A fully clean surviving checkpoint needs no recovery writes.
                if let Err(error) = outcome {
                    assert_eq!(error.kind, ErrorKind::UncertainDurability);
                    if !recovery_retain {
                        retry.bytes.copy_from_slice(&retry.durable);
                    }
                }
                retry.fail = usize::MAX;
                journal::recover_uid(&mut retry, [0xa5; 16], limits, audit, &r, &r).unwrap();
                let decoded = inspect(&retry, limits, audit, &r).unwrap();
                assert_eq!(
                    le32(&decoded.nodes[&2].raw, 44),
                    if cut == 3 && !retain { 501 } else { 777 }
                );
                drop(decoded);
                let writes = retry.writes;
                journal::recover_uid(&mut retry, [0xa5; 16], limits, audit, &r, &r).unwrap();
                assert_eq!(retry.writes, writes);
                assert_eq!(r.memory.used(), 0);
            }
            storage.fail = usize::MAX;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            let decoded = inspect(&storage, limits, audit, &r).unwrap();
            let expected = if cut == 3 && !retain { 501 } else { 777 };
            assert_eq!(
                le32(&decoded.nodes[&2].raw, 44),
                expected,
                "cut={cut} retain={retain}"
            );
            drop(decoded);
            let writes = storage.writes;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            assert_eq!(storage.writes, writes);
            assert_eq!(r.memory.used(), 0);
        }
    }
    for cut in 1..=3 {
        for retain in [false, true] {
            let bytes = journal_seed();
            let mut storage = Durable {
                durable: bytes.clone(),
                bytes,
                flushes: 0,
                fail: usize::MAX,
                writes: 0,
                fail_page: cut,
                page_writes: 0,
                stop_at: None,
            };
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            assert_eq!(
                session.write_uid(2, 777, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            drop(session);
            if !retain {
                storage.bytes.copy_from_slice(&storage.durable);
            }
            storage.durable.copy_from_slice(&storage.bytes);
            storage.fail_page = usize::MAX;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            let decoded = inspect(&storage, limits, audit, &r).unwrap();
            assert_eq!(
                le32(&decoded.nodes[&2].raw, 44),
                if cut == 3 { 777 } else { 501 },
                "page cut={cut} retain={retain}"
            );
            drop(decoded);
            let writes = storage.writes;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            assert_eq!(storage.writes, writes);
            assert_eq!(r.memory.used(), 0);
        }
    }
    for stop_at in [32768 + 69, 61440 + 69, 483 * 4096 + 9, 483 * 4096 + 73] {
        for retain in [false, true] {
            let mut bytes = journal_seed();
            for at in [32768 + 68, 61440 + 68, 483 * 4096 + 8] {
                bytes[at..at + 4].copy_from_slice(&255u32.to_le_bytes());
            }
            let mut storage = Durable {
                durable: bytes.clone(),
                bytes,
                flushes: 0,
                fail: usize::MAX,
                writes: 0,
                fail_page: usize::MAX,
                page_writes: 0,
                stop_at: Some(stop_at as u64),
            };
            let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
            assert_eq!(
                session.write_uid(2, 777, &r).unwrap_err().kind,
                ErrorKind::UncertainDurability
            );
            drop(session);
            if !retain {
                storage.bytes.copy_from_slice(&storage.durable);
            }
            storage.durable.copy_from_slice(&storage.bytes);
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            let decoded = inspect(&storage, limits, audit, &r).unwrap();
            assert_eq!(
                le32(&decoded.nodes[&2].raw, 44),
                501,
                "activation cut={stop_at} retain={retain}"
            );
            drop(decoded);
            let writes = storage.writes;
            journal::recover_uid(&mut storage, [0xa5; 16], limits, audit, &r, &r).unwrap();
            assert_eq!(storage.writes, writes);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
#[ignore = "requires fresh PARTMGR_JFS_LIFECYCLE_EVIDENCE and JFS_TOOLS; staged UID operation only"]
fn native_owned_uid_publication_home_error_recovery_and_checker() {
    use crate::storage::FileStorage;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        process::{Command, Stdio},
    };
    fn hash(b: &[u8]) -> String {
        format!("{:x}", Sha256::digest(b))
    }
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_JFS_LIFECYCLE_EVIDENCE")
            .expect("fresh evidence directory required"),
    );
    assert!(root.is_dir());
    let receipt_path = root.join("receipt.txt");
    assert!(!receipt_path.exists());
    let tools =
        PathBuf::from(std::env::var_os("JFS_TOOLS").expect("native jfsutils tools required"));
    let sources = [
        ("src/fs_jfs.rs", include_bytes!("fs_jfs.rs").as_slice()),
        (
            "src/fs_jfs_audit.rs",
            include_bytes!("fs_jfs_audit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_tree.rs",
            include_bytes!("fs_jfs_tree.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit.rs",
            include_bytes!("fs_jfs_edit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_journal.rs",
            include_bytes!("fs_jfs_edit_journal.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_allocation.rs",
            include_bytes!("fs_jfs_edit_allocation.rs").as_slice(),
        ),
        ("src/fs_core.rs", include_bytes!("fs_core.rs").as_slice()),
        ("src/storage.rs", include_bytes!("storage.rs").as_slice()),
        (
            "src/fs_storage.rs",
            include_bytes!("fs_storage.rs").as_slice(),
        ),
        (
            "tests/fixtures/jfs_clean.rs",
            include_bytes!("../tests/fixtures/jfs_clean.rs").as_slice(),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ];
    let mut receipt = String::from(
        "status=running\nprofile=staged-native-UID-only; own inline redo lifecycle/recovery; full write family/public exports unfinished\nmodel=normal and one partial home/error plus recovery home/error restart; actual FileStorage sync_all; not physical power loss\n",
    );
    for (name, baked) in sources {
        assert_eq!(fs::read(name).unwrap(), baked);
        let dst = root.join("source").join(name);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::write(dst, baked).unwrap();
        receipt.push_str(&format!("source={name} sha256={}\n", hash(baked)));
    }
    let binary = std::env::current_exe().unwrap();
    let binary_hash = hash(&fs::read(&binary).unwrap());
    receipt.push_str(&format!(
        "binary={} sha256={binary_hash}\n",
        binary.display()
    ));
    let bindings = ["mkfs.jfs", "fsck.jfs", "jfs_debugfs"].map(|name| {
        let p = tools.join(name);
        let digest = hash(&fs::read(&p).unwrap());
        receipt.push_str(&format!("tool={} sha256={digest}\n", p.display()));
        (p, digest)
    });
    let run = |label: &str, name: &str, args: &[&str], input: Option<&str>| {
        let mut command = Command::new(tools.join(name));
        command
            .args(args)
            .current_dir(&root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        fs::write(root.join(format!("{label}.stdout")), &out.stdout).unwrap();
        fs::write(root.join(format!("{label}.stderr")), &out.stderr).unwrap();
        fs::write(
            root.join(format!("{label}.argv")),
            format!(
                "{} {args:?} stdin={input:?} exit={}\n",
                tools.join(name).display(),
                out.status
            ),
        )
        .unwrap();
        assert!(out.status.success(), "{label}: {:?}", out.stderr);
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .to_lowercase();
        assert!(
            !message.contains("logredo failed") && !message.contains("rc=-"),
            "{label}: {message}"
        );
        out
    };
    let original = root.join("source.img");
    fs::File::create(&original)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    run(
        "format",
        "mkfs.jfs",
        &["-q", original.to_str().unwrap()],
        None,
    );
    let mut source = fs::read(&original).unwrap();
    fixture::insert_native(&mut source);
    fs::write(&original, &source).unwrap();
    run(
        "source-check",
        "fsck.jfs",
        &["-n", original.to_str().unwrap()],
        None,
    );
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let storage = FileStorage::open(&original).unwrap();
    let decoded = inspect(&storage, limits, audit, &r).unwrap();
    let node = &decoded.nodes[&4];
    let home = pxd(&node.raw, 16, decoded.geometry.blocks).unwrap().start * 4096 + 4 * 512;
    let mut binding = [0u8; 16];
    binding.copy_from_slice(&decoded.header[136..152]);
    drop((decoded, storage));
    assert_eq!(r.memory.used(), 0);
    struct Backend {
        file: FileStorage,
        home: u64,
        fail: bool,
        writes: usize,
        stop_at: Option<u64>,
    }
    impl Storage for Backend {
        fn len(&self) -> io::Result<u64> {
            self.file.len()
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.file.read_exact_at(at, out)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail && at == self.home + 37 {
                self.fail = false;
                self.file.write_at(at, &bytes[..9.min(bytes.len())])?;
                return Err(io::Error::other("modeled partial UID word"));
            }
            let mut n = 37.min(bytes.len());
            if self
                .stop_at
                .is_some_and(|stop| at <= stop && stop < at + n as u64)
            {
                n = (self.stop_at.unwrap() - at) as usize;
                if n > 0 {
                    self.file.write_at(at, &bytes[..n])?;
                }
                self.stop_at = None;
                return Err(io::Error::other("modeled native activation prefix"));
            }
            self.file.write_at(at, &bytes[..n])
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    let mut normal_hash = None;
    for (label, cut, recovery_cut) in [
        ("normal", false, false),
        ("home-error", true, false),
        ("recovery-error", true, true),
    ] {
        let image = root.join(format!("{label}.img"));
        fs::copy(&original, &image).unwrap();
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: cut,
            writes: 0,
            stop_at: None,
        };
        let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
        let result = session.write_uid(4, 0x12345678, &r);
        if cut {
            assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
        } else {
            result.unwrap();
        }
        drop(session);
        drop(storage);
        if cut {
            let native = root.join(format!("{label}-native-replay.img"));
            fs::copy(&image, &native).unwrap();
            let replay = run(
                &format!("{label}-native-replay"),
                "fsck.jfs",
                &["--replay_journal_only", native.to_str().unwrap()],
                None,
            );
            assert!(String::from_utf8_lossy(&replay.stdout).contains("Filesystem is clean"));
            let oracle = FileStorage::open(&native).unwrap();
            let native_index = inspect(&oracle, limits, audit, &r).unwrap();
            assert_eq!(le32(&native_index.nodes[&4].raw, 44), 0x12345678);
            drop((native_index, oracle));
            assert_eq!(r.memory.used(), 0);
        }
        if cut {
            let mut storage = Backend {
                file: FileStorage::open(&image).unwrap(),
                home,
                fail: recovery_cut,
                writes: 0,
                stop_at: None,
            };
            let result = journal::recover_uid(&mut storage, binding, limits, audit, &r, &r);
            if recovery_cut {
                assert_eq!(result.unwrap_err().kind, ErrorKind::UncertainDurability);
            } else {
                result.unwrap();
            }
            drop(storage);
            if recovery_cut {
                let mut storage = Backend {
                    file: FileStorage::open(&image).unwrap(),
                    home,
                    fail: false,
                    writes: 0,
                    stop_at: None,
                };
                journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
                drop(storage);
            }
        }
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: None,
        };
        journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
        assert_eq!(storage.writes, 0);
        let decoded = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(le32(&decoded.nodes[&4].raw, 44), 0x12345678);
        assert_eq!(le32(&decoded.nodes[&4].raw, 40), 2);
        drop((decoded, storage));
        assert_eq!(r.memory.used(), 0);
        let after = fs::read(&image).unwrap();
        let log_start = u64::from(le32(&source[32768..36864], 76));
        for (at, (before, now)) in source.iter().zip(&after).enumerate() {
            let at = at as u64;
            let allowed = [
                (32768 + 40, 4),
                (32768 + 68, 4),
                (61440 + 40, 4),
                (61440 + 68, 4),
                ((log_start + 1) * 4096, 4096),
                ((log_start + 2) * 4096, 4096),
                (home + 44, 4),
            ]
            .iter()
            .any(|(start, n)| *start <= at && at < *start + *n);
            if !allowed {
                assert_eq!(before, now, "native outside-byte mutation at {at}");
            }
        }
        let digest = hash(&after);
        if let Some(expected) = &normal_hash {
            assert_eq!(&digest, expected);
        } else {
            normal_hash = Some(digest.clone());
        }
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let debug = run(
            &format!("{label}-debug"),
            "jfs_debugfs",
            &[image.to_str().unwrap()],
            Some("inode 4\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&debug.stdout).contains("305419896"));
        assert_eq!(hash(&fs::read(&image).unwrap()), digest);
        receipt.push_str(&format!("case={label} source_sha256={} output_sha256={digest} uid=305419896 hardlinks=2 own_completed_recovery_writes=0 native_fsck=clean native_debugger_uid=exact outside_fields_payload_allocation_bytes=unchanged native_interrupted_copy_replay=checked-for-error-cases\n",hash(&source)));
    }
    let log_start = u64::from(le32(&source[32768..36864], 76));
    let old_uid = le32(&source, home as usize + 44);
    for (label, stop) in [
        ("bootstrap-primary-serial", 32768 + 69),
        ("bootstrap-log-activation", (log_start + 1) * 4096 + 73),
    ] {
        let image = root.join(format!("{label}.img"));
        fs::copy(&original, &image).unwrap();
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: Some(stop),
        };
        let mut session = NativeSession::open(&mut storage, limits, audit, &r).unwrap();
        assert_eq!(
            session.write_uid(4, 0x12345678, &r).unwrap_err().kind,
            ErrorKind::UncertainDurability
        );
        drop(session);
        drop(storage);
        let mut storage = Backend {
            file: FileStorage::open(&image).unwrap(),
            home,
            fail: false,
            writes: 0,
            stop_at: None,
        };
        journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
        let writes = storage.writes;
        journal::recover_uid(&mut storage, binding, limits, audit, &r, &r).unwrap();
        assert_eq!(storage.writes, writes);
        let decoded = inspect(&storage, limits, audit, &r).unwrap();
        assert_eq!(le32(&decoded.nodes[&4].raw, 44), old_uid);
        assert_eq!(le32(&decoded.nodes[&4].raw, 40), 2);
        drop((decoded, storage));
        assert_eq!(r.memory.used(), 0);
        let after = fs::read(&image).unwrap();
        for (at, (before, now)) in source.iter().zip(&after).enumerate() {
            let at = at as u64;
            let allowed = [
                (32768 + 40, 4),
                (32768 + 68, 4),
                (61440 + 40, 4),
                (61440 + 68, 4),
                ((log_start + 1) * 4096, 4096),
                ((log_start + 2) * 4096, 4096),
            ]
            .iter()
            .any(|(start, n)| *start <= at && at < *start + *n);
            if !allowed {
                assert_eq!(before, now, "aborted transaction changed byte {at}");
            }
        }
        let digest = hash(&after);
        let checked = run(
            &format!("{label}-check"),
            "fsck.jfs",
            &["-n", image.to_str().unwrap()],
            None,
        );
        assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
        let debug = run(
            &format!("{label}-debug"),
            "jfs_debugfs",
            &[image.to_str().unwrap()],
            Some("inode 4\nquit\n"),
        );
        assert!(String::from_utf8_lossy(&debug.stdout).contains(&format!("di_uid:\t\t{old_uid}")));
        assert_eq!(hash(&fs::read(&image).unwrap()), digest);
        receipt.push_str(&format!("case={label} source_sha256={} output_sha256={digest} uid={old_uid} hardlinks=2 own_completed_recovery_writes=0 native_fsck=clean native_debugger_uid=exact payload_allocation_all_home_inode_bytes=unchanged profile=uncommitted-abort-no-independent-native-interrupted-replay\n",hash(&source)));
    }
    // Independent native checker evidence for the allocation after-image
    // codec only: this authored fixture deliberately bypasses the journal.
    // It must never be described as an owned COW publication operation.
    let image = root.join("allocation-cow-codec-fixture.img");
    fs::copy(&original, &image).unwrap();
    let mut storage = FileStorage::open(&image).unwrap();
    let baseline = inspect(&storage, limits, audit, &r).unwrap();
    let node = &baseline.nodes[&6];
    assert_eq!(node.runs.len(), 1);
    let old = node.runs[0].physical.start;
    let new = (112..baseline.geometry.mapped)
        .find(|block| !baseline.bitmap[*block as usize])
        .unwrap();
    let plan = allocation::prepare_map(
        &Borrowed {
            storage: &storage,
            length: storage.len().unwrap(),
            resources: &r,
        },
        &baseline,
        &[(old, false), (new, true)],
        &r,
    )
    .unwrap();
    let mut raw = node.raw.clone();
    fixture::pxd(&mut raw, 224 + 40, new, 1);
    let inode_at = pxd(&node.raw, 16, baseline.geometry.blocks).unwrap().start * 4096 + 6 * 512;
    let mut patches: Vec<_> = plan
        .pages
        .iter()
        .map(|page| (page.at, page.after.to_vec()))
        .collect();
    patches.push((inode_at, raw.clone()));
    let overlay = Overlay {
        source: Borrowed {
            storage: &storage,
            length: storage.len().unwrap(),
            resources: &r,
        },
        patches: &patches,
    };
    let resulting = decode(&overlay, limits, &r).unwrap();
    assert!(audit_decoded(&resulting, audit, &r).unwrap().is_clean());
    drop(resulting);
    let mut payload = [0u8; 4096];
    storage
        .read_exact_at(old * 4096, &mut payload[..7])
        .unwrap();
    assert_eq!(&payload[..7], b"nested!");
    drop((patches, baseline));
    journal::write_checked(&mut storage, new * 4096, &payload, &r, &r).unwrap();
    storage.flush().unwrap();
    for page in &plan.pages {
        let mut observed = [0; 4096];
        storage.read_exact_at(page.at, &mut observed).unwrap();
        assert_eq!(observed, page.before);
        journal::write_checked(&mut storage, page.at, &page.after, &r, &r).unwrap();
    }
    journal::write_checked(&mut storage, inode_at, &raw, &r, &r).unwrap();
    storage.flush().unwrap();
    drop((plan, storage));
    assert_eq!(r.memory.used(), 0);
    let before_native = hash(&fs::read(&image).unwrap());
    let checked = run(
        "allocation-cow-codec-check",
        "fsck.jfs",
        &["-n", image.to_str().unwrap()],
        None,
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Filesystem is clean"));
    let debug = run(
        "allocation-cow-codec-xtree",
        "jfs_debugfs",
        &[image.to_str().unwrap()],
        Some("xtree 6\n\nx\nquit\n"),
    );
    assert!(String::from_utf8_lossy(&debug.stdout).contains(&format!("xad.addr\t  {new}")));
    let storage = FileStorage::open(&image).unwrap();
    assert!(inspect(&storage, limits, audit, &r).is_ok());
    let mut actual = [0; 7];
    storage.read_exact_at(new * 4096, &mut actual).unwrap();
    assert_eq!(&actual, b"nested!");
    drop(storage);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(hash(&fs::read(&image).unwrap()), before_native);
    receipt.push_str(&format!("case=allocation-cow-codec-fixture output_sha256={before_native} old_block={old} new_block={new} native_fsck=clean native_xtree_address=exact model_payload=exact codec-only-direct-fixture-no-journal-publication\n"));
    for (name, baked) in sources {
        assert_eq!(fs::read(name).unwrap(), baked);
    }
    for (p, digest) in bindings {
        assert_eq!(hash(&fs::read(p).unwrap()), digest);
    }
    assert_eq!(hash(&fs::read(binary).unwrap()), binary_hash);
    receipt.push_str("end_source_tool_binary_revalidation=passed\nstatus=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}
