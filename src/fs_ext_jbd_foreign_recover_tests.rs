//! Independent footer-free native recovery fault model and cold-retry checks.
use super::*;
use crate::fs_core::{Budget, Cancellation};
use std::cell::Cell;
const SCOPE: u128 = 18u128 << 64;
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> Limits {
    Limits {
        journal_blocks: 1024,
        bootstrap_work: 100000,
        records: 16,
        scan_work: 100000,
        audit: ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
    }
}
// The filesystem is independently authored by bootstrap tests; all foreign log
// records here are raw native descriptor/data/commit bytes, with no encoder/footer.
fn fixture(sequence: u32, transactions: usize) -> Vec<u8> {
    let mut image = bootstrap::tests::fixture().0;
    image[1120..1124].copy_from_slice(&6u32.to_le_bytes());
    let journal = &mut image[100 * 1024..101 * 1024];
    put32(journal, 40, 1);
    journal[80] = 0;
    put32(journal, 252, 0);
    put32(journal, 24, sequence);
    put32(journal, 28, 1);
    for index in 0..transactions {
        let physical = 101 + 3 * index;
        let id = sequence.wrapping_add(index as u32);
        let mut payload = image[1024..2048].to_vec();
        payload[48..52].copy_from_slice(&(1000 + index as u32).to_le_bytes());
        let desc = &mut image[physical * 1024..(physical + 1) * 1024];
        header(desc, 1, id);
        put32(desc, 12, 1);
        put32(desc, 16, 8);
        desc[20..36].fill(0x39);
        image[(physical + 1) * 1024..(physical + 2) * 1024].copy_from_slice(&payload);
        header(
            &mut image[(physical + 2) * 1024..(physical + 3) * 1024],
            2,
            id,
        );
    }
    image
}
struct Fault {
    visible: Vec<u8>,
    durable: Vec<u8>,
    events: usize,
    cut: usize,
    prefix: usize,
    immediate: bool,
    persist_flush: bool,
    short: usize,
    readback_fail: Cell<bool>,
    fail_after_write: bool,
    cancel_after_write: bool,
    cancellation: Cancellation,
}
impl Fault {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            durable: bytes.clone(),
            visible: bytes,
            events: 0,
            cut: usize::MAX,
            prefix: 0,
            immediate: true,
            persist_flush: true,
            short: usize::MAX,
            readback_fail: Cell::new(false),
            fail_after_write: false,
            cancel_after_write: false,
            cancellation: Cancellation::default(),
        }
    }
    fn cold(&mut self) {
        self.visible.clone_from(&self.durable);
        self.cut = usize::MAX;
        self.short = usize::MAX;
        self.fail_after_write = false;
        self.readback_fail.set(false);
        self.cancel_after_write = false;
    }
}
impl Storage for Fault {
    fn len(&self) -> io::Result<u64> {
        Ok(self.visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if self.readback_fail.get() {
            return Err(io::Error::other("independent readback failure"));
        }
        let at = at as usize;
        out.copy_from_slice(
            self.visible
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.events += 1;
        let fail = self.events == self.cut;
        let count = if fail {
            self.prefix.min(bytes.len())
        } else {
            self.short.min(bytes.len())
        };
        let at = at as usize;
        self.visible[at..at + count].copy_from_slice(&bytes[..count]);
        if self.immediate {
            self.durable[at..at + count].copy_from_slice(&bytes[..count]);
        }
        if self.fail_after_write {
            self.readback_fail.set(true);
        }
        if self.cancel_after_write {
            self.cancellation.cancel();
        }
        if fail {
            Err(io::Error::other("independent write cut"))
        } else {
            Ok(count)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.events += 1;
        let fail = self.events == self.cut;
        if !fail || self.persist_flush {
            self.durable.clone_from(&self.visible);
        }
        if fail {
            Err(io::Error::other("independent flush cut"))
        } else {
            Ok(())
        }
    }
}
fn assert_uncertain(error: io::Error) {
    let failure = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .unwrap();
    assert_eq!(failure.kind, ErrorKind::UncertainDurability);
    assert!(failure.source.is_some());
}

fn historical_fixture(sequence: u32) -> Vec<u8> {
    let mut image = fixture(sequence, 3);
    let active = image[101 * 1024..110 * 1024].to_vec();
    image[101 * 1024..110 * 1024].fill(0);
    let start = 0x123usize;
    image[(100 + start) * 1024..(100 + start + 9) * 1024].copy_from_slice(&active);
    put32(&mut image[100 * 1024..101 * 1024], 28, start as u32);
    // Prefix tears clearing 0x00000123 may select 0x23 instead. A fully
    // committed historical transaction there must never replace current home.
    let physical = 100 + 0x23;
    let mut payload = image[1024..2048].to_vec();
    payload[48..52].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    let desc = &mut image[physical * 1024..(physical + 1) * 1024];
    header(desc, 1, sequence.wrapping_add(4));
    put32(desc, 12, 1);
    put32(desc, 16, 8);
    desc[20..36].fill(0x39);
    image[(physical + 1) * 1024..(physical + 2) * 1024].copy_from_slice(&payload);
    header(
        &mut image[(physical + 2) * 1024..(physical + 3) * 1024],
        2,
        sequence.wrapping_add(4),
    );
    image
}
fn assert_final(source: &Fault, r: &Resources) {
    assert_eq!(&source.durable[1072..1076], &1002u32.to_le_bytes());
    assert_eq!(be32(&source.durable[100 * 1024..101 * 1024], 28), 0);
    assert_eq!(
        u32::from_le_bytes(source.durable[1120..1124].try_into().unwrap()) & 4,
        0
    );
    let (decoder, _) = crate::fs_ext::ExtDecoder::open_native_clean(source, SCOPE, r).unwrap();
    let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, r).unwrap();
    assert!(audit.is_clean());
}
#[test]
fn foreign_native_writer_cold_retry_every_barrier_and_control_prefix_keeps_latest_payload() {
    for sequence in [37, 0xfd, 0xfffd, 0xfffffd, u32::MAX - 2, u32::MAX] {
        let bytes = historical_fixture(sequence);
        let r = resources();
        let mut good = Fault::new(bytes.clone());
        recover::recover(&mut good, SCOPE, limits(), &r).unwrap();
        assert_final(&good, &r);
        // The boundary+1 ID exists at the historical torn-start destination.
        assert_ne!(
            be32(&good.durable[100 * 1024..101 * 1024], 24),
            sequence.wrapping_add(4)
        );
        let events = good.events;
        assert!(events >= 6);
        let mut prefixes: Vec<usize> = (0..=32).collect();
        prefixes.extend([511, 512, 1023, 1024]);
        for cut in 1..=events {
            for &prefix in &prefixes {
                let mut failed = Fault::new(bytes.clone());
                failed.cut = cut;
                failed.prefix = prefix;
                assert!(
                    recover::recover(&mut failed, SCOPE, limits(), &r).is_err(),
                    "sequence={sequence} cut={cut} prefix={prefix}"
                );
                assert_eq!(r.memory.used(), 0);
                failed.cold();
                recover::recover(&mut failed, SCOPE, limits(), &r).unwrap();
                assert_final(&failed, &r);
                assert_eq!(r.memory.used(), 0);
            }
        }
        for immediate in [false, true] {
            for persist in [false, true] {
                for cut in 1..=events {
                    let mut failed = Fault::new(bytes.clone());
                    failed.immediate = immediate;
                    failed.persist_flush = persist;
                    failed.cut = cut;
                    assert!(recover::recover(&mut failed, SCOPE, limits(), &r).is_err());
                    failed.cold();
                    recover::recover(&mut failed, SCOPE, limits(), &r).unwrap();
                    assert_final(&failed, &r);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
    }
}
#[test]
fn foreign_writer_short_writes_readback_failure_and_cancellation_have_safe_cold_retry() {
    for mode in 0..4 {
        let r = resources();
        let mut source = Fault::new(fixture(0xfffd, 3));
        match mode {
            0 => source.short = 3,
            1 => source.fail_after_write = true,
            2 => {
                source.cancel_after_write = true;
                source.cancellation = r.cancellation.clone();
            }
            _ => source.short = 0,
        }
        let result = recover::recover(&mut source, SCOPE, limits(), &r);
        if mode == 0 {
            result.unwrap();
        } else {
            assert_uncertain(result.err().unwrap());
        }
        assert_eq!(r.memory.used(), 0);
        source.cold();
        let fresh = resources();
        recover::recover(&mut source, SCOPE, limits(), &fresh).unwrap();
        assert_final(&source, &fresh);
        let before = source.durable.clone();
        let writes = source.events;
        recover::recover(&mut source, SCOPE, limits(), &fresh).unwrap();
        assert_eq!(source.durable, before);
        assert_eq!(source.events, writes);
        assert_eq!(fresh.memory.used(), 0);
    }
}
#[test]
fn inactive_dirty_closure_finishes_without_replaying_historical_records() {
    let r = resources();
    let mut image = fixture(37, 3);
    image[1072..1076].copy_from_slice(&1002u32.to_le_bytes());
    put32(&mut image[100 * 1024..101 * 1024], 28, 0);
    let mut source = Fault::new(image);
    recover::recover(&mut source, SCOPE, limits(), &r).unwrap();
    assert_final(&source, &r);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn checksum_profiles_and_pre_cancel_reject_before_writes() {
    for profile in 0..4 {
        let r = resources();
        let mut image = fixture(37, 3);
        match profile {
            0 | 1 => {
                let journal: &mut [u8; 1024] =
                    (&mut image[100 * 1024..101 * 1024]).try_into().unwrap();
                put32(journal, 40, if profile == 0 { 9 } else { 17 });
                journal[80] = 4;
                journal_checksum(
                    &Geometry {
                        block_bytes: 1024,
                        maximum: 1024,
                        first: 1,
                        sequence: 37,
                        start: 1,
                        uuid: [0x39; 16],
                        revoke: true,
                        checksums: if profile == 0 {
                            Checksums::V2
                        } else {
                            Checksums::V3
                        },
                    },
                    journal,
                );
            }
            2 => image[1124..1128].copy_from_slice(&0x401u32.to_le_bytes()),
            _ => r.cancellation.cancel(),
        }
        let mut source = Fault::new(image);
        let before = source.durable.clone();
        let error = recover::recover(&mut source, SCOPE, limits(), &r)
            .err()
            .unwrap();
        if profile < 3 {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
        assert_eq!(source.events, 0);
        assert_eq!(source.durable, before);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn unsupported_ring_lower_bound_and_ambiguous_first_record_are_prewrite() {
    for narrow_first in [false, true] {
        let r = resources();
        let mut image = fixture(37, 3);
        if narrow_first {
            let active = image[101 * 1024..110 * 1024].to_vec();
            image[101 * 1024..110 * 1024].fill(0);
            image[103 * 1024..112 * 1024].copy_from_slice(&active);
            put32(&mut image[100 * 1024..101 * 1024], 20, 2);
            put32(&mut image[100 * 1024..101 * 1024], 28, 3);
        } else {
            // Current ID exists later, while the original start points at an
            // older committed transaction whose payload differs from home.
            put32(&mut image[100 * 1024..101 * 1024], 24, 38);
        }
        let mut source = Fault::new(image);
        let before = source.durable.clone();
        let error = recover::recover(&mut source, SCOPE, limits(), &r)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(source.events, 0);
        assert_eq!(source.durable, before);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn recovery_phase_and_memory_budgets_fail_before_mutation_and_refund() {
    for phase in 0..4 {
        let mut cap = limits();
        let mut r = resources();
        match phase {
            0 => cap.bootstrap_work = 1,
            1 => cap.scan_work = 512,
            2 => cap.records = 0,
            _ => r.memory = Budget::new(1),
        }
        let mut source = Fault::new(fixture(37, 3));
        let before = source.durable.clone();
        assert!(recover::recover(&mut source, SCOPE, cap, &r).is_err());
        assert_eq!(source.events, 0);
        assert_eq!(source.durable, before);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn bootstrap_inode_table_guard_preserves_both_raw_pointer_words() {
    let mut original = [0u8; 64];
    original[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
    original[40..44].copy_from_slice(&0x11223344u32.to_le_bytes());
    for wide in [false, true] {
        let mut replacement = original;
        replacement[12] = 99; // Other descriptor observations may change.
        recover::same_bootstrap_inode_table(&original, &replacement, wide).unwrap();
        replacement[8] ^= 1;
        assert_eq!(
            recover::same_bootstrap_inode_table(&original, &replacement, wide)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
    let mut replacement = original;
    replacement[40] ^= 1;
    recover::same_bootstrap_inode_table(&original, &replacement, false).unwrap();
    assert_eq!(
        recover::same_bootstrap_inode_table(&original, &replacement, true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[test]
fn recovery_accepts_group_descriptor_redo_with_stable_bootstrap_pointer() {
    let r = resources();
    let mut image = fixture(37, 1);
    let descriptor = image[2 * 1024..3 * 1024].to_vec();
    put32(&mut image[101 * 1024..102 * 1024], 12, 2);
    image[102 * 1024..103 * 1024].copy_from_slice(&descriptor);
    let mut source = Fault::new(image);
    let outcome = recover::recover(&mut source, SCOPE, limits(), &r).unwrap();
    assert_eq!(outcome.transactions, 1);
    assert_eq!(outcome.blocks, 1);
    assert_eq!(&source.durable[2 * 1024..3 * 1024], descriptor.as_slice());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn fully_auditable_inode_table_relocation_is_rejected_before_checkpoint_writes() {
    let r = resources();
    let mut image = fixture(37, 1);
    let table = image[5 * 1024..21 * 1024].to_vec();
    image[1500 * 1024..1516 * 1024].copy_from_slice(&table);
    let mut descriptor = image[2 * 1024..3 * 1024].to_vec();
    descriptor[8..12].copy_from_slice(&1500u32.to_le_bytes());
    let mut bitmap = image[3 * 1024..4 * 1024].to_vec();
    for physical in 5..21 {
        let bit = physical - 1;
        bitmap[bit / 8] &= !(1 << (bit % 8));
    }
    for physical in 1500..1516 {
        let bit = physical - 1;
        bitmap[bit / 8] |= 1 << (bit % 8);
    }
    let tags = &mut image[101 * 1024..102 * 1024];
    tags.fill(0);
    header(tags, 1, 37);
    put32(tags, 12, 2);
    put32(tags, 16, 0);
    tags[20..36].fill(0x39);
    put32(tags, 36, 3);
    put32(tags, 40, 10); // SAME_UUID | LAST_TAG.
    image[102 * 1024..103 * 1024].copy_from_slice(&descriptor);
    image[103 * 1024..104 * 1024].copy_from_slice(&bitmap);
    header(&mut image[104 * 1024..105 * 1024], 2, 37);
    let mut source = Fault::new(image);
    let before = source.durable.clone();
    // The final image is valid and the journal bytes/map are identical. That
    // alone cannot prove that a torn table-pointer checkpoint remains bootstrapable.
    let plan = preflight(&source, SCOPE, limits(), &r).unwrap();
    assert!(plan.audit.is_clean());
    assert_eq!(plan.replay.blocks.len(), 2);
    drop(plan);
    let error = recover::recover(&mut source, SCOPE, limits(), &r)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(source.events, 0);
    assert_eq!(source.durable, before);
    assert_eq!(r.memory.used(), 0);
}
