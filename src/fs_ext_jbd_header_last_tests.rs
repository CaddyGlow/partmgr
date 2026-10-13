//! Publication-order regressions; every write byte-prefix is enumerated.
use super::*;
use crate::fs_core::{Budget, Cancellation};
use crate::storage::Storage;
use std::cell::{Cell, RefCell};

#[derive(Clone, Debug)]
enum Event {
    Write(u64, Vec<u8>),
    Read(usize),
    Flush,
}
struct Device {
    visible: Vec<u8>,
    durable: Vec<u8>,
    events: RefCell<Vec<Event>>,
    cut: Option<(usize, usize)>,
    immediate: bool,
    persist_flush: bool,
    stopped: Cell<bool>,
    corrupt_read: Option<usize>,
}
impl Device {
    fn new(
        bytes: &[u8],
        cut: Option<(usize, usize)>,
        immediate: bool,
        persist_flush: bool,
    ) -> Self {
        Self {
            visible: bytes.to_vec(),
            durable: bytes.to_vec(),
            events: RefCell::new(Vec::new()),
            cut,
            immediate,
            persist_flush,
            stopped: Cell::new(false),
            corrupt_read: None,
        }
    }
    fn attempt(&self, event: Event) -> io::Result<bool> {
        if self.stopped.get() {
            return Err(io::Error::other("sticky stopped device"));
        }
        let ordinal = self.events.borrow().len();
        self.events.borrow_mut().push(event);
        Ok(self.cut.is_some_and(|(at, _)| at == ordinal))
    }
}
impl Storage for Device {
    fn len(&self) -> io::Result<u64> {
        Ok(self.visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if self.attempt(Event::Read(out.len()))? {
            self.stopped.set(true);
            return Err(io::Error::other("readback failure"));
        }
        out.copy_from_slice(&self.visible[at as usize..at as usize + out.len()]);
        if self.corrupt_read == Some(self.events.borrow().len() - 1) {
            out[0] ^= 1;
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let fail = self.attempt(Event::Write(at, bytes.to_vec()))?;
        let n = if fail {
            self.cut.unwrap().1
        } else {
            bytes.len()
        };
        self.visible[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        if self.immediate {
            self.durable[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        }
        if fail {
            self.stopped.set(true);
            Err(io::Error::other("write-prefix failure"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let fail = self.attempt(Event::Flush)?;
        if !fail || self.persist_flush {
            self.durable.copy_from_slice(&self.visible);
        }
        if fail {
            self.stopped.set(true);
            Err(io::Error::other("flush failure"))
        } else {
            Ok(())
        }
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn geometry(checksums: Checksums, bs: usize) -> Geometry {
    Geometry {
        block_bytes: bs,
        first: 1,
        maximum: 12,
        start: 1,
        sequence: 36,
        uuid: [0x31; 16],
        checksums,
        revoke: false,
    }
}
fn proof(g: Geometry, r: &Resources) -> NativeJournalProof {
    NativeJournalProof {
        geometry: g,
        map: super::super::ExtDecodedFileMap {
            identity: crate::fs_core::ObjectId {
                source: 18u128 << 64,
                generation: 0,
                native: vec![8],
            },
            length: (12 * g.block_bytes) as u64,
            extents: vec![crate::fs_file::FileExtent {
                offset: 0,
                length: (12 * g.block_bytes) as u64,
                kind: crate::fs_file::ExtentKind::Data(4096),
            }],
            reservation: r.memory.reserve(512).unwrap(),
        },
    }
}
fn replay(
    g: &Geometry,
    p: &NativeJournalProof,
    bytes: &[u8],
    r: &Resources,
) -> io::Result<ReplayPlan> {
    scan_owned(
        g,
        8,
        1000,
        r,
        |at, out| {
            let at = p.physical(at)? as usize;
            out.copy_from_slice(&bytes[at..at + out.len()]);
            Ok(())
        },
        |_| Ok(()),
    )
}
fn fixtures(
    checksums: Checksums,
    bs: usize,
    r: &Resources,
) -> (Geometry, NativeJournalProof, EncodedTransaction, Vec<u8>) {
    let scan = geometry(checksums, bs);
    let input = |destination, marker| {
        let mut bytes = [marker; MAX_BLOCK];
        if destination == 100 {
            bytes[..4].copy_from_slice(&MAGIC.to_be_bytes());
        }
        ReplayBlock { destination, bytes }
    };
    let preparation = encode(&scan, &[input(99, 0x41)], 100, r, |_| Ok(())).unwrap();
    let mut mutation_geometry = scan;
    mutation_geometry.start = preparation.next_logical;
    mutation_geometry.sequence += 1;
    // Two encoder-produced one-tag descriptors are concatenated, exercising
    // multiple descriptors without hundreds of irrelevant payload blocks.
    let mut first = encode(&mutation_geometry, &[input(100, 0x42)], 100, r, |_| Ok(())).unwrap();
    let _ = first.blocks.pop();
    let mut next = mutation_geometry;
    next.start = first.blocks.last().unwrap().logical + 1;
    let second = encode(&next, &[input(101, 0x43)], 100, r, |_| Ok(())).unwrap();
    let end = second.next_logical;
    let mut blocks = Vec::with_capacity(first.blocks.len() + second.blocks.len());
    blocks.append(&mut first.blocks);
    blocks.extend(second.blocks);
    first.blocks = blocks;
    first._reservation = r
        .memory
        .reserve((first.blocks.len() * core::mem::size_of::<LogBlock>() + MAX_BLOCK + 128) as u64)
        .unwrap();
    first.next_logical = end;
    legacy::stamp(&mutation_geometry, &mut first.blocks).unwrap();
    let proof = proof(mutation_geometry, r);
    let mut original = vec![0xa5; 4096 + 12 * bs];
    original[4096..].fill(0);
    for block in &preparation.blocks {
        let at = proof.physical(block.logical).unwrap() as usize;
        original[at..at + bs].copy_from_slice(&block.bytes[..bs]);
    }
    // The first future descriptor is the zeroed previous durable tail. A later
    // descriptor and commit retain colliding old headers with malformed bodies.
    for block in first.blocks.iter().skip(1) {
        let at = proof.physical(block.logical).unwrap() as usize;
        original[at..at + bs].copy_from_slice(&block.bytes[..bs]);
        if encoded_descriptor(block) {
            original[at + 20] ^= 0x7f;
        }
    }
    (scan, proof, first, original)
}
fn assert_exact_committed_union(plan: &ReplayPlan, bs: usize) {
    assert!((1..=2).contains(&plan.committed_transactions));
    assert_eq!(plan.next_sequence, 36 + plan.committed_transactions as u32);
    let expected = [(99, 0x41), (100, 0x42), (101, 0x43)];
    let count = if plan.committed_transactions == 1 {
        1
    } else {
        3
    };
    assert_eq!(plan.blocks.len(), count);
    for (actual, (destination, marker)) in plan.blocks.iter().zip(&expected[..count]) {
        assert_eq!(actual.destination, *destination);
        let mut bytes = [*marker; MAX_BLOCK];
        if *destination == 100 {
            // Independent native JBD magic, restored from escaped journal data.
            bytes[..4].copy_from_slice(&[0xc0, 0x3b, 0x39, 0x98]);
        }
        assert_eq!(actual.bytes[..bs], bytes[..bs]);
    }
}
#[test]
fn every_publication_prefix_preserves_committed_prefix_with_stale_headers() {
    for bs in [1024, 2048, 4096] {
        for checksums in [Checksums::None, Checksums::V2, Checksums::V3] {
            let r = resources();
            let (scan, proof, encoded, original) = fixtures(checksums, bs, &r);
            let mut success = Device::new(&original, None, false, false);
            publish_log(&mut success, &proof, &encoded, &r).unwrap();
            let trace = success.events.borrow().clone();
            let full = replay(&scan, &proof, &success.durable, &r).unwrap();
            assert_eq!(full.committed_transactions, 2);
            assert_exact_committed_union(&full, bs);
            drop(full);
            let overhead = publication_overhead(&encoded, bs).unwrap();
            assert_eq!(overhead.written, 24);
            assert_eq!(overhead.read, 2 * (bs + 12));
            let actual_written: usize = trace
                .iter()
                .map(|event| match event {
                    Event::Write(at, bytes) => {
                        assert!(*at as usize + bytes.len() <= original.len());
                        bytes.len()
                    }
                    _ => 0,
                })
                .sum();
            assert_eq!(
                actual_written,
                (encoded.blocks.len() + 1) * bs + 12 + overhead.written
            );
            let actual_read: usize = trace
                .iter()
                .map(|event| match event {
                    Event::Read(bytes) => *bytes,
                    _ => 0,
                })
                .sum();
            assert_eq!(
                actual_read,
                (encoded.blocks.len() + 2) * bs + 12 + overhead.read
            );
            assert_eq!(
                trace
                    .iter()
                    .filter(|event| matches!(event, Event::Flush))
                    .count(),
                4
            );

            for (ordinal, event) in trace.iter().enumerate() {
                let length = match event {
                    Event::Write(_, bytes) => bytes.len(),
                    _ => 0,
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in 0..=length {
                            let mut device =
                                Device::new(&original, Some((ordinal, prefix)), immediate, persist);
                            assert!(publish_log(&mut device, &proof, &encoded, &r).is_err());
                            assert!(device.stopped.get());
                            assert_eq!(device.events.borrow().len(), ordinal + 1);
                            assert_eq!(&device.durable[..4096], &original[..4096]);
                            let plan = replay(&scan, &proof, &device.durable, &r).unwrap_or_else(|e| panic!("bs={bs} event={ordinal} prefix={prefix} immediate={immediate} persist={persist}: {e}"));
                            assert_exact_committed_union(&plan, bs);
                        }
                    }
                }
            }
            drop((proof, encoded));
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn committed_uuid_corruption_stays_strict_even_with_resealed_body() {
    for checksums in [Checksums::None, Checksums::V2, Checksums::V3] {
        let r = resources();
        let (scan, proof, mut encoded, original) = fixtures(checksums, 1024, &r);
        encoded.blocks[0].bytes[match checksums {
            Checksums::None => 20,
            Checksums::V2 => 22,
            Checksums::V3 => 28,
        }] ^= 1;
        metadata_checksum(&proof.geometry, &mut encoded.blocks[0].bytes[..1024], 1020);
        legacy::stamp(&proof.geometry, &mut encoded.blocks).unwrap();
        let mut forged = original;
        for block in &encoded.blocks {
            let at = proof.physical(block.logical).unwrap() as usize;
            forged[at..at + 1024].copy_from_slice(&block.bytes[..1024]);
        }
        assert!(
            replay(&scan, &proof, &forged, &r)
                .err()
                .unwrap()
                .to_string()
                .contains("UUID binding")
        );
        drop((proof, encoded));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn independent_publication_reservations_exact_one_below_and_overflow() {
    let r = resources();
    let (_, proof, encoded, _) = fixtures(Checksums::None, 1024, &r);
    let overhead = publication_overhead(&encoded, 1024).unwrap();
    let work = 7 + overhead.work * 2;
    let physical = 11 + overhead.written * 2;
    publication_budget(7, 11, &encoded, &encoded, 1024, work, physical as u64).unwrap();
    assert!(
        publication_budget(7, 11, &encoded, &encoded, 1024, work - 1, physical as u64).is_err()
    );
    assert!(
        publication_budget(7, 11, &encoded, &encoded, 1024, work, physical as u64 - 1).is_err()
    );
    assert!(
        publication_budget(
            usize::MAX,
            11,
            &encoded,
            &encoded,
            1024,
            usize::MAX,
            u64::MAX
        )
        .is_err()
    );
    assert!(
        publication_budget(
            7,
            usize::MAX,
            &encoded,
            &encoded,
            1024,
            usize::MAX,
            u64::MAX
        )
        .is_err()
    );
    drop((proof, encoded));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn descriptor_readback_mismatch_stops_publication_at_exact_observation() {
    let r = resources();
    let (scan, proof, encoded, original) = fixtures(Checksums::None, 1024, &r);
    let mut baseline = Device::new(&original, None, false, false);
    publish_log(&mut baseline, &proof, &encoded, &r).unwrap();
    for (ordinal, event) in baseline.events.borrow().iter().enumerate() {
        if !matches!(event, Event::Read(_)) {
            continue;
        }
        let mut device = Device::new(&original, None, true, true);
        device.corrupt_read = Some(ordinal);
        let error = publish_log(&mut device, &proof, &encoded, &r).unwrap_err();
        assert!(error.to_string().contains("readback mismatch"));
        assert_eq!(device.events.borrow().len(), ordinal + 1);
        let plan = replay(&scan, &proof, &device.durable, &r).unwrap();
        assert_exact_committed_union(&plan, 1024);
    }
    // Preserve strict refusal of the exact previously generated xattr shape:
    // a valid preparation followed by only 12 bytes of a mutation descriptor.
    let mut header_only = original;
    let first = &encoded.blocks[0];
    let at = proof.physical(first.logical).unwrap() as usize;
    header_only[at..at + 12].copy_from_slice(&first.bytes[..12]);
    assert!(
        replay(&scan, &proof, &header_only, &r)
            .err()
            .unwrap()
            .to_string()
            .contains("UUID binding")
    );
    drop((proof, encoded));
    assert_eq!(r.memory.used(), 0);
}
