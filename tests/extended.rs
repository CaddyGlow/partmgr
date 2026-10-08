#![cfg(feature = "std")]

use partmgr::extended::ExtendedLayout;
use std::io;
use virtdisk::ReadAt;
struct Memory(Vec<u8>);
impl ReadAt for Memory {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(
            self.0
                .get(o as usize..o as usize + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn put_entry(bytes: &mut [u8], offset: usize, slot: usize, kind: u8, start: u32, count: u32) {
    let e = offset + 446 + slot * 16;
    bytes[e + 4] = kind;
    bytes[e + 8..e + 12].copy_from_slice(&start.to_le_bytes());
    bytes[e + 12..e + 16].copy_from_slice(&count.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 200 * 512];
    for lba in [0, 10, 60] {
        b[lba * 512 + 510..lba * 512 + 512].copy_from_slice(&[0x55, 0xaa]);
    }
    put_entry(&mut b, 0, 2, 0x0f, 10, 180);
    put_entry(&mut b, 10 * 512, 0, 0x83, 1, 20);
    put_entry(&mut b, 10 * 512, 1, 0x0f, 50, 130);
    put_entry(&mut b, 60 * 512, 0, 0x83, 2, 25);
    b
}
#[test]
fn relative_bases_and_cycle() {
    let b = fixture();
    let l = ExtendedLayout::inspect(&Memory(b.clone()), 512, 16).unwrap();
    assert_eq!(l.logical()[0].range().start(), 11);
    assert_eq!(l.logical()[1].range().start(), 62);
    let mut b = b;
    put_entry(&mut b, 60 * 512, 1, 0x0f, 50, 130);
    assert!(ExtendedLayout::inspect(&Memory(b), 512, 16).is_err());
}
impl partmgr::storage::Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        let count = b.len().min(17);
        self.0[o as usize..o as usize + count].copy_from_slice(&b[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn transactional_edit_topology_commit_and_payload_preservation() {
    use partmgr::layout::LbaRange;
    let mut memory = Memory(fixture());
    memory.0[11 * 512..31 * 512].fill(0xa7);
    memory.0[62 * 512..87 * 512].fill(0xc2);
    let mut layout = ExtendedLayout::inspect(&memory, 512, 16).unwrap();
    let old = layout.clone();
    assert!(layout.set_range(0, LbaRange::new(11, 65).unwrap()).is_err());
    assert_eq!(layout.logical()[0].range(), old.logical()[0].range());
    layout
        .create(100, 0x83, LbaRange::new(101, 120).unwrap())
        .unwrap();
    let plan = layout.plan_against(&memory).unwrap();
    assert_eq!(plan.stages()[0].writes()[0].offset(), 100 * 512);
    plan.commit(&mut memory).unwrap();
    let reread = ExtendedLayout::inspect(&memory, 512, 16).unwrap();
    assert_eq!(reread.logical().len(), 3);
    assert!(memory.0[11 * 512..31 * 512].iter().all(|b| *b == 0xa7));
    assert!(memory.0[62 * 512..87 * 512].iter().all(|b| *b == 0xc2));
    let mut edited = reread;
    edited.delete(0).unwrap();
    edited
        .plan_against(&memory)
        .unwrap()
        .commit(&mut memory)
        .unwrap();
    assert_eq!(
        ExtendedLayout::inspect(&memory, 512, 16).unwrap().logical()[0]
            .range()
            .start(),
        62
    );
}
#[test]
fn chain_limits_and_metadata_overlaps_are_rejected() {
    assert!(ExtendedLayout::inspect(&Memory(fixture()), 512, 1).is_err());
    let mut bytes = fixture();
    put_entry(&mut bytes, 10 * 512, 0, 0x83, 1, 60);
    assert!(ExtendedLayout::inspect(&Memory(bytes), 512, 16).is_err());
}
#[test]
fn empty_chain_and_first_delete_preserve_boot_code_and_link_chs() {
    use partmgr::layout::{Geometry, LbaRange};
    let mut bytes = fixture();
    bytes[10 * 512..10 * 512 + 440].fill(0xa7);
    bytes[10 * 512 + 463..10 * 512 + 466].copy_from_slice(&[1, 2, 3]);
    bytes[10 * 512 + 467..10 * 512 + 470].copy_from_slice(&[4, 5, 6]);
    let mut memory = Memory(bytes);
    let mut layout = ExtendedLayout::inspect(&memory, 512, 16).unwrap();
    layout
        .create(100, 0x83, LbaRange::new(101, 120).unwrap())
        .unwrap();
    assert_eq!(&layout.logical()[0].sector()[463..466], &[1, 2, 3]);
    assert_eq!(&layout.logical()[0].sector()[467..470], &[4, 5, 6]);
    layout.delete(0).unwrap();
    assert!(
        layout.logical()[0].sector()[..440]
            .iter()
            .all(|b| *b == 0xa7)
    );
    layout.delete(1).unwrap();
    layout.delete(0).unwrap();
    layout
        .plan_against(&memory)
        .unwrap()
        .commit(&mut memory)
        .unwrap();
    let mut empty = ExtendedLayout::inspect(&memory, 512, 16).unwrap();
    assert!(empty.logical().is_empty());
    empty
        .create(10, 0x83, LbaRange::new(11, 30).unwrap())
        .unwrap();
    empty
        .plan_against(&memory)
        .unwrap()
        .commit(&mut memory)
        .unwrap();
    assert_eq!(
        ExtendedLayout::inspect(&memory, 512, 16)
            .unwrap()
            .logical()
            .len(),
        1
    );
    let initialized = ExtendedLayout::initialize(
        Geometry::new(200 * 512, 512).unwrap(),
        17,
        1,
        LbaRange::new(10, 190).unwrap(),
        &[],
    )
    .unwrap();
    assert!(initialized.logical().is_empty());
}
struct FaultDisk {
    memory: Memory,
    event: usize,
    fail: usize,
}
impl partmgr::storage::Storage for FaultDisk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.memory.0.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(&self.memory, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        let event = self.event;
        self.event += 1;
        if event == self.fail {
            return Err(io::Error::other("injected EBR interruption"));
        }
        let n = b.len().min(1);
        self.memory.0[o as usize..o as usize + n].copy_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let event = self.event;
        self.event += 1;
        if event == self.fail {
            Err(io::Error::other("injected EBR flush"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn every_ebr_short_write_and_flush_boundary_can_restore_selected_snapshot() {
    use partmgr::layout::LbaRange;
    let bytes = fixture();
    let original = ExtendedLayout::inspect(&Memory(bytes.clone()), 512, 16).unwrap();
    let mut proposed = original.clone();
    proposed
        .create(100, 0x83, LbaRange::new(101, 120).unwrap())
        .unwrap();
    let plan = proposed
        .edit_plan(&original, &Memory(bytes.clone()))
        .unwrap();
    let mut interrupted = 0;
    let mut invalid_states = 0;
    for fail in 0..1545 {
        let mut disk = FaultDisk {
            memory: Memory(bytes.clone()),
            event: 0,
            fail,
        };
        let result = plan.commit(&mut disk);
        if result.is_err() {
            interrupted += 1;
            if let Ok(partial) = ExtendedLayout::inspect(&disk.memory, 512, 16) {
                assert!(matches!(partial.logical().len(), 2 | 3));
            } else {
                invalid_states += 1;
            } /* Partially replaced EBR entries may fail strict inspection. The saved,
            explicitly selected source snapshot is the repair authority. */
            let repair = original.plan_against(&disk.memory).unwrap();
            repair.commit(&mut disk.memory).unwrap();
            let restored = ExtendedLayout::inspect(&disk.memory, 512, 16).unwrap();
            assert_eq!(restored.logical().len(), 2);
            for e in original.logical() {
                assert_eq!(
                    &disk.memory.0[e.ebr_lba() as usize * 512..e.ebr_lba() as usize * 512 + 512],
                    e.sector()
                );
            }
        } else {
            assert_eq!(
                ExtendedLayout::inspect(&disk.memory, 512, 16)
                    .unwrap()
                    .logical()
                    .len(),
                3
            );
        }
        assert_eq!(
            &disk.memory.0[11 * 512..31 * 512],
            &bytes[11 * 512..31 * 512]
        );
        assert_eq!(
            &disk.memory.0[62 * 512..87 * 512],
            &bytes[62 * 512..87 * 512]
        );
    }
    assert_eq!(interrupted, 3 * 513);
    assert!(invalid_states > 0);
}
#[test]
fn new_ebr_cannot_overwrite_deleted_source_payload() {
    use partmgr::layout::LbaRange;
    let memory = Memory(fixture());
    let old = ExtendedLayout::inspect(&memory, 512, 16).unwrap();
    let mut new = old.clone();
    new.delete(1).unwrap();
    new.create(70, 0x83, LbaRange::new(100, 120).unwrap())
        .unwrap();
    assert!(new.edit_plan(&old, &memory).is_err());
}
#[test]
fn independently_built_4096_chain_preserves_sector_tail() {
    let mut bytes = vec![0; 200 * 4096];
    for lba in [0, 10, 60] {
        bytes[lba * 4096 + 510..lba * 4096 + 512].copy_from_slice(&[0x55, 0xaa]);
        bytes[lba * 4096 + 512..(lba + 1) * 4096].fill(lba as u8 + 7);
    }
    put_entry(&mut bytes, 0, 2, 0x0f, 10, 180);
    put_entry(&mut bytes, 10 * 4096, 0, 0x83, 1, 20);
    put_entry(&mut bytes, 10 * 4096, 1, 0x0f, 50, 130);
    put_entry(&mut bytes, 60 * 4096, 0, 0x83, 2, 25);
    let mut memory = Memory(bytes);
    let old = ExtendedLayout::inspect(&memory, 4096, 16).unwrap();
    let mut new = old.clone();
    new.set_range(1, partmgr::layout::LbaRange::new(63, 87).unwrap())
        .unwrap();
    new.write_plan(&old).unwrap().commit(&mut memory).unwrap();
    assert!(
        memory.0[60 * 4096 + 512..61 * 4096]
            .iter()
            .all(|b| *b == 67)
    );
    assert_eq!(
        ExtendedLayout::inspect(&memory, 4096, 16)
            .unwrap()
            .logical()[1]
            .range()
            .start(),
        63
    );
}
#[test]
fn link_lengths_out_of_order_topology_and_aligned_placement() {
    use partmgr::layout::{Geometry, LbaRange};
    let mut bytes = fixture();
    put_entry(&mut bytes, 10 * 512, 1, 0x0f, 50, 1);
    assert!(ExtendedLayout::inspect(&Memory(bytes), 512, 16).is_err());
    let mut bytes = fixture();
    put_entry(&mut bytes, 10 * 512, 1, 0x0f, 50, 27);
    let old = ExtendedLayout::inspect(&Memory(bytes), 512, 16).unwrap();
    let mut new = old.clone();
    new.create(100, 0x83, LbaRange::new(101, 120).unwrap())
        .unwrap();
    assert_eq!(
        &old.logical()[0].sector()[462..478],
        &new.logical()[0].sector()[462..478]
    );
    let mut memory = Memory(vec![0; 200 * 512]);
    let init = ExtendedLayout::initialize(
        Geometry::new(200 * 512, 512).unwrap(),
        1,
        1,
        LbaRange::new(10, 190).unwrap(),
        &[
            (10, 0x83, LbaRange::new(11, 30).unwrap()),
            (100, 0x83, LbaRange::new(101, 120).unwrap()),
            (60, 0x83, LbaRange::new(61, 80).unwrap()),
        ],
    )
    .unwrap();
    init.plan_against(&memory)
        .unwrap()
        .commit(&mut memory)
        .unwrap();
    let mut reread = ExtendedLayout::inspect(&memory, 512, 16).unwrap();
    assert_eq!(reread.logical()[2].ebr_lba(), 60);
    let (ebr, range) = reread.place(5, 8).unwrap();
    assert_eq!(range.start() % 8, 0);
    reread.create(ebr, 0x83, range).unwrap();
    assert!(
        reread
            .free_space()
            .iter()
            .all(|gap| gap.end() <= range.start() || gap.start() >= range.end())
    );
}
