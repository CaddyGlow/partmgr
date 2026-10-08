#![cfg(feature = "std")]

use partmgr::layout::{DiskLayout, Geometry, LbaRange};
use std::io;
use virtdisk::ReadAt;
struct Memory(Vec<u8>);
impl ReadAt for Memory {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb88320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
fn mbr(size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    b
}
fn entry(bytes: &mut [u8], slot: usize, typ: u8, start: u32, count: u32) {
    let p = 446 + slot * 16;
    bytes[p + 4] = typ;
    put32(bytes, p + 8, start);
    put32(bytes, p + 12, count);
}
fn fix_header(b: &mut [u8], offset: usize) {
    put32(b, offset + 16, 0);
    let crc = crc(&b[offset..offset + 92]);
    put32(b, offset + 16, crc);
}
fn gpt(sector: usize) -> Vec<u8> {
    let total = 256;
    let mut b = mbr(total * sector);
    entry(&mut b, 0, 0xee, 1, total as u32 - 1);
    let table_size = 16384;
    let table_sectors = table_size / sector;
    let primary = sector * 2;
    let backup = (total - 1 - table_sectors) * sector;
    let mut table = vec![0; table_size];
    table[..16].copy_from_slice(&[1; 16]);
    table[16..32].copy_from_slice(&[2; 16]);
    put64(&mut table, 32, 40);
    put64(&mut table, 40, 100);
    for (i, c) in [b'W' as u16, 0xd800, 0].iter().enumerate() {
        table[56 + i * 2..58 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    b[primary..primary + table_size].copy_from_slice(&table);
    b[backup..backup + table_size].copy_from_slice(&table);
    for (current, other, table_lba) in
        [(1, total - 1, 2), (total - 1, 1, total - 1 - table_sectors)]
    {
        let h = current * sector;
        b[h..h + 8].copy_from_slice(b"EFI PART");
        put32(&mut b, h + 8, 0x10000);
        put32(&mut b, h + 12, 92);
        put64(&mut b, h + 24, current as u64);
        put64(&mut b, h + 32, other as u64);
        put64(&mut b, h + 40, (2 + table_sectors) as u64);
        put64(&mut b, h + 48, (total - 2 - table_sectors) as u64);
        b[h + 56..h + 72].fill(3);
        put64(&mut b, h + 72, table_lba as u64);
        put32(&mut b, h + 80, 128);
        put32(&mut b, h + 84, 128);
        put32(&mut b, h + 88, crc(&table));
        fix_header(&mut b, h);
    }
    b
}

#[test]
fn checked_ranges() {
    assert!(LbaRange::new(4, 4).is_err());
    assert!(LbaRange::from_inclusive(0, u64::MAX).is_err());
    assert!(Geometry::new(513, 512).is_err());
}
#[test]
fn owned_raw_metadata() {
    for sector in [512, 4096] {
        let bytes = gpt(sector);
        let disk = DiskLayout::inspect(&Memory(bytes.clone()), sector as u32).unwrap();
        let DiskLayout::Gpt(layout) = disk else {
            panic!()
        };
        assert_eq!(layout.primary_header(), &bytes[sector..sector * 2]);
        assert_eq!(layout.disk_guid(), [3; 16]);
        assert_eq!(layout.entries().len(), 128);
        assert_eq!(layout.entries()[0].raw_name()[1], 0xd800);
    }
}
#[test]
fn failed_edits_are_transactional() {
    let DiskLayout::Gpt(mut disk) = DiskLayout::inspect(&Memory(gpt(512)), 512).unwrap() else {
        panic!()
    };
    let original = disk.array().to_vec();
    assert!(disk.set_range(1, LbaRange::new(0, 100).unwrap()).is_err());
    assert_eq!(disk.array(), original);
    disk.set_range(1, LbaRange::new(45, 101).unwrap()).unwrap();
    assert_eq!(disk.entries()[0].range().unwrap().start(), 45);
}
#[test]
fn initialize_place_and_preserve_mbr_sector() {
    use partmgr::{
        guid::Guid,
        layout::{GptLayout, MbrLayout},
    };
    let geometry = Geometry::new(256 * 4096, 4096).unwrap();
    let id = Guid::from_bytes([3; 16]);
    let mut gpt = GptLayout::initialize(geometry, id, 128, 128).unwrap();
    let range = gpt.place(16, 8).unwrap();
    assert_eq!(range.start() % 8, 0);
    gpt.create(
        7,
        Guid::from_bytes([1; 16]),
        Guid::from_bytes([2; 16]),
        range,
    )
    .unwrap();
    assert!(
        gpt.create(
            8,
            Guid::from_bytes([1; 16]),
            Guid::from_bytes([2; 16]),
            LbaRange::new(100, 110).unwrap()
        )
        .is_err()
    );
    assert_eq!(gpt.entries()[6].range(), Some(range));
    let mut mbr = MbrLayout::initialize(geometry, 0x12345678);
    mbr.create(4, 0x83, LbaRange::new(20, 40).unwrap(), true)
        .unwrap();
    assert!(mbr.entries()[0].standalone_volume());
    assert_eq!(mbr.disk_signature(), 0x12345678);
    assert_eq!(&mbr.sector()[512..], vec![0; 4096 - 512]);
    let before = mbr.sector().to_vec();
    assert!(mbr.set_range(4, LbaRange::new(0, 10).unwrap()).is_err());
    assert_eq!(mbr.sector(), before);
}
#[test]
fn borrowed_view_is_bounded() {
    use partmgr::layout::PartitionView;
    let source = Memory(vec![7; 4096]);
    let view = PartitionView::new(
        &source,
        Geometry::new(4096, 512).unwrap(),
        LbaRange::new(1, 3).unwrap(),
    )
    .unwrap();
    assert_eq!(view.len(), 1024);
    assert!(view.read_exact_at(1024, &mut [0]).is_err());
    let mut bytes = [0; 4];
    view.read_exact_at(1020, &mut bytes).unwrap();
    assert_eq!(bytes, [7; 4]);
}
#[test]
fn opaque_unused_slots_and_dynamic_types_survive_inspection() {
    let sector = 512;
    let mut bytes = gpt(sector);
    let table_start = sector * 2;
    let backup = (256 - 1 - 32) * sector;
    bytes[table_start + 128 + 100] = 0xab;
    bytes[table_start..table_start + 16].copy_from_slice(&[
        0xaa, 0xc8, 0x08, 0x58, 0x8f, 0x7e, 0xe0, 0x42, 0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34, 0xcf,
        0xb3,
    ]);
    let table = bytes[table_start..table_start + 16384].to_vec();
    bytes[backup..backup + 16384].copy_from_slice(&table);
    for h in [sector, 255 * sector] {
        put32(&mut bytes, h + 88, crc(&table));
        fix_header(&mut bytes, h);
    }
    let DiskLayout::Gpt(mut disk) = DiskLayout::inspect(&Memory(bytes), 512).unwrap() else {
        panic!()
    };
    assert!(!disk.entries()[0].standalone_volume());
    assert_eq!(disk.entries()[1].raw()[100], 0xab);
    assert!(disk.rename(1, "new").is_err());
    assert_eq!(disk.entries()[1].raw()[100], 0xab);
}
#[test]
fn rejects_crc_bounds_and_inconsistent_copies() {
    for offset in [512 + 16, 1024 + 32, 255 * 512 + 56] {
        let mut bytes = gpt(512);
        bytes[offset] ^= 1;
        assert!(DiskLayout::inspect(&Memory(bytes), 512).is_err());
    }
}
fn replace_arrays(bytes: &mut [u8], table: &[u8]) {
    bytes[1024..1024 + 16384].copy_from_slice(table);
    bytes[(255 - 32) * 512..(255 - 32) * 512 + 16384].copy_from_slice(table);
    for h in [512, 255 * 512] {
        put32(bytes, h + 88, crc(table));
        fix_header(bytes, h);
    }
}
#[test]
fn semantic_invalidity_after_valid_checksums() {
    for case in 0..4 {
        let mut bytes = gpt(512);
        let mut table = bytes[1024..1024 + 16384].to_vec();
        match case {
            0 => {
                let first = table[..128].to_vec();
                table[128..256].copy_from_slice(&first);
            }
            1 => {
                let first = table[..128].to_vec();
                table[128..256].copy_from_slice(&first);
                table[144] = 9;
            }
            2 => put64(&mut table, 32, 1),
            _ => table[16..32].fill(0),
        }
        replace_arrays(&mut bytes, &table);
        assert!(DiskLayout::inspect(&Memory(bytes), 512).is_err());
    }
}
#[test]
fn extended_entries_are_lossless_and_header_extensions_refuse_mutation() {
    let mut bytes = gpt(512);
    let mut table = bytes[1024..1024 + 16384].to_vec();
    table[200] = 0xbe;
    table[256 + 127] = 0xef;
    for h in [512, 255 * 512] {
        put32(&mut bytes, h + 80, 64);
        put32(&mut bytes, h + 84, 256);
    }
    replace_arrays(&mut bytes, &table);
    assert!(DiskLayout::inspect(&Memory(bytes.clone()), 512).is_err());
    let DiskLayout::Gpt(mut disk) = DiskLayout::inspect_raw(&Memory(bytes.clone()), 512).unwrap()
    else {
        panic!()
    };
    assert!(disk.rename(1, "preserved").is_err());
    assert_eq!(disk.entries()[0].raw()[200], 0xbe);
    assert_eq!(disk.entries()[1].raw()[127], 0xef);
    for h in [512, 255 * 512] {
        put32(&mut bytes, h + 12, 96);
        bytes[h + 92] = 0xab;
        put32(&mut bytes, h + 16, 0);
        let sum = crc(&bytes[h..h + 96]);
        put32(&mut bytes, h + 16, sum);
    }
    let DiskLayout::Gpt(mut disk) = DiskLayout::inspect_raw(&Memory(bytes), 512).unwrap() else {
        panic!()
    };
    assert!(!disk.mutation_supported());
    assert!(disk.rename(1, "unsafe").is_err());
}
#[test]
fn basic_mbr_preserves_independent_boot_chs_signature_and_tail() {
    for sector in [512, 4096] {
        let mut bytes = mbr(256 * sector);
        for (i, b) in bytes[..440].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        put32(&mut bytes, 440, 0xdeadbeef);
        entry(&mut bytes, 3, 0x83, 40, 30);
        bytes[494] = 0x80;
        bytes[495..498].copy_from_slice(&[7, 8, 9]);
        bytes[499..502].copy_from_slice(&[10, 11, 12]);
        bytes[512..sector].fill(0xa9);
        let DiskLayout::Mbr(mut layout) =
            DiskLayout::inspect(&Memory(bytes.clone()), sector as u32).unwrap()
        else {
            panic!()
        };
        assert_eq!(layout.disk_signature(), 0xdeadbeef);
        assert_eq!(layout.entries()[0].raw()[..8], bytes[494..502]);
        layout.set_range(4, LbaRange::new(45, 70).unwrap()).unwrap();
        assert_eq!(&layout.sector()[..446], &bytes[..446]);
        assert_eq!(&layout.sector()[495..498], &[7, 8, 9]);
        assert_eq!(&layout.sector()[499..502], &[10, 11, 12]);
        assert_eq!(&layout.sector()[512..], &bytes[512..sector]);
        assert!(layout.set_type(4, 0x42, false).is_err());
    }
}
struct Sparse {
    length: u64,
    blocks: Vec<(u64, Vec<u8>)>,
    read_bytes: std::sync::atomic::AtomicU64,
}
impl ReadAt for Sparse {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        let end = o
            .checked_add(b.len() as u64)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if end > self.length {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        b.fill(0);
        for (start, data) in &self.blocks {
            let low = o.max(*start);
            let high = end.min(*start + data.len() as u64);
            if low < high {
                b[(low - o) as usize..(high - o) as usize]
                    .copy_from_slice(&data[(low - *start) as usize..(high - *start) as usize]);
            }
        }
        self.read_bytes
            .fetch_add(b.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
#[test]
fn sparse_large_geometry_uses_bounded_metadata_reads() {
    use partmgr::{guid::Guid, layout::GptLayout};
    for sector in [512, 4096] {
        let geometry = Geometry::new((1u64 << 45) * sector as u64, sector).unwrap();
        let g = GptLayout::initialize(geometry, Guid::from_bytes([3; 16]), 128, 128).unwrap();
        let source = Sparse {
            length: geometry.bytes(),
            blocks: vec![
                (0, g.mbr_sector().to_vec()),
                (sector as u64, g.primary_header().to_vec()),
                (
                    (geometry.sectors() - 1) * sector as u64,
                    g.backup_header().to_vec(),
                ),
                (g.primary_array_lba() * sector as u64, g.array().to_vec()),
                (g.backup_array_lba() * sector as u64, g.array().to_vec()),
            ],
            read_bytes: 0.into(),
        };
        assert!(DiskLayout::inspect(&source, sector).is_ok());
        assert!(source.read_bytes.load(std::sync::atomic::Ordering::Relaxed) < 65536);
    }
}
#[test]
fn exhaustive_small_alignment_and_checked_range_properties() {
    use partmgr::{guid::Guid, layout::GptLayout};
    for first in [0, 1, 10, u64::MAX - 1, u64::MAX] {
        for last in [0, 1, 10, u64::MAX - 1, u64::MAX] {
            let result = LbaRange::from_inclusive(first, last);
            assert_eq!(result.is_ok(), first <= last && last < u64::MAX);
            if let Ok(r) = result {
                assert_eq!(r.end() - 1, last);
                assert_eq!(r.start(), first);
            }
        }
    }
    for alignment in 1..32 {
        for count in 1..64 {
            let mut g = GptLayout::initialize(
                Geometry::new(256 * 512, 512).unwrap(),
                Guid::from_bytes([3; 16]),
                128,
                128,
            )
            .unwrap();
            let r = g.place(count, alignment).unwrap();
            assert_eq!(r.start() % alignment, 0);
            assert_eq!(r.sectors(), count);
            g.create(1, Guid::from_bytes([1; 16]), Guid::from_bytes([2; 16]), r)
                .unwrap();
            assert!(
                g.free_space()
                    .iter()
                    .all(|gap| gap.end() <= r.start() || gap.start() >= r.end())
            );
        }
    }
}
#[test]
fn reserved_attributes_raw_inspection_and_new_slot_prefix() {
    let mut bytes = gpt(512);
    let mut table = bytes[1024..1024 + 16384].to_vec();
    put64(&mut table, 48, 1 << 3);
    replace_arrays(&mut bytes, &table);
    assert!(DiskLayout::inspect(&Memory(bytes.clone()), 512).is_err());
    let DiskLayout::Gpt(mut disk) = DiskLayout::inspect_raw(&Memory(bytes), 512).unwrap() else {
        panic!()
    };
    assert!(!disk.mutation_supported());
    assert!(disk.rename(1, "refused").is_err());
    let mut bytes = gpt(512);
    let mut table = bytes[1024..1024 + 16384].to_vec();
    put64(&mut table, 128 + 48, u64::MAX);
    table[128 + 56] = b'X';
    replace_arrays(&mut bytes, &table);
    let DiskLayout::Gpt(mut disk) = DiskLayout::inspect(&Memory(bytes), 512).unwrap() else {
        panic!()
    };
    disk.create(
        2,
        partmgr::guid::Guid::from_bytes([1; 16]),
        partmgr::guid::Guid::from_bytes([4; 16]),
        LbaRange::new(110, 120).unwrap(),
    )
    .unwrap();
    assert_eq!(disk.entries()[1].attributes().bits(), 0);
    assert_eq!(disk.entries()[1].raw_name(), [0; 36]);
}

#[test]
fn batch_edits_match_sequential_edits_and_rollback_on_failure() {
    let DiskLayout::Gpt(original) = DiskLayout::inspect(&Memory(gpt(512)), 512).unwrap() else {
        panic!()
    };
    let mut sequential = original.clone();
    sequential.rename(1, "changed").unwrap();
    sequential
        .set_range(1, LbaRange::new(45, 101).unwrap())
        .unwrap();
    let mut batched = original;
    batched
        .edit_batch(|disk| {
            disk.rename(1, "changed")?;
            disk.set_range(1, LbaRange::new(45, 101).unwrap())
        })
        .unwrap();
    assert_eq!(batched.array(), sequential.array());
    assert_eq!(batched.primary_header(), sequential.primary_header());
    assert_eq!(batched.backup_header(), sequential.backup_header());
    let before = batched.array().to_vec();
    let header = batched.primary_header().to_vec();
    assert!(
        batched
            .edit_batch(|disk| {
                disk.rename(1, "must rollback")?;
                disk.set_range(1, LbaRange::new(0, 100).unwrap())
            })
            .is_err()
    );
    assert_eq!(batched.array(), before);
    assert_eq!(batched.primary_header(), header);
}
