#![cfg(feature = "std")]

use partmgr::{codec::edit_plan, layout::DiskLayout};
use std::io;
use virtdisk::ReadAt;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.0[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
}
#[test]
fn unchanged_mbr_has_exact_sector_preservation_plan() {
    let mut bytes = vec![0x5a; 4096 * 16];
    bytes[446..510].fill(0);
    bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
    let source = Bytes(bytes);
    let layout = DiskLayout::inspect(&source, 4096).unwrap();
    let plan = edit_plan(&layout, &layout).unwrap();
    assert_eq!(plan.stages().len(), 1);
    assert_eq!(plan.stages()[0].writes()[0].replacement().len(), 4096);
    assert_eq!(
        plan.stages()[0].writes()[0].replacement(),
        &source.0[..4096]
    );
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

impl partmgr::storage::Storage for Bytes {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.0[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn gpt_edit_backup_first_and_readback_validates_both_copies() {
    for sector in [512, 4096] {
        let mut disk = Bytes(gpt(sector));
        let old = DiskLayout::inspect(&disk, sector as u32).unwrap();
        let mut proposed = old.clone();
        let DiskLayout::Gpt(layout) = &mut proposed else {
            panic!("GPT")
        };
        layout.rename(1, "新😀").unwrap();
        let plan = edit_plan(&old, &proposed).unwrap();
        assert_eq!(plan.stages()[0].name(), "backup GPT");
        assert_eq!(plan.stages()[1].name(), "primary GPT");
        let payload = disk.0[40 * sector..101 * sector].to_vec();
        plan.commit(&mut disk).unwrap();
        let DiskLayout::Gpt(inspected) = DiskLayout::inspect(&disk, sector as u32).unwrap() else {
            panic!("GPT")
        };
        assert_eq!(inspected.entries()[0].raw_name()[0], 0x65b0);
        assert_eq!(&disk.0[40 * sector..101 * sector], payload.as_slice());
        // This independent fixture CRC routine validates emitted on-disk bytes.
        let mut header = disk.0[sector..sector + 92].to_vec();
        let checksum = u32::from_le_bytes(header[16..20].try_into().unwrap());
        header[16..20].fill(0);
        assert_eq!(crc(&header), checksum);
    }
}

#[test]
fn initialization_roundtrip_independent_crc_and_positions() {
    use partmgr::{
        codec::initialize_plan,
        guid::Guid,
        layout::{Geometry, GptLayout},
    };
    for sector in [512, 4096] {
        let geometry = Geometry::new(256 * sector, sector as u32).unwrap();
        let layout = DiskLayout::Gpt(
            GptLayout::initialize(geometry, Guid::from_bytes([0x12; 16]), 128, 128).unwrap(),
        );
        let mut disk = Bytes(vec![0xa5; geometry.bytes() as usize]);
        let before = disk.0.clone();
        let plan = initialize_plan(&disk, &layout).unwrap();
        assert_eq!(plan.stages().len(), 3);
        plan.commit(&mut disk).unwrap();
        let DiskLayout::Gpt(actual) = DiskLayout::inspect(&disk, sector as u32).unwrap() else {
            panic!("GPT")
        };
        assert_eq!(actual.disk_guid(), [0x12; 16]);
        let array = actual.array();
        assert_eq!(
            crc(array),
            u32::from_le_bytes(
                disk.0[sector as usize + 88..sector as usize + 92]
                    .try_into()
                    .unwrap()
            )
        );
        let untouched = actual.usable();
        assert_eq!(
            &disk.0[(untouched.start() * sector) as usize..(untouched.end() * sector) as usize],
            &before[(untouched.start() * sector) as usize..(untouched.end() * sector) as usize]
        );
    }
}

struct Interrupt {
    disk: Bytes,
    events: usize,
    fail: usize,
}
impl partmgr::storage::Storage for Interrupt {
    fn len(&self) -> io::Result<u64> {
        Ok(self.disk.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(&self.disk, offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.events += 1;
        if self.events == self.fail {
            return Err(io::Error::other("interruption"));
        }
        partmgr::storage::Storage::write_at(&mut self.disk, offset, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.events += 1;
        if self.events == self.fail {
            Err(io::Error::other("flush interruption"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn every_gpt_commit_boundary_has_explicit_recovery_outcome() {
    use partmgr::recovery::{RecoveryReport, RecoverySource};
    for fail in 1..=6 {
        let mut disk = Interrupt {
            disk: Bytes(gpt(512)),
            events: 0,
            fail,
        };
        let old = DiskLayout::inspect(&disk.disk, 512).unwrap();
        let mut changed = old.clone();
        let DiskLayout::Gpt(g) = &mut changed else {
            panic!("GPT")
        };
        g.rename(1, "changed").unwrap();
        let plan = edit_plan(&old, &changed).unwrap();
        assert!(plan.commit(&mut disk).is_err());
        let report = RecoveryReport::inspect(&disk.disk, 512, &[]).unwrap();
        // Backup array/header are updated before either primary structure.
        assert_eq!(report.primary().is_ok(), fail != 5);
        assert_eq!(report.backup().is_ok(), fail != 2);
        let selected = if fail >= 4 {
            RecoverySource::Backup
        } else {
            RecoverySource::Primary
        };
        let repair = report.repair_plan(&disk.disk, selected).unwrap();
        repair.commit(&mut disk.disk).unwrap();
        DiskLayout::inspect(&disk.disk, 512).unwrap();
    }
}
