use partmgr::partition::{PartitionTable, Scheme};
use std::{
    io::{self, Write},
    sync::Arc,
};
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
fn parse(bytes: Vec<u8>, sector: u32) -> io::Result<PartitionTable> {
    PartitionTable::read(Arc::new(Memory(bytes)), sector)
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
fn gpt_validates_both_sector_sizes_preserves_utf16_and_bounds_views() {
    for sector in [512, 4096] {
        let table = parse(gpt(sector), sector as u32).unwrap();
        assert_eq!(table.scheme(), Scheme::Gpt);
        assert_eq!(table.partitions()[0].name, vec![b'W' as u16, 0xd800]);
        let view = table.select(1).unwrap();
        assert_eq!(view.len(), 61 * sector as u64);
        assert!(view.read_exact_at(view.len(), &mut [0]).is_err());
        assert!(table.select(2).is_err());
    }
}
#[test]
fn gpt_rejects_corrupt_headers_and_arrays_on_either_copy() {
    for offset in [512 + 56, 255 * 512 + 56, 1024 + 56, 223 * 512 + 56] {
        let mut b = gpt(512);
        b[offset] ^= 1;
        assert!(parse(b, 512).is_err(), "offset {offset}");
    }
}
#[test]
fn gpt_rejects_valid_crc_but_inconsistent_backup() {
    let mut b = gpt(512);
    b[255 * 512 + 56] ^= 1;
    fix_header(&mut b, 255 * 512);
    assert!(parse(b, 512).is_err());
}
#[test]
fn gpt_rejects_overflowing_metadata_ranges_and_allocation_limits() {
    for (offset, value) in [(72, u64::MAX), (40, u64::MAX)] {
        let mut b = gpt(512);
        put64(&mut b, 512 + offset, value);
        fix_header(&mut b, 512);
        assert!(parse(b, 512).is_err());
    }
    let mut b = gpt(512);
    put32(&mut b, 512 + 80, u32::MAX);
    fix_header(&mut b, 512);
    assert!(parse(b, 512).is_err());
}
fn mutate_tables(mut b: Vec<u8>, mutation: impl Fn(&mut [u8])) -> Vec<u8> {
    for start in [1024, 223 * 512] {
        mutation(&mut b[start..start + 16384]);
    }
    for (header, table) in [(512, 1024), (255 * 512, 223 * 512)] {
        let crc = crc(&b[table..table + 16384]);
        put32(&mut b, header + 88, crc);
        fix_header(&mut b, header);
    }
    b
}
#[test]
fn gpt_rejects_partition_overlap_duplicate_guids_and_out_of_bounds() {
    let b = mutate_tables(gpt(512), |t| {
        let first = t[..128].to_vec();
        t[128..256].copy_from_slice(&first);
        t[144..160].fill(4);
    });
    assert!(parse(b, 512).is_err());
    let b = mutate_tables(gpt(512), |t| {
        let first = t[..128].to_vec();
        t[128..256].copy_from_slice(&first);
        put64(t, 160, 110);
        put64(t, 168, 120);
    });
    assert!(parse(b, 512).is_err());
    let b = mutate_tables(gpt(512), |t| put64(t, 40, 255));
    assert!(parse(b, 512).is_err());
}
#[test]
fn rejects_hybrid_and_malformed_protective_mbr() {
    let mut b = gpt(512);
    entry(&mut b, 1, 7, 40, 20);
    assert!(parse(b, 512).is_err());
    let mut b = gpt(512);
    put32(&mut b, 446 + 12, 254);
    assert!(parse(b, 512).is_err());
}
#[test]
fn mbr_preserves_slot_and_rejects_overlap_extended_dynamic_and_disk_overrun() {
    let mut b = mbr(256 * 512);
    entry(&mut b, 2, 7, 20, 30);
    let table = parse(b.clone(), 512).unwrap();
    assert_eq!(table.partitions()[0].index, 3);
    assert_eq!(table.scheme(), Scheme::Mbr);
    entry(&mut b, 1, 7, 40, 10);
    assert!(parse(b, 512).is_err());
    for typ in [5, 15, 0x85, 0x42] {
        let mut b = mbr(256 * 512);
        entry(&mut b, 0, typ, 20, 30);
        assert_eq!(
            parse(b, 512).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
    }
    let mut b = mbr(256 * 512);
    entry(&mut b, 0, 7, 250, 30);
    assert!(parse(b, 512).is_err());
}
#[test]
fn rejects_unknown_sector_size_bad_signature_and_partial_sector() {
    assert!(parse(mbr(512 * 256), 1024).is_err());
    assert!(parse(mbr(513), 512).is_err());
    assert!(parse(vec![0; 512 * 256], 512).is_err());
}
#[test]
#[ignore = "requires independent util-linux sfdisk partition writer"]
fn sfdisk_generated_gpt_is_accepted_with_exact_partition_positions() {
    use sha2::{Digest, Sha256};
    use std::process::{Command, Stdio};
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(64 * 1024 * 1024).unwrap();
    let mut child = Command::new("sfdisk")
        .arg(file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"label: gpt\nstart=2048,size=4096,type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7,name=Windows\nstart=8192,size=2048,type=DE94BBA4-06D1-4D40-A16A-BFD50179D6AC,name=Recovery\n").unwrap();
    assert!(child.wait().unwrap().success());
    let before = Sha256::digest(std::fs::read(file.path()).unwrap());
    let table =
        PartitionTable::read(Arc::new(virtdisk::RawDisk::open(file.path()).unwrap()), 512).unwrap();
    assert_eq!(
        table
            .partitions()
            .iter()
            .map(|p| (p.first_lba, p.sectors))
            .collect::<Vec<_>>(),
        vec![(2048, 4096), (8192, 2048)]
    );
    assert_eq!(Sha256::digest(std::fs::read(file.path()).unwrap()), before);
}

#[test]
#[ignore = "requires independent util-linux sfdisk partition writer"]
fn sfdisk_generated_4096_sector_gpt_preserves_positions_and_byte_views() {
    use sha2::{Digest, Sha256};
    use std::io::{Seek, SeekFrom};
    use std::process::{Command, Stdio};
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(64 * 1024 * 1024).unwrap();
    let mut child = Command::new("sfdisk")
        .args(["--sector-size", "4096"])
        .arg(file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"label: gpt\nstart=256,size=1024,type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7,name=Windows\nstart=1536,size=512,type=DE94BBA4-06D1-4D40-A16A-BFD50179D6AC,name=Recovery\n").unwrap();
    assert!(child.wait().unwrap().success());
    let mut marker_file = file.as_file().try_clone().unwrap();
    marker_file.seek(SeekFrom::Start(256 * 4096 + 17)).unwrap();
    marker_file.write_all(b"four-k-sector").unwrap();
    let before = Sha256::digest(std::fs::read(file.path()).unwrap());
    let table = PartitionTable::read(
        Arc::new(virtdisk::RawDisk::open(file.path()).unwrap()),
        4096,
    )
    .unwrap();
    assert_eq!(table.scheme(), Scheme::Gpt);
    assert_eq!(
        table
            .partitions()
            .iter()
            .map(|p| (p.first_lba, p.sectors))
            .collect::<Vec<_>>(),
        vec![(256, 1024), (1536, 512)]
    );
    assert_eq!(table.select(1).unwrap().len(), 1024 * 4096);
    assert_eq!(table.select(2).unwrap().len(), 512 * 4096);
    let mut marker = [0; 13];
    table
        .select(1)
        .unwrap()
        .read_exact_at(17, &mut marker)
        .unwrap();
    assert_eq!(&marker, b"four-k-sector");
    assert!(
        PartitionTable::read(Arc::new(virtdisk::RawDisk::open(file.path()).unwrap()), 512,)
            .is_err()
    );
    assert_eq!(Sha256::digest(std::fs::read(file.path()).unwrap()), before);
}

#[test]
#[ignore = "requires independent util-linux sfdisk partition writer"]
fn sfdisk_generated_basic_mbr_preserves_slots_positions_and_byte_views() {
    use sha2::{Digest, Sha256};
    use std::io::{Seek, SeekFrom};
    use std::process::{Command, Stdio};
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(64 * 1024 * 1024).unwrap();
    let mut child = Command::new("sfdisk")
        .arg(file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"label: dos\nstart=2048,size=4096,type=7,bootable\nstart=8192,size=2048,type=7\n",
        )
        .unwrap();
    assert!(child.wait().unwrap().success());
    let mut marker_file = file.as_file().try_clone().unwrap();
    marker_file.seek(SeekFrom::Start(8192 * 512 + 31)).unwrap();
    marker_file.write_all(b"basic-mbr").unwrap();
    let before = Sha256::digest(std::fs::read(file.path()).unwrap());
    let table =
        PartitionTable::read(Arc::new(virtdisk::RawDisk::open(file.path()).unwrap()), 512).unwrap();
    assert_eq!(table.scheme(), Scheme::Mbr);
    assert_eq!(
        table
            .partitions()
            .iter()
            .map(|p| (p.index, p.first_lba, p.sectors))
            .collect::<Vec<_>>(),
        vec![(1, 2048, 4096), (2, 8192, 2048)]
    );
    assert_eq!(table.select(1).unwrap().len(), 4096 * 512);
    assert_eq!(table.select(2).unwrap().len(), 2048 * 512);
    let mut marker = [0; 9];
    table
        .select(2)
        .unwrap()
        .read_exact_at(31, &mut marker)
        .unwrap();
    assert_eq!(&marker, b"basic-mbr");
    assert_eq!(Sha256::digest(std::fs::read(file.path()).unwrap()), before);
}

#[test]
fn gpt_rejects_reserved_header_padding_and_wrong_reciprocal_locations() {
    let mut b = gpt(512);
    b[512 + 92] = 1;
    assert!(parse(b, 512).is_err());
    let mut b = gpt(512);
    put64(&mut b, 255 * 512 + 32, 2);
    fix_header(&mut b, 255 * 512);
    assert!(parse(b, 512).is_err());
}

#[test]
fn gpt_rejects_windows_dynamic_disk_types_and_zero_unique_guids() {
    let b = mutate_tables(gpt(512), |t| t[16..32].fill(0));
    assert!(parse(b, 512).is_err());
    for typ in [
        [
            0xaa, 0xc8, 0x08, 0x58, 0x8f, 0x7e, 0xe0, 0x42, 0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34,
            0xcf, 0xb3,
        ],
        [
            0xa0, 0x60, 0x9b, 0xaf, 0x31, 0x14, 0x62, 0x4f, 0xbc, 0x68, 0x33, 0x11, 0x71, 0x4a,
            0x69, 0xad,
        ],
    ] {
        let b = mutate_tables(gpt(512), |t| t[..16].copy_from_slice(&typ));
        assert_eq!(
            parse(b, 512).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
    }
}

#[test]
fn accepts_windows_saturated_protective_mbr_with_independently_validated_gpt() {
    let mut b = gpt(512);
    put32(&mut b, 446 + 12, u32::MAX);
    assert_eq!(parse(b.clone(), 512).unwrap().scheme(), Scheme::Gpt);
    b[255 * 512 + 56] ^= 1;
    assert!(parse(b, 512).is_err());
}
