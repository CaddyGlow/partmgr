use partmgr::PartitionTable;
use std::{io, sync::Arc};
use virtdisk::ReadAt;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
impl partmgr::storage::Storage for Bytes {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, offset, out)
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(data.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        self.0
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn partitions(data: &[u8]) {
    if data.len() > 1 << 20 {
        return;
    }
    let source: Arc<dyn ReadAt> = Arc::new(Bytes(data.to_vec()));
    for sector in [512, 4096] {
        if let Ok(table) = PartitionTable::read(Arc::clone(&source), sector) {
            for part in table.partitions().iter().take(128) {
                if let Ok(view) = table.select(part.index) {
                    let mut output = [0; 512];
                    let count = view.len().min(512) as usize;
                    let _ = view.read_exact_at(0, &mut output[..count]);
                }
            }
        }
    }
}

pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "partitions" => partitions(data),
        "guid" => guid(data),
        "layouts" => layouts(data),
        "payload" => payload(data),
        _ => return Err("unknown fuzz target"),
    }
    Ok(())
}
pub const TARGETS: &[&str] = &["partitions", "guid", "layouts", "payload"];
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    if target == "guid" {
        return vec![
            b"c12a7328-f81f-11d2-ba4b-00a0c93ec93b".to_vec(),
            vec![0; 16],
            vec![255; 36],
        ];
    }
    if target == "payload" {
        let disk = Bytes((0..64).collect());
        let mut recovery = Bytes(vec![0; 320]);
        partmgr::payload::CopyOperation::prepare(&disk, &mut recovery, 0, 4, 16, 8).unwrap();
        return vec![recovery.0, vec![0; 320], b"PMCOPY01".to_vec()];
    }
    let mut image = vec![0; 4096];
    image[510] = 0x55;
    image[511] = 0xaa;
    image[450] = 7;
    image[454..458].copy_from_slice(&1u32.to_le_bytes());
    image[458..462].copy_from_slice(&7u32.to_le_bytes());
    let source: Arc<dyn ReadAt> = Arc::new(Bytes(image.clone()));
    assert_eq!(
        PartitionTable::read(source, 512)
            .unwrap()
            .partitions()
            .len(),
        1
    );
    let mut extended = mbr(200 * 512);
    entry(&mut extended, 0, 0x0f, 10, 180);
    for lba in [10, 60] {
        extended[lba * 512 + 510..lba * 512 + 512].copy_from_slice(&[0x55, 0xaa]);
    }
    entry(&mut extended[10 * 512..], 0, 0x83, 1, 20);
    entry(&mut extended[10 * 512..], 1, 0x0f, 50, 130);
    entry(&mut extended[60 * 512..], 0, 0x83, 2, 25);
    let mut damaged = gpt(512);
    damaged[512] ^= 1;
    vec![
        image,
        gpt(512),
        gpt(4096),
        extended,
        damaged,
        vec![0; 4096],
        vec![],
    ]
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

/// GUID byte and canonical string invariants plus malformed text handling.
pub fn guid(data: &[u8]) {
    use partmgr::guid::Guid;
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(id) = text.parse::<Guid>()
    {
        assert_eq!(id.to_string().parse::<Guid>().unwrap(), id);
    }
    if let Some(bytes) = data.get(..16) {
        let id = Guid::from_bytes(bytes.try_into().unwrap());
        assert_eq!(Guid::from_gpt_bytes(id.to_gpt_bytes()), id);
    }
}
/// Owned decoder and transactional edit sequences on an independent GPT fixture.
pub fn layouts(data: &[u8]) {
    use partmgr::{
        guid::Guid,
        layout::{DiskLayout, LbaRange},
    };
    if data.len() > 1 << 20 {
        return;
    }
    let image = Bytes(data.to_vec());
    let _ = DiskLayout::inspect(&image, 512);
    let _ = partmgr::extended::ExtendedLayout::inspect(&image, 512, 128);
    if let Ok(report) = partmgr::recovery::RecoveryReport::inspect(&image, 512, &[]) {
        for source in [
            partmgr::recovery::RecoverySource::Primary,
            partmgr::recovery::RecoverySource::Backup,
        ] {
            let _ = report.repair_plan(&image, source);
        }
    }
    use partmgr::storage::{Barrier, WritePlan, WriteRange};
    if let Some(prefix) = data.get(..16) {
        let offset = u64::from_le_bytes(prefix[..8].try_into().unwrap());
        let length = u64::from_le_bytes(prefix[8..].try_into().unwrap());
        if let Ok(range) = WriteRange::new(offset, vec![0; 16], vec![1; 16]) {
            let stage = Barrier::new("fuzz", vec![range]).unwrap();
            let _ = WritePlan::new(length, vec![stage]);
        }
    }
    let DiskLayout::Gpt(mut layout) = DiskLayout::inspect(&Bytes(gpt(512)), 512).unwrap() else {
        unreachable!()
    };
    for instruction in data.chunks(4).take(64) {
        let old = layout.array().to_vec();
        let slot = u32::from(instruction.get(1).copied().unwrap_or(1));
        let result = match instruction[0] % 4 {
            0 => layout.delete(slot),
            1 => layout.rename(slot, &String::from_utf8_lossy(instruction)),
            2 => layout.set_identity(
                slot,
                Guid::from_bytes([instruction.get(2).copied().unwrap_or(0); 16]),
                Guid::from_bytes([1; 16]),
            ),
            _ => {
                let start = u64::from(instruction.get(2).copied().unwrap_or(0));
                let end = u64::from(instruction.get(3).copied().unwrap_or(0));
                match LbaRange::new(start, end) {
                    Ok(range) => layout.set_range(slot, range),
                    Err(e) => Err(e),
                }
            }
        };
        if result.is_err() {
            assert_eq!(layout.array(), old);
        }
    }
}
/// Untrusted persisted recovery records must decode without panics or allocations
/// controlled by unchecked disk lengths.
pub fn payload(data: &[u8]) {
    use partmgr::storage::Storage;
    struct Recovery(Vec<u8>);
    impl Storage for Recovery {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
            let start = usize::try_from(o).map_err(io::Error::other)?;
            let end = start
                .checked_add(b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            b.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::Unsupported.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    if data.len() <= 1 << 20 {
        let _ = partmgr::payload::CopyOperation::load(&Recovery(data.to_vec()), 4096);
    }
}

#[cfg(test)]
mod smoke {
    #[test]
    fn corpus_and_truncations_exercise_owned_harnesses() {
        for target in super::TARGETS {
            for seed in super::seeds(target) {
                super::run(target, &seed).unwrap();
                for end in [0, seed.len() / 2, seed.len().saturating_sub(1)] {
                    super::run(target, &seed[..end]).unwrap();
                }
                for offset in (0..seed.len()).step_by((seed.len() / 16).max(1)) {
                    let mut mutation = seed.clone();
                    mutation[offset] ^= 0xff;
                    super::run(target, &mutation).unwrap();
                }
            }
        }
    }
}
