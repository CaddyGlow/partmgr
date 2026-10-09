mod apfs;
mod bitlocker;
mod ext_profile;
mod fixtures;
mod flash;
mod hfs;
mod hfsplus;
mod jffs2;
mod jffs2_edit;
mod jfs;
#[path = "../../tests/fixtures/ntfs_clean.rs"]
mod ntfs_clean_fixture;
#[path = "../../tests/fixtures/ntfs_index.rs"]
mod ntfs_index_fixture;
#[path = "../../tests/fixtures/xfs_clean.rs"]
mod xfs_fixture;
use partmgr::PartitionTable;
use partmgr::io;
use partmgr::io::ReadAt;
use std::sync::Arc;
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

/// Declared logical flash geometry, transition and bounded failure-model oracles.
pub fn flash(data: &[u8]) {
    flash::run(data);
}

pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "bitlocker" => bitlocker(data),
        "bitlocker-reader" => bitlocker_reader(data),
        "partitions" => partitions(data),
        "guid" => guid(data),
        "layouts" => layouts(data),
        "payload" => payload(data),
        "fat" => fat(data),
        "ext" => ext(data),
        "exfat" => exfat(data),
        "ntfs" => ntfs(data),
        "xfs" => xfs(data),
        "jffs2" => jffs2(data),
        "hfsplus" => hfsplus(data),
        "hfs" => hfs(data),
        "jfs" => jfs(data),
        "apfs" => apfs(data),
        "flash" => flash(data),
        "undo" => undo(data),
        _ => return Err("unknown fuzz target"),
    }
    Ok(())
}
pub const TARGETS: &[&str] = &[
    "bitlocker",
    "bitlocker-reader",
    "partitions",
    "guid",
    "layouts",
    "payload",
    "fat",
    "ext",
    "exfat",
    "ntfs",
    "xfs",
    "jffs2",
    "hfsplus",
    "hfs",
    "jfs",
    "apfs",
    "flash",
    "undo",
];
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    if matches!(target, "bitlocker" | "bitlocker-reader") {
        return bitlocker::seeds();
    }
    if target == "apfs" {
        return apfs::seeds();
    }
    if target == "jfs" {
        return jfs::seeds();
    }
    if target == "hfs" {
        return hfs::seeds();
    }
    if target == "hfsplus" {
        return hfsplus::seeds();
    }
    if target == "jffs2" {
        return jffs2::seeds();
    }
    if target == "flash" {
        return flash::seeds();
    }
    if target == "xfs" {
        let clean = xfs_fixture::xfs_seed();
        let mut superblock = clean.clone();
        superblock[224] ^= 1;
        let mut secondary = clean.clone();
        secondary[64 * 4096 + 224] ^= 1;
        let mut inode = clean.clone();
        inode[8 * 4096 + 3 * 512 + 100] ^= 1;
        return vec![
            clean.clone(),
            superblock,
            secondary,
            inode,
            clean[..512].to_vec(),
            vec![0; 512],
        ];
    }
    if target == "ntfs" {
        let clean = fixtures::ntfs_seed();
        let mut dirty = clean.clone();
        dirty[2048 + 3 * 1024 + 56 + 24 + 10] = 1;
        let mut torn = clean.clone();
        torn[2048 + 25 * 1024 + 510] ^= 1;
        let mut runs = clean.clone();
        runs[2048 + 25 * 1024 + 56 + 72] = 0x19;
        let index = ntfs_index_fixture::ntfs_index_seed();
        let mut index_torn = index.clone();
        index_torn[400 * 512 + 510] ^= 1;
        let mut index_bitmap = index.clone();
        index_bitmap[2048 + 5 * 1024 + 256] = 0;
        let mut index_vcn = index.clone();
        index_vcn[2048 + 5 * 1024 + 136] = 2;
        let audit = ntfs_clean_fixture::ntfs_audit_seed();
        let mut audit_mirror = audit.clone();
        audit_mirror[500 * 512 + 510] ^= 1;
        let bitmap = 2048
            + 6 * 1024
            + 56
            + ntfs_clean_fixture::resident(0x30, &ntfs_clean_fixture::name_value("$Bitmap", 5), 2)
                .len()
            + 24;
        let mut audit_lost = audit.clone();
        audit_lost[bitmap + 700 / 8] |= 1 << (700 % 8);
        let mut audit_free = audit.clone();
        audit_free[bitmap + 90 / 8] &= !(1 << (90 % 8));
        return vec![
            clean,
            dirty,
            torn,
            runs,
            vec![0; 512],
            index,
            index_torn,
            index_vcn,
            index_bitmap,
            audit,
            audit_mirror,
            audit_lost,
            audit_free,
        ];
    }
    if target == "undo" {
        return undo_seeds();
    }

    if target == "exfat" {
        let mut bytes = vec![0; 24 * 512];
        bytes[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        bytes[3..11].copy_from_slice(b"EXFAT   ");
        bytes[72..80].copy_from_slice(&2048u64.to_le_bytes());
        for (offset, value) in [(80, 24u32), (84, 16), (88, 40), (92, 2008), (96, 2)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[105] = 1;
        bytes[108] = 9;
        bytes[110] = 1;
        bytes[112] = 255;
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        for sector in 1..=8 {
            bytes[(sector + 1) * 512 - 4..(sector + 1) * 512]
                .copy_from_slice(&0xaa550000u32.to_le_bytes());
        }
        bytes.copy_within(..12 * 512, 12 * 512);
        for first in [0, 12 * 512] {
            let mut checksum = 0u32;
            for index in 0..11 * 512 {
                if matches!(index, 106 | 107 | 112) {
                    continue;
                }
                checksum = ((checksum >> 1) | ((checksum & 1) << 31))
                    .wrapping_add(u32::from(bytes[first + index]));
            }
            for offset in (first + 11 * 512..first + 12 * 512).step_by(4) {
                bytes[offset..offset + 4].copy_from_slice(&checksum.to_le_bytes());
            }
        }
        return vec![
            bytes,
            include_bytes!("../fixtures/exfat-basic-prefix.bin").to_vec(),
        ];
    }
    if target == "ext" {
        let mut bytes = vec![0; 64 * 1024];
        for (offset, value) in [
            (1024, 16u32),
            (1028, 64),
            (1044, 1),
            (1056, 64),
            (1060, 64),
            (1064, 16),
            (1100, 1),
            (1120, 2),
            (2048, 3),
            (2052, 4),
            (2056, 5),
            (5252, 1024),
            (5288, 7),
            (5380, 1024),
            (5416, 8),
            (7168, 2),
            (7180, 2),
            (7192, 3),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (1080, 0xef53u16),
            (1082, 1),
            (1112, 128),
            (5248, 0x41ed),
            (5274, 2),
            (5376, 0x81a4),
            (5402, 1),
            (7172, 12),
            (7184, 12),
            (7196, 1000),
        ] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[3072..3080].fill(255);
        bytes[4096] = 6;
        bytes[7174] = 1;
        bytes[7175] = 2;
        bytes[7176] = b'.';
        bytes[7186] = 2;
        bytes[7187] = 2;
        bytes[7188..7190].copy_from_slice(b"..");
        bytes[7198] = 2;
        bytes[7199] = 1;
        bytes[7200..7202].copy_from_slice(&[b'x', 255]);
        bytes[8192..9216].fill(42);
        let mut audited = bytes.clone();
        audited.copy_within(5376..5504, 6400);
        audited[5376..5504].fill(0);
        for (offset, value) in [
            (1036, 55u32),
            (1040, 5),
            (1108, 11),
            (5276, 2),
            (6428, 2),
            (7192, 11),
        ] {
            audited[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(2060, 55u16), (2062, 5), (2064, 1)] {
            audited[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        audited[3072..4096].fill(0xff);
        audited[3073..3079].fill(0);
        audited[3079] = 0x80;
        audited[4096..5120].fill(0xff);
        audited[4097] = 7;
        let mut seeds = vec![bytes, audited, vec![0; 2048], ext_profile::seed()];
        seeds.extend(ext_profile::modern_seeds());
        return seeds;
    }
    if target == "fat" {
        // Independent tiny FAT12 fixture; no production formatter is involved.
        let mut image = vec![0; 512 * 128];
        image[0..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
        image[11..13].copy_from_slice(&512u16.to_le_bytes());
        image[13] = 1;
        image[14..16].copy_from_slice(&1u16.to_le_bytes());
        image[16] = 1;
        image[17..19].copy_from_slice(&16u16.to_le_bytes());
        image[19..21].copy_from_slice(&128u16.to_le_bytes());
        image[21] = 0xf8;
        image[22..24].copy_from_slice(&1u16.to_le_bytes());
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[512..518].copy_from_slice(&[0xf8, 0xff, 0xff, 0xff, 0x0f, 0]);
        image[1024..1035].copy_from_slice(b"PAYLOAD BIN");
        image[1035] = 0x20;
        image[1050..1052].copy_from_slice(&2u16.to_le_bytes());
        image[1052..1056].copy_from_slice(&512u32.to_le_bytes());
        image[1536..2048].fill(0x76);
        return vec![image, vec![0; 512]];
    }
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

pub fn fat(data: &[u8]) {
    use partmgr::{
        fs_core::{Budget, Cancellation, Resources},
        fs_fat::FatVolume,
    };
    if data.len() > 1 << 20 {
        return;
    }
    let source: Arc<dyn ReadAt> = Arc::new(Bytes(data.to_vec()));
    if let Ok(volume) = FatVolume::open(source.clone()) {
        let resources = Resources {
            memory: Budget::new(256 * 1024),
            cancellation: Cancellation::default(),
        };
        let _ = partmgr::fs_fat_audit::audit_fat(
            source,
            partmgr::fs_fat_audit::FatAuditLimits {
                clusters: 512,
                entries: 64,
                directory_slots: 64,
                findings: 32,
            },
            &resources,
        );
        if let Ok(directory) = volume.root_directory(16, 64, &resources) {
            for entry in directory.entries().iter().take(8) {
                let _ = directory.lookup(entry.name());
                if entry.is_directory() {
                    let _ = volume.read_directory(entry, 16, 64, &resources);
                } else if let Ok(file) = volume.open_entry(entry, 16, &resources) {
                    use partmgr::fs_core::FileRead;
                    let mut buffer = [0; 37];
                    let _ = file.read_at(0, &mut buffer, &resources);
                }
            }
        }
        for first in [0, 2] {
            for length in [0, 512, 1024] {
                if let Ok(file) = volume.open_file(first, length, 16, &resources) {
                    let mut buffer = [0u8; 37];
                    for offset in [0, u64::from(length) / 2, u64::from(length), u64::MAX] {
                        let _ = file.read_at(offset, &mut buffer, &resources);
                    }
                }
            }
        }
    }
    let _ = fat_edit(data);
}

// Separate owned in-memory stores: no reader aliases survive into the edit session.
fn fat_edit(data: &[u8]) -> bool {
    use partmgr::{
        fs_core::{Budget, Cancellation, NativeName, Resources},
        fs_fat_audit::FatAuditLimits,
        fs_fat_edit::{
            FatEditBinding, FatEditLimits, FatEditRegion, FatEditState, FatEditor, FatReplacement,
        },
        fs_undo::UndoLimits,
    };
    if data.len() < 512 || data.len() > 1 << 20 {
        return false;
    }
    let r = Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = FatEditLimits {
        audit: FatAuditLimits {
            clusters: 512,
            entries: 32,
            directory_slots: 64,
            findings: 32,
        },
        file_clusters: 16,
        affected_bytes: 64,
        replacements: 4,
        work: 64,
        undo: UndoLimits {
            patches: 32,
            body_bytes: 4096,
        },
    };
    let result = (|| {
        let mut editor = FatEditor::open(
            Bytes(data.to_vec()),
            Bytes(vec![0; 8192]),
            FatEditRegion {
                offset: 0,
                length: data.len() as u64,
            },
            FatEditBinding {
                volume: [0x31; 32],
                generation: 1,
            },
            limits,
            &r,
        )
        .ok()?;
        let file = editor
            .open_file(&[NativeName::Bytes(b"PAYLOAD BIN".to_vec())], &r)
            .ok()?;
        if file.is_empty() {
            return None;
        }
        let random = u64::from_le_bytes(data[..8].try_into().unwrap());
        let at = random % file.len();
        let n = (file.len() - at).min(13) as usize;
        let replacement = [0xa5; 13];
        let batch = editor
            .plan_batch(
                &[FatReplacement {
                    file: &file,
                    offset: at,
                    bytes: &replacement[..n],
                }],
                &r,
            )
            .ok()?;
        let mut expected = data.to_vec();
        for patch in batch.patches() {
            let at = patch.offset() as usize;
            assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
            expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
        }
        if editor.commit(batch, [0x41; 16], &r).is_err() {
            let _ = editor.recover(&r);
            return None;
        }
        let mut out = [0; 13];
        assert!(editor.read_at(&file, at, &mut out[..n], &r).is_err());
        drop(file);
        let fresh = editor
            .open_file(&[NativeName::Bytes(b"PAYLOAD BIN".to_vec())], &r)
            .unwrap();
        assert_eq!(editor.read_at(&fresh, at, &mut out[..n], &r).unwrap(), n);
        assert_eq!(&out[..n], &replacement[..n]);
        drop(fresh);
        let (target, _, state) = editor.into_stores();
        assert_eq!(state, FatEditState::Ready);
        assert_eq!(target.0, expected);
        Some(())
    })()
    .is_some();
    assert_eq!(r.memory.used(), 0);
    result
}

pub fn ext(data: &[u8]) {
    use partmgr::{
        fs_core::{Budget, Cancellation, Resources},
        fs_ext::ExtVolume,
        fs_ext_audit::{ExtAuditLimits, audit},
        fs_ext_tree::ExtTreeSource,
    };
    if data.len() > 1 << 20 {
        return;
    }
    let resources = Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    };
    let source: Arc<dyn ReadAt> = Arc::new(Bytes(data.to_vec()));
    if let Ok(volume) = ExtVolume::open(source, &resources) {
        if let Ok(directory) = volume.directory(2, 64, 64, &resources) {
            for entry in directory.entries().iter().take(8) {
                if let Ok(file) = volume.open_file(entry.inode, 64, &resources) {
                    let mut buffer = [0u8; 37];
                    for offset in [0, 1023, file.len() / 2, file.len(), u64::MAX] {
                        let _ = file.read_at(offset, &mut buffer, &resources);
                    }
                }
            }
        }
        let _ = audit(
            &volume,
            ExtAuditLimits {
                blocks: 128,
                inodes: 64,
                work: 65536,
                directory_blocks: 64,
                directory_entries: 128,
                findings: 32,
            },
            &resources,
        );
        let _ = ExtTreeSource::inventory(volume, 32, 64, 64, 64, &resources);
    }
    assert_eq!(resources.memory.used(), 0);
}

/// A deterministic zero-padded logical image; input bytes only supply its prefix.
struct ExfatInput(Vec<u8>);
impl ReadAt for ExfatInput {
    fn len(&self) -> u64 {
        (2 << 20).max(self.0.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.len())
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        out.fill(0);
        if at < self.0.len() as u64 {
            let start = at as usize;
            let count = out.len().min(self.0.len() - start);
            out[..count].copy_from_slice(&self.0[start..start + count]);
        }
        Ok(())
    }
}
pub fn exfat(data: &[u8]) {
    use partmgr::{
        fs_core::{Budget, Cancellation, FileRead, Resources},
        fs_exfat::ExfatBoot,
        fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    };
    if data.len() > 1 << 20 {
        return;
    }
    let r = Resources {
        memory: Budget::new(2 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let source: Arc<dyn ReadAt> = Arc::new(ExfatInput(data.to_vec()));
    if let Ok(boot) = ExfatBoot::inspect(&*source, &r) {
        for cluster in [
            0,
            1,
            2,
            boot.clusters,
            boot.clusters.saturating_add(1),
            u32::MAX,
        ] {
            let _ = boot.cluster_offset(cluster);
        }
    }
    let _ = partmgr::fs_exfat_audit::audit_exfat(
        source.clone(),
        exfat_read_limits(),
        exfat_audit_limits(),
        &r,
    );
    if let Ok(volume) = ExfatVolume::open(
        source,
        ExfatReadLimits {
            max_chain_clusters: 64,
            max_directory_slots: 64,
            max_upcase_bytes: 131072,
        },
        &r,
    ) && let Ok(root) = volume.root_directory(&r)
    {
        for entry in root.entries().iter().take(8) {
            if entry.is_directory() {
                let _ = volume.read_directory(entry, &r);
            } else if let Ok(file) = volume.open_file(entry, &r) {
                let mut output = [0; 37];
                for at in [0, 511, entry.valid_data_length(), file.len(), u64::MAX] {
                    let _ = file.read_at(at, &mut output, &r);
                }
            }
        }
    }
    assert_eq!(r.memory.used(), 0);
}

fn exfat_read_limits() -> partmgr::fs_exfat_volume::ExfatReadLimits {
    partmgr::fs_exfat_volume::ExfatReadLimits {
        max_chain_clusters: 64,
        max_directory_slots: 64,
        max_upcase_bytes: 131072,
    }
}
fn exfat_audit_limits() -> partmgr::fs_exfat_audit::ExfatAuditLimits {
    partmgr::fs_exfat_audit::ExfatAuditLimits {
        clusters: 4096,
        entries: 32,
        directory_slots: 256,
        work: 16384,
        findings: 32,
    }
}
fn ntfs_audit_limits() -> partmgr::fs_ntfs_audit::NtfsAuditLimits {
    partmgr::fs_ntfs_audit::NtfsAuditLimits {
        clusters: 2048,
        records: 128,
        attributes: 1024,
        ranges: 256,
        entries: 128,
        index_blocks: 32,
        depth: 8,
        work: 50000,
        findings: 64,
        free_ranges: 64,
    }
}
fn xfs_read_limits() -> partmgr::fs_xfs::XfsReadLimits {
    partmgr::fs_xfs::XfsReadLimits {
        allocation_groups: 8,
        inodes: 256,
        metadata_records: 4096,
        extent_records: 256,
        work: 65536,
        log_bytes: 65536,
    }
}
fn xfs_audit_limits() -> partmgr::fs_xfs_audit::XfsAuditLimits {
    partmgr::fs_xfs_audit::XfsAuditLimits {
        blocks: 4096,
        entries: 128,
        work: 65536,
        findings: 64,
    }
}
/// XFS v5 leaf AG trees, checksums, clean log, ownership and deferred native tree access.
pub fn xfs(data: &[u8]) {
    use partmgr::{
        fs_core::{Budget, Cancellation, FileRead, Resources, StreamKind, TreeSource},
        fs_xfs::XfsVolume,
        fs_xfs_tree::{XfsTreeLimits, XfsTreeSource},
    };
    if data.len() > 1 << 20 {
        return;
    }
    let r = Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    };
    if let Ok(volume) = XfsVolume::open(Arc::new(Bytes(data.to_vec())), xfs_read_limits(), &r) {
        if let Ok(report) = partmgr::fs_xfs_audit::audit(&volume, xfs_audit_limits(), &r) {
            if !report.is_clean() || !report.is_complete() {
                assert!(report.free_ranges().is_empty());
            }
            drop(report);
        }
        let random = data
            .get(..8)
            .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
        for number in [volume.geometry().root_inode(), 67, random % 256, u64::MAX] {
            if let Ok(file) = volume.open_file(number, &r) {
                let mut out = [0; 73];
                let _ = file.visit_extents(&r, &mut |_| Ok(()));
                for at in [0, 4095, 4096, random, file.len(), u64::MAX] {
                    if let Ok(n) = file.read_at(at, &mut out, &r) {
                        assert!(n <= out.len());
                        if at >= file.len() {
                            assert_eq!(n, 0);
                        }
                    }
                }
            }
        }
        if let Ok(tree) = XfsTreeSource::inventory(
            volume,
            XfsTreeLimits {
                objects: 32,
                entries: 64,
                depth: 8,
            },
            &r,
        ) {
            let root = tree.root();
            let _ = tree.metadata(&root, &r);
            if let Ok(page) = tree.directory_page(&root, None, 8, &r) {
                for entry in &page.entries {
                    let _ = tree.metadata(&entry.object, &r);
                    let _ = tree.streams(&entry.object, &r);
                    let _ = tree.directory_page(&entry.object, None, 8, &r);
                    if let Ok(file) = tree.open_stream(&entry.object, &StreamKind::Data, &r) {
                        let mut out = [0; 73];
                        let _ = file.read_at(random, &mut out, &r);
                    }
                }
            }
            drop(tree);
        }
    }
    assert_eq!(r.memory.used(), 0);
}
/// Boot, MFT, indexes, complete bounded allocation audit and positional reads.
pub fn ntfs(data: &[u8]) {
    use partmgr::{
        fs_core::{Budget, Cancellation, FileRead, Resources, StreamKind, TreeSource},
        fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
        fs_ntfs_tree::{NtfsTreePolicy, NtfsTreeSource},
    };
    if data.len() > 1 << 20 {
        return;
    }
    let mut r = Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    };
    let random = data
        .get(..8)
        .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
    if let Ok(report) = partmgr::fs_ntfs_audit::audit_ntfs(
        Arc::new(Bytes(data.to_vec())),
        NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 8,
        },
        ntfs_audit_limits(),
        &r,
    ) {
        if !report.is_clean() || !report.is_complete() {
            assert!(report.free_ranges().is_empty());
        }
        assert!(report.owned_clusters() <= report.clusters());
        drop(report);
    }
    assert_eq!(r.memory.used(), 0);
    if let Ok(volume) = NtfsVolume::open(
        Arc::new(Bytes(data.to_vec())),
        NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 8,
        },
        &r,
    ) {
        for number in [
            0,
            3,
            24,
            25,
            random % 1024,
            volume.record_count().saturating_sub(1),
            volume.record_count(),
            u64::MAX,
        ] {
            if let Ok(record) = volume.record(number, &r) {
                let _ = record.metadata(&r);
                let _ = volume.open_object(record.identity(), &r);
                let mut stale = record.identity().clone();
                stale.generation ^= 1;
                assert!(volume.open_object(&stale, &r).is_err());
            }
            if let Ok(file) = volume.open_file(number, &r) {
                let mut buffer = [0; 73];
                let _ = file.visit_extents(&r, &mut |_| Ok(()));
                for at in [
                    0,
                    511,
                    512,
                    1023,
                    random,
                    file.len() / 2,
                    file.len(),
                    u64::MAX,
                ] {
                    if let Ok(n) = file.read_at(at, &mut buffer, &r) {
                        assert!(n <= buffer.len());
                        if at >= file.len() {
                            assert_eq!(n, 0);
                        }
                    }
                }
                r.cancellation.cancel();
                assert!(file.read_at(0, &mut buffer, &r).is_err());
                r.cancellation = Cancellation::default();
            }
        }
        let index_limits = NtfsDirectoryLimits {
            blocks: 16,
            entries: 32,
            depth: 8,
        };
        if let Ok(root) = volume.root_identity(&r) {
            let _ = volume.directory(&root, index_limits, &r);
            let mut stale = root.clone();
            stale.generation ^= 1;
            assert!(volume.directory(&stale, index_limits, &r).is_err());
        }
        if let Ok(tree) = NtfsTreeSource::inventory_with_policy(
            volume,
            32,
            8,
            index_limits,
            NtfsTreePolicy::UserNamespace,
            &r,
        ) {
            let root = tree.root();
            let _ = tree.metadata(&root, &r);
            let _ = tree.revalidate(&root, &r);
            if let Ok(page) = tree.directory_page(&root, None, 8, &r) {
                if let Some(next) = &page.next {
                    let _ = tree.directory_page(&root, Some(next), 8, &r);
                }
                for entry in &page.entries {
                    let _ = tree.metadata(&entry.object, &r);
                    let _ = tree.streams(&entry.object, &r);
                    if let Ok(file) = tree.open_stream(&entry.object, &StreamKind::Data, &r) {
                        let mut bytes = [0; 73];
                        let _ = file.read_at(random, &mut bytes, &r);
                        assert_eq!(file.read_at(file.len(), &mut bytes, &r).unwrap_or(0), 0);
                    }
                }
            }
            let _ = tree.directory_page(&root, Some(data.get(..40).unwrap_or(data)), 8, &r);
            r.cancellation.cancel();
            assert!(tree.revalidate(&root, &r).is_err());
        }
    }
    assert_eq!(r.memory.used(), 0);
}

fn undo_binding() -> partmgr::fs_undo::UndoBinding {
    partmgr::fs_undo::UndoBinding {
        volume: [0x11; 32],
        generation: 7,
        transaction: [0x22; 16],
    }
}
fn undo_limits() -> partmgr::fs_undo::UndoLimits {
    partmgr::fs_undo::UndoLimits {
        patches: 32,
        body_bytes: 128 * 1024,
    }
}
/// Independent v1 journal wire fixture; never produced by UndoPlan or its codec.
fn undo_seeds() -> Vec<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let mut bytes = vec![0; 1024 + 32];
    bytes[..8].copy_from_slice(b"PMFSUNDO");
    put32(&mut bytes, 8, 1);
    bytes[12] = 1;
    bytes[16..48].fill(0x11);
    put64(&mut bytes, 48, 7);
    bytes[56..72].fill(0x22);
    put64(&mut bytes, 72, 65536);
    put64(&mut bytes, 80, 32);
    put32(&mut bytes, 88, 1);
    put64(&mut bytes, 1024, 13);
    put64(&mut bytes, 1032, 8);
    bytes[1040..1048].fill(1);
    bytes[1048..1056].fill(2);
    let body = Sha256::digest(&bytes[1024..]);
    bytes[96..128].copy_from_slice(&body);
    let hash = Sha256::digest(&bytes[..480]);
    bytes[480..512].copy_from_slice(&hash);
    let mut committed = bytes.clone();
    committed.copy_within(..512, 512);
    committed[524] = 2;
    let hash = Sha256::digest(&committed[512..992]);
    committed[992..1024].copy_from_slice(&hash);
    let mut invalid_range = bytes.clone();
    put64(&mut invalid_range, 1024, u64::MAX);
    let mut limits = bytes.clone();
    put32(&mut limits, 88, u32::MAX);
    vec![
        bytes,
        committed,
        invalid_range,
        limits,
        vec![0; 1024],
        b"PMFSUNDO".to_vec(),
    ]
}
/// Recompute only integrity fields, retaining mutated version/state/binding/bounds.
/// This reaches semantic preflight instead of ending every case at SHA validation.
fn undo_rehash(bytes: &mut [u8]) {
    use sha2::{Digest, Sha256};
    for base in [0, 512] {
        if bytes.len() < base + 512 || &bytes[base..base + 8] != b"PMFSUNDO" {
            continue;
        }
        let body = u64::from_le_bytes(bytes[base + 80..base + 88].try_into().unwrap());
        if let Ok(n) = usize::try_from(body)
            && let Some(end) = 1024usize.checked_add(n)
            && let Some(body) = bytes.get(1024..end)
        {
            let hash = Sha256::digest(body);
            bytes[base + 96..base + 128].copy_from_slice(&hash);
        }
        let hash = Sha256::digest(&bytes[base..base + 480]);
        bytes[base + 480..base + 512].copy_from_slice(&hash);
    }
}
fn undo_case(bytes: Vec<u8>) {
    use partmgr::fs_core::{Budget, Cancellation, Resources};
    let r = Resources {
        memory: Budget::new(256 * 1024),
        cancellation: Cancellation::default(),
    };
    let mut journal = Bytes(bytes);
    let _ = partmgr::fs_undo::inspect(&journal, &r);
    let mut target = Bytes(vec![2; 65536]);
    let before = target.0.clone();
    if let Err(error) =
        partmgr::fs_undo::recover(&mut target, &mut journal, undo_binding(), undo_limits(), &r)
        && !error.target_may_have_changed
    {
        assert_eq!(target.0, before);
    }
    assert_eq!(target.0.len(), 65536);
    assert_eq!(r.memory.used(), 0);
    r.cancellation.cancel();
    assert!(partmgr::fs_undo::inspect(&journal, &r).is_err());
    assert!(
        partmgr::fs_undo::recover(&mut target, &mut journal, undo_binding(), undo_limits(), &r)
            .is_err()
    );
    assert_eq!(r.memory.used(), 0);
}
/// Malformed journal inspection/recovery uses only isolated bounded memory stores.
pub fn undo(data: &[u8]) {
    if data.len() > 1 << 20 {
        return;
    }
    undo_case(data.to_vec());
    let mut normalized = data.to_vec();
    undo_rehash(&mut normalized);
    undo_case(normalized);
}

/// Declared logical NOR JFFS2 history reconstruction and deferred namespace reads.
pub fn jffs2(data: &[u8]) {
    jffs2::run(data);
}

pub fn hfsplus(data: &[u8]) {
    hfsplus::run(data);
}

pub fn hfs(data: &[u8]) {
    hfs::run(data);
}

pub fn jfs(data: &[u8]) {
    jfs::run(data);
}

pub fn apfs(data: &[u8]) {
    apfs::run(data);
}

#[cfg(test)]
mod smoke {
    #[test]
    fn flash_seed_reaches_program_erase_flush_and_failure_oracles() {
        let seeds = super::flash::seeds();
        assert!(super::flash::run(&seeds[0]));
        for seed in seeds {
            super::flash(&seed);
        }
    }
    #[test]
    fn xfs_seed_reaches_complete_audit_and_sparse_native_hardlinks() {
        use partmgr::{
            fs_core::{Budget, Cancellation, Resources, StreamKind, TreeSource},
            fs_xfs::XfsVolume,
            fs_xfs_tree::{XfsTreeLimits, XfsTreeSource},
        };
        let r = Resources {
            memory: Budget::new(4 << 20),
            cancellation: Cancellation::default(),
        };
        let seed = super::xfs_fixture::xfs_seed();
        super::xfs(&seed);
        let volume = XfsVolume::open(
            std::sync::Arc::new(super::Bytes(seed)),
            super::xfs_read_limits(),
            &r,
        )
        .unwrap();
        let report = partmgr::fs_xfs_audit::audit(&volume, super::xfs_audit_limits(), &r).unwrap();
        assert!(report.is_complete() && report.is_clean());
        assert!(!report.free_ranges().is_empty());
        drop(report);
        let tree = XfsTreeSource::inventory(
            volume,
            XfsTreeLimits {
                objects: 32,
                entries: 64,
                depth: 8,
            },
            &r,
        )
        .unwrap();
        let root = tree.directory_page(&tree.root(), None, 8, &r).unwrap();
        let nested = tree
            .directory_page(&root.entries[1].object, None, 8, &r)
            .unwrap();
        assert_eq!(nested.entries[0].object, root.entries[0].object);
        let file = tree
            .open_stream(&root.entries[0].object, &StreamKind::Data, &r)
            .unwrap();
        drop(nested);
        drop(root);
        drop(tree);
        let mut out = [0xff; 73];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 73);
        assert_eq!(out, [0; 73]);
        assert_eq!(file.read_at(4099, &mut out, &r).unwrap(), 73);
        assert_eq!(
            out,
            std::array::from_fn(|i| (((i + 3) * 73 + 11) % 256) as u8)
        );
        r.cancellation.cancel();
        assert!(file.read_at(file.len(), &mut [], &r).is_err());
        drop(file);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn fat_seed_reaches_owned_recoverable_range_edit_and_generation_invalidation() {
        assert!(super::fat_edit(&super::seeds("fat").remove(0)));
    }
    #[test]
    fn exfat_seed_reaches_complete_clean_audit() {
        use partmgr::fs_core::{Budget, Cancellation, Resources};
        let r = Resources {
            memory: Budget::new(2 << 20),
            cancellation: Cancellation::default(),
        };
        let report = partmgr::fs_exfat_audit::audit_exfat(
            std::sync::Arc::new(super::ExfatInput(super::seeds("exfat").remove(1))),
            super::exfat_read_limits(),
            super::exfat_audit_limits(),
            &r,
        )
        .unwrap();
        assert!(report.namespace_complete());
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.objects(), 5);
        assert!(!report.free_ranges().is_empty());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn ntfs_clean_seed_reaches_complete_system_allocation_and_mirror_audit() {
        use partmgr::{
            fs_core::{Budget, Cancellation, Resources},
            fs_ntfs::NtfsReadLimits,
            fs_ntfs_audit::audit_ntfs,
        };
        let r = Resources {
            memory: Budget::new(2 << 20),
            cancellation: Cancellation::default(),
        };
        let bytes = super::ntfs_clean_fixture::ntfs_audit_seed();
        super::ntfs(&bytes);
        let report = audit_ntfs(
            std::sync::Arc::new(super::Bytes(bytes)),
            NtfsReadLimits {
                attributes: 64,
                runs: 64,
                names: 16,
            },
            super::ntfs_audit_limits(),
            &r,
        )
        .unwrap();
        assert!(report.is_complete());
        assert!(report.is_clean());
        assert_eq!(report.clusters(), 1024);
        assert_eq!(report.allocated_clusters(), 335);
        assert_eq!(report.owned_clusters(), 335);
        assert_eq!(report.allocated_records(), 18);
        assert!(!report.free_ranges().is_empty());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn ntfs_index_seed_reaches_allocation_bitmap_hardlinks_and_deferred_tree_reads() {
        use partmgr::{
            fs_core::{Budget, Cancellation, Resources, StreamKind, TreeSource},
            fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
            fs_ntfs_tree::NtfsTreeSource,
        };
        let r = Resources {
            memory: Budget::new(2 << 20),
            cancellation: Cancellation::default(),
        };
        let bytes = super::ntfs_index_fixture::ntfs_index_seed();
        super::ntfs(&bytes);
        let volume = NtfsVolume::open(
            std::sync::Arc::new(super::Bytes(bytes)),
            NtfsReadLimits {
                attributes: 32,
                runs: 64,
                names: 8,
            },
            &r,
        )
        .unwrap();
        let limits = NtfsDirectoryLimits {
            blocks: 16,
            entries: 32,
            depth: 8,
        };
        let root = volume.root_identity(&r).unwrap();
        let directory = volume.directory(&root, limits, &r).unwrap();
        assert_eq!(directory.entries().len(), 2);
        assert_eq!(
            directory.entries()[0].identity,
            directory.entries()[1].identity
        );
        drop(directory);
        let tree = NtfsTreeSource::inventory(volume, 32, 8, limits, &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 8, &r).unwrap();
        assert_eq!(page.entries.len(), 2);
        let file = tree
            .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
            .unwrap();
        drop(page);
        drop(tree);
        let mut out = [0; 8];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 5);
        assert_eq!(&out[..5], b"hello");
        drop(file);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn ntfs_seed_reaches_resident_sparse_unwritten_metadata_and_eof() {
        use partmgr::{
            fs_core::{Budget, Cancellation, FileRead, NativeName, Resources},
            fs_ntfs::{NtfsReadLimits, NtfsVolume},
        };
        let r = Resources {
            memory: Budget::new(2 << 20),
            cancellation: Cancellation::default(),
        };
        let volume = NtfsVolume::open(
            std::sync::Arc::new(super::Bytes(super::seeds("ntfs").remove(0))),
            NtfsReadLimits {
                attributes: 32,
                runs: 64,
                names: 8,
            },
            &r,
        )
        .unwrap();
        let record = volume.record(24, &r).unwrap();
        assert_eq!(
            record.names()[0].name,
            NativeName::Utf16(vec![0x65e5, 0xd800])
        );
        let metadata = record.metadata(&r).unwrap();
        let resident = volume.open_object(record.identity(), &r).unwrap();
        let mut small = [0; 8];
        assert_eq!(resident.read_at(0, &mut small, &r).unwrap(), 5);
        assert_eq!(&small[..5], b"hello");
        assert_eq!(resident.read_at(5, &mut small, &r).unwrap(), 0);
        let file = volume.open_file(25, &r).unwrap();
        let mut bytes = [0xff; 1600];
        assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 1536);
        assert!(bytes[..512].iter().all(|v| *v == 0x31));
        assert!(bytes[512..1024].iter().all(|v| *v == 0));
        assert!(bytes[1024..1280].iter().all(|v| *v == 0x72));
        assert!(bytes[1280..1536].iter().all(|v| *v == 0));
        drop((file, resident, metadata, record, volume));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn independent_undo_seed_restores_and_rehashed_bounds_fail_before_writes() {
        use partmgr::{
            fs_core::{Budget, Cancellation, ErrorKind, Resources},
            fs_undo::{UndoState, recover},
        };
        let r = Resources {
            memory: Budget::new(256 << 10),
            cancellation: Cancellation::default(),
        };
        let seeds = super::undo_seeds();
        let mut journal = super::Bytes(seeds[0].clone());
        let mut target = super::Bytes(vec![2; 65536]);
        let status = recover(
            &mut target,
            &mut journal,
            super::undo_binding(),
            super::undo_limits(),
            &r,
        )
        .unwrap();
        assert_eq!(status.state, UndoState::RolledBack);
        assert_eq!(&target.0[13..21], &[1; 8]);
        assert_eq!(
            recover(
                &mut target,
                &mut journal,
                super::undo_binding(),
                super::undo_limits(),
                &r
            )
            .unwrap()
            .state,
            UndoState::RolledBack
        );
        for (seed, kind) in [
            (&seeds[2], ErrorKind::InvalidData),
            (&seeds[3], ErrorKind::BudgetExhausted),
        ] {
            let mut bytes = seed.clone();
            super::undo_rehash(&mut bytes);
            let mut target = super::Bytes(vec![2; 65536]);
            let mut journal = super::Bytes(bytes);
            let failure = recover(
                &mut target,
                &mut journal,
                super::undo_binding(),
                super::undo_limits(),
                &r,
            )
            .unwrap_err();
            assert_eq!(failure.source.kind, kind);
            assert!(!failure.target_may_have_changed);
            assert_eq!(target.0, vec![2; 65536]);
        }
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn exfat_seed_reaches_namespace_file_map_and_valid_length_zero_tail() {
        use partmgr::{
            fs_core::{Budget, Cancellation, FileRead, Resources},
            fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
        };
        let r = Resources {
            memory: Budget::new(2 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let volume = ExfatVolume::open(
            std::sync::Arc::new(super::ExfatInput(super::seeds("exfat").remove(1))),
            ExfatReadLimits {
                max_chain_clusters: 64,
                max_directory_slots: 64,
                max_upcase_bytes: 131072,
            },
            &r,
        )
        .unwrap();
        let root = volume.root_directory(&r).unwrap();
        assert_eq!(root.entries().len(), 3);
        let name: Vec<u16> = "prefixNoChain.bin".encode_utf16().collect();
        let entry = root.lookup(&name).unwrap().unwrap();
        let file = volume.open_file(entry, &r).unwrap();
        let mut bytes = [0; 37];
        assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 37);
        assert_eq!(
            bytes,
            std::array::from_fn(|index| ((index * 17 + 3) % 251) as u8)
        );
        file.read_at(600, &mut bytes, &r).unwrap();
        assert_eq!(bytes, [0; 37]);
    }
    #[test]
    fn ext_seed_reaches_complete_allocation_audit() {
        use partmgr::{
            fs_core::{Budget, Cancellation, Resources},
            fs_ext::ExtVolume,
            fs_ext_audit::{ExtAuditLimits, audit},
        };
        let r = Resources {
            memory: Budget::new(256 * 1024),
            cancellation: Cancellation::default(),
        };
        let volume = ExtVolume::open(
            std::sync::Arc::new(super::Bytes(super::seeds("ext").remove(1))),
            &r,
        )
        .unwrap();
        let report = audit(
            &volume,
            ExtAuditLimits {
                blocks: 128,
                inodes: 64,
                work: 65536,
                directory_blocks: 64,
                directory_entries: 128,
                findings: 32,
            },
            &r,
        )
        .unwrap();
        assert!(report.is_clean(), "{:?}", report.findings());
    }
    #[test]
    fn exfat_seed_reaches_both_boot_checksum_validation() {
        use partmgr::{
            fs_core::{Budget, Cancellation, Resources},
            fs_exfat::ExfatBoot,
        };
        let r = Resources {
            memory: Budget::new(8192),
            cancellation: Cancellation::default(),
        };
        let seed = super::seeds("exfat").remove(0);
        let boot = ExfatBoot::inspect(&super::ExfatInput(seed), &r).unwrap();
        assert_eq!(boot.clusters, 2008);
    }
    #[test]
    fn ext_seed_reaches_native_directory_and_payload_decoding() {
        use partmgr::{
            fs_core::{Budget, Cancellation, Resources},
            fs_ext::ExtVolume,
        };
        let resources = Resources {
            memory: Budget::new(256 * 1024),
            cancellation: Cancellation::default(),
        };
        let volume = ExtVolume::open(
            std::sync::Arc::new(super::Bytes(super::seeds("ext").remove(0))),
            &resources,
        )
        .unwrap();
        assert_eq!(
            volume
                .directory(2, 64, 64, &resources)
                .unwrap()
                .entries()
                .len(),
            3
        );
        let file = volume.open_file(3, 64, &resources).unwrap();
        let mut bytes = [0; 37];
        file.read_at(0, &mut bytes, &resources).unwrap();
        assert_eq!(bytes, [42; 37]);
    }
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

/// Bounded BitLocker envelope and metadata inspection without credential work.
pub fn bitlocker(data: &[u8]) {
    bitlocker::inspection(data);
}
/// Fixed-key bounded decrypted reader and logical mapping fuzzing.
pub fn bitlocker_reader(data: &[u8]) {
    bitlocker::reader(data);
}
