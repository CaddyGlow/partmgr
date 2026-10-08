#![cfg(feature = "std")]

use partmgr::storage::Storage;
use partmgr::{
    guid::Guid,
    layout::{Geometry, GptLayout},
    recovery::{RecoveryReport, RecoverySource},
};
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, out: &mut [u8]) -> std::io::Result<()> {
        out.copy_from_slice(&self.0[o as usize..o as usize + out.len()]);
        Ok(())
    }
}
fn image() -> Image {
    let g = GptLayout::initialize(
        Geometry::new(512 * 4096, 512).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    let mut bytes = vec![0; 512 * 4096];
    for (o, b) in [
        (0, g.mbr_sector()),
        (512, g.primary_header()),
        (g.primary_array_lba() as usize * 512, g.array()),
        (g.backup_array_lba() as usize * 512, g.array()),
        (4095 * 512, g.backup_header()),
    ] {
        bytes[o..o + b.len()].copy_from_slice(b)
    }
    Image(bytes)
}
#[test]
fn damaged_copy_requires_explicit_source() {
    let mut i = image();
    i.0[512] = 0;
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    assert!(r.primary().is_err());
    assert!(r.backup().is_ok());
    assert!(r.repair_plan(&i, RecoverySource::Primary).is_err());
    let p = r.repair_plan(&i, RecoverySource::Backup).unwrap();
    assert_eq!(p.stages()[0].name(), "repair-primary");
}
#[test]
fn bounded_displaced_backup_discovery() {
    let mut i = image();
    i.0.resize(512 * 8192, 0);
    i.0[512] = 0;
    let r = RecoveryReport::inspect(&i, 512, &[4095]).unwrap();
    assert!(r.backup().is_err());
    assert_eq!(r.displaced().len(), 1);
    assert!(r.repair_plan(&i, RecoverySource::Displaced(4095)).is_ok());
}
#[test]
fn repair_commits_and_revalidates_independently() {
    use partmgr::layout::DiskLayout;
    let mut i = image();
    i.0[512] = 0;
    let report = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    report
        .repair_plan(&i, RecoverySource::Backup)
        .unwrap()
        .commit(&mut i)
        .unwrap();
    assert!(DiskLayout::inspect(&i, 512).is_ok());
    i.0.resize(512 * 8192, 0);
    let report = RecoveryReport::inspect(&i, 512, &[4095]).unwrap();
    report
        .repair_plan(&i, RecoverySource::Primary)
        .unwrap()
        .commit(&mut i)
        .unwrap();
    assert!(DiskLayout::inspect(&i, 512).is_ok());
    let report = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    report
        .geometry_plan(&i, RecoverySource::Primary, 512 * 4096)
        .unwrap()
        .commit(&mut i)
        .unwrap();
    i.0.truncate(512 * 4096);
    assert!(DiskLayout::inspect(&i, 512).is_ok());
}

impl Storage for Image {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        ReadAt::read_exact_at(self, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> std::io::Result<usize> {
        self.0[o as usize..o as usize + b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn both_damage_and_array_corruption_are_reported() {
    let mut i = image();
    i.0[512] = 0;
    i.0[4095 * 512] = 0;
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    assert!(r.primary().is_err());
    assert!(r.backup().is_err());
    let mut i = image();
    i.0[2 * 512] ^= 1;
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    assert!(r.primary().is_err());
    assert!(r.backup().is_ok());
    assert!(RecoveryReport::inspect(&i, 512, &[4095; 65]).is_err());
}
#[test]
fn valid_divergence_never_selects_implicitly_and_shrink_rejects_overlap() {
    let mut i = image();
    let mut alternate = GptLayout::initialize(
        Geometry::new(512 * 4096, 512).unwrap(),
        Guid::from_bytes([9; 16]),
        128,
        128,
    )
    .unwrap();
    alternate
        .create(
            1,
            partmgr::guid::EFI_SYSTEM_PARTITION,
            Guid::from_bytes([8; 16]),
            partmgr::layout::LbaRange::new(3000, 4000).unwrap(),
        )
        .unwrap();
    let o = alternate.backup_array_lba() as usize * 512;
    i.0[o..o + alternate.array().len()].copy_from_slice(alternate.array());
    i.0[4095 * 512..].copy_from_slice(alternate.backup_header());
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    assert!(r.primary().is_ok());
    assert!(r.backup().is_ok());
    assert!(r.divergent());
    assert!(
        r.geometry_plan(&i, RecoverySource::Backup, 512 * 3072)
            .is_err()
    );
    let p = r.repair_plan(&i, RecoverySource::Backup).unwrap();
    p.commit(&mut i).unwrap();
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    assert!(!r.divergent());
    assert_eq!(
        r.primary().unwrap().disk_guid(),
        Guid::from_bytes([9; 16]).to_gpt_bytes()
    );
}
#[test]
fn stale_selected_source_is_rejected_before_and_after_planning() {
    let mut i = image();
    i.0[512] = 0;
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    let p = r.repair_plan(&i, RecoverySource::Backup).unwrap();
    i.0[4095 * 512 + 16] ^= 1;
    assert!(r.repair_plan(&i, RecoverySource::Backup).is_err());
    assert!(matches!(
        p.commit(&mut i),
        Err(partmgr::storage::CommitError::Stale { .. })
    ));
    assert_eq!(i.0[512], 0);
}
#[test]
fn protective_mbr_damage_is_repaired_at_same_geometry() {
    let mut i = image();
    i.0[510] = 0;
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    r.repair_plan(&i, RecoverySource::Primary)
        .unwrap()
        .commit(&mut i)
        .unwrap();
    assert!(partmgr::layout::DiskLayout::inspect(&i, 512).is_ok());
}
impl partmgr::storage::ResizableStorage for Image {
    fn resize(&mut self, n: u64) -> std::io::Result<()> {
        self.0.resize(n as usize, 0);
        Ok(())
    }
}
#[test]
fn adapter_resize_grows_then_relocates_and_shrinks_after_metadata_commit() {
    let mut i = image();
    let grown = partmgr::recovery::resize_gpt(&mut i, 512, 512 * 8192, RecoverySource::Backup, &[])
        .unwrap();
    assert_eq!(grown.geometry().sectors(), 8192);
    let shrunk =
        partmgr::recovery::resize_gpt(&mut i, 512, 512 * 4096, RecoverySource::Primary, &[])
            .unwrap();
    assert_eq!(shrunk.geometry().sectors(), 4096);
}
#[test]
fn hybrid_mbr_recovery_mutation_is_refused() {
    let mut i = image();
    i.0[466] = 0x83;
    i.0[470..474].copy_from_slice(&100u32.to_le_bytes());
    i.0[474..478].copy_from_slice(&10u32.to_le_bytes());
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    assert!(r.primary().is_ok());
    assert!(r.repair_plan(&i, RecoverySource::Primary).is_err());
}
fn independent_crc(bytes: &[u8]) -> u32 {
    let mut c = 0xffff_ffff;
    for &b in bytes {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xedb88320
            } else {
                c >> 1
            };
        }
    }
    !c
}
fn refresh_header(bytes: &mut [u8]) {
    bytes[16..20].fill(0);
    let n = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let c = independent_crc(&bytes[..n]);
    bytes[16..20].copy_from_slice(&c.to_le_bytes());
}
#[test]
fn noncanonical_primary_table_and_custom_usable_bounds_survive_repair() {
    let mut i = image();
    for lba in [1, 4095] {
        let h = &mut i.0[lba * 512..(lba + 1) * 512];
        h[40..48].copy_from_slice(&64u64.to_le_bytes());
        if lba == 1 {
            h[72..80].copy_from_slice(&4u64.to_le_bytes());
        }
        refresh_header(h);
    }
    assert!(partmgr::layout::DiskLayout::inspect(&i, 512).is_ok());
    i.0[4095 * 512] = 0;
    let r = RecoveryReport::inspect(&i, 512, &[]).unwrap();
    r.repair_plan(&i, RecoverySource::Primary)
        .unwrap()
        .commit(&mut i)
        .unwrap();
    let partmgr::layout::DiskLayout::Gpt(g) =
        partmgr::layout::DiskLayout::inspect(&i, 512).unwrap()
    else {
        panic!("GPT")
    };
    assert_eq!(g.primary_array_lba(), 4);
    assert_eq!(g.usable().start(), 64);
}
