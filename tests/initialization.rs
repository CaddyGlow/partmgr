#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    codec::{edit_plan, initialize_plan},
    guid::Guid,
    layout::{DiskLayout, Geometry, GptLayout},
    recovery::{RecoveryReport, RecoverySource},
    storage::{CommitError, Storage},
};
use virtdisk::ReadAt;
struct Disk {
    bytes: Vec<u8>,
    event: usize,
    fail: Option<usize>,
    writes: usize,
}
impl ReadAt for Disk {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.bytes[o as usize..o as usize + b.len()]);
        Ok(())
    }
}
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        self.event += 1;
        if self.fail == Some(self.event) {
            return Err(io::Error::other("write interruption"));
        }
        self.writes += 1;
        self.bytes[o as usize..o as usize + b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.event += 1;
        if self.fail == Some(self.event) {
            Err(io::Error::other("flush interruption"))
        } else {
            Ok(())
        }
    }
}
fn empty(sector: u32) -> (Disk, DiskLayout) {
    let geometry = Geometry::new(u64::from(sector) * 256, sector).unwrap();
    let layout = DiskLayout::Gpt(
        GptLayout::initialize(geometry, Guid::from_bytes([7; 16]), 128, 128).unwrap(),
    );
    (
        Disk {
            bytes: vec![0xa5; geometry.bytes() as usize],
            event: 0,
            fail: None,
            writes: 0,
        },
        layout,
    )
}
#[test]
fn initialization_preserves_mbr_sector_tail() {
    let (mut disk, layout) = empty(4096);
    let before = disk.bytes[512..4096].to_vec();
    initialize_plan(&disk, &layout)
        .unwrap()
        .commit(&mut disk)
        .unwrap();
    assert!(
        &disk.bytes[512..4096] == before.as_slice(),
        "MBR sector tail changed"
    );
}
#[test]
fn stale_unchanged_protective_mbr_prevents_gpt_edit_writes() {
    let (mut disk, layout) = empty(512);
    initialize_plan(&disk, &layout)
        .unwrap()
        .commit(&mut disk)
        .unwrap();
    let old = DiskLayout::inspect(&disk, 512).unwrap();
    let mut new = old.clone();
    let DiskLayout::Gpt(g) = &mut new else {
        panic!("GPT")
    };
    g.create(
        1,
        Guid::from_bytes([8; 16]),
        Guid::from_bytes([9; 16]),
        partmgr::layout::LbaRange::new(40, 100).unwrap(),
    )
    .unwrap();
    let plan = edit_plan(&old, &new).unwrap();
    disk.bytes[510] = 0;
    disk.writes = 0;
    assert!(matches!(
        plan.commit(&mut disk),
        Err(CommitError::Stale { .. })
    ));
    assert_eq!(disk.writes, 0);
}
fn independent_crc(bytes: &[u8]) -> u32 {
    let mut c = u32::MAX;
    for &b in bytes {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb88320
            } else {
                c >> 1
            };
        }
    }
    !c
}
#[test]
fn every_initialization_write_and_flush_boundary_has_explicit_outcomes() {
    for sector in [512, 4096] {
        for fail in 1..=8 {
            let (mut disk, layout) = empty(sector);
            disk.bytes[446..512].fill(0);
            let before = disk.bytes.clone();
            let plan = initialize_plan(&disk, &layout).unwrap();
            disk.fail = Some(fail);
            let error = plan.commit(&mut disk).unwrap_err();
            let CommitError::Interrupted {
                completed_stages,
                stage,
                durability_uncertain,
                ..
            } = error
            else {
                panic!("expected interrupted commit")
            };
            assert!(durability_uncertain);
            assert_eq!(
                completed_stages.len(),
                if fail <= 3 {
                    0
                } else if fail <= 6 {
                    1
                } else {
                    2
                }
            );
            assert_eq!(
                stage,
                if fail <= 3 {
                    "initialize backup GPT"
                } else if fail <= 6 {
                    "initialize primary GPT"
                } else {
                    "initialize protective MBR"
                }
            );
            assert_eq!(disk.event, fail);
            assert_eq!(
                &disk.bytes[510..512],
                if fail <= 7 { &[0, 0] } else { &[0x55, 0xaa] }
            );
            let report = RecoveryReport::inspect(&disk, sector, &[]).unwrap();
            assert_eq!(report.backup().is_ok(), fail >= 3);
            assert_eq!(report.primary().is_ok(), fail >= 6);
            assert_eq!(DiskLayout::inspect(&disk, sector).is_ok(), fail == 8);
            let DiskLayout::Gpt(ref proposed) = layout else {
                panic!("GPT")
            };
            let range = proposed.usable();
            let start = (range.start() * u64::from(sector)) as usize;
            let end = (range.end() * u64::from(sector)) as usize;
            assert_eq!(&disk.bytes[start..end], &before[start..end]);
            assert!(
                disk.bytes[512..sector as usize] == before[512..sector as usize],
                "MBR sector tail changed at sector {sector}, event {fail}"
            );
            if fail >= 3 {
                let offset = 255 * sector as usize;
                let h = &disk.bytes[offset..offset + sector as usize];
                assert_eq!(&h[..8], b"EFI PART");
                assert_eq!(u64::from_le_bytes(h[24..32].try_into().unwrap()), 255);
                assert_eq!(u64::from_le_bytes(h[32..40].try_into().unwrap()), 1);
                let mut prefix = h[..92].to_vec();
                let expected = u32::from_le_bytes(prefix[16..20].try_into().unwrap());
                prefix[16..20].fill(0);
                assert_eq!(independent_crc(&prefix), expected);
                let table_offset =
                    u64::from_le_bytes(h[72..80].try_into().unwrap()) as usize * sector as usize;
                assert_eq!(
                    independent_crc(&disk.bytes[table_offset..table_offset + 16384]),
                    u32::from_le_bytes(h[88..92].try_into().unwrap())
                );
                disk.fail = None;
                report
                    .repair_plan(&disk, RecoverySource::Backup)
                    .unwrap()
                    .commit(&mut disk)
                    .unwrap();
                assert!(DiskLayout::inspect(&disk, sector).is_ok());
                assert_eq!(&disk.bytes[start..end], &before[start..end]);
            } else {
                assert!(report.repair_plan(&disk, RecoverySource::Backup).is_err());
            }
        }
    }
}
#[test]
fn stale_initialization_preflight_writes_nothing() {
    let (mut disk, layout) = empty(512);
    let plan = initialize_plan(&disk, &layout).unwrap();
    disk.bytes[255 * 512] ^= 1;
    disk.writes = 0;
    assert!(matches!(
        plan.commit(&mut disk),
        Err(CommitError::Stale { .. })
    ));
    assert_eq!(disk.writes, 0);
    assert_eq!(disk.event, 0);
}
struct ReadFailure(Disk);
impl Storage for ReadFailure {
    fn len(&self) -> io::Result<u64> {
        Storage::len(&self.0)
    }
    fn read_exact_at(&self, _: u64, _: &mut [u8]) -> io::Result<()> {
        Err(io::Error::other("preflight read"))
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        Storage::write_at(&mut self.0, o, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Storage::flush(&mut self.0)
    }
}
#[test]
fn preflight_io_failure_never_writes_or_flushes() {
    let (disk, layout) = empty(512);
    let plan = initialize_plan(&disk, &layout).unwrap();
    let mut failing = ReadFailure(disk);
    assert!(matches!(
        plan.commit(&mut failing),
        Err(CommitError::Preflight(_))
    ));
    assert_eq!(failing.0.event, 0);
    assert_eq!(failing.0.writes, 0);
}
struct GeometryChange {
    disk: Disk,
    flushes: usize,
}
impl Storage for GeometryChange {
    fn len(&self) -> io::Result<u64> {
        Storage::len(&self.disk)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        Storage::read_exact_at(&self.disk, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        Storage::write_at(&mut self.disk, o, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flushes == 3 {
            let n = self.disk.bytes.len();
            self.disk.bytes.resize(n + 512, 0);
        }
        Ok(())
    }
}
#[test]
fn commit_reinspection_rejects_geometry_changed_by_adapter() {
    let (disk, layout) = empty(512);
    let plan = initialize_plan(&disk, &layout).unwrap();
    let mut adapter = GeometryChange { disk, flushes: 0 };
    let error = partmgr::codec::commit_and_inspect(&plan, &mut adapter, 512)
        .err()
        .expect("changed geometry must fail");
    let partmgr::error::Error::PartialCommit(CommitError::Interrupted {
        completed_stages,
        stage,
        durability_uncertain,
        ..
    }) = error
    else {
        panic!("expected post-commit verification failure")
    };
    assert_eq!(completed_stages.len(), 3);
    assert!(stage.contains("geometry"));
    assert!(!durability_uncertain);
    assert_eq!(adapter.flushes, 3);
}
