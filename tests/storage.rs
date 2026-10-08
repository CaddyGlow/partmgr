#![cfg(feature = "std")]

use partmgr::storage::{Barrier, CommitError, Storage, WritePlan, WriteRange};
use std::io;

struct Memory {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail_flush: bool,
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.bytes[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(2);
        self.bytes[offset as usize..offset as usize + count].copy_from_slice(&bytes[..count]);
        self.writes += 1;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::other("flush"))
        } else {
            Ok(())
        }
    }
}
fn memory() -> Memory {
    Memory {
        bytes: vec![0; 32],
        writes: 0,
        flushes: 0,
        fail_flush: false,
    }
}
fn plan() -> WritePlan {
    WritePlan::new(
        32,
        vec![
            Barrier::new(
                "backup",
                vec![WriteRange::new(8, vec![0; 4], vec![1; 4]).unwrap()],
            )
            .unwrap(),
            Barrier::new(
                "primary",
                vec![WriteRange::new(0, vec![0; 4], vec![2; 4]).unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
#[test]
fn short_writes_are_completed_and_unaffected_bytes_preserved() {
    let mut disk = memory();
    let report = plan().commit(&mut disk).unwrap();
    assert_eq!(report.completed_stages(), &["backup", "primary"]);
    assert_eq!(disk.writes, 4);
    assert_eq!(disk.flushes, 2);
    assert_eq!(&disk.bytes[0..4], &[2; 4]);
    assert_eq!(&disk.bytes[8..12], &[1; 4]);
    assert!(disk.bytes[12..].iter().all(|b| *b == 0));
}
#[test]
fn stale_plan_does_not_write() {
    let mut disk = memory();
    disk.bytes[0] = 3;
    assert!(matches!(
        plan().commit(&mut disk),
        Err(CommitError::Stale { .. })
    ));
    assert_eq!(disk.writes, 0);
}
#[test]
fn failed_flush_reports_uncertain_durability_and_stops() {
    let mut disk = memory();
    disk.fail_flush = true;
    match plan().commit(&mut disk).unwrap_err() {
        CommitError::Interrupted {
            completed_stages,
            stage,
            durability_uncertain,
            ..
        } => {
            assert!(completed_stages.is_empty());
            assert_eq!(stage, "backup");
            assert!(durability_uncertain);
        }
        other => panic!("{other}"),
    }
    assert_eq!(&disk.bytes[0..4], &[0; 4]);
}

#[test]
fn file_adapter_lock_short_write_plan_and_bounds() {
    use partmgr::storage::FileStorage;
    let image = tempfile::NamedTempFile::new().unwrap();
    image.as_file().set_len(32).unwrap();
    let mut disk = FileStorage::open(image.path()).unwrap();
    assert!(FileStorage::open(image.path()).is_err());
    plan().commit(&mut disk).unwrap();
    assert!(disk.write_at(32, &[1]).is_err());
    assert!(disk.read_exact_at(33, &mut []).is_err());
    drop(disk);
    assert!(FileStorage::open(image.path()).is_ok());
}

struct Fault {
    disk: Memory,
    boundary: usize,
    fail: usize,
}
impl Storage for Fault {
    fn len(&self) -> io::Result<u64> {
        self.disk.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.disk.read_exact_at(offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.boundary += 1;
        if self.boundary == self.fail {
            return Err(io::Error::other("write interruption"));
        }
        self.disk.write_at(offset, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.boundary += 1;
        if self.boundary == self.fail {
            return Err(io::Error::other("flush interruption"));
        }
        self.disk.flush()
    }
}
#[test]
fn every_write_and_flush_boundary_reports_progress_and_stops() {
    for fail in 1..=6 {
        let mut disk = Fault {
            disk: memory(),
            boundary: 0,
            fail,
        };
        let CommitError::Interrupted {
            completed_stages,
            durability_uncertain,
            ..
        } = plan().commit(&mut disk).unwrap_err()
        else {
            panic!("interruption")
        };
        assert!(durability_uncertain);
        assert_eq!(disk.boundary, fail);
        assert_eq!(completed_stages.len(), usize::from(fail > 3));
        if fail <= 3 {
            assert_eq!(&disk.disk.bytes[..4], &[0; 4]);
        }
    }
}
