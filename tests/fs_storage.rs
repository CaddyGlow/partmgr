#![cfg(feature = "std")]

use partmgr::{
    fs_storage::{BoundedSession, SectorGeometry, UncertainMutation},
    storage::{FileStorage, Storage},
};
use std::{
    io,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    writes: usize,
    fail_write: bool,
    fail_flush: bool,
}
struct Backend(Arc<Mutex<State>>);
impl Storage for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            &self.0.lock().unwrap().bytes[offset as usize..offset as usize + out.len()],
        );
        Ok(())
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        state.writes += 1;
        let n = bytes.len().min(2);
        state.bytes[offset as usize..offset as usize + n].copy_from_slice(&bytes[..n]);
        if state.fail_write {
            return Err(io::Error::other("injected partial write"));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.0.lock().unwrap().fail_flush {
            Err(io::Error::other("injected flush"))
        } else {
            Ok(())
        }
    }
}
fn fixture() -> (BoundedSession<Backend>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        bytes: vec![7; 16],
        ..Default::default()
    }));
    (
        BoundedSession::new(Backend(state.clone()), 4, 8, SectorGeometry::default()).unwrap(),
        state,
    )
}
#[test]
fn bounds_are_checked_before_mutation_and_short_writes_are_preserved() {
    let (mut session, state) = fixture();
    assert_eq!(session.len().unwrap(), 8);
    assert_eq!(session.geometry(), SectorGeometry::default());
    for (offset, count) in [(7, 2), (u64::MAX, 2), (9, 0)] {
        assert!(session.write_at(offset, &vec![0; count]).is_err());
        assert!(session.zero_at(offset, count as u64).is_err());
        assert!(session.read_exact_at(offset, &mut vec![0; count]).is_err());
    }
    assert_eq!(state.lock().unwrap().writes, 0);
    assert!(!session.mutation_uncertain());
    assert_eq!(session.write_at(0, &[1, 2, 3]).unwrap(), 2);
    let mut out = [0; 3];
    session.read_exact_at(0, &mut out).unwrap();
    assert_eq!(out, [1, 2, 7]);
    session.zero_at(0, 8).unwrap();
    assert_eq!(
        state.lock().unwrap().bytes,
        [vec![7; 4], vec![0; 8], vec![7; 4]].concat()
    );
    assert!(session.write_at(8, &[]).is_ok());
}
#[test]
fn partial_write_and_flush_failures_retain_uncertainty_and_sources() {
    let (mut session, state) = fixture();
    state.lock().unwrap().fail_write = true;
    let error = session.write_at(0, &[1, 2, 3]).unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<UncertainMutation>()
            .unwrap()
            .operation(),
        "write"
    );
    assert!(session.mutation_uncertain());
    let mut out = [0; 3];
    session.read_exact_at(0, &mut out).unwrap();
    assert_eq!(out, [1, 2, 7]);
    state.lock().unwrap().fail_write = false;
    session.flush().unwrap();
    assert!(session.mutation_uncertain());
    let (mut session, state) = fixture();
    state.lock().unwrap().fail_flush = true;
    let error = session.flush().unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<UncertainMutation>()
            .unwrap()
            .operation(),
        "flush"
    );
    assert!(session.mutation_uncertain());
}
#[test]
fn changed_geometry_and_constructor_overflow_are_rejected() {
    let (mut session, state) = fixture();
    state.lock().unwrap().bytes.push(0);
    assert!(session.write_at(0, &[0]).is_err());
    assert_eq!(state.lock().unwrap().writes, 0);
    assert!(session.flush().is_err());
    assert!(session.mutation_uncertain());
    assert!(BoundedSession::new(Backend(state), u64::MAX, 2, SectorGeometry::default()).is_err());
    assert!(SectorGeometry::new(Some(0), None).is_err());
}
#[test]
fn raw_file_session_reads_after_write_and_retains_backend_lock() {
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(32).unwrap();
    let backend = FileStorage::open(file.path()).unwrap();
    let mut session = BoundedSession::new(
        backend,
        8,
        16,
        SectorGeometry::new(Some(512), None).unwrap(),
    )
    .unwrap();
    assert!(FileStorage::open(file.path()).is_err());
    assert_eq!(session.write_at(4, &[1, 2, 3]).unwrap(), 3);
    session.flush().unwrap();
    let mut out = [0; 3];
    session.read_exact_at(4, &mut out).unwrap();
    assert_eq!(out, [1, 2, 3]);
    drop(session);
    assert!(FileStorage::open(file.path()).is_ok());
}

#[test]
fn immutable_region_retains_context_budget_and_nonzero_translation() {
    use partmgr::fs_storage::ImmutableRegion;
    use std::io::Write;
    use virtdisk::{ParserLimits, RawDisk, ReadAt, ReadBudget, ReadContext, contextual_reader};
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&(0u8..32).collect::<Vec<_>>()).unwrap();
    let budget = ReadBudget::new(ParserLimits::default()).unwrap();
    let context = ReadContext {
        container: Some(file.path().into()),
        record: Some(42),
        ..Default::default()
    };
    let source = contextual_reader(
        budget.reader(Arc::new(RawDisk::open(file.path()).unwrap())),
        context.clone(),
    );
    let region = ImmutableRegion::new(source, 8, 8)
        .unwrap()
        .with_partition(3);
    let mut out = [0; 4];
    region.read_exact_at(2, &mut out).unwrap();
    assert_eq!(out, [10, 11, 12, 13]);
    assert_eq!(region.context().record, context.record);
    assert_eq!(region.context().container, context.container);
    assert_eq!(region.context().partition, Some(3));
    region.budget().unwrap().metadata(17).unwrap();
    assert_eq!(budget.usage().metadata_bytes, 17);
    assert!(budget.usage().work_items > 0);
    assert!(region.read_exact_at(7, &mut out).is_err());
    assert!(region.read_exact_at(u64::MAX, &mut []).is_err());
}
