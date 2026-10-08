use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_flash::{FlashGeometry, FlashImage, FlashLayout, FlashLimits, FlashProgramming},
    storage::Storage,
};
use std::{
    io,
    sync::{Arc, Mutex},
};
struct State {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    reads: usize,
    writes: usize,
    short: usize,
    fail_write: Option<usize>,
    fail_read: Option<usize>,
    fail_flush: bool,
    cancel_after_write: Option<Cancellation>,
}
struct Backend(Arc<Mutex<State>>);
impl Storage for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        state.reads += 1;
        if state.fail_read == Some(state.reads) {
            return Err(io::Error::other("injected flash read"));
        }
        let at = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            state
                .bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        state.writes += 1;
        let n = bytes.len().min(state.short);
        let at = at as usize;
        state.bytes[at..at + n].copy_from_slice(&bytes[..n]);
        if let Some(cancel) = &state.cancel_after_write {
            cancel.cancel();
        }
        if state.fail_write == Some(state.writes) {
            Err(io::Error::other("injected torn flash write"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.fail_flush {
            return Err(io::Error::other("injected flash flush"));
        }
        state.durable = state.bytes.clone();
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    }
}
fn geometry() -> FlashGeometry {
    FlashGeometry {
        erased_byte: 0xff,
        programming: FlashProgramming::ClearBitsOnly,
        erase_bytes: 32,
        program_bytes: 4,
        layout: FlashLayout::LogicalNor,
    }
}
fn limits() -> FlashLimits {
    FlashLimits {
        bad_blocks: 8,
        operation_bytes: 128,
        scratch_bytes: 16,
    }
}
fn make_backend() -> (Backend, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        bytes: vec![0xff; 256],
        durable: vec![0xff; 256],
        reads: 0,
        writes: 0,
        short: 2,
        fail_write: None,
        fail_read: None,
        fail_flush: false,
        cancel_after_write: None,
    }));
    (Backend(state.clone()), state)
}
#[test]
fn aligned_nor_program_erase_readback_flush_and_refunds() {
    let r = resources();
    let (backend, state) = make_backend();
    let mut flash = FlashImage::new(backend, geometry(), &[3], limits(), &r).unwrap();
    assert_eq!(flash.len(), 256);
    assert!(!flash.is_empty());
    assert_eq!(flash.geometry(), geometry());
    assert_eq!(flash.erased_byte(), 0xff);
    assert_eq!(flash.bad_blocks(), [3]);
    let done = flash.program(16, &[0x5a; 48], &r).unwrap();
    assert_eq!(done.accepted_bytes, 48);
    assert_eq!(done.verified_bytes, 48);
    assert_eq!(state.lock().unwrap().durable, [0xff; 256]);
    let done = flash.program(16, &[0x18; 48], &r).unwrap();
    assert_eq!(done.verified_bytes, 48);
    let mut out = [0; 48];
    flash.read_exact_at(16, &mut out, &r).unwrap();
    assert_eq!(out, [0x18; 48]);
    flash.flush(&r).unwrap();
    assert_eq!(&state.lock().unwrap().durable[16..64], &[0x18; 48]);
    let done = flash.erase(0, 64, &r).unwrap();
    assert_eq!(done.verified_bytes, 64);
    flash.program(0, &[0x7f; 8], &r).unwrap();
    flash.flush(&r).unwrap();
    let state = state.lock().unwrap();
    assert_eq!(&state.bytes[..8], &[0x7f; 8]);
    assert_eq!(&state.bytes[8..], &[0xff; 248]);
    assert!(!flash.mutation_uncertain());
    drop(state);
    drop(flash);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn whole_range_transition_bad_blocks_bounds_alignment_and_caps_preflight() {
    let r = resources();
    let (backend, state) = make_backend();
    // Invalid transition occurs only in the final scratch chunk: no earlier bytes change.
    state.lock().unwrap().bytes[47] = 0;
    let mut flash = FlashImage::new(backend, geometry(), &[3], limits(), &r).unwrap();
    let error = flash.program(0, &[0xfe; 48], &r).unwrap_err();
    assert_eq!(error.source.kind, ErrorKind::InvalidOperation);
    assert!(!error.mutation_attempted);
    assert_eq!(state.lock().unwrap().writes, 0);
    for (offset, count) in [(1, 4), (0, 3), (252, 8), (u64::MAX, 4), (80, 32), (0, 132)] {
        assert!(flash.program(offset, &vec![0; count], &r).is_err());
    }
    for (offset, count) in [
        (1, 32),
        (0, 31),
        (224, 64),
        (u64::MAX, 32),
        (64, 64),
        (0, 160),
    ] {
        assert!(flash.erase(offset, count, &r).is_err());
    }
    assert_eq!(state.lock().unwrap().writes, 0);
    assert!(!flash.mutation_uncertain());
    flash.read_exact_at(96, &mut [0; 8], &r).unwrap(); // Bad-block inspection is explicit.
    assert!(flash.read_exact_at(257, &mut [], &r).is_err());
    assert!(flash.program(256, &[], &r).is_ok());
    drop(flash);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn declared_layout_geometry_bad_indices_and_memory_fail_before_mutation() {
    let r = resources();
    for bad in [vec![2, 1], vec![1, 1], vec![8]] {
        let (backend, state) = make_backend();
        assert!(FlashImage::new(backend, geometry(), &bad, limits(), &r).is_err());
        assert_eq!(state.lock().unwrap().writes, 0);
        assert_eq!(r.memory.used(), 0);
    }
    for g in [
        FlashGeometry {
            erased_byte: 0,
            ..geometry()
        },
        FlashGeometry {
            programming: FlashProgramming::SetBitsOnly,
            ..geometry()
        },
        FlashGeometry {
            erase_bytes: 0,
            ..geometry()
        },
        FlashGeometry {
            program_bytes: 3,
            ..geometry()
        },
        FlashGeometry {
            layout: FlashLayout::PhysicalNand {
                page_bytes: 2048,
                spare_bytes: 64,
            },
            ..geometry()
        },
    ] {
        let (backend, state) = make_backend();
        assert!(FlashImage::new(backend, g, &[], limits(), &r).is_err());
        assert_eq!(state.lock().unwrap().writes, 0);
    }
    let (backend, _) = make_backend();
    let tiny = Resources {
        memory: Budget::new(287),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        FlashImage::new(backend, geometry(), &[], limits(), &tiny)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(tiny.memory.used(), 0);
    let (backend, state) = make_backend();
    let excessive = FlashLimits {
        scratch_bytes: usize::MAX - 3,
        ..limits()
    };
    assert_eq!(
        FlashImage::new(backend, geometry(), &[], excessive, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(state.lock().unwrap().writes, 0);
    assert_eq!(r.memory.used(), 0);
    let (backend, state) = make_backend();
    state.lock().unwrap().bytes.pop();
    assert!(FlashImage::new(backend, geometry(), &[], limits(), &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn preflight_io_stale_length_and_cancellation_do_not_mutate() {
    let r = resources();
    let (backend, state) = make_backend();
    let mut flash = FlashImage::new(backend, geometry(), &[], limits(), &r).unwrap();
    state.lock().unwrap().fail_read = Some(2);
    let error = flash.program(0, &[0x7f; 48], &r).unwrap_err();
    assert_eq!(error.source.kind, ErrorKind::Io);
    assert!(!error.mutation_attempted);
    assert_eq!(state.lock().unwrap().writes, 0);
    r.cancellation.cancel();
    assert_eq!(
        flash.erase(0, 32, &r).unwrap_err().source.kind,
        ErrorKind::Cancelled
    );
    assert!(flash.read_exact_at(256, &mut [], &r).is_err());
    let active = resources();
    state.lock().unwrap().bytes.pop();
    assert_eq!(
        flash.erase(0, 32, &active).unwrap_err().source.kind,
        ErrorKind::StalePlan
    );
    assert!(!flash.mutation_uncertain());
    drop(flash);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn torn_writes_readback_cancellation_and_flush_have_explicit_uncertainty() {
    for mode in 0..4 {
        let r = resources();
        let (backend, state) = make_backend();
        let mut flash = FlashImage::new(backend, geometry(), &[], limits(), &r).unwrap();
        match mode {
            0 => state.lock().unwrap().fail_write = Some(2),
            1 => state.lock().unwrap().fail_read = Some(2), // First read is preflight; second is readback.
            2 => state.lock().unwrap().cancel_after_write = Some(r.cancellation.clone()),
            _ => state.lock().unwrap().fail_flush = true,
        }
        if mode == 3 {
            flash.program(0, &[0x7f; 8], &r).unwrap();
            let error = flash.flush(&r).unwrap_err();
            assert_eq!(error.source.kind, ErrorKind::UncertainDurability);
            state.lock().unwrap().fail_flush = false;
            flash.flush(&r).unwrap();
        } else {
            let error = flash.program(0, &[0x7f; 8], &r).unwrap_err();
            assert!(error.mutation_attempted);
            assert_eq!(error.source.kind, ErrorKind::InterruptedWrite);
            if mode == 0 {
                assert_eq!(error.progress.accepted_bytes, 2);
            }
            if mode == 1 {
                assert_eq!(error.progress.accepted_bytes, 8);
                assert_eq!(error.progress.verified_bytes, 0);
            }
            assert!(std::error::Error::source(&error).is_some());
        }
        assert!(flash.mutation_uncertain());
        let (_, uncertain) = flash.into_storage();
        assert!(uncertain);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn every_program_and_erase_write_cut_preserves_unaffected_blocks() {
    use partmgr::fs_flash::FlashStorage;
    for erase in [false, true] {
        let count = if erase { 64 } else { 32 };
        for cut in 1..=count / 2 {
            let r = resources();
            let (backend, state) = make_backend();
            let initial = if erase { 0 } else { 0xff };
            {
                let mut state = state.lock().unwrap();
                state.bytes.fill(initial);
                state.durable.fill(initial);
                state.fail_write = Some(cut);
            }
            let mut image = FlashImage::new(backend, geometry(), &[], limits(), &r).unwrap();
            let flash: &mut dyn FlashStorage = &mut image;
            assert_eq!(flash.len().unwrap(), 256);
            assert!(!flash.is_empty().unwrap());
            assert_eq!(flash.geometry(), geometry());
            let error = if erase {
                flash.erase(32, count as u64, &r)
            } else {
                flash.program(32, &[0x7f; 32], &r)
            }
            .unwrap_err();
            assert!(error.mutation_attempted);
            assert_eq!(error.source.kind, ErrorKind::InterruptedWrite);
            assert_eq!(error.progress.accepted_bytes, ((cut - 1) * 2) as u64);
            assert!(error.progress.verified_bytes <= error.progress.accepted_bytes);
            assert!(flash.mutation_uncertain());
            let state = state.lock().unwrap();
            assert_eq!(&state.bytes[..32], vec![initial; 32]);
            assert_eq!(&state.bytes[32 + count..], vec![initial; 256 - 32 - count]);
            assert_eq!(state.durable, vec![initial; 256]);
            let changed = if erase { 0xff } else { 0x7f };
            assert_eq!(&state.bytes[32..32 + cut * 2], vec![changed; cut * 2]);
            drop(state);
            drop(image);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
