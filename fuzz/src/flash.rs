use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_flash::{FlashGeometry, FlashImage, FlashLayout, FlashLimits, FlashProgramming},
    storage::Storage,
};
use std::sync::{Arc, Mutex};
struct State {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    writes: usize,
    short: usize,
    cut: Option<usize>,
    fail_flush: bool,
}
struct Backend(Arc<Mutex<State>>);
impl Storage for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let s = self.0.lock().unwrap();
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            s.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap();
        s.writes += 1;
        let n = bytes.len().min(s.short);
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start.checked_add(n).ok_or(io::ErrorKind::UnexpectedEof)?;
        s.bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&bytes[..n]);
        if s.cut == Some(s.writes) {
            Err(io::Error::other("fuzz torn flash write"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        if s.fail_flush {
            return Err(io::Error::other("fuzz flash flush failure"));
        }
        s.durable = s.bytes.clone();
        Ok(())
    }
}
pub(crate) fn seeds() -> Vec<Vec<u8>> {
    let mut good = vec![0, 2, 0, 0, 3, 0, 64, 0];
    good.extend([0, 0, 0, 16, 0x7f, 0, 0, 0]);
    good.extend([0, 0, 0, 16, 0x3f, 0, 0, 0]);
    good.extend([1, 0, 0, 16, 0, 0, 0, 0]);
    good.extend([2, 0, 0, 16, 0, 0, 0, 0]);
    good.extend([3, 0, 0, 0, 0, 0, 0, 0]);
    let mut torn = good.clone();
    torn[5] = 2;
    let mut nand = good.clone();
    nand[3] = 1;
    let mut flush = good.clone();
    flush[3] = 2;
    let mut transition = good.clone();
    transition[20] = 0xff;
    vec![good, torn, nand, flush, transition, vec![0; 8]]
}
// Mutable backend implements Storage only; no immutable ReadAt adapter is created.
pub(crate) fn run(data: &[u8]) -> bool {
    if data.len() > 65536 {
        return false;
    }
    let byte = |at| data.get(at).copied().unwrap_or(0);
    let erase = 1u32 << (byte(0) % 7 + 4);
    let geometry = FlashGeometry {
        erase_bytes: erase,
        program_bytes: 1 << (byte(1) % 6),
        erased_byte: 0xff,
        programming: FlashProgramming::ClearBitsOnly,
        layout: if byte(3) & 1 == 0 {
            FlashLayout::LogicalNor
        } else {
            FlashLayout::PhysicalNand {
                page_bytes: 512,
                spare_bytes: 16,
            }
        },
    };
    let initial = if byte(7) & 1 == 0 { 0xff } else { 0 };
    let state = Arc::new(Mutex::new(State {
        bytes: vec![initial; 1024],
        durable: vec![initial; 1024],
        writes: 0,
        short: usize::from(byte(4) % 16 + 1),
        cut: if byte(5) == 0 {
            None
        } else {
            Some(usize::from(byte(5) % 64 + 1))
        },
        fail_flush: byte(3) & 2 != 0,
    }));
    let r = Resources {
        memory: Budget::new(u64::from(byte(6)) * 64),
        cancellation: Cancellation::default(),
    };
    let bad = if byte(2) & 1 == 0 {
        Vec::new()
    } else {
        vec![1024 / u64::from(erase) - 1]
    };
    let opened = FlashImage::new(
        Backend(state.clone()),
        geometry,
        &bad,
        FlashLimits {
            bad_blocks: 1,
            operation_bytes: 64,
            scratch_bytes: 32,
        },
        &r,
    );
    let mut flash = match opened {
        Ok(flash) => flash,
        Err(_) => {
            assert_eq!(r.memory.used(), 0);
            return false;
        }
    };
    let mut successful_program = false;
    for op in data
        .get(8..)
        .unwrap_or_default()
        .as_chunks::<8>()
        .0
        .iter()
        .take(16)
    {
        let at = if op[0] & 0x80 != 0 {
            u64::MAX
        } else {
            u64::from(u16::from_le_bytes([op[1], op[2]]))
        };
        let count = usize::from(op[3]);
        let before = state.lock().unwrap().bytes.clone();
        match op[0] % 4 {
            0 | 1 => {
                let erase = op[0] % 4 == 1;
                let result = if erase {
                    flash.erase(at, count as u64, &r)
                } else {
                    flash.program(at, &vec![op[4]; count], &r)
                };
                match result {
                    Ok(progress) => {
                        assert_eq!(progress.accepted_bytes, count as u64);
                        assert_eq!(progress.verified_bytes, count as u64);
                        let mut expected = before;
                        expected[at as usize..at as usize + count].fill(if erase {
                            0xff
                        } else {
                            op[4]
                        });
                        assert_eq!(state.lock().unwrap().bytes, expected);
                        successful_program |= !erase && count != 0;
                    }
                    Err(error) => {
                        if error.mutation_attempted {
                            assert!(flash.mutation_uncertain());
                        } else {
                            assert_eq!(state.lock().unwrap().bytes, before);
                        }
                        assert!(error.progress.verified_bytes <= error.progress.accepted_bytes);
                    }
                }
            }
            2 => {
                let mut out = vec![0; count];
                if flash.read_exact_at(at, &mut out, &r).is_ok() {
                    assert_eq!(out, before[at as usize..at as usize + count]);
                }
                assert_eq!(state.lock().unwrap().bytes, before);
            }
            _ => {
                if flash.flush(&r).is_ok() {
                    let s = state.lock().unwrap();
                    assert_eq!(s.bytes, s.durable);
                } else {
                    assert!(flash.mutation_uncertain());
                }
                assert_eq!(state.lock().unwrap().bytes, before);
            }
        }
    }
    r.cancellation.cancel();
    assert!(flash.program(0, &[], &r).is_err());
    assert!(flash.read_exact_at(1024, &mut [], &r).is_err());
    drop(flash);
    assert_eq!(r.memory.used(), 0);
    successful_program
}
