//! Private consuming resize transaction; cold resize recovery is separate work.
use super::*;
use crate::fs_undo::{UndoBinding, UndoFailure, UndoLimits, UndoPlan};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
struct Held<'a>(&'a mut dyn Storage);
impl Storage for Held<'_> {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
pub(crate) struct ResizeFailure<S> {
    pub(crate) target: S,
    pub(crate) error: UndoFailure,
}
pub(crate) struct ResizeRequest<'a> {
    pub(crate) path: &'a [NativeName],
    pub(crate) kind: &'a StreamKind,
    pub(crate) length: u64,
    pub(crate) offset: u64,
    pub(crate) replacement: &'a [u8],
}
impl<S: Storage> Prepared<S> {
    pub(crate) fn commit_resize(
        mut self,
        request: ResizeRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        undo: UndoLimits,
        r: &Resources,
    ) -> crate::platform::result::Result<Prepared<S>, ResizeFailure<S>> {
        let ResizeRequest {
            path,
            kind,
            length,
            offset,
            replacement,
        } = request;
        let planned = (|| -> Result<_> {
            let allocation = self.plan_resize_allocation(path, kind, length, r)?;
            let payload = self.stage_resize_payload(&allocation, offset, replacement, r)?;
            let metadata = self.stage_resize_metadata(path, kind, &allocation, r)?;
            let clean = self.volume.header()[6];
            let last = self.snapshot.length - 1018;
            let mut alternate = [0];
            self.target
                .read_exact_at(last, &mut alternate)
                .map_err(|e| Error::io("HFS+ resize alternate state", e))?;
            if clean & 1 == 0 || alternate != [clean] {
                return Err(bad("HFS+ resize native states disagree"));
            }
            let count = payload.patches.len();
            let meta_count = metadata.patches.len();
            let _lease = r.memory.reserve((count + meta_count + 2) as u64 * 128)?;
            let mut patches = vector(count + meta_count + 2)?;
            patches.extend(payload.patches);
            patches.extend(metadata.patches);
            patches.push(
                WriteRange::new(1030, vec![clean], vec![clean])
                    .map_err(|e| Error::io("HFS+ resize primary state", e))?,
            );
            patches.push(
                WriteRange::new(last, vec![clean], vec![clean])
                    .map_err(|e| Error::io("HFS+ resize alternate state", e))?,
            );
            let stages = if count == 0 {
                vec![meta_count, 2]
            } else {
                vec![count, meta_count, 2]
            };
            let plan =
                UndoPlan::new_staged(binding, self.snapshot.length, patches, &stages, undo, r)?;
            self.revalidate(r)?;
            Ok((plan, [(1030, clean), (last, clean)]))
        })();
        let (plan, states) = match planned {
            Ok(v) => v,
            Err(source) => {
                return Err(ResizeFailure {
                    target: self.target,
                    error: UndoFailure {
                        stage: "HFS+ resize preflight",
                        recovery_required: false,
                        target_may_have_changed: false,
                        source,
                    },
                });
            }
        };
        if let Err(error) = super::super::transaction::commit_dirty(
            &mut self.target,
            journal,
            &plan,
            states,
            self.limits,
            r,
        ) {
            return Err(ResizeFailure {
                target: self.target,
                error,
            });
        }
        let limits = self.limits;
        let renewed = Prepared::open(Held(&mut self.target), limits, r);
        match renewed {
            Ok(ready) => {
                let Prepared {
                    snapshot,
                    volume,
                    proof,
                    range_bytes,
                    limits,
                    generation,
                    uncertain,
                    ..
                } = ready;
                Ok(Prepared {
                    target: self.target,
                    snapshot,
                    volume,
                    proof,
                    range_bytes,
                    limits,
                    generation,
                    uncertain,
                })
            }
            Err(source) => Err(ResizeFailure {
                target: self.target,
                error: UndoFailure {
                    stage: "HFS+ resize renewed metadata",
                    recovery_required: true,
                    target_may_have_changed: true,
                    source,
                },
            }),
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn private_resize_commit_reopens_clean_and_preserves_old_physical_bytes() {
    struct Memory(Vec<u8>);
    impl Storage for Memory {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = at as usize;
            out.copy_from_slice(&self.0[at..at + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(997);
            self.0[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct NoWrites<'a>(&'a mut dyn Storage);
    impl Storage for NoWrites<'_> {
        fn len(&self) -> io::Result<u64> {
            self.0.len()
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(at, out)
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("semantic rejection wrote")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("semantic rejection flushed")
        }
    }
    struct Stop(Memory, bool);
    impl Storage for Stop {
        fn len(&self) -> io::Result<u64> {
            self.0.len()
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(at, out)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            if self.1 && at == 4096 {
                self.0.write_at(at, &bytes[..bytes.len().div_ceil(2)])?;
                return Err(std::io::Error::from_raw_os_error(5).into());
            }
            self.0.write_at(at, bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    for binary in [false, true] {
        for length in [0, 7, 4097, 70000] {
            let r = Resources {
                memory: Budget::new(16 << 20),
                cancellation: Cancellation::default(),
            };
            let mut original = super::super::super::independent::hfsplus_seed(binary);
            let header_at = 2 * 4096;
            let ranges =
                crate::fs_hfsplus::offsets(&original[header_at..header_at + 1024]).unwrap();
            let native_header = header_at + ranges[0].0;
            original[native_header + 30..native_header + 32].copy_from_slice(&[0x75, 0x19]);
            original[native_header + 32..native_header + 36]
                .copy_from_slice(&0x12000u32.to_be_bytes());
            original[native_header + 42..native_header + 106].fill(0x39);
            let user = header_at + ranges[1].0..header_at + ranges[1].1;
            original[user.clone()].fill(0x5a);
            let preserved_header = original[native_header + 30..native_header + 106].to_vec();
            let path = [NativeName::Utf16(
                super::super::super::independent::native_name(binary),
            )];
            let prepared = Prepared::open(Memory(original.clone()), limits, &r).unwrap();
            let allocation = prepared
                .plan_resize_allocation(&path, &StreamKind::Data, length, &r)
                .unwrap();
            let old = allocation.released.clone();
            drop(allocation);
            let mut journal = Memory(vec![0; 1 << 20]);
            let ready = match prepared.commit_resize(
                ResizeRequest {
                    path: &path,
                    kind: &StreamKind::Data,
                    length,
                    offset: 0,
                    replacement: &[],
                },
                &mut journal,
                UndoBinding {
                    volume: [0x55; 32],
                    generation: 1,
                    transaction: [0x77; 16],
                },
                UndoLimits {
                    patches: 256,
                    body_bytes: 1 << 19,
                },
                &r,
            ) {
                Ok(v) => v,
                Err(e) => {
                    assert_eq!(e.target.0.len(), original.len());
                    panic!("{}", e.error.source);
                }
            };
            assert!(ready.proof.is_clean());
            let changed_ranges =
                crate::fs_hfsplus::offsets(&ready.target.0[header_at..header_at + 1024]).unwrap();
            let changed_header = header_at + changed_ranges[0].0;
            assert_eq!(
                &ready.target.0[changed_header + 30..changed_header + 106],
                preserved_header
            );
            assert_eq!(
                &ready.target.0[header_at + changed_ranges[1].0..header_at + changed_ranges[1].1],
                &original[user.clone()]
            );
            let id = ready.volume.lookup(&path, &r).unwrap();
            assert_eq!(
                ready
                    .volume
                    .open_fork(&id, &StreamKind::Data, &r)
                    .unwrap()
                    .len(),
                length
            );
            for (start, count) in old {
                let range = start as usize * 4096..(start + count) as usize * 4096;
                assert_eq!(&ready.target.0[range.clone()], &original[range]);
            }
            let mut target = ready.into_storage();
            assert_eq!(
                super::recovery::recover_resize(
                    &mut target,
                    &mut journal,
                    ResizeRequest {
                        path: &path,
                        kind: &StreamKind::Data,
                        length,
                        offset: 0,
                        replacement: &[]
                    },
                    UndoBinding {
                        volume: [0x55; 32],
                        generation: 1,
                        transaction: [0x77; 16]
                    },
                    limits,
                    UndoLimits {
                        patches: 256,
                        body_bytes: 1 << 19
                    },
                    &r
                )
                .unwrap()
                .state,
                crate::fs_undo::UndoState::Committed
            );
            assert_eq!(r.memory.used(), 0);
            let prepared =
                Prepared::open(Stop(Memory(original.clone()), true), limits, &r).unwrap();
            let mut interrupted_journal = Memory(vec![0; 1 << 20]);
            let binding = UndoBinding {
                volume: [0x55; 32],
                generation: 1,
                transaction: [0x77; 16],
            };
            let undo = UndoLimits {
                patches: 256,
                body_bytes: 1 << 19,
            };
            let failed = match prepared.commit_resize(
                ResizeRequest {
                    path: &path,
                    kind: &StreamKind::Data,
                    length,
                    offset: 0,
                    replacement: &[],
                },
                &mut interrupted_journal,
                binding,
                undo,
                &r,
            ) {
                Ok(_) => panic!("bitmap cut did not fail"),
                Err(e) => e,
            };
            assert!(failed.error.recovery_required);
            let mut target = failed.target;
            target.1 = false;
            assert_eq!(target.0.0[1030] & 1, 0);
            {
                let mut guarded_target = NoWrites(&mut target);
                let mut guarded_journal = NoWrites(&mut interrupted_journal);
                assert!(
                    super::recovery::recover_resize(
                        &mut guarded_target,
                        &mut guarded_journal,
                        ResizeRequest {
                            path: &path,
                            kind: &StreamKind::Data,
                            length: length + 1,
                            offset: 0,
                            replacement: &[]
                        },
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .is_err()
                );
                assert!(
                    super::recovery::recover_resize(
                        &mut guarded_target,
                        &mut guarded_journal,
                        ResizeRequest {
                            path: &path,
                            kind: &StreamKind::ResourceFork,
                            length,
                            offset: 0,
                            replacement: &[]
                        },
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .is_err()
                );
            }
            assert_eq!(
                super::recovery::recover_resize(
                    &mut target,
                    &mut interrupted_journal,
                    ResizeRequest {
                        path: &path,
                        kind: &StreamKind::Data,
                        length,
                        offset: 0,
                        replacement: &[]
                    },
                    binding,
                    limits,
                    undo,
                    &r
                )
                .unwrap()
                .state,
                crate::fs_undo::UndoState::RolledBack
            );
            assert_eq!(target.0.0, original);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
