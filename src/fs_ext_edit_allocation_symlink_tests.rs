//! Private prefinish authority tests using an independently authored byte fixture.
use super::super::namespace::ExtCreateMetadata;
use super::super::transaction::SymlinkAction;
use super::*;
use crate::fs_core::{Budget, Cancellation};
use crate::fs_maintenance_audit::clean_fixture as independent;
struct Memory {
    bytes: Vec<u8>,
    writes: usize,
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let at = usize::try_from(at).map_err(io::Error::other)?;
        self.bytes
            .get_mut(at..at + input.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn limits() -> ExtEditLimits {
    ExtEditLimits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 64,
            inodes: 16,
            work: 1_000_000,
            directory_blocks: 8,
            directory_entries: 64,
            findings: 32,
        },
        file_blocks: 32,
        directory_entries: 64,
        affected_bytes: 65536,
        work: 500_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 128,
            body_bytes: 131072,
        },
    }
}
fn single_slow_symlink() -> Vec<u8> {
    let mut raw = independent::fixture();
    let at = 5 * 1024 + 10 * 128;
    raw[at..at + 2].copy_from_slice(&0xa1ffu16.to_le_bytes());
    raw[at + 4..at + 8].copy_from_slice(&60u32.to_le_bytes());
    raw[at + 26..at + 28].copy_from_slice(&1u16.to_le_bytes());
    raw[7 * 1024 + 24 + 7] = 7;
    raw[7 * 1024 + 40..7 * 1024 + 44].fill(0); // remove alias, retaining legal unused record
    raw[8 * 1024..9 * 1024].fill(0);
    raw[8 * 1024..8 * 1024 + 60].fill(b't');
    raw
}
#[derive(Clone, Copy, Debug)]
enum Attack {
    ValidCreate,
    CreateOldGuard,
    Generation,
    Target,
    Bitmap,
    Source,
    RawGuard,
    SlowGuard,
    ValidUnlink,
    UnlinkFresh,
    Work,
}
#[test]
fn symlink_prefinish_forgery_refusals_are_write_free_and_refund() {
    use Attack::*;
    for attack in [
        ValidCreate,
        CreateOldGuard,
        Generation,
        Target,
        Bitmap,
        Source,
        RawGuard,
        SlowGuard,
        ValidUnlink,
        UnlinkFresh,
        Work,
    ] {
        let r = Resources {
            memory: Budget::new(256 << 20),
            cancellation: Cancellation::default(),
        };
        let unlink = matches!(attack, SlowGuard | ValidUnlink | UnlinkFresh);
        let original = if unlink {
            single_slow_symlink()
        } else {
            independent::fixture()
        };
        let editor = ExtEditor::open(
            Memory {
                bytes: original.clone(),
                writes: 0,
            },
            Memory {
                bytes: vec![0; 131072],
                writes: 0,
            },
            ExtEditRegion {
                offset: 0,
                length: 65536,
            },
            ExtEditBinding {
                volume: [0x79; 32],
                generation: 0,
            },
            limits(),
            &r,
        )
        .unwrap();
        {
            let context = editor.planning_context(&r).unwrap();
            let parent = context.open_directory(&[], &r).unwrap();
            // Obtain independently validated lifecycle patches, then replay their
            // operation effects with adversarial typed authority. finish() appends
            // its own clean-state patch; that generated patch is not an input
            // operation effect and must not be replayed a second time.
            let mut valid = if unlink {
                context
                    .plan_unlink_symlink(&parent, &[b'x', 255], 1_700_000_000, &r)
                    .unwrap()
            } else {
                context
                    .plan_create_symlink(
                        &parent,
                        b"new-link",
                        &[b'z'; 60],
                        &ExtCreateMetadata::zeroed(0xa1ff),
                        &r,
                    )
                    .unwrap()
            };
            let mut evidence = valid.symlink.pop().unwrap();
            assert_eq!(
                evidence.action,
                if unlink {
                    SymlinkAction::Unlink
                } else {
                    SymlinkAction::Create
                }
            );
            match attack {
                CreateOldGuard => {
                    evidence.original_slow = Some((8 * 1024, original[8 * 1024..9 * 1024].to_vec()))
                }
                Generation => evidence.final_inode[100..104].copy_from_slice(&77u32.to_le_bytes()),
                Target => evidence.target[0] ^= 1,
                Source => evidence.source ^= 1,
                RawGuard => evidence.original_inode[12] ^= 1,
                SlowGuard => evidence.original_slow.as_mut().unwrap().1[0] ^= 1,
                UnlinkFresh => evidence.fresh_slow = Some(9),
                _ => {}
            }
            let inode_offset = evidence.inode_offset;
            let mut p = Planner::new(&context, &r).unwrap();
            p.begin_symlink_metadata().unwrap();
            let mut generated_clean_patches = 0;
            for patch in &valid.patches {
                if patch.offset() == 1024 + 58 && patch.replacement().len() == 2 {
                    assert_eq!(patch.replacement(), &[1, 0]);
                    generated_clean_patches += 1;
                    continue;
                }
                let mut body = patch.replacement().to_vec();
                if matches!(attack, Generation)
                    && patch.offset() <= inode_offset + 100
                    && inode_offset + 104 <= patch.offset() + body.len() as u64
                {
                    let offset = (inode_offset + 100 - patch.offset()) as usize;
                    body[offset..offset + 4].copy_from_slice(&77u32.to_le_bytes());
                }
                // Clear the newly assigned inode bitmap bit while retaining the
                // native counters and namespace: the prospective audit must refuse.
                if matches!(attack, Bitmap)
                    && patch.offset() <= 4097
                    && 4097 < patch.offset() + body.len() as u64
                {
                    body[(4097 - patch.offset()) as usize] &= !(1 << 3);
                }
                p.patch(patch.offset(), body, Phase::Publish).unwrap();
            }
            assert_eq!(generated_clean_patches, 1);
            let result = p.set_symlink_evidence(evidence).and_then(|()| {
                if matches!(attack, Work) {
                    p.work = p.limits.work;
                }
                p.finish(context.scope, context.generation, None)
            });
            if matches!(attack, ValidCreate | ValidUnlink) {
                drop(result.expect("valid control must pass"));
            } else {
                let error = result.err().expect("forged authority must refuse");
                let expected = match attack {
                    CreateOldGuard => "symlink creation carries original target guard",
                    Generation => "symlink lifecycle proof differs",
                    Target => "symlink target bytes differ",
                    Bitmap => "prospective ownership audit rejected",
                    Source => "symlink purpose/evidence mismatch",
                    RawGuard => "symlink inode guard changed",
                    SlowGuard => "symlink target source changed",
                    UnlinkFresh => "symlink final unlink carries fresh target",
                    Work => "work",
                    _ => unreachable!(),
                };
                assert!(
                    error.to_string().contains(expected),
                    "{attack:?}: {error:?}"
                );
            }
        }
        let (target, journal, state) = editor.into_stores();
        assert_eq!(state, ExtEditState::Ready);
        assert_eq!(target.writes + journal.writes, 0);
        assert_eq!(target.bytes, original);
        drop((target, journal));
        assert_eq!(r.memory.used(), 0, "{attack:?}");
    }
}
