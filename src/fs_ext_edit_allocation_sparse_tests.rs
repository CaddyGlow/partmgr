//! Private authority adversaries; fixture bytes are independent of the planner.
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
fn sparse_fixture() -> Vec<u8> {
    let mut raw = independent::fixture();
    let inode = 5 * 1024 + 10 * 128;
    raw[inode + 4..inode + 8].copy_from_slice(&(13 * 1024 + 128u32).to_le_bytes());
    raw[inode + 28..inode + 32].copy_from_slice(&30u32.to_le_bytes());
    for logical in 0..12 {
        raw[inode + 40 + logical * 4..inode + 44 + logical * 4]
            .copy_from_slice(&(8 + logical as u32).to_le_bytes());
    }
    raw[inode + 88..inode + 92].copy_from_slice(&20u32.to_le_bytes());
    raw[20 * 1024..21 * 1024].fill(0);
    raw[20 * 1024..20 * 1024 + 4].copy_from_slice(&21u32.to_le_bytes());
    raw[20 * 1024 + 4..20 * 1024 + 8].copy_from_slice(&22u32.to_le_bytes());
    raw[3072..4096].fill(255);
    for bit in 22..63 {
        raw[3072 + bit / 8] &= !(1 << (bit % 8));
    }
    raw[1036..1040].copy_from_slice(&41u32.to_le_bytes());
    raw[2060..2062].copy_from_slice(&41u16.to_le_bytes());
    for block in (8..20).chain(21..23) {
        raw[block * 1024..(block + 1) * 1024].fill(block as u8 + 40);
    }
    raw
}
#[test]
fn sparse_prefinish_authority_adversaries_and_valid_controls_are_write_free() {
    for attack in 0..10 {
        let r = Resources {
            memory: Budget::new(256 << 20),
            cancellation: Cancellation::default(),
        };
        let original = if attack == 9 {
            independent::fixture()
        } else {
            sparse_fixture()
        };
        let limits = ExtEditLimits {
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
                volume: [0x72; 32],
                generation: 0,
            },
            limits,
            &r,
        )
        .unwrap();
        {
            let context = editor.planning_context(&r).unwrap();
            let file = context.file_handle(11, &r).unwrap();
            let mut p = Planner::new(&context, &r).unwrap();
            let new_length = if attack == 9 { 4096 } else { 16 * 1024 };
            p.begin_ordered(OrderedOperation::SparseExtend {
                inode: 11,
                inode_generation: file.inode.generation(),
                old_length: file.len(),
                new_length,
            })
            .unwrap();
            let mut data = if attack == 9 {
                vec![8, 0, 0, 0]
            } else {
                (8..20).chain([21, 22, 0, 0]).collect::<Vec<u32>>()
            };
            if attack != 9 {
                let mut body = vec![0; 1024];
                body[..128].copy_from_slice(&original[22 * 1024..22 * 1024 + 128]);
                if attack == 2 {
                    body[0] ^= 1;
                }
                if attack == 3 {
                    body[1023] = 99;
                }
                let token = p.allocate_regular(13).unwrap();
                data[13] = Planner::regular_block(&token);
                p.patch_regular_fresh(token, body).unwrap();
                if attack == 6 {
                    p.ordered.as_mut().unwrap().data[0].origin =
                        OrderedOrigin::ExistingAppendTail {
                            visible_prefix_bytes: 128,
                        };
                }
                if attack != 1 {
                    p.ordered.as_mut().unwrap().source_guard = Some((
                        if attack == 0 { 21 * 1024 } else { 22 * 1024 },
                        original[22 * 1024..23 * 1024].to_vec(),
                        r.memory.reserve(1024).unwrap(),
                    ));
                }
                p.free_block(22).unwrap();
                if attack == 4 {
                    let block = p.allocate().unwrap();
                    data[14] = block;
                    p.patch(u64::from(block) * 1024, vec![0; 1024], Phase::Initialize)
                        .unwrap();
                }
            }
            publish_map(&mut p, &file.inode, &data, new_length).unwrap();
            if attack == 5 {
                // Preserve the final logical data map but relocate its indirect node.
                let replacement = p.allocate().unwrap();
                let mut page = original[20 * 1024..21 * 1024].to_vec();
                page[4..8].copy_from_slice(&data[13].to_le_bytes());
                p.patch(u64::from(replacement) * 1024, page, Phase::Initialize)
                    .unwrap();
                p.free_block(20).unwrap();
                let at = p.inode_offset(11).unwrap();
                p.edit(at + 88, &replacement.to_le_bytes(), Phase::Publish)
                    .unwrap();
            }
            if attack == 7 {
                let at = p.inode_offset(11).unwrap();
                p.edit(at + 12, &77u32.to_le_bytes(), Phase::Publish)
                    .unwrap();
            }
            let result = p.finish(context.scope, context.generation, None);
            if attack >= 8 {
                drop(result.expect("valid sparse control must pass"));
            } else {
                let error = result.err().expect("forged sparse authority must refuse");
                let expected = match attack {
                    0 => "sparse extension guard mapping",
                    1 => "ordered data coverage incomplete",
                    2 | 3 => "sparse COW bytes differ",
                    4 => "sparse extension mapping differs",
                    5 => "sparse extension pointer root changed",
                    6 => "ordered data origin bounds",
                    7 => "sparse extension changed unrelated inode metadata",
                    _ => unreachable!(),
                };
                assert!(
                    error.to_string().contains(expected),
                    "attack={attack}: {error:?}"
                );
            }
        }
        let (target, journal, state) = editor.into_stores();
        assert_eq!(state, ExtEditState::Ready);
        assert_eq!(target.writes + journal.writes, 0);
        assert_eq!(target.bytes, original);
        drop((target, journal));
        assert_eq!(r.memory.used(), 0);
    }
}
