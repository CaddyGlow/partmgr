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
fn fixture() -> Vec<u8> {
    let mut raw = independent::fixture();
    // Give the aliased regular inode two genuinely allocated logical blocks.
    let inode = 5 * 1024 + 10 * 128;
    raw[inode + 4..inode + 8].copy_from_slice(&2048u32.to_le_bytes());
    raw[inode + 28..inode + 32].copy_from_slice(&4u32.to_le_bytes());
    raw[inode + 44..inode + 48].copy_from_slice(&9u32.to_le_bytes());
    raw[3073] |= 1; // Physical9 -> bitmap bit8 (firstdata1).
    raw[1036..1040].copy_from_slice(&54u32.to_le_bytes());
    raw[2060..2062].copy_from_slice(&54u16.to_le_bytes());
    raw[9 * 1024..10 * 1024].fill(0x62);
    raw
}
#[test]
fn overwrite_prefinish_rejects_forged_guard_body_origin_and_untouched_map_without_writes() {
    for attack in 0..=6 {
        let r = Resources {
            memory: Budget::new(256 << 20),
            cancellation: Cancellation::default(),
        };
        let original = fixture();
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
            work: 250_000,
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
                length: original.len() as u64,
            },
            ExtEditBinding {
                volume: [0x71; 32],
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
            p.begin_ordered(OrderedOperation::Overwrite {
                inode: 11,
                inode_generation: file.inode.generation(),
                length: 2048,
                offset: 3,
                bytes: 2,
            })
            .unwrap();
            let mut body = original[8192..9216].to_vec();
            body[3..5].copy_from_slice(&[7, 8]);
            if attack == 2 {
                body[0] ^= 1;
            }
            if attack == 3 {
                body[1023] ^= 1;
            }
            let token = p.allocate_regular(0).unwrap();
            let fresh = Planner::regular_block(&token);
            p.patch_regular_fresh(token, body).unwrap();
            if attack == 4 {
                p.ordered.as_mut().unwrap().data[0].origin = OrderedOrigin::ExistingAppendTail {
                    visible_prefix_bytes: 3,
                };
            }
            let mut guards = Vec::with_capacity(1);
            if attack != 1 {
                guards.push((
                    if attack == 0 { 9216 } else { 8192 },
                    original[8192..9216].to_vec(),
                    r.memory.reserve(1024).unwrap(),
                ));
            }
            let evidence_lease = r
                .memory
                .reserve((core::mem::size_of::<(u64, Vec<u8>, Reservation)>() + 2) as u64)
                .unwrap();
            p.ordered.as_mut().unwrap().overwrite = Some(OverwriteEvidence {
                guards,
                input: vec![7, 8],
                _lease: evidence_lease,
            });
            p.free_block(8).unwrap();
            let second = if attack == 5 {
                p.free_block(9).unwrap();
                0
            } else {
                9
            };
            publish_map(&mut p, &file.inode, &[fresh, second], 2048).unwrap();
            let result = p.finish(context.scope, context.generation, None);
            if attack == 6 {
                drop(result.expect("uncorrupted COW control must pass the same proof"));
            } else {
                let error = result.err().expect("forged authority must be refused");
                let expected = match attack {
                    0 => "overwrite source guard mapping",
                    1 => "overwrite mapped source guard absent",
                    2 | 3 => "overwrite replacement bytes differ",
                    4 => "ordered data origin bounds",
                    5 => "overwrite changed untouched mapping",
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
