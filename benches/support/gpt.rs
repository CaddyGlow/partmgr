//! Compare eight small GPT edits with one atomic batch at increasing array sizes.
use super::{Case, RunMetrics};
use partmgr::{
    guid::Guid,
    layout::{Geometry, GptLayout, LbaRange},
};

const EDITS: u64 = 8;
fn layout(entries: u32) -> GptLayout {
    let geometry = Geometry::new(128 << 20, 512).unwrap();
    let mut layout =
        GptLayout::initialize(geometry, Guid::from_bytes([1; 16]), entries, 128).unwrap();
    let first = 2 + (u64::from(entries) * 128).div_ceil(512) + 8;
    layout
        .create(
            1,
            Guid::from_bytes([2; 16]),
            Guid::from_bytes([3; 16]),
            LbaRange::new(first, first + 128).unwrap(),
        )
        .unwrap();
    layout
}
fn edit(layout: &mut GptLayout, batch: bool) {
    if batch {
        layout
            .edit_batch(|edit| {
                for i in 0..EDITS {
                    edit.rename(1, if i % 2 == 0 { "bench-a" } else { "bench-b" })?;
                }
                Ok(())
            })
            .unwrap();
    } else {
        for i in 0..EDITS {
            layout
                .rename(1, if i % 2 == 0 { "bench-a" } else { "bench-b" })
                .unwrap();
        }
    }
}
pub fn cases(large: bool) -> Vec<Case> {
    let mut sizes = vec![128, 1024, 8192];
    if large {
        sizes.push(131072);
    }
    let mut cases = Vec::new();
    for entries in sizes {
        let original = layout(entries);
        let mut sequential = original.clone();
        let mut batched = original;
        edit(&mut sequential, false);
        edit(&mut batched, true);
        assert_eq!(sequential.array(), batched.array());
        assert_eq!(sequential.primary_header(), batched.primary_header());
        assert_eq!(sequential.backup_header(), batched.backup_header());
        for (batch, mut layout) in [(false, sequential), (true, batched)] {
            cases.push(Case {
                name: if batch {
                    "gpt.batch_rename"
                } else {
                    "gpt.sequential_rename"
                }
                .into(),
                size: entries as usize,
                operations: EDITS,
                run: Box::new(move || {
                    edit(&mut layout, batch);
                    let header = std::hint::black_box(layout.primary_header());
                    let checksum =
                        u64::from(u32::from_le_bytes(header[16..20].try_into().unwrap()))
                            | (u64::from(u32::from_le_bytes(header[88..92].try_into().unwrap()))
                                << 32);
                    RunMetrics {
                        checksum,
                        backend_reads: 0,
                        backend_bytes: 0,
                    }
                }),
            });
        }
    }
    cases
}
