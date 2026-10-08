//! Deterministic supported metadata serialization and durability ordering.
use crate::gpt::crc32;
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::{
    layout::{DiskLayout, GptLayout},
    storage::{Barrier, WritePlan, WriteRange},
};
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn header(raw: &[u8], array: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = raw.to_vec();
    let length = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| invalid("header size"))?,
    ) as usize;
    if length != 92 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unknown GPT header extension",
        ));
    }
    bytes[88..92].copy_from_slice(&crc32(array).to_le_bytes());
    bytes[16..20].fill(0);
    let crc = crc32(&bytes[..length]);
    bytes[16..20].copy_from_slice(&crc.to_le_bytes());
    Ok(bytes)
}
fn gpt_stage(name: &str, old: &GptLayout, new: &GptLayout, backup: bool) -> io::Result<Barrier> {
    let sector = u64::from(old.geometry().sector_size());
    let (lba, raw_old, raw_new, header_lba) = if backup {
        (
            old.backup_array_lba(),
            old.backup_header(),
            new.backup_header(),
            old.geometry().sectors() - 1,
        )
    } else {
        (
            old.primary_array_lba(),
            old.primary_header(),
            new.primary_header(),
            1,
        )
    };
    Barrier::new(
        name,
        vec![
            WriteRange::new(lba * sector, old.array().to_vec(), new.array().to_vec())?,
            WriteRange::new(
                header_lba * sector,
                raw_old.to_vec(),
                header(raw_new, new.array())?,
            )?,
        ],
    )
}
/// Build an existing-layout edit plan with backup GPT durability before primary.
///
/// Scheme and geometry changes require separate initialization/conversion/repair
/// plans. Opaque extensions are refused. MBR sector tails and boot code are kept
/// exactly as represented by the proposed owned layout.
pub fn edit_plan(old: &DiskLayout, proposed: &DiskLayout) -> io::Result<WritePlan> {
    match (old, proposed) {
        (DiskLayout::Gpt(old), DiskLayout::Gpt(new)) => {
            if old.geometry() != new.geometry()
                || old.primary_array_lba() != new.primary_array_lba()
                || old.backup_array_lba() != new.backup_array_lba()
                || old.array().len() != new.array().len()
            {
                return Err(invalid("edit changes metadata geometry"));
            }
            if !old.mutation_supported() || !new.mutation_supported() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unknown GPT metadata extension",
                ));
            }
            let mut stages = vec![
                gpt_stage("backup GPT", old, new, true)?,
                gpt_stage("primary GPT", old, new, false)?,
            ];
            if old.mbr_sector() != new.mbr_sector() {
                stages.push(Barrier::new(
                    "protective MBR",
                    vec![WriteRange::new(
                        0,
                        old.mbr_sector().to_vec(),
                        new.mbr_sector().to_vec(),
                    )?],
                )?);
            }
            WritePlan::new(old.geometry().bytes(), stages)?.with_preconditions(vec![
                crate::storage::ReadCondition::new(0, old.mbr_sector().to_vec())?,
            ])
        }
        (DiskLayout::Mbr(old), DiskLayout::Mbr(new)) => {
            if old.geometry() != new.geometry() {
                return Err(invalid("edit changes disk geometry"));
            }
            WritePlan::new(
                old.geometry().bytes(),
                vec![Barrier::new(
                    "MBR",
                    vec![WriteRange::new(
                        0,
                        old.sector().to_vec(),
                        new.sector().to_vec(),
                    )?],
                )?],
            )
        }
        _ => Err(invalid(
            "scheme conversion requires an explicit conversion plan",
        )),
    }
}

/// Plan initialization on a caller-reviewed image, writing GPT backup first,
/// primary second, and protective MBR last. MBR initialization has one barrier.
///
/// This can overwrite payload bytes in metadata ranges. The caller must ensure
/// the target is blank or has approved the destructive initialization explicitly.
/// Until the final MBR barrier strict scheme discovery may see an old/empty MBR;
/// after GPT backup durability, explicit recovery can select that valid copy.
pub fn initialize_plan(
    source: &dyn crate::io::ReadAt,
    layout: &DiskLayout,
) -> io::Result<WritePlan> {
    let replacement = |offset: u64, mut bytes: Vec<u8>| -> io::Result<WriteRange> {
        let mut expected = vec![0; bytes.len()];
        source.read_exact_at(offset, &mut expected)?;
        if offset == 0 {
            bytes[512..].copy_from_slice(&expected[512..]);
        }
        WriteRange::new(offset, expected, bytes)
    };
    match layout {
        DiskLayout::Gpt(gpt) => {
            if source.len() != gpt.geometry().bytes() {
                return Err(invalid("initialization geometry differs from storage"));
            }
            if !gpt.mutation_supported() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unknown GPT metadata extension",
                ));
            }
            let size = u64::from(gpt.geometry().sector_size());
            WritePlan::new(
                source.len(),
                vec![
                    Barrier::new(
                        "initialize backup GPT",
                        vec![
                            replacement(gpt.backup_array_lba() * size, gpt.array().to_vec())?,
                            replacement(
                                (gpt.geometry().sectors() - 1) * size,
                                header(gpt.backup_header(), gpt.array())?,
                            )?,
                        ],
                    )?,
                    Barrier::new(
                        "initialize primary GPT",
                        vec![
                            replacement(gpt.primary_array_lba() * size, gpt.array().to_vec())?,
                            replacement(size, header(gpt.primary_header(), gpt.array())?)?,
                        ],
                    )?,
                    Barrier::new(
                        "initialize protective MBR",
                        vec![replacement(0, gpt.mbr_sector().to_vec())?],
                    )?,
                ],
            )
        }
        DiskLayout::Mbr(mbr) => {
            if source.len() != mbr.geometry().bytes() {
                return Err(invalid("initialization geometry differs from storage"));
            }
            WritePlan::new(
                source.len(),
                vec![Barrier::new(
                    "initialize MBR",
                    vec![replacement(0, mbr.sector().to_vec())?],
                )?],
            )
        }
    }
}

/// Commit a plan and strictly reinspect the resulting GPT/MBR metadata.
///
/// Readback failure is reported as a completed-write verification failure. Keep
/// exclusive storage access through this function, and inspect/recover after any
/// partial commit error rather than blindly retrying the stale plan.
pub fn commit_and_inspect<S: crate::storage::Storage + Send + Sync>(
    plan: &WritePlan,
    storage: &mut S,
    sector_size: u32,
) -> Result<DiskLayout, crate::error::Error> {
    struct Reader<'a, S>(&'a S, u64);
    impl<S: crate::storage::Storage + Send + Sync> crate::io::ReadAt for Reader<'_, S> {
        fn len(&self) -> u64 {
            self.1
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(offset, out)
        }
    }
    let report = plan.commit(storage).map_err(crate::error::Error::from)?;
    let length = storage.len().map_err(|source| {
        crate::error::Error::PartialCommit(crate::storage::CommitError::Interrupted {
            completed_stages: report.completed_stages().to_vec(),
            stage: "geometry verification".into(),
            durability_uncertain: false,
            source,
        })
    })?;
    if length != plan.length() {
        return Err(crate::error::Error::PartialCommit(
            crate::storage::CommitError::Interrupted {
                completed_stages: report.completed_stages().to_vec(),
                stage: "geometry verification".into(),
                durability_uncertain: false,
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "geometry changed during commit",
                ),
            },
        ));
    }
    DiskLayout::inspect(&Reader(storage, length), sector_size).map_err(|source| {
        crate::error::Error::PartialCommit(crate::storage::CommitError::Interrupted {
            completed_stages: report.completed_stages().to_vec(),
            stage: "strict table reinspection".into(),
            durability_uncertain: false,
            source,
        })
    })
}
