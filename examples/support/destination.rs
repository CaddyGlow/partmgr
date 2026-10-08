//! Staged standalone or single-partition destination shared by copy examples.
use partmgr::{
    codec::initialize_plan,
    fs_storage::{BoundedSession, SectorGeometry},
    guid::Guid,
    layout::{DiskLayout, Geometry, GptLayout, LbaRange, MbrLayout},
    storage::FileStorage,
};
use std::{path::Path, sync::Arc};
use virtdisk::{DiskView, RawDisk, ReadAt};
#[derive(Debug)]
struct OutputStageFailure {
    stage: &'static str,
    cause: Box<dyn std::error::Error + Send + Sync>,
}
impl std::fmt::Display for OutputStageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} failed; output was not published and temporary staging is discarded: {}",
            self.stage, self.cause
        )
    }
}
impl std::error::Error for OutputStageFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
pub fn stage<T, E: std::error::Error + Send + Sync + 'static>(
    name: &'static str,
    result: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|cause| {
        Box::new(OutputStageFailure {
            stage: name,
            cause: Box::new(cause),
        }) as Box<dyn std::error::Error>
    })
}
pub struct DestinationLayout {
    pub offset: u64,
    pub filesystem_bytes: u64,
    pub disk_bytes: u64,
    pub scheme: Option<String>,
    layout: Option<DiskLayout>,
    range: LbaRange,
    gpt_type: Guid,
    mbr_type: u8,
}
impl DestinationLayout {
    pub fn new(
        filesystem_bytes: u64,
        scheme: Option<String>,
        mbr_type: u8,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_type(
            filesystem_bytes,
            scheme,
            mbr_type,
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7".parse()?,
        )
    }
    pub fn with_type(
        filesystem_bytes: u64,
        scheme: Option<String>,
        mbr_type: u8,
        gpt_type: Guid,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if scheme
            .as_deref()
            .is_some_and(|s| !matches!(s, "gpt" | "mbr"))
        {
            return Err("partition table must be gpt or mbr".into());
        }
        let offset = if scheme.is_some() { 1 << 20 } else { 0 };
        let disk_bytes = filesystem_bytes
            .checked_add(if scheme.is_some() { 2 << 20 } else { 0 })
            .ok_or("destination size overflow")?;
        if filesystem_bytes == 0 || !filesystem_bytes.is_multiple_of(512) {
            return Err("filesystem length must be a nonzero multiple of 512".into());
        }
        let range = LbaRange::new(offset / 512, (offset + filesystem_bytes) / 512)?;
        let layout = match scheme.as_deref() {
            Some("gpt") => {
                let mut table = GptLayout::initialize(
                    Geometry::new(disk_bytes, 512)?,
                    Guid::from_bytes([0x31; 16]),
                    128,
                    128,
                )?;
                table.create(1, gpt_type, Guid::from_bytes([0x32; 16]), range)?;
                Some(DiskLayout::Gpt(table))
            }
            Some("mbr") => {
                let mut table = MbrLayout::initialize(Geometry::new(disk_bytes, 512)?, 0x504d4653);
                table.create(1, mbr_type, range, false)?;
                Some(DiskLayout::Mbr(table))
            }
            _ => None,
        };
        Ok(Self {
            offset,
            filesystem_bytes,
            disk_bytes,
            scheme,
            layout,
            range,
            gpt_type,
            mbr_type,
        })
    }
    pub fn session(
        &self,
        path: &Path,
    ) -> Result<BoundedSession<FileStorage>, Box<dyn std::error::Error>> {
        Ok(BoundedSession::new(
            FileStorage::open(path)?,
            self.offset,
            self.filesystem_bytes,
            SectorGeometry::new(Some(512), None)?,
        )?)
    }
    pub fn commit_table(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(layout) = &self.layout {
            let source = RawDisk::open(path)?;
            let plan = stage("partition table planning", initialize_plan(&source, layout))?;
            let mut storage = FileStorage::open(path)?;
            stage("partition table commit", plan.commit(&mut storage))?;
            drop(storage);
            let inspected = stage(
                "partition table reopen",
                DiskLayout::inspect(&RawDisk::open(path)?, 512),
            )?;
            let matches = match inspected {
                DiskLayout::Gpt(table) => {
                    self.scheme.as_deref() == Some("gpt")
                        && table.entries().first().is_some_and(|entry| {
                            entry.range() == Some(self.range)
                                && entry.type_id() == Some(self.gpt_type)
                        })
                }
                DiskLayout::Mbr(table) => {
                    self.scheme.as_deref() == Some("mbr")
                        && table.entries().first().is_some_and(|entry| {
                            entry.range() == self.range && entry.raw()[4] == self.mbr_type
                        })
                }
            };
            if !matches {
                return Err("partition table reopen mismatch; output remains unpublished".into());
            }
            println!(
                "partition_commit=completed partition_reopen=validated scheme={}",
                self.scheme.as_deref().unwrap()
            );
        }
        Ok(())
    }
    pub fn reopen(&self, path: &Path) -> Result<Arc<dyn ReadAt>, Box<dyn std::error::Error>> {
        Ok(Arc::new(DiskView::new(
            Arc::new(RawDisk::open(path)?),
            self.offset,
            self.filesystem_bytes,
        )?))
    }
}
