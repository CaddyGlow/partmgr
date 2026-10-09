#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    fs_copy::*,
    fs_core::*,
    fs_fat::{FatFamily, FatVolume},
    fs_fat_builder::{FatBuildOptions, FatTreeMetadataPolicy},
    storage::Storage,
};
use std::sync::Arc;
use virtdisk::ReadAt;
#[derive(Clone, Copy)]
enum Mode {
    Normal,
    ExtraStream,
    HardLink,
    Unstable,
    InvalidName,
    Special,
    CancelFinalRead,
}
struct Source {
    mode: Mode,
}
fn id(n: u8) -> ObjectId {
    ObjectId {
        source: 7,
        generation: u64::from(n),
        native: vec![n],
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn metadata() -> Metadata {
    Metadata {
        created: MetadataField::Uninspectable {
            reason: "test unknown precision".into(),
        },
        modified: MetadataField::Absent,
        accessed: MetadataField::Absent,
        owner: MetadataField::Known(vec![42]),
        mode: MetadataField::Absent,
        security: MetadataField::Absent,
        attributes: vec![],
        native_flags: MetadataField::Absent,
        symlink_target: MetadataField::Absent,
        reparse_data: MetadataField::Absent,
    }
}
struct File(ObjectId, bool);
impl FileRead for File {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        513
    }
    fn read_at(&self, offset: u64, out: &mut [u8], resources: &Resources) -> Result<usize> {
        resources.cancellation.check()?;
        let n = out
            .len()
            .min(513u64.saturating_sub(offset) as usize)
            .min(23);
        for (i, byte) in out[..n].iter_mut().enumerate() {
            *byte = ((offset + i as u64) % 251) as u8;
        }
        if self.1 && offset + n as u64 == self.len() {
            resources.cancellation.cancel();
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        visitor(LogicalExtent {
            offset: 0,
            length: 513,
            kind: ExtentKind::Data,
        })
    }
}
impl TreeSource for Source {
    fn root(&self) -> ObjectId {
        id(0)
    }
    fn stability(&self) -> SourceStability {
        if matches!(self.mode, Mode::Unstable) {
            SourceStability::ChangeDetectionOnly
        } else {
            SourceStability::CallerGuaranteedStable
        }
    }
    fn metadata(&self, _: &ObjectId, resources: &Resources) -> Result<Budgeted<Metadata>> {
        Budgeted::try_new(&resources.memory, 4096, || Ok(metadata()))
    }
    fn directory_page(
        &self,
        directory: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        resources: &Resources,
    ) -> Result<DirectoryPage> {
        assert!(continuation.is_none());
        assert!(maximum_entries >= 2);
        let entries = if directory == &id(0) {
            vec![DirectoryEntry {
                name: NativeName::Utf16("EFI".encode_utf16().collect()),
                object: id(1),
                kind: ObjectKind::Directory,
            }]
        } else {
            let entry = DirectoryEntry {
                name: if matches!(self.mode, Mode::InvalidName) {
                    NativeName::Bytes(vec![255])
                } else {
                    NativeName::Utf16("Long payload.txt".encode_utf16().collect())
                },
                object: id(2),
                kind: if matches!(self.mode, Mode::Special) {
                    ObjectKind::Special
                } else {
                    ObjectKind::File
                },
            };
            if matches!(self.mode, Mode::HardLink) {
                vec![
                    entry.clone(),
                    DirectoryEntry {
                        name: NativeName::Utf16("alias.txt".encode_utf16().collect()),
                        ..entry
                    },
                ]
            } else {
                vec![entry]
            }
        };
        Ok(DirectoryPage {
            reservation: resources.memory.reserve(2048)?,
            entries,
            next: None,
        })
    }
    fn streams(
        &self,
        object: &ObjectId,
        resources: &Resources,
    ) -> Result<Budgeted<Vec<StreamInfo>>> {
        Budgeted::try_new(&resources.memory, 1024, || {
            Ok(if object == &id(2) {
                let mut streams = vec![StreamInfo {
                    kind: StreamKind::Data,
                    length: 513,
                }];
                if matches!(self.mode, Mode::ExtraStream) {
                    streams.push(StreamInfo {
                        kind: StreamKind::Named(NativeName::Bytes(b"extra".to_vec())),
                        length: 4,
                    });
                }
                streams
            } else {
                vec![]
            })
        })
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        _: &StreamKind,
        _: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        Ok(Arc::new(File(
            object.clone(),
            matches!(self.mode, Mode::CancelFinalRead),
        )))
    }
    fn revalidate(&self, _: &ObjectId, resources: &Resources) -> Result<()> {
        resources.cancellation.check()
    }
}
struct Memory {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail: bool,
}
impl ReadAt for Memory {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let range = self
            .bytes
            .get(offset as usize..offset as usize + out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(range);
        Ok(())
    }
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(ReadAt::len(self))
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, offset, out)
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail {
            return Err(io::Error::other("injected destination write"));
        }
        self.bytes[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}
fn options() -> FatCopyOptions {
    FatCopyOptions {
        image_bytes: 2 << 20,
        filesystem: FatBuildOptions {
            family: FatFamily::Fat12,
            sectors_per_cluster: 2,
            volume_id: 55,
        },
        names: CopyNamePolicy::StrictUtf8,
        metadata: FatTreeMetadataPolicy::DeterministicDefaults,
        limits: CopyLimits {
            objects: 4,
            pages: 4,
            page_entries: 16,
        },
    }
}
#[test]
fn copy_reports_unknown_metadata_and_streams_nested_payload_with_short_source_reads() {
    let resources = resources();
    let plan = FatCopyPlan::new(
        Arc::new(Source { mode: Mode::Normal }),
        options(),
        &resources,
    )
    .unwrap();
    assert!(plan.outcomes().iter().any(|outcome|outcome.class=="created"&&matches!(&outcome.decision,Preservation::Transform {report,..} if report.contains("uninspectable"))));
    assert!(
        plan.outcomes()
            .iter()
            .any(|outcome| outcome.class == "owner"
                && matches!(outcome.decision, Preservation::Transform { .. }))
    );
    for class in ["modified", "native_flags"] {
        assert!(plan.outcomes().iter().filter(|outcome| outcome.class == class && outcome.object != id(0)).all(|outcome| matches!(&outcome.decision, Preservation::Transform { report, .. } if report.contains("synthesized"))));
    }
    for class in [
        "accessed",
        "mode",
        "security",
        "symlink_target",
        "reparse_data",
    ] {
        assert!(
            plan.outcomes()
                .iter()
                .filter(|outcome| outcome.class == class)
                .all(|outcome| matches!(outcome.decision, Preservation::Preserve))
        );
    }
    assert!(plan.outcomes().iter().any(|outcome| outcome.object == id(0)
        && outcome.class == "modified"
        && matches!(outcome.decision, Preservation::Preserve)));
    let mut output = Memory {
        bytes: vec![99; 2 << 20],
        writes: 0,
        flushes: 0,
        fail: false,
    };
    let report = plan.emit(&mut output, &resources).unwrap();
    assert_eq!(report.files, 1);
    assert_eq!(output.flushes, 1);
    let volume = FatVolume::open(Arc::new(output)).unwrap();
    let root = volume.root_directory(16, 64, &resources).unwrap();
    let directory = volume
        .read_directory(&root.entries()[0], 16, 64, &resources)
        .unwrap();
    assert_eq!(
        directory.entries()[0].name(),
        &NativeName::Utf16("Long payload.txt".encode_utf16().collect())
    );
    let file = volume
        .open_entry(&directory.entries()[0], 16, &resources)
        .unwrap();
    let content = read_all(&file, 513, &resources).unwrap();
    assert_eq!(
        *content.get(),
        (0..513).map(|n| (n % 251) as u8).collect::<Vec<_>>()
    );
    drop(content);
    drop(file);
    drop(directory);
    drop(root);
    drop(volume);
    drop(plan);
    assert_eq!(resources.memory.used(), 0);
}
#[test]
fn unsupported_inventory_and_budget_fail_before_destination_mutation() {
    for mode in [
        Mode::ExtraStream,
        Mode::HardLink,
        Mode::Unstable,
        Mode::InvalidName,
        Mode::Special,
    ] {
        let resources = resources();
        assert!(FatCopyPlan::new(Arc::new(Source { mode }), options(), &resources).is_err());
        assert_eq!(resources.memory.used(), 0);
    }
    let resources = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert!(
        matches!(FatCopyPlan::new(Arc::new(Source {mode:Mode::Normal}),options(),&resources),Err(error) if error.kind==ErrorKind::BudgetExhausted)
    );
}
#[test]
fn staged_write_failure_retains_underlying_io_and_has_no_success_report() {
    let resources = resources();
    let plan = FatCopyPlan::new(
        Arc::new(Source { mode: Mode::Normal }),
        options(),
        &resources,
    )
    .unwrap();
    let mut output = Memory {
        bytes: vec![0; 2 << 20],
        writes: 0,
        flushes: 0,
        fail: true,
    };
    let error = plan.emit(&mut output, &resources).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert_eq!(
        error.source.unwrap().to_string(),
        "injected destination write"
    );
    assert_eq!(output.flushes, 0);
}

#[test]
fn cancellation_returned_with_final_source_bytes_never_completes_staging() {
    let r = resources();
    let plan = FatCopyPlan::new(
        Arc::new(Source {
            mode: Mode::CancelFinalRead,
        }),
        options(),
        &r,
    )
    .unwrap();
    let mut output = Memory {
        bytes: vec![0; 2 << 20],
        writes: 0,
        flushes: 0,
        fail: false,
    };
    let error = plan.emit(&mut output, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert_eq!(output.writes, 0);
    assert_eq!(output.flushes, 0);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
