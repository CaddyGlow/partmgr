use partmgr::{
    fs_copy::{CopyLimits, CopyNamePolicy},
    fs_core::*,
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_builder::{ExfatBuildLimits, ExfatBuildNameProfile, ExfatBuildOptions},
    fs_exfat_copy::*,
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    storage::Storage,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use virtdisk::ReadAt;
#[derive(Clone, Copy)]
enum Mode {
    Normal,
    Hardlink,
    Ads,
    Symlink,
    Special,
    Unstable,
    InvalidName,
    Foreign,
    Pages,
}
struct State {
    stale: AtomicBool,
    length: AtomicU64,
    identity_changed: AtomicBool,
    reads: AtomicUsize,
}
impl Default for State {
    fn default() -> Self {
        Self {
            stale: AtomicBool::new(false),
            length: AtomicU64::new(150001),
            identity_changed: AtomicBool::new(false),
            reads: AtomicUsize::new(0),
        }
    }
}
struct Source {
    mode: Mode,
    state: Arc<State>,
}
struct File {
    original: ObjectId,
    changed: ObjectId,
    state: Arc<State>,
}
fn id(n: u8) -> ObjectId {
    ObjectId {
        source: 7,
        generation: 0,
        native: vec![n],
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
impl FileRead for File {
    fn identity(&self) -> &ObjectId {
        if self.state.identity_changed.load(Ordering::SeqCst) {
            &self.changed
        } else {
            &self.original
        }
    }
    fn len(&self) -> u64 {
        self.state.length.load(Ordering::SeqCst)
    }
    fn read_at(&self, offset: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        self.state.reads.fetch_add(1, Ordering::SeqCst);
        let n = self
            .len()
            .saturating_sub(offset)
            .min(out.len() as u64)
            .min(137) as usize;
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = ((offset + i as u64) % 251) as u8
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        visit: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        visit(LogicalExtent {
            offset: 0,
            length: self.len(),
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
    fn revalidate(&self, _: &ObjectId, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.state.stale.load(Ordering::SeqCst) {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "modeled tree generation change",
            ));
        }
        Ok(())
    }
    fn metadata(&self, _: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        Budgeted::try_new(&r.memory, 1024, || {
            Ok(Metadata {
                created: MetadataField::Uninspectable {
                    reason: "source timestamp unreadable".into(),
                },
                modified: MetadataField::Absent,
                accessed: MetadataField::Absent,
                owner: MetadataField::Known(vec![42]),
                mode: MetadataField::Known(0o640),
                security: MetadataField::Opaque {
                    interpretation: "source ACL".into(),
                    bytes: vec![9],
                },
                attributes: vec![],
                native_flags: MetadataField::Absent,
                symlink_target: MetadataField::Absent,
                reparse_data: MetadataField::Absent,
            })
        })
    }
    fn streams(&self, object: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        Budgeted::try_new(&r.memory, 256, || {
            if object != &id(2) {
                return Ok(vec![]);
            }
            let mut streams = vec![StreamInfo {
                kind: StreamKind::Data,
                length: 150001,
            }];
            if matches!(self.mode, Mode::Ads) {
                streams.push(StreamInfo {
                    kind: StreamKind::Named(NativeName::Bytes(b"ads".to_vec())),
                    length: 2,
                })
            }
            Ok(streams)
        })
    }
    fn open_stream(
        &self,
        object: &ObjectId,
        _: &StreamKind,
        _: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        assert_eq!(object, &id(2));
        Ok(Arc::new(File {
            original: id(2),
            changed: id(9),
            state: self.state.clone(),
        }))
    }
    fn directory_page(
        &self,
        directory: &ObjectId,
        continuation: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        assert!(maximum >= 2);
        if matches!(self.mode, Mode::Pages) {
            return Ok(DirectoryPage {
                reservation: r.memory.reserve(128)?,
                entries: vec![],
                next: Some(vec![1]),
            });
        }
        assert!(continuation.is_none());
        let mut entries = if directory == &id(0) {
            vec![DirectoryEntry {
                object: id(1),
                name: NativeName::Utf16("EFI".encode_utf16().collect()),
                kind: ObjectKind::Directory,
            }]
        } else {
            vec![DirectoryEntry {
                object: if matches!(self.mode, Mode::Foreign) {
                    ObjectId {
                        source: 99,
                        ..id(2)
                    }
                } else {
                    id(2)
                },
                name: if matches!(self.mode, Mode::InvalidName) {
                    NativeName::Bytes(vec![255])
                } else {
                    NativeName::Utf16("Long ä payload.txt".encode_utf16().collect())
                },
                kind: match self.mode {
                    Mode::Symlink => ObjectKind::Symlink,
                    Mode::Special => ObjectKind::Special,
                    _ => ObjectKind::File,
                },
            }]
        };
        if matches!(self.mode, Mode::Hardlink) && directory == &id(1) {
            entries.push(DirectoryEntry {
                object: id(2),
                name: NativeName::Bytes(b"other name".to_vec()),
                kind: ObjectKind::File,
            })
        }
        Ok(DirectoryPage {
            reservation: r.memory.reserve(2048)?,
            entries,
            next: None,
        })
    }
}
struct Image {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail: bool,
    stale_on_flush: Option<Arc<State>>,
    late_identity: Option<Arc<State>>,
}
impl Image {
    fn new() -> Self {
        Self {
            bytes: vec![0xa7; 2 << 20],
            writes: 0,
            flushes: 0,
            fail: false,
            stale_on_flush: None,
            late_identity: None,
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
        if at + out.len() as u64 == self.bytes.len() as u64
            && let Some(state) = &self.late_identity
        {
            state.identity_changed.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}
impl Storage for Image {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail {
            return Err(io::Error::other("causal staged target failure"));
        }
        self.bytes[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if let Some(state) = &self.stale_on_flush {
            state.stale.store(true, Ordering::SeqCst)
        }
        Ok(())
    }
}
fn options() -> ExfatCopyOptions {
    ExfatCopyOptions {
        image_bytes: 2 << 20,
        filesystem: ExfatBuildOptions {
            cluster_shift: 3,
            volume_id: 7,
            name_profile: ExfatBuildNameProfile::RecommendedTable,
        },
        names: CopyNamePolicy::StrictUtf8,
        metadata: ExfatCopyMetadataPolicy::ContentOnlyDeterministicDefaults,
        limits: CopyLimits {
            objects: 4,
            pages: 4,
            page_entries: 16,
        },
        build_limits: ExfatBuildLimits {
            objects: 4,
            name_units: 1024,
            clusters: 10000,
            depth: 4,
            directory_slots: 1000,
        },
    }
}
#[test]
fn deferred_large_payload_and_explicit_metadata_outcomes_reopen_clean() {
    let r = resources();
    let state = Arc::new(State::default());
    let p = ExfatCopyPlan::new(
        Arc::new(Source {
            mode: Mode::Normal,
            state: state.clone(),
        }),
        options(),
        &r,
    )
    .unwrap();
    assert_eq!(state.reads.load(Ordering::SeqCst), 0);
    for class in ["created", "owner", "mode", "security", "names"] {
        assert!(
            p.outcomes()
                .iter()
                .any(|o| o.class == class && matches!(o.decision, Preservation::Transform { .. }))
        )
    }
    assert!(p.outcomes().iter().any(|o|o.class=="created"&&matches!(&o.decision,Preservation::Transform{report,..}if report.contains("uninspectable"))));
    let mut out = Image::new();
    assert_eq!(p.emit(&mut out, &r).unwrap().files, 1);
    assert_eq!(out.flushes, 1);
    let source: Arc<dyn ReadAt> = Arc::new(out);
    let limits = ExfatReadLimits {
        max_chain_clusters: 1000,
        max_directory_slots: 1000,
        max_upcase_bytes: 131072,
    };
    let audit = audit_exfat(
        source.clone(),
        limits,
        ExfatAuditLimits {
            clusters: 10000,
            entries: 10,
            directory_slots: 1000,
            work: 20000,
            findings: 10,
        },
        &r,
    )
    .unwrap();
    assert!(audit.is_clean());
    drop(audit);
    let v = ExfatVolume::open(source, limits, &r).unwrap();
    let root = v.root_directory(&r).unwrap();
    let dir = v.read_directory(&root.entries()[0], &r).unwrap();
    assert_eq!(
        dir.entries()[0].name(),
        &"Long ä payload.txt".encode_utf16().collect::<Vec<_>>()
    );
    let file = v.open_file(&dir.entries()[0], &r).unwrap();
    let content = read_all(&file, 150001, &r).unwrap();
    assert_eq!(
        content.bytes,
        (0..150001).map(|i| (i % 251) as u8).collect::<Vec<_>>()
    );
    drop(content);
    drop(file);
    drop(dir);
    drop(root);
    drop(v);
    drop(p);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn unsupported_inventory_and_preservation_reject_before_output() {
    for mode in [
        Mode::Hardlink,
        Mode::Ads,
        Mode::Symlink,
        Mode::Special,
        Mode::Unstable,
        Mode::InvalidName,
        Mode::Foreign,
        Mode::Pages,
    ] {
        let r = resources();
        assert!(
            ExfatCopyPlan::new(
                Arc::new(Source {
                    mode,
                    state: Arc::new(State::default())
                }),
                options(),
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let mut opts = options();
    opts.metadata = ExfatCopyMetadataPolicy::RequirePreservation;
    assert!(
        matches!(ExfatCopyPlan::new(Arc::new(Source{mode:Mode::Normal,state:Arc::new(State::default())}),opts,&r),Err(e)if e.kind==ErrorKind::Unsupported)
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn identity_size_generation_budget_and_cancel_revalidate_before_writes() {
    for case in 0..3 {
        let r = resources();
        let state = Arc::new(State::default());
        let p = ExfatCopyPlan::new(
            Arc::new(Source {
                mode: Mode::Normal,
                state: state.clone(),
            }),
            options(),
            &r,
        )
        .unwrap();
        match case {
            0 => state.length.store(7, Ordering::SeqCst),
            1 => state.identity_changed.store(true, Ordering::SeqCst),
            _ => state.stale.store(true, Ordering::SeqCst),
        }
        let mut out = Image::new();
        assert_eq!(p.emit(&mut out, &r).unwrap_err().kind, ErrorKind::StalePlan);
        assert_eq!(out.writes, 0);
        drop(p);
        assert_eq!(r.memory.used(), 0);
    }
    let low = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        ExfatCopyPlan::new(
            Arc::new(Source {
                mode: Mode::Normal,
                state: Arc::new(State::default())
            }),
            options(),
            &low
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::BudgetExhausted
    );
    let r = resources();
    r.cancellation.cancel();
    assert_eq!(
        ExfatCopyPlan::new(
            Arc::new(Source {
                mode: Mode::Normal,
                state: Arc::new(State::default())
            }),
            options(),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Cancelled
    );
}
#[test]
fn postmutation_source_and_target_failures_do_not_return_success() {
    let r = resources();
    let state = Arc::new(State::default());
    let p = ExfatCopyPlan::new(
        Arc::new(Source {
            mode: Mode::Normal,
            state: state.clone(),
        }),
        options(),
        &r,
    )
    .unwrap();
    let mut out = Image::new();
    out.stale_on_flush = Some(state.clone());
    assert_eq!(
        p.emit(&mut out, &r).unwrap_err().kind,
        ErrorKind::InterruptedWrite
    );
    assert_eq!(out.flushes, 1);
    state.stale.store(false, Ordering::SeqCst);
    let mut late = Image::new();
    late.late_identity = Some(state.clone());
    let error = p.emit(&mut late, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert!(
        error
            .context
            .contains("source stream changed after emission")
    );
    state.identity_changed.store(false, Ordering::SeqCst);
    let mut out = Image::new();
    out.fail = true;
    let error = p.emit(&mut out, &r).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InterruptedWrite);
    assert_eq!(
        error.source.unwrap().to_string(),
        "causal staged target failure"
    );
}
