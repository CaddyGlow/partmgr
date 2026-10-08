#![cfg(feature = "native-writer")]
use partmgr::fs_core::*;
use partmgr_optical::write::*;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
fn identity(n: u8) -> ObjectId {
    ObjectId {
        source: 71,
        generation: 3,
        native: vec![n],
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(4 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> WriteLimits {
    WriteLimits {
        maximum_entries: 16,
        maximum_bytes: 64 << 10,
        maximum_extents: 16,
        page_entries: 4,
        byte_names: ByteNames::Utf8,
    }
}
fn expected() -> Vec<u8> {
    let mut b: Vec<u8> = (0..90003)
        .map(|n| ((n * 31 + n / 19) % 251) as u8)
        .collect();
    b[69632..77824].fill(0);
    b
}
struct File {
    object: ObjectId,
    bytes: Vec<u8>,
    fail: Arc<AtomicBool>,
    cancel_on_read: bool,
}
impl FileRead for File {
    fn identity(&self) -> &ObjectId {
        &self.object
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, o: u64, b: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::io(
                "injected deferred failure",
                io::Error::other("payload unreadable"),
            ));
        }
        let n = self.len().saturating_sub(o).min(b.len() as u64) as usize;
        if n > 0 {
            b[..n].copy_from_slice(&self.bytes[o as usize..o as usize + n]);
        }
        if self.cancel_on_read {
            r.cancellation.cancel();
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        for e in [
            LogicalExtent {
                offset: 0,
                length: 69632,
                kind: ExtentKind::Data,
            },
            LogicalExtent {
                offset: 69632,
                length: 8192,
                kind: ExtentKind::Hole,
            },
            LogicalExtent {
                offset: 77824,
                length: self.len() - 77824,
                kind: ExtentKind::Data,
            },
        ] {
            v(e)?;
        }
        Ok(())
    }
}
struct Tree {
    empty: bool,
    alias: bool,
    file: Arc<File>,
    name: NativeName,
}
fn tree(fail: bool, name: NativeName) -> Arc<Tree> {
    Arc::new(Tree {
        empty: false,
        alias: true,
        file: Arc::new(File {
            object: identity(2),
            bytes: expected(),
            fail: Arc::new(AtomicBool::new(fail)),
            cancel_on_read: false,
        }),
        name,
    })
}
fn metadata() -> Metadata {
    Metadata {
        created: MetadataField::Known(NativeTimestamp {
            ticks: 1,
            ticks_per_second: 1,
            epoch: "Unix".into(),
        }),
        modified: MetadataField::Uninspectable {
            reason: "unknown native precision".into(),
        },
        accessed: MetadataField::Absent,
        owner: MetadataField::Uninspectable {
            reason: "undecoded".into(),
        },
        mode: MetadataField::Known(0o100644),
        security: MetadataField::Absent,
        attributes: Vec::new(),
        native_flags: MetadataField::Absent,
        symlink_target: MetadataField::Absent,
        reparse_data: MetadataField::Absent,
    }
}
impl TreeSource for Tree {
    fn root(&self) -> ObjectId {
        identity(1)
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn metadata(&self, _: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        Budgeted::try_new(&r.memory, 4096, || Ok(metadata()))
    }
    fn directory_page(
        &self,
        _: &ObjectId,
        t: Option<&[u8]>,
        max: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        assert!(t.is_none());
        assert!(max >= 2);
        let reservation = r.memory.reserve(2048)?;
        Ok(DirectoryPage {
            entries: if self.empty {
                Vec::new()
            } else {
                let mut entries = vec![
                    DirectoryEntry {
                        name: self.name.clone(),
                        object: identity(2),
                        kind: ObjectKind::File,
                    },
                    DirectoryEntry {
                        name: NativeName::Bytes(b"alias.bin".to_vec()),
                        object: identity(2),
                        kind: ObjectKind::File,
                    },
                ];
                if !self.alias {
                    entries.pop();
                }
                entries
            },
            next: None,
            reservation,
        })
    }
    fn streams(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        Budgeted::try_new(&r.memory, 128, || {
            Ok(if id == &identity(1) {
                Vec::new()
            } else {
                vec![StreamInfo {
                    kind: StreamKind::Data,
                    length: self.file.len(),
                }]
            })
        })
    }
    fn open_stream(
        &self,
        _: &ObjectId,
        _: &StreamKind,
        _: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        Ok(self.file.clone())
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if id != &identity(1) && id != &identity(2) {
            return Err(Error::new(ErrorKind::StalePlan, "foreign identity"));
        }
        Ok(())
    }
}
#[test]
fn iso_udf_staged_streaming_payload_hardlinks_and_accounting() {
    let temp = tempfile::tempdir().unwrap();
    let r = resources();
    let source = tree(false, NativeName::Bytes(b"payload.bin".to_vec()));
    let iso = libmkiso::IsoOptions {
        rock_ridge: true,
        max_entries: 32,
        max_metadata_bytes: 128 << 10,
        ..Default::default()
    };
    let staged = stage_iso(
        source.clone(),
        r.clone(),
        limits(),
        WritePolicy::ContentOnly,
        temp.path(),
        &iso,
    )
    .unwrap();
    assert_eq!(staged.report().files, 1);
    assert_eq!(staged.report().materialized_zero_ranges, 1);
    assert_eq!(staged.report().metadata_objects, 3);
    assert!(r.memory.used() > 0);
    let mut reader = libmkiso::IsoReader::open_with_options(
        std::fs::File::open(staged.path()).unwrap(),
        libmkiso::IsoReadOptions {
            namespace: libmkiso::IsoNamespace::RockRidge,
            ..Default::default()
        },
    )
    .unwrap();
    for name in ["payload.bin", "alias.bin"] {
        let index = reader
            .index()
            .entries
            .iter()
            .position(|e| e.name == name)
            .unwrap();
        assert_eq!(reader.read_entry(index, 100_000).unwrap(), expected());
    }
    let path = staged.path().to_path_buf();
    drop(staged);
    assert!(!path.exists());
    assert_eq!(r.memory.used(), 0);
    let udf = libmkiso::UdfOptions {
        max_entries: 32,
        max_metadata_bytes: 128 << 10,
        ..Default::default()
    };
    let staged = stage_udf(
        source,
        r.clone(),
        limits(),
        WritePolicy::ContentOnly,
        temp.path(),
        &udf,
    )
    .unwrap();
    assert_eq!(staged.report().retained_zero_ranges, 1);
    let bytes = std::fs::read(staged.path()).unwrap();
    let reader = libmkiso::UdfReader::open(&bytes, libmkiso::UdfLimits::default()).unwrap();
    let original = reader
        .entries()
        .iter()
        .position(|e| e.name == "payload.bin")
        .unwrap();
    let alias = reader
        .entries()
        .iter()
        .position(|e| e.name == "alias.bin")
        .unwrap();
    assert_eq!(reader.entries()[original].icb, reader.entries()[alias].icb);
    for index in [original, alias] {
        assert_eq!(reader.read_entry(index, 100_000).unwrap(), expected());
    }
    drop(staged);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn failure_cancel_preservation_and_bad_names_never_publish() {
    let temp = tempfile::tempdir().unwrap();
    let r = resources();
    let options = libmkiso::IsoOptions {
        rock_ridge: true,
        max_entries: 32,
        max_metadata_bytes: 128 << 10,
        ..Default::default()
    };
    assert!(
        stage_iso(
            tree(true, NativeName::Bytes(b"payload.bin".to_vec())),
            r.clone(),
            limits(),
            WritePolicy::ContentOnly,
            temp.path(),
            &options
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    assert_eq!(r.memory.used(), 0);
    assert!(
        stage_iso(
            tree(false, NativeName::Bytes(b"payload.bin".to_vec())),
            r.clone(),
            limits(),
            WritePolicy::RequireMetadata,
            temp.path(),
            &options
        )
        .is_err()
    );
    for name in [
        NativeName::Bytes(vec![255]),
        NativeName::Utf16(vec![0xd800]),
        NativeName::Bytes(b"../bad".to_vec()),
    ] {
        assert!(
            stage_iso(
                tree(false, name),
                r.clone(),
                limits(),
                WritePolicy::ContentOnly,
                temp.path(),
                &options
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
    r.cancellation.cancel();
    assert!(
        stage_iso(
            tree(false, NativeName::Bytes(b"payload.bin".to_vec())),
            r.clone(),
            limits(),
            WritePolicy::ContentOnly,
            temp.path(),
            &options
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn deferred_cancellation_empty_inventory_and_explicit_name_maps() {
    let temp = tempfile::tempdir().unwrap();
    let options = libmkiso::IsoOptions {
        rock_ridge: true,
        max_entries: 32,
        max_metadata_bytes: 128 << 10,
        ..Default::default()
    };
    let r = resources();
    let source = Arc::new(Tree {
        empty: false,
        alias: true,
        name: NativeName::Bytes(b"payload.bin".to_vec()),
        file: Arc::new(File {
            object: identity(2),
            bytes: expected(),
            fail: Arc::new(AtomicBool::new(false)),
            cancel_on_read: true,
        }),
    });
    assert!(
        stage_iso(
            source,
            r.clone(),
            limits(),
            WritePolicy::ContentOnly,
            temp.path(),
            &options
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let original = tree(false, NativeName::Bytes(b"unused".to_vec()));
    let source = Arc::new(Tree {
        empty: true,
        alias: false,
        name: original.name.clone(),
        file: original.file.clone(),
    });
    let staged = stage_iso(
        source,
        r.clone(),
        limits(),
        WritePolicy::ContentOnly,
        temp.path(),
        &options,
    )
    .unwrap();
    assert_eq!(staged.report().entries, 0);
    assert!(r.memory.used() > 0);
    drop(staged);
    assert_eq!(r.memory.used(), 0);
    for (native, policy, output) in [
        (
            NativeName::Bytes(b"PAYLOAD BIN".to_vec()),
            ByteNames::FatShortAscii,
            "PAYLOAD.BIN",
        ),
        (
            NativeName::Utf16("payload.bin".encode_utf16().collect()),
            ByteNames::Utf8,
            "payload.bin",
        ),
    ] {
        let original = tree(false, native.clone());
        let source = Arc::new(Tree {
            empty: false,
            alias: false,
            name: native,
            file: original.file.clone(),
        });
        let mut bounds = limits();
        bounds.byte_names = policy;
        let staged = stage_iso(
            source,
            r.clone(),
            bounds,
            WritePolicy::ContentOnly,
            temp.path(),
            &options,
        )
        .unwrap();
        let mut reader = libmkiso::IsoReader::open_with_options(
            std::fs::File::open(staged.path()).unwrap(),
            libmkiso::IsoReadOptions {
                namespace: libmkiso::IsoNamespace::RockRidge,
                ..Default::default()
            },
        )
        .unwrap();
        let index = reader
            .index()
            .entries
            .iter()
            .position(|e| e.name == output)
            .unwrap();
        assert_eq!(reader.read_entry(index, 100_000).unwrap(), expected());
        drop(staged);
        assert_eq!(r.memory.used(), 0);
    }
}

struct PatternFile {
    object: ObjectId,
    length: u64,
    seed: u64,
}
impl FileRead for PatternFile {
    fn identity(&self) -> &ObjectId {
        &self.object
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, offset: u64, buffer: &mut [u8], resources: &Resources) -> Result<usize> {
        resources.cancellation.check()?;
        let count = self.length.saturating_sub(offset).min(buffer.len() as u64) as usize;
        for (i, b) in buffer[..count].iter_mut().enumerate() {
            let n = offset + i as u64;
            *b = if self.seed == 1 && (1024..2048).contains(&n) {
                0
            } else {
                ((n * 13 + n / 23 + self.seed) % 251) as u8
            };
        }
        Ok(count)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        if self.seed == 1 {
            for extent in [
                LogicalExtent {
                    offset: 0,
                    length: 1024,
                    kind: ExtentKind::Data,
                },
                LogicalExtent {
                    offset: 1024,
                    length: 1024,
                    kind: ExtentKind::Hole,
                },
                LogicalExtent {
                    offset: 2048,
                    length: self.length - 2048,
                    kind: ExtentKind::Data,
                },
            ] {
                v(extent)?;
            }
            Ok(())
        } else {
            v(LogicalExtent {
                offset: 0,
                length: self.length,
                kind: ExtentKind::Data,
            })
        }
    }
}
struct StreamTree(Arc<Tree>, u8);
#[test]
fn resource_fork_mapping_rejects_existing_byte_or_utf16_stream_name() {
    for spelling in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let r = resources();
        let source: Arc<dyn TreeSource> = Arc::new(StreamTree(
            tree(false, NativeName::Bytes(b"payload.bin".to_vec())),
            spelling,
        ));
        let result = stage_udf(
            source,
            r.clone(),
            limits(),
            WritePolicy::ContentOnlyResourceForkAsNamedStream,
            directory.path(),
            &libmkiso::UdfOptions {
                revision: libmkiso::UdfRevision::V201,
                ..Default::default()
            },
        );
        let error = match result {
            Ok(_) => panic!("colliding resource stream must reject"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("duplicate mapped stream name"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert_eq!(r.memory.used(), 0);
    }
}
impl TreeSource for StreamTree {
    fn root(&self) -> ObjectId {
        self.0.root()
    }
    fn stability(&self) -> SourceStability {
        self.0.stability()
    }
    fn metadata(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.0.metadata(o, r)
    }
    fn directory_page(
        &self,
        o: &ObjectId,
        t: Option<&[u8]>,
        n: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        if o == &identity(3) {
            return Ok(DirectoryPage {
                entries: Vec::new(),
                next: None,
                reservation: r.memory.reserve(0)?,
            });
        }
        let mut page = self.0.directory_page(o, t, n, r)?;
        page.entries
            .try_reserve(1)
            .map_err(|e| Error::new(ErrorKind::BudgetExhausted, e.to_string()))?;
        page.entries.push(DirectoryEntry {
            name: NativeName::Bytes(b"docs".to_vec()),
            object: identity(3),
            kind: ObjectKind::Directory,
        });
        Ok(page)
    }
    fn streams(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        Budgeted::try_new(&r.memory, 2048, || {
            Ok(if o == &identity(3) {
                vec![StreamInfo {
                    kind: StreamKind::Named(NativeName::Bytes(b"dirstream".to_vec())),
                    length: 65_537,
                }]
            } else if o == &identity(1) {
                vec![
                    StreamInfo {
                        kind: StreamKind::Named(NativeName::Bytes(b"rootmeta".to_vec())),
                        length: 128_003,
                    },
                    StreamInfo {
                        kind: StreamKind::System(NativeName::Bytes(b"systemmeta".to_vec())),
                        length: 160_001,
                    },
                ]
            } else if self.1 != 0 {
                vec![
                    StreamInfo {
                        kind: StreamKind::Data,
                        length: self.0.file.len(),
                    },
                    StreamInfo {
                        kind: StreamKind::Named(if self.1 == 1 {
                            NativeName::Bytes(b"com.apple.ResourceFork".to_vec())
                        } else {
                            NativeName::Utf16("com.apple.ResourceFork".encode_utf16().collect())
                        }),
                        length: 7,
                    },
                    StreamInfo {
                        kind: StreamKind::ResourceFork,
                        length: 7,
                    },
                ]
            } else {
                vec![
                    StreamInfo {
                        kind: StreamKind::Data,
                        length: self.0.file.len(),
                    },
                    StreamInfo {
                        kind: StreamKind::Named(NativeName::Bytes(b"aux".to_vec())),
                        length: 8_000_123,
                    },
                ]
            })
        })
    }
    fn open_stream(
        &self,
        o: &ObjectId,
        s: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        r.cancellation.check()?;
        let (length, seed) = match s {
            StreamKind::Data => return self.0.open_stream(o, s, r),
            StreamKind::ResourceFork if self.1 != 0 => (7, 5),
            StreamKind::Named(_) if self.1 != 0 && o != &identity(1) && o != &identity(3) => (7, 5),
            StreamKind::Named(NativeName::Bytes(n)) if n == b"aux" => (8_000_123, 1),
            StreamKind::Named(NativeName::Bytes(n)) if n == b"rootmeta" => (128_003, 2),
            StreamKind::System(_) => (160_001, 3),
            StreamKind::Named(NativeName::Bytes(n)) if n == b"dirstream" => (65_537, 4),
            _ => return Err(Error::new(ErrorKind::Unsupported, "unknown test stream")),
        };
        Ok(Arc::new(PatternFile {
            object: o.clone(),
            length,
            seed,
        }))
    }
    fn revalidate(&self, o: &ObjectId, r: &Resources) -> Result<()> {
        if o == &identity(3) {
            r.cancellation.check()
        } else {
            self.0.revalidate(o, r)
        }
    }
}
#[test]
fn udf_owned_named_root_and_system_streams_exceed_payload_budget() {
    let temp = tempfile::tempdir().unwrap();
    let r = resources();
    let source: Arc<dyn TreeSource> = Arc::new(StreamTree(
        tree(false, NativeName::Bytes(b"payload.bin".to_vec())),
        0,
    ));
    let options = libmkiso::UdfOptions {
        revision: libmkiso::UdfRevision::V260,
        max_entries: 32,
        max_metadata_bytes: 128 << 10,
        ..Default::default()
    };
    let staged = stage_udf(
        source.clone(),
        r.clone(),
        limits(),
        WritePolicy::ContentOnly,
        temp.path(),
        &options,
    )
    .unwrap();
    assert_eq!(staged.report().streams, 4);
    assert_eq!(staged.report().materialized_stream_zero_ranges, 1);
    assert!(r.memory.used() < 4 << 20);
    let bytes = std::fs::read(staged.path()).unwrap();
    let reader = libmkiso::UdfReader::open(&bytes, libmkiso::UdfLimits::default()).unwrap();
    let alias = reader
        .entries()
        .iter()
        .position(|e| e.name == "alias.bin")
        .unwrap();
    for (name, length, seed, system) in [
        ("aux", 8_000_123, 1, false),
        ("rootmeta", 128_003, 2, false),
        ("systemmeta", 160_001, 3, true),
        ("dirstream", 65_537, 4, false),
    ] {
        let index = reader
            .entries()
            .iter()
            .position(|e| e.stream.as_ref().is_some_and(|s| s.name == name))
            .unwrap();
        let info = reader.entries()[index].stream.as_ref().unwrap();
        assert_eq!(info.system, system);
        if name == "aux" {
            let owner = info.owner.unwrap();
            assert_eq!(reader.entries()[owner].icb, reader.entries()[alias].icb);
        } else if name == "dirstream" {
            assert!(reader.entries()[info.owner.unwrap()].directory);
            assert_eq!(reader.entries()[info.owner.unwrap()].name, "docs");
        } else {
            assert!(info.owner.is_none());
        }
        assert_eq!(reader.entries()[index].size, length);
        let mut offset = 0;
        let mut buffer = [0; 8192];
        while offset < length {
            let count = reader.read_at(index, offset, &mut buffer).unwrap();
            assert!(count > 0);
            for (i, byte) in buffer[..count].iter().enumerate() {
                let n = offset + i as u64;
                assert_eq!(
                    *byte,
                    if seed == 1 && (1024..2048).contains(&n) {
                        0
                    } else {
                        ((n * 13 + n / 23 + seed) % 251) as u8
                    }
                );
            }
            offset += count as u64;
        }
    }
    drop(staged);
    assert_eq!(r.memory.used(), 0);
    let iso = libmkiso::IsoOptions {
        rock_ridge: true,
        max_entries: 32,
        max_metadata_bytes: 128 << 10,
        ..Default::default()
    };
    assert!(
        stage_iso(
            source,
            r.clone(),
            limits(),
            WritePolicy::ContentOnly,
            temp.path(),
            &iso
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    assert_eq!(r.memory.used(), 0);
}
