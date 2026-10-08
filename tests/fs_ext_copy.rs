use partmgr::{
    fs_copy::CopyLimits,
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources, StreamKind, TreeSource},
    fs_ext_audit::{ExtAuditLimits, audit},
    fs_ext_builder::{ExtBuildLimits, ExtBuildMetadata, ExtBuildOptions},
    fs_ext_copy::{ExtCopyMetadataPolicy, ExtCopyNamePolicy, ExtCopyOptions, ExtCopyPlan},
    fs_image::{AllocationPolicy, ReadImage, ReadOptions},
    storage::Storage,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod apfs_fixture;
#[path = "fixtures/ext2_clean.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "fixtures/jffs2_clean.rs"]
mod jffs2_fixture;

#[test]
fn apfs_resource_fork_rejects_ext2_capture_before_destination_mutation() {
    use partmgr::{fs_apfs::ApfsReadLimits, fs_apfs_audit::ApfsAuditLimits};
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = apfs_fixture::apfs_seed();
    let source = Arc::new(Source {
        length: AtomicU64::new(bytes.len() as u64),
        bytes,
    });
    let image = Arc::new(
        ReadImage::open(
            source,
            ReadOptions::Apfs {
                read: ApfsReadLimits {
                    blocks: 65536,
                    checkpoint_blocks: 256,
                    objects: 256,
                    records: 256,
                    work: 64 << 20,
                },
                audit: ApfsAuditLimits {
                    blocks: 65536,
                    objects: 512,
                    depth: 32,
                    work: 64 << 20,
                    findings: 64,
                },
                volume_oid: 1026,
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap(),
    );
    let page = image.directory_page(&image.root(), None, 16, &r).unwrap();
    let file = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"A\xc3\xa9-file".to_vec()))
        .unwrap();
    let streams = image.streams(&file.object, &r).unwrap();
    assert!(streams.iter().any(|s| s.kind == StreamKind::ResourceFork));
    let baseline = r.memory.used();
    let target = Target::new();
    let error = match ExtCopyPlan::new(image.clone(), options(), &r) {
        Ok(_) => panic!("APFS resource fork must not disappear during ext2 capture"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(error.context.contains("one unnamed data stream"));
    assert_eq!(target.writes, 0);
    assert!(target.bytes.iter().all(|b| *b == 0xa7));
    assert_eq!(r.memory.used(), baseline);
    drop(streams);
    drop(page);
    drop(image);
    assert_eq!(r.memory.used(), 0);
}
struct Source {
    bytes: Vec<u8>,
    length: AtomicU64,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Acquire)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.bytes
                .get(
                    at..at
                        .checked_add(out.len())
                        .ok_or(io::ErrorKind::UnexpectedEof)?,
                )
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
struct Target {
    bytes: Vec<u8>,
    writes: usize,
    short: usize,
    fail: bool,
    change_on_flush: Option<Arc<Source>>,
}
impl Target {
    fn new() -> Self {
        Self {
            bytes: vec![0xa7; 1 << 20],
            writes: 0,
            short: 31,
            fail: false,
            change_on_flush: None,
        }
    }
}
impl Storage for Target {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail {
            return Err(io::Error::other("modeled ext copy target failure"));
        }
        let n = bytes.len().min(self.short);
        self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(source) = &self.change_on_flush {
            source.length.store(0, Ordering::Release);
        }
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn audit_limits() -> ExtAuditLimits {
    ExtAuditLimits {
        blocks: 2048,
        inodes: 256,
        work: 65536,
        directory_blocks: 64,
        directory_entries: 64,
        findings: 16,
    }
}
fn options() -> ExtCopyOptions {
    ExtCopyOptions {
        image_bytes: 1 << 20,
        filesystem: ExtBuildOptions {
            block_size: 1024,
            blocks_per_group: 1024,
            uuid: [0x31; 16],
        },
        names: ExtCopyNamePolicy::ExactBytes,
        metadata: ExtCopyMetadataPolicy::ContentOnlyDefaults(ExtBuildMetadata {
            file_permissions: 0o640,
            directory_permissions: 0o750,
            uid: 123,
            gid: 456,
            timestamp: 7,
        }),
        limits: CopyLimits {
            objects: 16,
            pages: 16,
            page_entries: 4,
        },
        build_limits: ExtBuildLimits {
            objects: 16,
            links: 16,
            name_bytes: 4096,
            blocks: 2048,
            work: 65536,
            depth: 8,
        },
    }
}
fn tree(r: &Resources) -> (Arc<Source>, Arc<dyn TreeSource>) {
    let source = Arc::new(Source {
        bytes: fixture::fixture(),
        length: AtomicU64::new(65536),
    });
    let image = ReadImage::open(
        source.clone(),
        ReadOptions::Ext2 {
            audit: audit_limits(),
            objects: 16,
            entries: 16,
            map_blocks: 64,
            directory_slots: 32,
        },
        AllocationPolicy::RequireClean,
        r,
    )
    .unwrap();
    (source, Arc::new(image))
}
#[test]
fn native_byte_hardlinks_deferred_payload_and_caller_defaults_round_trip() {
    let r = resources();
    let (_, source) = tree(&r);
    let plan = ExtCopyPlan::new(source, options(), &r).unwrap();
    assert!(plan.outcomes().iter().any(|o| o.class == "hardlinks"
        && matches!(o.decision, partmgr::fs_core::Preservation::Preserve)));
    let mut target = Target::new();
    let report = plan.emit(&mut target, &r).unwrap();
    assert_eq!(report.files, 1);
    assert_eq!(report.verified_bytes, 1 << 20);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
    let source: Arc<dyn ReadAt> = Arc::new(Source {
        length: AtomicU64::new(target.bytes.len() as u64),
        bytes: target.bytes,
    });
    let volume = partmgr::fs_ext::ExtVolume::open(source.clone(), &r).unwrap();
    assert!(audit(&volume, audit_limits(), &r).unwrap().is_clean());
    drop(volume);
    let image = ReadImage::open(
        source,
        ReadOptions::Ext2 {
            audit: audit_limits(),
            objects: 16,
            entries: 16,
            map_blocks: 64,
            directory_slots: 32,
        },
        AllocationPolicy::RequireClean,
        &r,
    )
    .unwrap();
    let page = image.directory_page(&image.root(), None, 8, &r).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].object, page.entries[1].object);
    assert!(
        page.entries
            .iter()
            .any(|e| e.name == NativeName::Bytes(vec![b'x', 255]))
    );
    let metadata = image.metadata(&page.entries[0].object, &r).unwrap();
    assert_eq!(
        metadata.mode,
        partmgr::fs_core::MetadataField::Known(0o100640)
    );
    drop(metadata);
    let file = image
        .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
        .unwrap();
    drop(page);
    drop(image);
    let mut bytes = [0; 73];
    assert_eq!(file.read_at(951, &mut bytes, &r).unwrap(), 73);
    assert_eq!(bytes, [73; 73]);
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn preservation_links_inventory_limits_and_stale_source_reject_before_writes() {
    let r = resources();
    for mode in 0..3 {
        let (_, source) = tree(&r);
        let mut o = options();
        if mode == 0 {
            o.metadata = ExtCopyMetadataPolicy::RequirePreservation;
        }
        if mode == 1 {
            o.build_limits.links = 1;
        }
        if mode == 2 {
            o.limits.objects = 1;
        }
        assert!(ExtCopyPlan::new(source, o, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    let (underlying, source) = tree(&r);
    let plan = ExtCopyPlan::new(source, options(), &r).unwrap();
    underlying.length.store(0, Ordering::Release);
    let mut target = Target::new();
    assert_eq!(
        plan.emit(&mut target, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(target.writes, 0);
    assert!(target.bytes.iter().all(|b| *b == 0xa7));
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn output_failures_and_source_change_after_flush_are_staged_interruptions() {
    let r = resources();
    for late in [false, true] {
        let (underlying, source) = tree(&r);
        let plan = ExtCopyPlan::new(source, options(), &r).unwrap();
        let mut target = Target::new();
        if late {
            target.change_on_flush = Some(underlying);
        } else {
            target.fail = true;
        }
        let error = plan.emit(&mut target, &r).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InterruptedWrite);
        assert!(target.writes > 0);
        if !late {
            assert!(std::error::Error::source(&error).is_some());
        }
        drop(plan);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
#[cfg(unix)]
#[ignore = "explicit e2fsprogs gate requires PARTMGR_EXT_COPY_EVIDENCE and E2FSPROGS_TOOLS"]
fn independent_e2fsck_debugfs_hardlinks_and_native_byte_payload_copy() {
    use sha2::{Digest, Sha256};
    use std::{os::unix::ffi::OsStrExt, path::PathBuf, process::Command};
    let base = PathBuf::from(
        std::env::var_os("PARTMGR_EXT_COPY_EVIDENCE").expect("PARTMGR_EXT_COPY_EVIDENCE required"),
    );
    let tools =
        PathBuf::from(std::env::var_os("E2FSPROGS_TOOLS").expect("E2FSPROGS_TOOLS required"));
    std::fs::create_dir_all(&base).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("ext2-copy-")
        .tempdir_in(&base)
        .unwrap()
        .keep();
    let output = directory.join("destination.img");
    let recovery = directory.join("recovered");
    std::fs::create_dir(&recovery).unwrap();
    let source_hashes: Vec<_> = [
        "src/fs_ext_copy.rs",
        "src/fs_ext_builder.rs",
        "src/fs_ext.rs",
        "src/fs_ext_tree.rs",
        "src/fs_ext_audit.rs",
        "src/fs_image.rs",
        "tests/fs_ext_copy.rs",
        "tests/fixtures/ext2_clean.rs",
        "Cargo.toml",
        "Cargo.lock",
    ]
    .into_iter()
    .map(|source| {
        (
            source,
            <[u8; 32]>::from(Sha256::digest(std::fs::read(source).unwrap())),
        )
    })
    .collect();
    let binary = std::env::current_exe().unwrap();
    let binary_hash: [u8; 32] = Sha256::digest(std::fs::read(&binary).unwrap()).into();
    let r = resources();
    let (original, source) = tree(&r);
    let original_hash: [u8; 32] = Sha256::digest(&original.bytes).into();
    let mut o = options();
    o.image_bytes = 16 << 20;
    o.filesystem.blocks_per_group = 8192;
    o.build_limits.blocks = 32768;
    o.build_limits.work = 262144;
    let plan = ExtCopyPlan::new(source, o, &r).unwrap();
    let file = std::fs::File::create(&output).unwrap();
    file.set_len(16 << 20).unwrap();
    drop(file);
    let mut storage = partmgr::storage::FileStorage::open(&output).unwrap();
    let report = plan.emit(&mut storage, &r).unwrap();
    drop(storage);
    drop(plan);
    assert_eq!(report.files, 1);
    assert_eq!(r.memory.used(), 0);
    let before: [u8; 32] = Sha256::digest(std::fs::read(&output).unwrap()).into();
    let mut receipt = String::from(
        "profile=classic-ext2-content-only-hardlinks-native-byte-copy-v1\nstatus=running\nscope=offline native validation; no source metadata preservation, physical durability or firmware claim\n",
    );
    receipt.push_str(&format!("binary={binary:?} sha256={binary_hash:x?}\n"));
    for (tool, args) in [
        ("e2fsck", vec!["-V".to_string()]),
        ("debugfs", vec!["-V".to_string()]),
    ] {
        let command = tools.join(tool);
        receipt.push_str(&format!(
            "tool_sha256={:x}\n",
            Sha256::digest(std::fs::read(&command).unwrap())
        ));
        let result = Command::new(&command).args(&args).output().unwrap();
        receipt.push_str(&format!(
            "tool={command:?} args={args:?} exit={} stdout={} stderr={}\n",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    for (tool, args) in [
        (
            "e2fsck",
            vec![
                "-f".to_string(),
                "-n".to_string(),
                output.display().to_string(),
            ],
        ),
        (
            "debugfs",
            vec![
                "-R".to_string(),
                format!("rdump / {}", recovery.display()),
                output.display().to_string(),
            ],
        ),
        (
            "debugfs",
            vec![
                "-R".to_string(),
                "stat /alias".to_string(),
                output.display().to_string(),
            ],
        ),
    ] {
        let command = tools.join(tool);
        let result = Command::new(&command).args(&args).output().unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        receipt.push_str(&format!(
            "tool={command:?} args={args:?} exit={} stdout={stdout} stderr={}\n",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ));
        assert!(result.status.success(), "native tool failed: {receipt}");
        if args.get(1).is_some_and(|a| a == "stat /alias") {
            assert!(stdout.contains("Links: 2"), "{stdout}");
        }
    }
    for name in [
        std::ffi::OsStr::new("alias"),
        std::ffi::OsStr::from_bytes(&[b'x', 255]),
    ] {
        assert_eq!(std::fs::read(recovery.join(name)).unwrap(), vec![73; 1024]);
    }
    assert_eq!(
        before,
        <[u8; 32]>::from(Sha256::digest(std::fs::read(&output).unwrap()))
    );
    assert_eq!(
        original_hash,
        <[u8; 32]>::from(Sha256::digest(&original.bytes))
    );
    for (source, digest) in &source_hashes {
        assert_eq!(
            *digest,
            <[u8; 32]>::from(Sha256::digest(std::fs::read(source).unwrap())),
            "native gate source changed: {source}"
        );
        receipt.push_str(&format!("source={source} sha256={digest:x?}\n"));
    }
    receipt.push_str(&format!("image_sha256={before:x?}\nsource_sha256={original_hash:x?}\npayload_bytes=1024 payload_sha256={:x}\nstatus=passed\n", Sha256::digest([73; 1024])));
    let receipt_path = directory.join("receipt.txt");
    std::fs::write(&receipt_path, receipt).unwrap();
    std::fs::File::open(&receipt_path)
        .unwrap()
        .sync_all()
        .unwrap();
    println!("evidence={}", receipt_path.display());
}

struct ChangedInventory {
    source: Arc<dyn TreeSource>,
    mode: u8,
}
impl TreeSource for ChangedInventory {
    fn root(&self) -> partmgr::fs_core::ObjectId {
        self.source.root()
    }
    fn stability(&self) -> partmgr::fs_core::SourceStability {
        self.source.stability()
    }
    fn revalidate(
        &self,
        object: &partmgr::fs_core::ObjectId,
        r: &Resources,
    ) -> partmgr::fs_core::Result<()> {
        self.source.revalidate(object, r)
    }
    fn metadata(
        &self,
        object: &partmgr::fs_core::ObjectId,
        r: &Resources,
    ) -> partmgr::fs_core::Result<partmgr::fs_core::Budgeted<partmgr::fs_core::Metadata>> {
        self.source.metadata(object, r)
    }
    fn streams(
        &self,
        object: &partmgr::fs_core::ObjectId,
        r: &Resources,
    ) -> partmgr::fs_core::Result<partmgr::fs_core::Budgeted<Vec<partmgr::fs_core::StreamInfo>>>
    {
        let streams = self.source.streams(object, r)?;
        if self.mode == 3 && object != &self.root() {
            return partmgr::fs_core::Budgeted::try_new(&r.memory, 1024, || {
                let mut streams = streams.get().clone();
                streams.push(partmgr::fs_core::StreamInfo {
                    kind: StreamKind::Named(NativeName::Bytes(b"extra".to_vec())),
                    length: 0,
                });
                Ok(streams)
            });
        }
        Ok(streams)
    }
    fn open_stream(
        &self,
        object: &partmgr::fs_core::ObjectId,
        stream: &StreamKind,
        r: &Resources,
    ) -> partmgr::fs_core::Result<Arc<dyn partmgr::fs_core::FileRead>> {
        self.source.open_stream(object, stream, r)
    }
    fn directory_page(
        &self,
        directory: &partmgr::fs_core::ObjectId,
        continuation: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> partmgr::fs_core::Result<partmgr::fs_core::DirectoryPage> {
        let mut page = self
            .source
            .directory_page(directory, continuation, maximum, r)?;
        for entry in &mut page.entries {
            if entry.name == NativeName::Bytes(b"alias".to_vec()) {
                entry.name = match self.mode {
                    0 => NativeName::Utf16("λ".encode_utf16().collect()),
                    1 => NativeName::Utf16(vec![0xd800]),
                    2 => NativeName::Bytes(vec![b'a'; 256]),
                    _ => entry.name.clone(),
                };
            }
        }
        Ok(page)
    }
}
#[test]
fn explicit_utf16_conversion_and_unrepresentable_names_or_extra_streams_preflight() {
    let r = resources();
    for mode in 0..4 {
        for convert in [false, true] {
            let (_, source) = tree(&r);
            let source: Arc<dyn TreeSource> = Arc::new(ChangedInventory { source, mode });
            let mut o = options();
            if convert {
                o.names = ExtCopyNamePolicy::BytesAndUtf16ToUtf8;
            }
            let result = ExtCopyPlan::new(source, o, &r);
            if mode == 0 && convert {
                let plan = result.unwrap();
                let mut target = Target::new();
                plan.emit(&mut target, &r).unwrap();
                drop(plan);
                let volume = partmgr::fs_ext::ExtVolume::open(
                    Arc::new(Source {
                        length: AtomicU64::new(target.bytes.len() as u64),
                        bytes: target.bytes,
                    }),
                    &r,
                )
                .unwrap();
                let directory = volume.directory(2, 64, 32, &r).unwrap();
                assert!(
                    directory
                        .entries()
                        .iter()
                        .any(|e| e.name == NativeName::Bytes("λ".as_bytes().to_vec()))
                );
                drop(directory);
                drop(volume);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[path = "fixtures/jfs_clean.rs"]
#[allow(dead_code)]
mod jfs_fixture;
#[test]
fn jfs_to_ext2_preserves_hardlinks_nested_payload_and_sparse_logical_bytes() {
    jfs_copy(None);
}
fn jfs_copy(evidence: Option<&std::path::Path>) {
    use partmgr::{fs_jfs::JfsReadLimits, fs_jfs_audit::JfsAuditLimits};
    for valid in [false, true] {
        let r = Resources {
            memory: Budget::new(32 << 20),
            cancellation: Cancellation::default(),
        };
        let mut bytes = jfs_fixture::jfs_seed();
        if valid {
            for at in 0..bytes.len() - 5 {
                if bytes[at..at + 6] == [0xa9, 3, 0, 0xd8, 0x78, 0] {
                    bytes[at..at + 4].copy_from_slice(&[b'z', 0, b'b', 0]);
                }
            }
        }
        let image = ReadImage::open(
            Arc::new(Source {
                length: AtomicU64::new(bytes.len() as u64),
                bytes,
            }),
            ReadOptions::Jfs {
                read: JfsReadLimits {
                    blocks: 65536,
                    inodes: 512,
                    entries: 1024,
                    pages: 1024,
                    extents: 4096,
                    work: 64 * 1024 * 1024,
                },
                audit: JfsAuditLimits {
                    blocks: 65536,
                    objects: 1024,
                    depth: 32,
                    work: 1_000_000,
                    findings: 64,
                },
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        let mut o = options();
        o.names = ExtCopyNamePolicy::BytesAndUtf16ToUtf8;
        let result = ExtCopyPlan::new(Arc::new(image), o, &r);
        if !valid {
            assert!(result.is_err());
            drop(result);
            assert_eq!(r.memory.used(), 0);
            continue;
        }
        let plan = result.unwrap();
        assert!(plan.outcomes().iter().any(|o| o.class == "hardlinks"
            && matches!(o.decision, partmgr::fs_core::Preservation::Preserve)));
        let mut target = Target::new();
        plan.emit(&mut target, &r).unwrap();
        drop(plan);
        assert_eq!(r.memory.used(), 0);
        if let Some(root) = evidence {
            native_jfs_destination(root, &target.bytes);
        }
        let dest = ReadImage::open(
            Arc::new(Source {
                length: AtomicU64::new(target.bytes.len() as u64),
                bytes: target.bytes,
            }),
            ReadOptions::Ext2 {
                audit: audit_limits(),
                objects: 16,
                entries: 16,
                map_blocks: 64,
                directory_slots: 32,
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        let page = dest.directory_page(&dest.root(), None, 8, &r).unwrap();
        let id = |name: &[u8]| {
            page.entries
                .iter()
                .find(|e| e.name == NativeName::Bytes(name.to_vec()))
                .unwrap()
                .object
                .clone()
        };
        let original = id(b"zbx");
        assert_eq!(original, id(b"Alias"));
        let parent = id(b"Box");
        drop(page);
        let file = dest.open_stream(&original, &StreamKind::Data, &r).unwrap();
        let mut expected = vec![0; 4 * jfs_fixture::BLOCK + 7];
        for block in [0, 2] {
            for byte in 0..jfs_fixture::BLOCK {
                expected[block * jfs_fixture::BLOCK + byte] = (byte * 17 % 251) as u8;
            }
        }
        let mut observed = vec![0xaa; expected.len()];
        assert_eq!(file.read_at(0, &mut observed, &r).unwrap(), expected.len());
        assert_eq!(observed, expected);
        drop(file);
        let page = dest.directory_page(&parent, None, 8, &r).unwrap();
        let child = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"Child".to_vec()))
            .unwrap()
            .object
            .clone();
        drop(page);
        let file = dest.open_stream(&child, &StreamKind::Data, &r).unwrap();
        let mut out = [0; 7];
        assert_eq!(file.read_at(0, &mut out, &r).unwrap(), 7);
        assert_eq!(&out, b"nested!");
        drop(file);
        drop(dest);
        assert_eq!(r.memory.used(), 0);
    }
}

fn jfs_native_command(
    root: &std::path::Path,
    label: &str,
    tool: &str,
    args: &[&std::ffi::OsStr],
) -> std::process::Output {
    let binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join(tool))
        .find(|p| p.is_file())
        .expect("required native tool");
    let output = std::process::Command::new(&binary)
        .args(args)
        .output()
        .expect("native command execution");
    std::fs::write(root.join(format!("{label}.stdout")), &output.stdout).unwrap();
    std::fs::write(root.join(format!("{label}.stderr")), &output.stderr).unwrap();
    std::fs::write(
        root.join(format!("{label}.command.txt")),
        format!(
            "program={binary:?} args={args:?} status={}\n",
            output.status
        ),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "native {tool}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn native_jfs_destination(root: &std::path::Path, bytes: &[u8]) {
    use std::ffi::OsStr;
    let image = root.join("destination.ext2");
    std::fs::write(&image, bytes).unwrap();
    let mut expected = vec![0; 4 * jfs_fixture::BLOCK + 7];
    for block in [0, 2] {
        for byte in 0..jfs_fixture::BLOCK {
            expected[block * jfs_fixture::BLOCK + byte] = (byte * 17 % 251) as u8;
        }
    }
    jfs_native_command(
        root,
        "e2fsck",
        "e2fsck",
        &[OsStr::new("-fn"), image.as_os_str()],
    );
    let mut inodes = Vec::new();
    for (index, (name, wanted)) in [
        ("zbx", expected.as_slice()),
        ("Alias", expected.as_slice()),
        ("Box/Child", b"nested!".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let command = format!("cat /{name}");
        let output = jfs_native_command(
            root,
            &format!("{index}-cat"),
            "debugfs",
            &[OsStr::new("-R"), OsStr::new(&command), image.as_os_str()],
        );
        assert!(output.stdout == wanted, "native payload mismatch /{name}");
        let stat = jfs_native_command(
            root,
            &format!("{index}-stat"),
            "debugfs",
            &[
                OsStr::new("-R"),
                OsStr::new(&format!("stat /{name}")),
                image.as_os_str(),
            ],
        );
        let text = String::from_utf8(stat.stdout).unwrap();
        let inode = text
            .strip_prefix("Inode: ")
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        inodes.push(inode);
    }
    assert_eq!(inodes[0], inodes[1]);
    assert_ne!(inodes[0], inodes[2]);
    assert_eq!(std::fs::read(&image).unwrap(), bytes);
}
#[test]
#[ignore = "explicit e2fsprogs JFS copy gate requires fresh PARTMGR_JFS_EXT_COPY_EVIDENCE"]
fn native_jfs_to_ext2_complete_payload_and_hardlink_oracle() {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_JFS_EXT_COPY_EVIDENCE").expect("fresh evidence required"),
    );
    std::fs::create_dir(&root).unwrap();
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        std::fs::read(repository.join("tests/fs_ext_copy.rs")).unwrap(),
        include_bytes!("fs_ext_copy.rs")
    );
    let hash = |p: &std::path::Path| {
        let output = Command::new("sha256sum").arg(p).output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };
    let mut paths = vec![std::env::current_exe().unwrap()];
    for name in [
        "tests/fs_ext_copy.rs",
        "tests/fixtures/jfs_clean.rs",
        "src/fs_jfs.rs",
        "src/fs_jfs_audit.rs",
        "src/fs_jfs_tree.rs",
        "src/fs_ext_copy.rs",
        "src/fs_ext_builder.rs",
        "Cargo.lock",
    ] {
        paths.push(repository.join(name));
    }
    for name in ["e2fsck", "debugfs"] {
        paths.push(
            std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|p| p.join(name))
                .find(|p| p.is_file())
                .expect("native tool required"),
        );
    }
    let before: Vec<_> = paths.iter().map(|p| hash(p)).collect();
    for tool in ["e2fsck", "debugfs"] {
        jfs_native_command(
            &root,
            &format!("{tool}-version"),
            tool,
            &[std::ffi::OsStr::new("-V")],
        );
    }
    jfs_copy(Some(&root));
    for (p, h) in paths.iter().zip(&before) {
        assert_eq!(&hash(p), h);
    }
    let mut receipt = String::from(
        "profile=audited-JFS-to-classic-ext2-content-only\nscope=independent destination fsck/payload/hardlink oracle; no native JFS extraction or firmware\n",
    );
    for h in before {
        receipt.push_str(&h);
    }
    receipt.push_str(&hash(&root.join("destination.ext2")));
    receipt.push_str("status=passed\nsource_tool_executable_end_revalidation=passed\n");
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}

#[test]
fn jfs_copy_source_changes_before_and_after_mutation_have_distinct_outcomes() {
    use partmgr::{fs_jfs::JfsReadLimits, fs_jfs_audit::JfsAuditLimits};
    for late in [false, true] {
        let r = Resources {
            memory: Budget::new(32 << 20),
            cancellation: Cancellation::default(),
        };
        let mut bytes = jfs_fixture::jfs_seed();
        for at in 0..bytes.len() - 5 {
            if bytes[at..at + 6] == [0xa9, 3, 0, 0xd8, 0x78, 0] {
                bytes[at..at + 4].copy_from_slice(&[b'z', 0, b'b', 0]);
            }
        }
        let underlying = Arc::new(Source {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
        });
        let image = ReadImage::open(
            underlying.clone(),
            ReadOptions::Jfs {
                read: JfsReadLimits {
                    blocks: 65536,
                    inodes: 512,
                    entries: 1024,
                    pages: 1024,
                    extents: 4096,
                    work: 64 * 1024 * 1024,
                },
                audit: JfsAuditLimits {
                    blocks: 65536,
                    objects: 1024,
                    depth: 32,
                    work: 1_000_000,
                    findings: 64,
                },
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        let mut o = options();
        o.names = ExtCopyNamePolicy::BytesAndUtf16ToUtf8;
        let plan = ExtCopyPlan::new(Arc::new(image), o, &r).unwrap();
        let mut target = Target::new();
        if late {
            target.change_on_flush = Some(underlying.clone());
        } else {
            underlying.length.store(0, Ordering::Release);
        }
        let error = plan.emit(&mut target, &r).unwrap_err();
        if late {
            assert_eq!(error.kind, ErrorKind::InterruptedWrite);
            assert!(target.writes > 0);
        } else {
            assert_eq!(error.kind, ErrorKind::StalePlan);
            assert_eq!(target.writes, 0);
            assert!(target.bytes.iter().all(|b| *b == 0xa7));
        }
        drop(error);
        drop(plan);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn compressed_jffs2_common_tree_capture_preserves_exact_names_hardlinks_and_payload() {
    use partmgr::{
        fs_core::read_all,
        fs_flash::{FlashGeometry, FlashLayout, FlashProgramming},
        fs_jffs2::{Jffs2CompressionLimits, Jffs2Endian, Jffs2ReadLimits},
        fs_jffs2_audit::Jffs2AuditLimits,
    };
    for big in [false, true] {
        let r = resources();
        let mut bytes = jffs2_fixture::inode((1, 1), (0x41ed, 0), 0, b"", 0, big);
        let mut node = jffs2_fixture::inode((2, 1), (0x81a0, 256), 0, &[b'A', 255], 0, big);
        jffs2_fixture::dword(&mut node, 52, 256, big);
        node[56] = 2;
        let checksum = jffs2_fixture::crc(&node[..60]);
        jffs2_fixture::dword(&mut node, 64, checksum, big);
        bytes.extend(node);
        bytes.extend(jffs2_fixture::inode((3, 1), (0x41ed, 0), 0, b"", 0, big));
        bytes.extend(jffs2_fixture::dir(1, 1, 2, b"file", 8, big));
        bytes.extend(jffs2_fixture::dir(1, 2, 3, b"nested", 4, big));
        bytes.extend(jffs2_fixture::dir(3, 1, 2, &[b'x', 255], 8, big));
        bytes.resize(8192, 255);
        let source = Arc::new(Source {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
        });
        let image = ReadImage::open(
            source,
            ReadOptions::Jffs2Compressed {
                geometry: FlashGeometry {
                    erased_byte: 255,
                    programming: FlashProgramming::ClearBitsOnly,
                    erase_bytes: 4096,
                    program_bytes: 4,
                    layout: FlashLayout::LogicalNor,
                },
                endian: if big {
                    Jffs2Endian::Big
                } else {
                    Jffs2Endian::Little
                },
                read: Jffs2ReadLimits {
                    scan_bytes: 8192,
                    nodes: 32,
                    inodes: 16,
                    fragments: 64,
                    native_bytes: 256,
                    work: 65536,
                },
                compression: Jffs2CompressionLimits {
                    compressed_node_bytes: 64,
                    decoded_node_bytes: 256,
                    compressed_bytes: 1024,
                    decoded_bytes: 4096,
                    work: 8192,
                },
                audit: Jffs2AuditLimits {
                    entries: 32,
                    work: 4096,
                    findings: 16,
                },
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        let plan = ExtCopyPlan::new(Arc::new(image), options(), &r).unwrap();
        let mut target = Target::new();
        assert_eq!(plan.emit(&mut target, &r).unwrap().files, 1);
        drop(plan);
        assert_eq!(r.memory.used(), 0);
        let output = Arc::new(Source {
            length: AtomicU64::new(target.bytes.len() as u64),
            bytes: target.bytes,
        });
        let image = ReadImage::open(
            output,
            ReadOptions::Ext2 {
                audit: audit_limits(),
                objects: 16,
                entries: 16,
                map_blocks: 64,
                directory_slots: 32,
            },
            AllocationPolicy::RequireClean,
            &r,
        )
        .unwrap();
        let root = image.directory_page(&image.root(), None, 8, &r).unwrap();
        let original = root
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"file".to_vec()))
            .unwrap();
        let nested = root
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"nested".to_vec()))
            .unwrap();
        let child = image.directory_page(&nested.object, None, 8, &r).unwrap();
        assert_eq!(child.entries.len(), 1);
        assert_eq!(child.entries[0].name, NativeName::Bytes(vec![b'x', 255]));
        assert_eq!(child.entries[0].object, original.object);
        let file = image
            .open_stream(&original.object, &StreamKind::Data, &r)
            .unwrap();
        drop(child);
        drop(root);
        drop(image);
        assert_eq!(
            *read_all(file.as_ref(), 256, &r).unwrap().get(),
            vec![b'A'; 256]
        );
        drop(file);
        assert_eq!(r.memory.used(), 0);
    }
}
