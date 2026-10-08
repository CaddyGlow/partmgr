//! Explicit partitioned APFS range/recovery gate across registry storage writers.
#![cfg(target_os = "linux")]
use partmgr::{
    fs_apfs::ApfsReadLimits,
    fs_apfs_audit::ApfsAuditLimits,
    fs_apfs_edit::{ApfsEditLimits, ApfsEditor, ApfsRecoveryAnchor},
    fs_core::{
        Budget, Cancellation, ExtentKind, FileRead, LogicalExtent, NativeName, ObjectId, Resources,
        StreamKind, TreeSource,
    },
    fs_image::{AllocationPolicy, ReadImage, ReadOptions},
    fs_storage::SectorGeometry,
    layout::DiskLayout,
    storage::Storage,
};
use partmgr_storage_integration::WriterSession;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use virtdisk::{DiskView, Image, ImageFormat, ImageWriter, ReadAt};

fn limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 128,
        attempts: 129,
        work: 64 << 30,
        read: ApfsReadLimits {
            blocks: 16384,
            checkpoint_blocks: 8,
            objects: 256,
            records: 256,
            work: 64 << 20,
        },
        audit: ApfsAuditLimits {
            blocks: 16384,
            objects: 512,
            depth: 32,
            work: 64 << 20,
            findings: 64,
        },
    }
}
struct Input(ObjectId);
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        29
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let n = out.len().min(7).min(29u64.saturating_sub(at) as usize);
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = ((at + i as u64) * 31 + 10) as u8;
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visit: &mut dyn FnMut(LogicalExtent) -> partmgr::fs_core::Result<()>,
    ) -> partmgr::fs_core::Result<()> {
        r.cancellation.check()?;
        visit(LogicalExtent {
            offset: 0,
            length: 29,
            kind: ExtentKind::Data,
        })
    }
}
struct TornBoot {
    inner: WriterSession,
    fail: bool,
}
impl Storage for TornBoot {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if at == 0 && std::mem::take(&mut self.fail) {
            // Persist exactly31 changed bytes, then lose the caller's completion.
            assert_eq!(self.inner.write_at(at, &bytes[..31])?, 31);
            self.inner.flush()?;
            return Err(io::Error::other("injected durable partial boot-hint write"));
        }
        self.inner.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn hash(path: &Path) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum required");
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}
fn run(dir: &Path, label: &str, tool: &Path, args: &[String], success: bool) -> Vec<u8> {
    let out = Command::new(tool)
        .args(args)
        .output()
        .expect("enabled tool required");
    fs::write(
        dir.join(format!("{label}.command")),
        format!(
            "program={}\nargs={args:?}\nexit={:?}\n",
            tool.display(),
            out.status.code()
        ),
    )
    .unwrap();
    fs::write(dir.join(format!("{label}.stdout")), &out.stdout).unwrap();
    fs::write(dir.join(format!("{label}.stderr")), &out.stderr).unwrap();
    assert_eq!(
        out.status.success(),
        success,
        "{label}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn region(image: &Image, scheme: &str) -> (u64, u64) {
    let range = match DiskLayout::inspect(image, 512).unwrap() {
        DiskLayout::Gpt(table) => {
            assert_eq!(scheme, "gpt");
            table.entries()[0].range().unwrap()
        }
        DiskLayout::Mbr(table) => {
            assert_eq!(scheme, "mbr");
            table.entries()[0].range()
        }
    };
    let result = (
        range.start().checked_mul(512).unwrap(),
        range.sectors().checked_mul(512).unwrap(),
    );
    assert_eq!(result, (1 << 20, 64 << 20));
    result
}

#[test]
#[ignore = "requires validated PARTMGR_APFS_EDIT_RAW directory and fresh PARTMGR_APFS_EDIT_CONTAINER_EVIDENCE; native tools are mandatory"]
fn partitioned_raw_qcow2_range_torn_boot_cold_recovery_and_native_models() {
    let input = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_EDIT_RAW").expect("validated input directory required"),
    );
    let output = PathBuf::from(
        std::env::var_os("PARTMGR_APFS_EDIT_CONTAINER_EVIDENCE")
            .expect("fresh evidence directory required"),
    );
    let qemu = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("qemu-img"))
        .find(|p| p.is_file())
        .expect("qemu-img required");
    let checker =
        PathBuf::from("/nix/store/dwq1kn1xs49psy3759pw67dwbvvkzl5g-apfsprogs-0.2.1/bin/apfsck");
    let icat =
        PathBuf::from("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        fs::read(manifest.join("tests/apfs_edit.rs")).unwrap(),
        include_bytes!("apfs_edit.rs")
    );
    let bindings: Vec<_> = [
        qemu.clone(),
        checker.clone(),
        icat.clone(),
        std::env::current_exe().unwrap(),
        manifest.join("tests/apfs_edit.rs"),
        manifest.join("Cargo.toml"),
        manifest.join("Cargo.lock"),
        input.join("gpt.raw"),
        input.join("mbr.raw"),
    ]
    .into_iter()
    .map(|p| {
        let h = hash(&p);
        (p, h)
    })
    .collect();
    fs::create_dir(&output).expect("evidence directory must be absent");
    fs::copy(
        std::env::current_exe().unwrap(),
        output.join("compiled-test"),
    )
    .unwrap();
    let mut receipt = String::from(
        "scope=partitioned APFS owned range and cold anchor recovery through raw/QCOW2 writers; no hardware power-loss, reclamation, broader geometry or firmware claim\n",
    );
    for (path, sha) in &bindings {
        receipt.push_str(&format!("binding={} sha256={sha}\n", path.display()));
    }
    for scheme in ["gpt", "mbr"] {
        let raw = input.join(format!("{scheme}.raw"));
        let original = fs::read(&raw).unwrap();
        for (format, format_name) in [(ImageFormat::Raw, "raw"), (ImageFormat::Qcow2, "qcow2")] {
            for torn in [false, true] {
                let label = format!(
                    "{scheme}-{format_name}-{}",
                    if torn { "torn" } else { "normal" }
                );
                let dir = output.join(&label);
                fs::create_dir(&dir).unwrap();
                let disk = dir.join("disk.img");
                run(
                    &dir,
                    "initial-convert",
                    &qemu,
                    &[
                        "convert".into(),
                        "-f".into(),
                        "raw".into(),
                        "-O".into(),
                        format_name.into(),
                        raw.display().to_string(),
                        disk.display().to_string(),
                    ],
                    true,
                );
                let image = Image::open(&disk, Some(format)).unwrap();
                assert_eq!(image.len(), original.len() as u64);
                let (base, length) = region(&image, scheme);
                drop(image);
                let r = Resources {
                    memory: Budget::new(256 << 20),
                    cancellation: Cancellation::default(),
                };
                let session = WriterSession::new(
                    ImageWriter::open(&disk, format).unwrap(),
                    base,
                    length,
                    SectorGeometry::default(),
                )
                .unwrap();
                let mut editor = ApfsEditor::open(
                    TornBoot {
                        inner: session,
                        fail: torn,
                    },
                    1026,
                    limits(),
                    &r,
                )
                .unwrap();
                let old = editor.file_identity(16, &r).unwrap();
                let plan = editor
                    .plan_range(
                        &old,
                        4091,
                        Arc::new(Input(ObjectId {
                            source: 99,
                            generation: 7,
                            native: vec![1],
                        })),
                        &r,
                    )
                    .unwrap();
                let volume_block = plan.planned_volume_block();
                let anchor_path = dir.join("anchor.bin");
                fs::write(&anchor_path, editor.recovery_anchor().encode()).unwrap();
                fs::File::open(&anchor_path).unwrap().sync_all().unwrap();
                fs::File::open(&dir).unwrap().sync_all().unwrap();
                let anchor = ApfsRecoveryAnchor::decode(&fs::read(&anchor_path).unwrap()).unwrap();
                let result = editor.commit_range(plan, &anchor, &r);
                assert_eq!(result.is_err(), torn);
                assert!(editor.read_file_at(&old, 0, &mut [0], &r).is_err());
                assert!(
                    ImageWriter::open(&disk, format).is_err(),
                    "exclusive owner lock"
                );
                if torn {
                    let store = editor.into_storage();
                    let mut snapshot = vec![0; length as usize];
                    store.read_exact_at(0, &mut snapshot).unwrap();
                    let partial = dir.join("torn.apfs");
                    fs::write(&partial, snapshot).unwrap();
                    drop(store);
                    run(
                        &dir,
                        "torn-apfsck",
                        &checker,
                        &[
                            "-c".into(),
                            "-u".into(),
                            "-w".into(),
                            partial.display().to_string(),
                        ],
                        false,
                    );
                    let target = WriterSession::new(
                        ImageWriter::open(&disk, format).unwrap(),
                        base,
                        length,
                        SectorGeometry::default(),
                    )
                    .unwrap();
                    let recovered =
                        ApfsEditor::recover_with_anchor(target, &anchor, limits(), &r).unwrap();
                    assert_eq!(recovered.checkpoint_xid(), 2);
                    assert!(recovered.allocation_proof().is_clean());
                    drop(recovered);
                } else {
                    assert_eq!(result.unwrap().xid, 2);
                    drop(editor);
                }
                assert_eq!(r.memory.used(), 0);
                let image = Image::open(&disk, Some(format)).unwrap();
                assert_eq!(region(&image, scheme), (base, length));
                let mut logical = vec![0; original.len()];
                image.read_exact_at(0, &mut logical).unwrap();
                assert_eq!(&logical[..base as usize], &original[..base as usize]);
                assert_eq!(
                    &logical[(base + length) as usize..],
                    &original[(base + length) as usize..]
                );
                let volume = dir.join("final.apfs");
                fs::write(&volume, &logical[base as usize..(base + length) as usize]).unwrap();
                let volume_sha = hash(&volume);
                let disk_sha = hash(&disk);
                let read = ReadImage::open(
                    Arc::new(DiskView::new(Arc::new(image), base, length).unwrap()),
                    ReadOptions::Apfs {
                        read: limits().read,
                        audit: limits().audit,
                        volume_oid: 1026,
                    },
                    AllocationPolicy::RequireClean,
                    &r,
                )
                .unwrap();
                let page = read.directory_page(&read.root(), None, 16, &r).unwrap();
                let object = page
                    .entries
                    .iter()
                    .find(|e| e.name == NativeName::Bytes(b"A\xc3\xa9-file".to_vec()))
                    .unwrap()
                    .object
                    .clone();
                let data = read.open_stream(&object, &StreamKind::Data, &r).unwrap();
                let fork = read
                    .open_stream(&object, &StreamKind::ResourceFork, &r)
                    .unwrap();
                drop(page);
                drop(read);
                let mut expected: Vec<u8> = (0..16397)
                    .map(|i| {
                        if (4096..8192).contains(&i) || (12288..16384).contains(&i) {
                            0
                        } else {
                            (i % 4096 * 17 % 251) as u8
                        }
                    })
                    .collect();
                for i in 0..29 {
                    expected[4091 + i] = (i * 31 + 10) as u8;
                }
                let mut actual = vec![0; expected.len()];
                let mut offset = 0;
                while offset < actual.len() {
                    let end = (offset + 73).min(actual.len());
                    let n = data
                        .read_at(offset as u64, &mut actual[offset..end], &r)
                        .unwrap();
                    assert!(n > 0);
                    offset += n;
                }
                assert_eq!(actual, expected);
                let mut resource = [0; 8];
                assert_eq!(fork.read_at(0, &mut resource, &r).unwrap(), 8);
                assert_eq!(&resource, b"resource");
                drop(data);
                drop(fork);
                assert_eq!(r.memory.used(), 0);
                let checked = run(
                    &dir,
                    "apfsck",
                    &checker,
                    &[
                        "-c".into(),
                        "-u".into(),
                        "-w".into(),
                        volume.display().to_string(),
                    ],
                    true,
                );
                assert!(checked.is_empty());
                assert!(fs::read(dir.join("apfsck.stderr")).unwrap().is_empty());
                let mut args = vec![
                    "-P".into(),
                    "apfs".into(),
                    "-B".into(),
                    volume_block.to_string(),
                    "-f".into(),
                    "apfs".into(),
                    volume.display().to_string(),
                    "16".into(),
                ];
                assert_eq!(run(&dir, "native-data", &icat, &args, true), expected);
                *args.last_mut().unwrap() = "16-4353-1".into();
                assert_eq!(run(&dir, "native-fork", &icat, &args, true), b"resource");
                if format == ImageFormat::Qcow2 {
                    run(
                        &dir,
                        "container-check",
                        &qemu,
                        &[
                            "check".into(),
                            "-f".into(),
                            format_name.into(),
                            disk.display().to_string(),
                        ],
                        true,
                    );
                }
                let restored = dir.join("restored.raw");
                run(
                    &dir,
                    "final-convert",
                    &qemu,
                    &[
                        "convert".into(),
                        "-f".into(),
                        format_name.into(),
                        "-O".into(),
                        "raw".into(),
                        disk.display().to_string(),
                        restored.display().to_string(),
                    ],
                    true,
                );
                assert_eq!(fs::read(&restored).unwrap(), logical);
                assert_eq!(hash(&volume), volume_sha);
                assert_eq!(hash(&disk), disk_sha);
                fs::write(dir.join("stages.txt"), format!("partition=inspected_unchanged\ncontainer=whole_logical_conversion_verified\nfilesystem=range_xid2_complete_audit\nrecovery={}\ncopy=data_and_resource_native_models_verified\nboot=not_tested\n", if torn { "cold_saved_anchor_completed" } else { "not_required" })).unwrap();
                receipt.push_str(&format!("case={label} inspected_offset={base} inspected_length={length} xid=2 native_data_bytes=16397 native_fork_bytes=8 whole_logical_disk=match framing=unchanged restored_sha256={}\n", hash(&restored)));
            }
        }
    }
    for (path, sha) in &bindings {
        assert_eq!(&hash(path), sha, "binding changed: {}", path.display());
    }
    receipt.push_str("status=passed\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
    fn sync_tree(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sync_tree(&path);
            } else {
                fs::File::open(path).unwrap().sync_all().unwrap();
            }
        }
        fs::File::open(path).unwrap().sync_all().unwrap();
    }
    sync_tree(&output);
}
