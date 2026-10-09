#![cfg(feature = "std")]

#[path = "fixtures/ext2_clean.rs"]
mod clean_fixture;
use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{ExtAuditFinding as Finding, ExtAuditLimits, audit},
};
use std::{process::Command, sync::Arc};
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(o).map_err(io::Error::other)?;
        let end = at
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        b.copy_from_slice(self.0.get(at..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtAuditLimits {
    ExtAuditLimits {
        blocks: 32768,
        inodes: 8192,
        work: 1_000_000,
        directory_blocks: 256,
        directory_entries: 1024,
        findings: 1024,
    }
}
fn w(b: &mut [u8], o: usize, n: u16) {
    b[o..o + 2].copy_from_slice(&n.to_le_bytes())
}
fn d(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes())
}
const FILE: usize = 5 * 1024 + 10 * 128;
// Independent small raw ext2 fixture: standard reserved inodes, root, hard-linked file.
fn fixture() -> Vec<u8> {
    clean_fixture::fixture()
}

fn volume(b: Vec<u8>, r: &Resources) -> ExtVolume {
    ExtVolume::open(Arc::new(Image(b)), r).unwrap()
}
#[test]
fn independent_clean_hardlink_and_free_ranges() {
    let r = resources();
    let v = volume(fixture(), &r);
    let report = audit(&v, limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_inodes(), 2);
    assert_eq!(report.owned_blocks(), 2);
    assert_eq!(report.free_ranges()[0].offset, 9 * 1024);
    assert_eq!(report.free_ranges()[0].length, 55 * 1024);
    assert!(r.memory.used() > 0);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn lost_crosslinked_free_beyond_eof_and_cycle() {
    let r = resources();
    let mut b = fixture();
    b[3073] |= 1;
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::LostBlock { block: 9 }));
    assert!(report.free_ranges().is_empty());
    drop(report);
    let mut b = fixture();
    b[4097] |= 8;
    let second = FILE + 128;
    let copied = b[FILE..FILE + 128].to_vec();
    b[second..second + 128].copy_from_slice(&copied);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().iter().any(|f| matches!(
        f,
        Finding::CrossLink {
            block: 8,
            first_inode: 11,
            second_inode: 12
        }
    )));
    assert!(
        report
            .findings()
            .contains(&Finding::UnreachableInode { inode: 12 })
    );
    drop(report);
    let mut b = fixture();
    b[3072] &= !(1 << 7);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::ReferencedFreeBlock {
        block: 8,
        inode: 11
    }));
    drop(report);
    let mut b = fixture();
    b[3073] |= 3;
    d(&mut b, FILE + 88, 9);
    d(&mut b, 9 * 1024, 10);
    d(&mut b, FILE + 28, 6);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::BeyondEof {
        inode: 11,
        block: 9
    }));
    assert!(report.findings().contains(&Finding::BeyondEof {
        inode: 11,
        block: 10
    }));
    drop(report);
    let mut b = fixture();
    b[3073] |= 1;
    d(&mut b, FILE + 92, 9);
    d(&mut b, 9 * 1024, 9);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::IndirectCycle {
        inode: 11,
        block: 9
    }));
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn counters_links_namespace_and_metadata_alias() {
    let r = resources();
    let mut b = fixture();
    w(&mut b, FILE + 26, 1);
    d(&mut b, FILE + 28, 0);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::LinkCount {
        inode: 11,
        recorded: 1,
        actual: 2
    }));
    assert!(report.findings().contains(&Finding::BlockCount {
        inode: 11,
        recorded: 0,
        actual: 2
    }));
    drop(report);
    let mut b = fixture();
    d(&mut b, 7 * 1024 + 24, 12);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::InvalidInodeReference {
        directory: 2,
        inode: 12
    }));
    drop(report);
    let mut b = fixture();
    d(&mut b, 7 * 1024 + 12, 11);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(
        report
            .findings()
            .contains(&Finding::DirectoryTopology { inode: 2 })
    );
    drop(report);
    let mut b = fixture();
    d(&mut b, FILE + 40, 3);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::CrossLink {
        block: 3,
        first_inode: 0,
        second_inode: 11
    }));
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn budgets_cancel_and_unsupported_abort_without_clean_report() {
    let r = resources();
    let v = volume(fixture(), &r);
    let mut cap = limits();
    cap.work = 1;
    assert_eq!(
        audit(&v, cap, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    let mut cap = limits();
    cap.blocks = 1;
    assert_eq!(
        audit(&v, cap, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    let tiny = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        audit(&v, limits(), &tiny).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(tiny.memory.used(), 0);
    r.cancellation.cancel();
    assert_eq!(
        audit(&v, limits(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    let r = resources();
    let mut b = fixture();
    w(&mut b, FILE, 0xa1ff);
    assert_eq!(
        audit(&volume(b, &r), limits(), &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), 0);
}
fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
fn json(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn retain(path: &std::path::Path, bytes: &[u8]) {
    use partmgr::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn native_command(
    directory: &std::path::Path,
    label: &str,
    tool: &str,
    arguments: &[String],
) -> String {
    let executable =
        std::env::split_paths(&std::env::var_os("PATH").expect("native gate requires PATH"))
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("required native gate tool missing: {tool}"));
    let output = Command::new(&executable)
        .args(arguments)
        .output()
        .unwrap_or_else(|e| panic!("required native gate tool {tool} failed: {e}"));
    let stdout = format!("{label}-stdout.txt");
    let stderr = format!("{label}-stderr.txt");
    retain(&directory.join(&stdout), &output.stdout);
    retain(&directory.join(&stderr), &output.stderr);
    let argv = std::iter::once(
        executable
            .to_str()
            .expect("tool path must be UTF-8 for exact receipt")
            .to_owned(),
    )
    .chain(arguments.iter().cloned())
    .map(|s| json(&s))
    .collect::<Vec<_>>()
    .join(",");
    let receipt = format!(
        "{{\"argv\":[{argv}],\"executable_sha256\":{},\"exit_code\":{},\"stdout\":{},\"stdout_sha256\":{},\"stderr\":{},\"stderr_sha256\":{}}}",
        json(&sha256(&std::fs::read(&executable).unwrap())),
        output.status.code().unwrap_or(-1),
        json(&stdout),
        json(&sha256(&output.stdout)),
        json(&stderr),
        json(&sha256(&output.stderr))
    );
    retain(
        &directory.join(format!("{label}-command.json")),
        receipt.as_bytes(),
    );
    assert!(
        output.status.success(),
        "native gate command {tool} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    receipt
}
#[test]
#[ignore = "explicit native interoperability gate; requires PARTMGR_EXT_AUDIT_EVIDENCE and e2fsprogs tools"]
fn native_mke2fs_debugfs_full_audit_with_backups() {
    let destination = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_EXT_AUDIT_EVIDENCE")
            .expect("enabled native gate requires PARTMGR_EXT_AUDIT_EVIDENCE destination"),
    );
    assert!(
        destination.is_absolute(),
        "native evidence destination must be absolute"
    );
    std::fs::create_dir_all(&destination).unwrap();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let directory = destination.join(format!(
        "{}-{}-{}",
        time.as_secs(),
        time.subsec_nanos(),
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    retain(
        &directory.join("gate-start.json"),
        format!(
            "{{\"status\":\"running\",\"started_unix_ns\":{}}}",
            time.as_nanos()
        )
        .as_bytes(),
    );
    let mut native = Vec::new();
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        native.push(native_command(
            &directory,
            &format!("{tool}-version"),
            tool,
            &["-V".into()],
        ));
    }
    let path = directory.join("ext.img");
    let image = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    image.set_len(16 * 1024 * 1024).unwrap();
    image.sync_all().unwrap();
    drop(image);
    let mut arguments = [
        "-q", "-F", "-t", "ext2", "-b", "1024", "-O", "none", "-I", "128",
    ]
    .map(String::from)
    .to_vec();
    arguments.push(path.to_str().unwrap().into());
    native.push(native_command(
        &directory,
        "mke2fs-create",
        "mke2fs",
        &arguments,
    ));
    let payload = directory.join("payload.bin");
    let payload_bytes: Vec<u8> = (0..400_003)
        .map(|n| ((n * 37 + n / 13) % 251) as u8)
        .collect();
    retain(&payload, &payload_bytes);
    let commands = directory.join("debugfs-commands.txt");
    let script = format!(
        "write {} /payload\nlink /payload /alias\nset_inode_field /payload links_count 2\n",
        payload.display()
    );
    retain(&commands, script.as_bytes());
    native.push(native_command(
        &directory,
        "debugfs-author",
        "debugfs",
        &[
            "-w".into(),
            "-f".into(),
            commands.to_str().unwrap().into(),
            path.to_str().unwrap().into(),
        ],
    ));
    std::fs::File::open(&path).unwrap().sync_all().unwrap();
    let unchanged = std::fs::read(&path).unwrap();
    let before = sha256(&unchanged);
    let r = resources();
    let v = volume(unchanged.clone(), &r);
    let report = audit(&v, limits(), &r).unwrap();
    retain(
        &directory.join("audit-findings.txt"),
        format!("{:?}\n", report.findings()).as_bytes(),
    );
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_inodes(), 3);
    assert!(report.owned_blocks() > 390);
    let allocated_inodes = report.allocated_inodes();
    let owned_blocks = report.owned_blocks();
    let free_ranges = report.free_ranges().len();
    drop(report);
    assert_eq!(r.memory.used(), 0);
    native.push(native_command(
        &directory,
        "e2fsck-read-only",
        "e2fsck",
        &["-fn".into(), path.to_str().unwrap().into()],
    ));
    let after_bytes = std::fs::read(&path).unwrap();
    assert_eq!(after_bytes, unchanged);
    let after = sha256(&after_bytes);
    let mut bad = unchanged.clone();
    bad[8193 * 1024 + 24] ^= 1;
    retain(&directory.join("backup-super-corrupt.img"), &bad);
    let report = audit(&volume(bad.clone(), &r), limits(), &r).unwrap();
    retain(
        &directory.join("backup-super-findings.txt"),
        format!("{:?}\n", report.findings()).as_bytes(),
    );
    assert!(
        report
            .findings()
            .contains(&Finding::BackupSuperblock { group: 1 })
    );
    let super_corrupt_hash = sha256(&bad);
    drop(report);
    let mut bad = unchanged;
    bad[8194 * 1024] ^= 1;
    retain(&directory.join("backup-descriptor-corrupt.img"), &bad);
    let report = audit(&volume(bad.clone(), &r), limits(), &r).unwrap();
    retain(
        &directory.join("backup-descriptor-findings.txt"),
        format!("{:?}\n", report.findings()).as_bytes(),
    );
    assert!(report.findings().contains(&Finding::BackupDescriptor {
        backup_group: 1,
        group: 0
    }));
    let descriptor_corrupt_hash = sha256(&bad);
    drop(report);
    assert_eq!(r.memory.used(), 0);
    let cap = limits();
    let receipt = format!(
        r#"{{
  "status":"passed",
  "gate":"native_mke2fs_debugfs_full_audit_with_backups",
  "crate_version":{},
  "source_profile":"owned immutable snapshot of independently authored 16MiB regular-file ext2 image; direct/single/double indirect payload and native hardlink",
  "source_sha256":{{"src/fs_ext.rs":{},"src/fs_ext_audit.rs":{},"src/fs_core.rs":{},"src/fs_file.rs":{},"Cargo.lock":{},"tests/fs_ext_audit.rs":{}}},
  "limits":{{"blocks":{},"inodes":{},"work":{},"directory_blocks":{},"directory_entries":{},"findings":{}}},
  "payload":{{"path":"payload.bin","length":400003,"sha256":{}}},
  "authoring_script":{{"path":"debugfs-commands.txt","sha256":{}}},
  "image":{{"path":"ext.img","length":16777216,"sha256_before_read_only_check":{},"sha256_after_read_only_check":{},"unchanged":true}},
  "audit":{{"clean":true,"namespace_complete":true,"allocated_inodes":{},"owned_blocks":{},"free_ranges":{}}},
  "negative_controls":{{"backup_geometry_detected":true,"backup_geometry_image_sha256":{},"backup_descriptor_detected":true,"backup_descriptor_image_sha256":{}}},
  "native_commands":[{}]
}}
"#,
        json(env!("CARGO_PKG_VERSION")),
        json(&sha256(include_bytes!("../src/fs_ext.rs"))),
        json(&sha256(include_bytes!("../src/fs_ext_audit.rs"))),
        json(&sha256(include_bytes!("../src/fs_core.rs"))),
        json(&sha256(include_bytes!("../src/fs_file.rs"))),
        json(&sha256(include_bytes!("../Cargo.lock"))),
        json(&sha256(include_bytes!("fs_ext_audit.rs"))),
        cap.blocks,
        cap.inodes,
        cap.work,
        cap.directory_blocks,
        cap.directory_entries,
        cap.findings,
        json(&sha256(&payload_bytes)),
        json(&sha256(script.as_bytes())),
        json(&before),
        json(&after),
        allocated_inodes,
        owned_blocks,
        free_ranges,
        json(&super_corrupt_hash),
        json(&descriptor_corrupt_hash),
        native.join(",")
    );
    retain(&directory.join("evidence.json"), receipt.as_bytes());
    std::fs::File::open(&directory).unwrap().sync_all().unwrap();
    std::fs::File::open(&destination)
        .unwrap()
        .sync_all()
        .unwrap();
    eprintln!(
        "native ext audit receipt: {}",
        directory.join("evidence.json").display()
    );
}

#[test]
fn sparse_triple_indirect_map_is_audited_without_payload_allocation() {
    let r = resources();
    let mut b = fixture();
    b[3073] |= 15;
    w(&mut b, 2060, 51);
    d(&mut b, 1036, 51);
    d(&mut b, FILE + 4, (12 + 256 + 65536 + 1) * 1024);
    d(&mut b, FILE + 28, 10);
    d(&mut b, FILE + 96, 9);
    d(&mut b, 9 * 1024, 10);
    d(&mut b, 10 * 1024, 11);
    d(&mut b, 11 * 1024, 12);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.owned_blocks(), 6);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn directory_decode_completeness_types_tails_and_finding_cap() {
    let r = resources();
    let mut b = fixture();
    w(&mut b, 7 * 1024 + 4, 10);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(!report.namespace_complete());
    assert!(!report.is_clean());
    assert!(
        report
            .findings()
            .contains(&Finding::InvalidDirectory { inode: 2 })
    );
    assert!(report.free_ranges().is_empty());
    drop(report);
    let mut b = fixture();
    b[7 * 1024 + 31] = 2;
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::DirectoryType {
        directory: 2,
        inode: 11
    }));
    drop(report);
    let mut b = fixture();
    b[3079] &= 127;
    let report = audit(&volume(b.clone(), &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::BitmapTail {
        group: 0,
        inodes: false
    }));
    drop(report);
    let mut cap = limits();
    cap.findings = 0;
    assert_eq!(
        audit(&volume(b, &r), cap, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn cancellation_during_scan_and_underlying_io_are_retained() {
    use std::sync::atomic::{AtomicU8, Ordering};
    struct Controlled {
        image: Image,
        action: Arc<AtomicU8>,
        cancellation: Cancellation,
    }
    impl ReadAt for Controlled {
        fn len(&self) -> u64 {
            self.image.len()
        }
        fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
            match self.action.load(Ordering::Relaxed) {
                1 => self.cancellation.cancel(),
                2 => return Err(io::Error::other("independent injected audit IO")),
                _ => {}
            }
            self.image.read_exact_at(o, b)
        }
    }
    let r = resources();
    let action = Arc::new(AtomicU8::new(0));
    let v = ExtVolume::open(
        Arc::new(Controlled {
            image: Image(fixture()),
            action: action.clone(),
            cancellation: r.cancellation.clone(),
        }),
        &r,
    )
    .unwrap();
    action.store(1, Ordering::Relaxed);
    assert_eq!(
        audit(&v, limits(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let action = Arc::new(AtomicU8::new(0));
    let v = ExtVolume::open(
        Arc::new(Controlled {
            image: Image(fixture()),
            action: action.clone(),
            cancellation: r.cancellation.clone(),
        }),
        &r,
    )
    .unwrap();
    action.store(2, Ordering::Relaxed);
    let failure = audit(&v, limits(), &r).err().unwrap();
    assert_eq!(failure.kind, ErrorKind::Io);
    assert!(
        failure
            .source
            .unwrap()
            .to_string()
            .contains("independent injected audit IO")
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn all_counter_classes_reserved_allocations_and_fragment_gates() {
    let r = resources();
    let mut b = fixture();
    b[3073] |= 1;
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::GroupFreeCount {
        group: 0,
        inodes: false,
        recorded: 55,
        actual: 54
    }));
    assert!(report.findings().contains(&Finding::SuperFreeCount {
        inodes: false,
        recorded: 55,
        actual: 54
    }));
    drop(report);
    let mut b = fixture();
    w(&mut b, 2064, 0);
    w(&mut b, 2062, 4);
    d(&mut b, 1040, 4);
    let report = audit(&volume(b, &r), limits(), &r).unwrap();
    assert!(report.findings().contains(&Finding::GroupDirectoryCount {
        group: 0,
        recorded: 0,
        actual: 1
    }));
    assert!(report.findings().contains(&Finding::GroupFreeCount {
        group: 0,
        inodes: true,
        recorded: 4,
        actual: 5
    }));
    assert!(report.findings().contains(&Finding::SuperFreeCount {
        inodes: true,
        recorded: 4,
        actual: 5
    }));
    drop(report);
    let mut b = fixture();
    d(&mut b, 5 * 1024 + 40, 8);
    assert_eq!(
        audit(&volume(b, &r), limits(), &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    let mut b = fixture();
    b[FILE + 116] = 1;
    assert_eq!(
        audit(&volume(b, &r), limits(), &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    let mut cap = limits();
    cap.directory_blocks = 0;
    assert_eq!(
        audit(&volume(fixture(), &r), cap, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}
