use partmgr::{fs_core::*, fs_ntfs::*, fs_ntfs_security::*};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
#[path = "fixtures/ntfs_clean.rs"]
mod fixture;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        let at = o as usize;
        b.copy_from_slice(
            self.0
                .get(at..at + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    }
}
fn readlimits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 128,
        runs: 128,
        names: 32,
    }
}
fn limits() -> NtfsSecureLimits {
    NtfsSecureLimits {
        descriptor: NtfsSecurityLimits {
            bytes: 65536,
            aces: 1024,
            work: 65536,
        },
        blocks: 64,
        entries: 1024,
        depth: 8,
        work: 4 << 20,
    }
}
fn sd() -> Vec<u8> {
    let mut b = vec![0; 44];
    b[0] = 1;
    fixture::w(&mut b, 2, 0x8004);
    fixture::d(&mut b, 4, 20);
    fixture::d(&mut b, 16, 36);
    b[20..36].copy_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]);
    b[36..44].copy_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    b
}
fn named_resident(kind: u32, name: &str, value: &[u8], id: u16) -> Vec<u8> {
    let n: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let off = (24 + n.len()).next_multiple_of(8);
    let mut b = vec![0; (off + value.len()).next_multiple_of(8)];
    let len = b.len();
    fixture::d(&mut b, 0, kind);
    fixture::d(&mut b, 4, len as u32);
    b[9] = name.len() as u8;
    fixture::w(&mut b, 10, 24);
    fixture::w(&mut b, 14, id);
    fixture::d(&mut b, 16, value.len() as u32);
    fixture::w(&mut b, 20, off as u16);
    b[24..24 + n.len()].copy_from_slice(&n);
    b[off..off + value.len()].copy_from_slice(value);
    b
}
fn header(sd: &[u8]) -> Vec<u8> {
    let mut h = vec![0; 20];
    let hash = sd.as_chunks::<4>().0.iter().fold(0u32, |h, n| {
        h.rotate_left(3).wrapping_add(u32::from_le_bytes(*n))
    });
    fixture::d(&mut h, 0, hash);
    fixture::d(&mut h, 4, 256);
    fixture::d(&mut h, 16, (20 + sd.len()) as u32);
    h
}
fn index(hash: bool, h: &[u8]) -> Vec<u8> {
    let key = if hash {
        h[..8].to_vec()
    } else {
        h[4..8].to_vec()
    };
    let data = 16 + key.len();
    let size = (data + 20).next_multiple_of(8);
    let mut b = vec![0; 32 + size + 16];
    fixture::d(&mut b, 4, if hash { 0x12 } else { 0x10 });
    fixture::d(&mut b, 8, 2048);
    b[12] = 4;
    fixture::d(&mut b, 16, 16);
    fixture::d(&mut b, 20, (16 + size + 16) as u32);
    fixture::d(&mut b, 24, (16 + size + 16) as u32);
    fixture::w(&mut b, 32, data as u16);
    fixture::w(&mut b, 34, 20);
    fixture::w(&mut b, 40, size as u16);
    fixture::w(&mut b, 42, key.len() as u16);
    b[48..48 + key.len()].copy_from_slice(&key);
    b[32 + data..32 + data + 20].copy_from_slice(h);
    fixture::w(&mut b, 32 + size + 8, 16);
    fixture::w(&mut b, 32 + size + 12, 2);
    b
}
fn seed() -> Vec<u8> {
    let mut b = fixture::ntfs_audit_seed();
    b.resize(2048 * 512, 0);
    fixture::q(&mut b, 40, 2048);
    let descriptor = sd();
    let h = header(&descriptor);
    let mut attr = vec![0; 80];
    fixture::d(&mut attr, 0, 0x80);
    fixture::d(&mut attr, 4, 80);
    attr[8] = 1;
    attr[9] = 4;
    fixture::w(&mut attr, 10, 64);
    fixture::w(&mut attr, 14, 1);
    fixture::q(&mut attr, 24, 1023);
    fixture::w(&mut attr, 32, 72);
    for off in [40, 48, 56] {
        fixture::q(&mut attr, off, 0x80000);
    }
    attr[64..72].copy_from_slice(&[36, 0, 83, 0, 68, 0, 83, 0]);
    attr[72..78].copy_from_slice(&[0x22, 0, 4, 0, 4, 0]);
    let secure = fixture::record(
        9,
        &[
            attr,
            named_resident(0x90, "$SII", &index(false, &h), 2),
            named_resident(0x90, "$SDH", &index(true, &h), 3),
        ],
    );
    b[4 * 512 + 9 * 1024..4 * 512 + 10 * 1024].copy_from_slice(&secure);
    let mut standard = vec![0; 72];
    fixture::d(&mut standard, 52, 256);
    let file = fixture::record(
        24,
        &[
            fixture::resident(0x10, &standard, 0),
            fixture::resident(0x80, b"bytes", 1),
        ],
    );
    b[4 * 512 + 24 * 1024..4 * 512 + 25 * 1024].copy_from_slice(&file);
    for base in [0x80000, 0xc0000] {
        b[base..base + 20].copy_from_slice(&h);
        b[base + 20..base + 20 + descriptor.len()].copy_from_slice(&descriptor);
    }
    b
}
#[test]
fn independent_secure_indexes_mirror_hash_binding_caps_and_refunds() {
    let r = resources();
    let bytes = seed();
    let volume = NtfsVolume::open(Arc::new(Bytes(bytes.clone())), readlimits(), &r).unwrap();
    let record = volume.record(24, &r).unwrap();
    let baseline = r.memory.used();
    let proof = lookup_ntfs_security(&volume, &record, limits(), &r).unwrap();
    assert_eq!(proof.record(), record.identity());
    assert_eq!(proof.descriptor().raw(), sd());
    assert_eq!(
        proof
            .descriptor()
            .owner()
            .unwrap()
            .subauthorities()
            .collect::<Vec<_>>(),
        [32, 544]
    );
    assert!(matches!(
        proof.origin(),
        NtfsSecurityOrigin::Secure { id: 256, .. }
    ));
    drop(proof);
    assert_eq!(r.memory.used(), baseline);
    for l in [
        NtfsSecureLimits {
            entries: 0,
            ..limits()
        },
        NtfsSecureLimits {
            work: 1,
            ..limits()
        },
        NtfsSecureLimits {
            descriptor: NtfsSecurityLimits {
                bytes: 1,
                ..limits().descriptor
            },
            ..limits()
        },
    ] {
        assert!(lookup_ntfs_security(&volume, &record, l, &r).is_err());
        assert_eq!(r.memory.used(), baseline)
    }
    drop((record, volume));
    assert_eq!(r.memory.used(), 0);
    for location in [0x80000usize, 0xc0000, 0x80000 + 25] {
        let mut corrupted = bytes.clone();
        corrupted[location] ^= 1;
        let volume = NtfsVolume::open(Arc::new(Bytes(corrupted)), readlimits(), &r).unwrap();
        let record = volume.record(24, &r).unwrap();
        assert!(lookup_ntfs_security(&volume, &record, limits(), &r).is_err());
        drop((record, volume));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
#[ignore = "explicit native security gate requires PARTMGR_NTFS_SECURITY_EVIDENCE and pinned ntfs3g/TSK tools"]
fn native_secure_ids_sds_sii_sdh_and_ntfs3g_raw_oracle() {
    native_security_gate(false);
}
#[test]
#[ignore = "explicit allocated native security gate requires PARTMGR_NTFS_SECURITY_ALLOCATED_EVIDENCE and Linux user namespaces"]
fn native_security_database_allocated_indexes_full_native_acl_oracle() {
    native_security_gate(true);
}
fn native_security_gate(allocated: bool) {
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let out = PathBuf::from(
        std::env::var_os(if allocated {
            "PARTMGR_NTFS_SECURITY_ALLOCATED_EVIDENCE"
        } else {
            "PARTMGR_NTFS_SECURITY_EVIDENCE"
        })
        .expect("enabled gate requires evidence directory"),
    );
    fs::create_dir(&out).unwrap();
    let sources: [(&str, &[u8]); 14] = [
        (
            "src/fs_ntfs_bootstrap.rs",
            include_bytes!("../src/fs_ntfs_bootstrap.rs"),
        ),
        (
            "src/fs_ntfs_stream.rs",
            include_bytes!("../src/fs_ntfs_stream.rs"),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        ("src/fs_ntfs.rs", include_bytes!("../src/fs_ntfs.rs")),
        (
            "src/fs_ntfs_secure.rs",
            include_bytes!("../src/fs_ntfs_secure.rs"),
        ),
        (
            "src/fs_ntfs_security.rs",
            include_bytes!("../src/fs_ntfs_security.rs"),
        ),
        (
            "src/fs_ntfs_metadata.rs",
            include_bytes!("../src/fs_ntfs_metadata.rs"),
        ),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        (
            "tests/fs_ntfs_secure.rs",
            include_bytes!("fs_ntfs_secure.rs"),
        ),
        (
            "tests/fixtures/ntfs_clean.rs",
            include_bytes!("fixtures/ntfs_clean.rs"),
        ),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
    ];
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut bindings = String::new();
    for (name, bytes) in sources {
        assert_eq!(
            Sha256::digest(bytes),
            Sha256::digest(fs::read(root.join(name)).unwrap())
        );
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        bindings.push_str(&format!("{name} {:x}\n", Sha256::digest(bytes)));
    }
    fs::write(out.join("source-start.sha256"), &bindings).unwrap();
    let binary = std::env::current_exe().unwrap();
    let executable = fs::read(&binary).unwrap();
    fs::write(out.join("compiled-test"), &executable).unwrap();
    fs::write(
        out.join("binary.sha256"),
        format!("{:x}", Sha256::digest(&executable)),
    )
    .unwrap();
    let ntfs = PathBuf::from("/nix/store/3ankmn51mpka2xrhnyma5kfn16y59br8-ntfs3g-2026.9.18/bin");
    let tsk = PathBuf::from("/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin");
    let mut paths = vec![
        ntfs.join("mkntfs"),
        ntfs.join("ntfscp"),
        ntfs.join("ntfsinfo"),
        ntfs.join("ntfscat"),
        tsk.join("fls"),
    ];
    if allocated {
        paths.extend([
            ntfs.join("ntfssecaudit"),
            PathBuf::from("/run/current-system/sw/bin/unshare"),
        ]);
    }
    let tools = || {
        paths
            .iter()
            .map(|p| {
                format!(
                    "{} {:x}\n",
                    p.display(),
                    Sha256::digest(fs::read(p).expect("enabled gate missing tool"))
                )
            })
            .collect::<String>()
    };
    let starttools = tools();
    fs::write(out.join("tools-start.sha256"), &starttools).unwrap();
    let run = |label: &str, path: &std::path::Path, args: &[&str]| {
        fs::write(
            out.join(format!("{label}.command")),
            format!("{} {args:?}", path.display()),
        )
        .unwrap();
        let result = Command::new(path)
            .args(args)
            .output()
            .expect("enabled native tool execution");
        fs::write(out.join(format!("{label}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{label}.stderr")), &result.stderr).unwrap();
        fs::write(
            out.join(format!("{label}.status")),
            result.status.to_string(),
        )
        .unwrap();
        assert!(
            result.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    };
    for (i, path) in paths.iter().enumerate() {
        let result = Command::new(path).arg("--version").output().unwrap();
        fs::write(out.join(format!("version-{i}.stdout")), result.stdout).unwrap();
        fs::write(out.join(format!("version-{i}.stderr")), result.stderr).unwrap();
        fs::write(
            out.join(format!("version-{i}.status")),
            result.status.to_string(),
        )
        .unwrap();
    }
    let image = out.join("native.ntfs");
    let file = fs::File::create(&image).unwrap();
    file.set_len(64 << 20).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let imagearg = image.to_str().unwrap();
    run(
        "mkntfs",
        &paths[0],
        &["-F", "-Q", "-s", "512", "-c", "4096", imagearg],
    );
    let host = out.join("probe.bin");
    fs::write(&host, b"native security source").unwrap();
    run(
        "ntfscp",
        &paths[1],
        &[imagearg, host.to_str().unwrap(), "/Probe"],
    );
    if allocated {
        for mode in 0..512 {
            let octal = format!("{mode:04o}");
            run(
                &format!("set-security-{mode}"),
                &paths[6],
                &[
                    "--user",
                    "--map-root-user",
                    paths[5].to_str().unwrap(),
                    imagearg,
                    &octal,
                    "/Probe",
                ],
            );
        }
        run(
            "security-native-audit",
            &paths[6],
            &[
                "--user",
                "--map-root-user",
                paths[5].to_str().unwrap(),
                "-a",
                imagearg,
            ],
        );
    }
    let before = Sha256::digest(fs::read(&image).unwrap());
    let names = run("fls", &paths[4], &["-f", "ntfs", imagearg]);
    let text = String::from_utf8(names.stdout).unwrap();
    let line = text.lines().find(|l| l.ends_with("\tProbe")).unwrap();
    let token = line.split_whitespace().nth(1).unwrap();
    let number = token
        .split(['-', ':'])
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let sds = run("sds", &paths[3], &["-i", "9", "-n", "$SDS", imagearg]).stdout;
    let r = resources();
    let volume =
        NtfsVolume::open(Arc::new(Bytes(fs::read(&image).unwrap())), readlimits(), &r).unwrap();
    let baseline = r.memory.used();
    if allocated {
        let secure = volume.record(9, &r).unwrap();
        let native = volume
            .native_attributes(
                secure.identity(),
                NtfsStreamLimits {
                    extension_records: 8,
                    list_entries: 128,
                    list_bytes: 65536,
                    attributes: 128,
                    runs: 128,
                    work: 65536,
                },
                &r,
            )
            .unwrap();
        let mut topology = String::new();
        for name in ["$SII", "$SDH"] {
            let units: Vec<u16> = name.encode_utf16().collect();
            assert!(
                native
                    .iter()
                    .any(|a| a.kind == 0xa0 && a.name == units && a.nonresident),
                "native allocated {name} missing"
            );
        }
        for a in native.iter().filter(|a| a.kind == 0xa0 && a.nonresident) {
            let length = u64::from_le_bytes(a.raw[48..56].try_into().unwrap());
            topology.push_str(&format!(
                "name={:?} bytes={length} nodes={}\n",
                a.name,
                length / volume.geometry().index_bytes() as u64
            ));
        }
        fs::write(out.join("native-index-topology.txt"), topology).unwrap();
        drop((native, secure));
        assert_eq!(r.memory.used(), baseline);
    }
    for n in [5, number] {
        let record = volume.record(n, &r).unwrap();
        let resolved =
            lookup_ntfs_security_object(&volume, record.identity(), object_limits(), &r).unwrap();
        let (expected, provenance) = match resolved.origin() {
            NtfsSecurityOrigin::Secure { id, hash, offset } => {
                let at = offset as usize;
                let size = u32::from_le_bytes(sds[at + 16..at + 20].try_into().unwrap()) as usize;
                assert_eq!(&sds[at..at + size], &sds[at + 0x40000..at + 0x40000 + size]);
                (
                    sds[at + 20..at + size].to_vec(),
                    format!("id={id}\nhash={hash}\noffset={offset}\n"),
                )
            }
            NtfsSecurityOrigin::PerRecord => {
                let actual = run(
                    &format!("record-security-{n}"),
                    &paths[3],
                    &["-i", &n.to_string(), "-a", "0x50", imagearg],
                );
                (
                    actual.stdout,
                    "origin=per-record native security attribute\n".into(),
                )
            }
        };
        assert_eq!(resolved.descriptor().raw(), expected);
        fs::write(
            out.join(format!("descriptor-{n}.bin")),
            resolved.descriptor().raw(),
        )
        .unwrap();
        fs::write(
            out.join(format!("descriptor-{n}.provenance")),
            format!("record={n}\n{provenance}"),
        )
        .unwrap();
        assert_eq!(resolved.record(), record.identity());
        assert!(resolved.descriptor().owner().is_some());
        if allocated && n == number {
            assert!(matches!(
                resolved.origin(),
                NtfsSecurityOrigin::Secure { .. }
            ));
        }
        drop(resolved);
        let metadata =
            partmgr::fs_ntfs_metadata::inspect_ntfs_native_metadata(&volume, &record, limits(), &r)
                .unwrap();
        assert_eq!(metadata.record(), record.identity());
        assert_eq!(metadata.security().descriptor().raw(), expected.as_slice());
        let owner = metadata
            .security()
            .descriptor()
            .owner()
            .unwrap()
            .raw()
            .to_vec();
        let mapped = metadata.into_metadata(&r).unwrap();
        assert_eq!(mapped.get().security, MetadataField::Known(expected));
        assert_eq!(mapped.get().owner, MetadataField::Known(owner));
        drop((mapped, record));
        assert_eq!(r.memory.used(), baseline);
        run(
            &format!("ntfsinfo-{n}"),
            &paths[2],
            &["-i", &n.to_string(), imagearg],
        );
    }
    if allocated {
        let mut at = 0usize;
        let mut count = 0;
        while at + 20 <= sds.len() {
            if at & 0x40000 != 0 {
                at = (at / 0x80000 + 1) * 0x80000;
                continue;
            }
            let size = u32::from_le_bytes(sds[at + 16..at + 20].try_into().unwrap()) as usize;
            if size == 0 {
                at = (at / 0x80000 + 1) * 0x80000;
                continue;
            }
            let id = u32::from_le_bytes(sds[at + 4..at + 8].try_into().unwrap());
            let actual =
                lookup_ntfs_secure_id_with_attributes(&volume, id, object_limits(), &r).unwrap();
            assert_eq!(actual.descriptor().raw(), &sds[at + 20..at + size]);
            assert_eq!(&sds[at..at + size], &sds[at + 0x40000..at + 0x40000 + size]);
            fs::write(
                out.join(format!("indexed-{id}.bin")),
                actual.descriptor().raw(),
            )
            .unwrap();
            fs::write(out.join(format!("indexed-{id}.offset")), at.to_string()).unwrap();
            drop(actual);
            assert_eq!(r.memory.used(), baseline);
            count += 1;
            at += size.next_multiple_of(16);
        }
        assert_eq!(count, 514);
        fs::write(out.join("indexed-count.txt"), count.to_string()).unwrap();
    }
    let native_id = u32::from_le_bytes(sds[4..8].try_into().unwrap());
    let indexed =
        lookup_ntfs_secure_id_with_attributes(&volume, native_id, object_limits(), &r).unwrap();
    let size = u32::from_le_bytes(sds[16..20].try_into().unwrap()) as usize;
    assert_eq!(indexed.descriptor().raw(), &sds[20..size]);
    assert_eq!(
        indexed.secure_record(),
        volume.record(9, &r).unwrap().identity()
    );
    fs::write(
        out.join("indexed-descriptor.bin"),
        indexed.descriptor().raw(),
    )
    .unwrap();
    assert!(matches!(indexed.origin(), NtfsSecurityOrigin::Secure { id, .. } if id == native_id));
    drop((indexed, volume));
    assert_eq!(r.memory.used(), 0);
    assert_eq!(before, Sha256::digest(fs::read(&image).unwrap()));
    for (name, bytes) in sources {
        assert_eq!(
            Sha256::digest(bytes),
            Sha256::digest(fs::read(root.join(name)).unwrap()),
            "source changed {name}"
        );
    }
    assert_eq!(fs::read(binary).unwrap(), executable);
    assert_eq!(tools(), starttools);
    fs::write(out.join("source-end.sha256"), bindings).unwrap();
    fs::write(out.join("tools-end.sha256"), starttools).unwrap();
    fs::write(out.join("receipt.txt"),format!("status=passed\nimage_sha256={before:x}\norigin=mkntfs+ntfscp\nindependent_descriptor_oracle=ntfs3g ntfscat SDS exact bytes+mirror\nprofile=portable readonly security lookup; no ACL restoration or Windows snapshot claim\n")).unwrap();
}

fn allocation(name: &str, lcn: u16, id: u16) -> Vec<u8> {
    let mut a = vec![0; 80];
    fixture::d(&mut a, 0, 0xa0);
    fixture::d(&mut a, 4, 80);
    a[8] = 1;
    a[9] = 4;
    fixture::w(&mut a, 10, 64);
    fixture::w(&mut a, 14, id);
    fixture::q(&mut a, 24, 3);
    fixture::w(&mut a, 32, 72);
    for off in [40, 48, 56] {
        fixture::q(&mut a, off, 2048);
    }
    let n: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    a[64..72].copy_from_slice(&n);
    a[72..77].copy_from_slice(&[0x21, 4, lcn as u8, (lcn >> 8) as u8, 0]);
    a
}
fn branch(hash: bool) -> Vec<u8> {
    let mut b = vec![0; 56];
    fixture::d(&mut b, 4, if hash { 0x12 } else { 0x10 });
    fixture::d(&mut b, 8, 2048);
    b[12] = 4;
    fixture::d(&mut b, 16, 16);
    fixture::d(&mut b, 20, 40);
    fixture::d(&mut b, 24, 40);
    fixture::d(&mut b, 28, 1);
    fixture::w(&mut b, 40, 24);
    fixture::w(&mut b, 44, 3);
    b
}
fn node(hash: bool, h: &[u8]) -> Vec<u8> {
    let root = index(hash, h);
    let entries = &root[32..];
    let mut b = vec![0; 2048];
    b[..4].copy_from_slice(b"INDX");
    fixture::w(&mut b, 4, 40);
    fixture::w(&mut b, 6, 5);
    fixture::d(&mut b, 24, 40);
    fixture::d(&mut b, 28, (40 + entries.len()) as u32);
    fixture::d(&mut b, 32, 2024);
    b[64..64 + entries.len()].copy_from_slice(entries);
    fixture::w(&mut b, 40, 0xcafe);
    for i in 1..=4 {
        let at = i * 512 - 2;
        let old = u16::from_le_bytes(b[at..at + 2].try_into().unwrap());
        fixture::w(&mut b, 40 + i * 2, old);
        fixture::w(&mut b, at, 0xcafe);
    }
    b
}
fn allocated_seed() -> Vec<u8> {
    let mut b = seed();
    let h = header(&sd());
    let attr = b[4 * 512 + 9 * 1024 + 56..4 * 512 + 9 * 1024 + 136].to_vec();
    let record = fixture::record(
        9,
        &[
            attr,
            named_resident(0x90, "$SII", &branch(false), 2),
            named_resident(0x90, "$SDH", &branch(true), 3),
            allocation("$SII", 700, 4),
            allocation("$SDH", 704, 5),
            named_resident(0xb0, "$SII", &[1], 6),
            named_resident(0xb0, "$SDH", &[1], 7),
        ],
    );
    b[4 * 512 + 9 * 1024..4 * 512 + 10 * 1024].copy_from_slice(&record);
    b[700 * 512..704 * 512].copy_from_slice(&node(false, &h));
    b[704 * 512..708 * 512].copy_from_slice(&node(true, &h));
    b
}
#[test]
fn allocated_indexes_torn_fixups_child_cycles_free_bitmap_and_metadata_copy_failures() {
    let r = resources();
    let bytes = allocated_seed();
    let volume = NtfsVolume::open(Arc::new(Bytes(bytes.clone())), readlimits(), &r).unwrap();
    let record = volume.record(24, &r).unwrap();
    let baseline = r.memory.used();
    let result = lookup_ntfs_security(&volume, &record, limits(), &r).unwrap();
    assert_eq!(result.descriptor().raw(), sd());
    drop(result);
    assert_eq!(r.memory.used(), baseline);
    let metadata =
        partmgr::fs_ntfs_metadata::inspect_ntfs_native_metadata(&volume, &record, limits(), &r)
            .unwrap();
    let held = r.memory.reserve((64 << 20) - r.memory.used()).unwrap();
    assert!(metadata.into_metadata(&r).is_err());
    drop(held);
    assert_eq!(r.memory.used(), baseline);
    let metadata =
        partmgr::fs_ntfs_metadata::inspect_ntfs_native_metadata(&volume, &record, limits(), &r)
            .unwrap();
    r.cancellation.cancel();
    assert!(metadata.into_metadata(&r).is_err());
    drop((record, volume));
    assert_eq!(r.memory.used(), 0);
    for mode in 0..5 {
        let r = resources();
        let mut malformed = bytes.clone();
        match mode {
            0 => malformed[700 * 512 + 510] ^= 1,
            1 => fixture::q(&mut malformed, 700 * 512 + 16, 9),
            2 => {
                fixture::d(&mut malformed, 700 * 512 + 28, 64);
                fixture::d(&mut malformed, 700 * 512 + 36, 1);
                malformed[700 * 512 + 64..700 * 512 + 88].fill(0);
                fixture::w(&mut malformed, 700 * 512 + 72, 24);
                fixture::w(&mut malformed, 700 * 512 + 76, 3);
            }
            3 => {
                let first_bitmap = 4 * 512
                    + 9 * 1024
                    + 56
                    + 80
                    + 2 * named_resident(0x90, "$SII", &branch(false), 2).len()
                    + 2 * allocation("$SII", 700, 4).len();
                malformed[first_bitmap + 32] = 0;
            }
            _ => fixture::d(&mut malformed, 700 * 512 + 64 + 16, 999),
        }
        let volume = NtfsVolume::open(Arc::new(Bytes(malformed)), readlimits(), &r).unwrap();
        let record = volume.record(24, &r).unwrap();
        assert!(
            lookup_ntfs_security(&volume, &record, limits(), &r).is_err(),
            "mode{mode}"
        );
        drop((record, volume));
        assert_eq!(r.memory.used(), 0);
    }
}

fn object_limits() -> NtfsSecureObjectLimits {
    NtfsSecureObjectLimits {
        security: limits(),
        streams: NtfsStreamLimits {
            extension_records: 8,
            list_entries: 32,
            list_bytes: 8192,
            attributes: 128,
            runs: 128,
            work: 65536,
        },
    }
}
fn security_list_entry(kind: u32, number: u64, instance: u16) -> Vec<u8> {
    let mut b = vec![0; 32];
    fixture::d(&mut b, 0, kind);
    fixture::w(&mut b, 4, 32);
    b[7] = 26;
    fixture::q(&mut b, 16, number | (7 << 48));
    fixture::w(&mut b, 24, instance);
    b
}
#[test]
fn extension_security_object_retains_exact_bytes_and_rejects_foreign_binding() {
    let mut bytes = seed();
    let mut list = security_list_entry(0x10, 24, 1);
    list.extend(security_list_entry(0x50, 26, 9));
    list.extend(security_list_entry(0x80, 24, 3));
    let base = fixture::record(
        24,
        &[
            fixture::resident(0x10, &[0; 72], 1),
            fixture::resident(0x20, &list, 4),
            fixture::resident(0x80, b"bytes", 3),
        ],
    );
    let mut ext = fixture::record(26, &[fixture::resident(0x50, &sd(), 9)]);
    fixture::q(&mut ext, 32, 24 | (7 << 48));
    bytes[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&base);
    bytes[2048 + 26 * 1024..2048 + 27 * 1024].copy_from_slice(&ext);
    let r = resources();
    let volume = NtfsVolume::open(Arc::new(Bytes(bytes.clone())), readlimits(), &r).unwrap();
    let object = volume.stream_identity(24, &r).unwrap();
    let resolved = lookup_ntfs_security_object(&volume, &object, object_limits(), &r).unwrap();
    assert_eq!(resolved.record(), &object);
    assert_eq!(resolved.descriptor().raw(), sd());
    assert_eq!(resolved.origin(), NtfsSecurityOrigin::PerRecord);
    let other = NtfsVolume::open(Arc::new(Bytes(bytes)), readlimits(), &r).unwrap();
    assert!(lookup_ntfs_security_object(&other, &object, object_limits(), &r).is_err());
    drop((resolved, volume, other));
    assert_eq!(r.memory.used(), 0);
}

fn named_security_list_entry(kind: u32, name: &str, number: u64, instance: u16) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut b = security_list_entry(kind, number, instance);
    b.resize((26 + units.len() * 2).next_multiple_of(8), 0);
    let length = b.len();
    fixture::w(&mut b, 4, length as u16);
    b[6] = units.len() as u8;
    for (i, u) in units.iter().enumerate() {
        fixture::w(&mut b, 26 + i * 2, *u);
    }
    b
}
#[test]
fn secure_extension_roots_use_full_catalog_checks_and_reject_owner_mismatch() {
    let mut bytes = seed();
    let base_at = 2048 + 9 * 1024;
    let sds = bytes[base_at + 56..base_at + 136].to_vec();
    let mut list = named_security_list_entry(0x80, "$SDS", 9, 1);
    list.extend(named_security_list_entry(0x90, "$SDH", 27, 3));
    list.extend(named_security_list_entry(0x90, "$SII", 26, 2));
    let base = fixture::record(9, &[fixture::resident(0x20, &list, 4), sds]);
    bytes[base_at..base_at + 1024].copy_from_slice(&base);
    for (number, name, hash, instance) in [(26, "$SII", false, 2), (27, "$SDH", true, 3)] {
        let mut extension = fixture::record(
            number,
            &[named_resident(
                0x90,
                name,
                &index(hash, &header(&sd())),
                instance,
            )],
        );
        fixture::q(&mut extension, 32, 9 | (7 << 48));
        let at = 2048 + number as usize * 1024;
        bytes[at..at + 1024].copy_from_slice(&extension);
    }
    let r = resources();
    let volume = NtfsVolume::open(Arc::new(Bytes(bytes.clone())), readlimits(), &r).unwrap();
    let object = volume.stream_identity(24, &r).unwrap();
    let resolved = lookup_ntfs_security_object(&volume, &object, object_limits(), &r).unwrap();
    assert_eq!(resolved.descriptor().raw(), sd());
    assert!(matches!(
        resolved.origin(),
        NtfsSecurityOrigin::Secure { id: 256, .. }
    ));
    drop(resolved);
    let mut tiny = object_limits();
    tiny.streams.extension_records = 1;
    assert!(lookup_ntfs_security_object(&volume, &object, tiny, &r).is_err());
    drop(volume);
    fixture::q(&mut bytes, 2048 + 26 * 1024 + 32, 8 | (7 << 48));
    let volume = NtfsVolume::open(Arc::new(Bytes(bytes)), readlimits(), &r).unwrap();
    let object = volume.stream_identity(24, &r).unwrap();
    assert!(lookup_ntfs_security_object(&volume, &object, object_limits(), &r).is_err());
    drop(volume);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn security_capture_rejects_foreign_record_identity_and_refunds() {
    let r = resources();
    let bytes = seed();
    let volume = NtfsVolume::open(Arc::new(Bytes(bytes.clone())), readlimits(), &r).unwrap();
    let other = NtfsVolume::open(Arc::new(Bytes(bytes)), readlimits(), &r).unwrap();
    let foreign = other.record(24, &r).unwrap();
    let baseline = r.memory.used();
    let error = lookup_ntfs_security(&volume, &foreign, limits(), &r)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::StalePlan);
    assert_eq!(r.memory.used(), baseline);
    let error =
        partmgr::fs_ntfs_metadata::inspect_ntfs_native_metadata(&volume, &foreign, limits(), &r)
            .err()
            .unwrap();
    assert_eq!(error.kind, ErrorKind::StalePlan);
    assert_eq!(r.memory.used(), baseline);
    drop((foreign, other, volume));
    assert_eq!(r.memory.used(), 0);
}
