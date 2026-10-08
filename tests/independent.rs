#![cfg(feature = "std")]

//! Explicit external-tool gates: ignored in portable CI, mandatory in tool CI.
use partmgr::{
    codec::initialize_plan,
    conversion::{BootCodePolicy, ConversionPolicy, TypeMapping, conversion_plan},
    guid::{EFI_SYSTEM_PARTITION, Guid},
    layout::{DiskLayout, Geometry, GptLayout, LbaRange},
    storage::FileStorage,
};
use std::{
    io::{Seek, SeekFrom, Write},
    process::Command,
};
fn payload_digest(path: &std::path::Path, offset: u64, length: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let source = virtdisk::RawDisk::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut bytes = [0; 4096];
    let mut copied = 0;
    while copied < length {
        let count = (length - copied).min(4096) as usize;
        virtdisk::ReadAt::read_exact_at(&source, offset + copied, &mut bytes[..count]).unwrap();
        hash.update(&bytes[..count]);
        copied += count as u64;
    }
    hash.finalize().into()
}
fn inspect_tool(path: &std::path::Path, sector: u32, label: &str, start: u64) {
    let out = Command::new("sfdisk")
        .args(["--sector-size", &sector.to_string(), "--json"])
        .arg(path)
        .output()
        .expect("sfdisk required");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(&format!("\"label\": \"{label}\"")), "{text}");
    assert!(text.contains(&format!("\"start\": {start}")), "{text}");
    if sector == 512 && label == "gpt" {
        let out = Command::new("sgdisk")
            .arg("--verify")
            .arg(path)
            .output()
            .expect("sgdisk required");
        assert!(out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("No problems found"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
#[test]
#[ignore = "requires sfdisk and sgdisk independent validators"]
fn independent_emitted_conversion_and_sparse_geometry() {
    for sector in [512, 4096] {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let geometry = Geometry::new(64 * 1024 * 1024, sector).unwrap();
        let mut gpt = GptLayout::initialize(geometry, Guid::from_bytes([1; 16]), 128, 128).unwrap();
        let range = LbaRange::new(2048, 4096).unwrap();
        gpt.create(1, EFI_SYSTEM_PARTITION, Guid::from_bytes([2; 16]), range)
            .unwrap();
        let mut storage = FileStorage::open(file.path()).unwrap();
        let reader = virtdisk::RawDisk::open(file.path()).unwrap();
        initialize_plan(&reader, &DiskLayout::Gpt(gpt))
            .unwrap()
            .commit(&mut storage)
            .unwrap();
        inspect_tool(file.path(), sector, "gpt", 2048);
        let mut payload = file.as_file().try_clone().unwrap();
        payload
            .seek(SeekFrom::Start(2048 * u64::from(sector)))
            .unwrap();
        payload.write_all(&[0x5a; 4096]).unwrap();
        payload.sync_all().unwrap();
        let before = payload_digest(
            file.path(),
            2048 * u64::from(sector),
            2048 * u64::from(sector),
        );
        let policy = ConversionPolicy::new(Guid::from_bytes([3; 16]), 123, BootCodePolicy::Clear);
        let maps = [TypeMapping::new(0xef, EFI_SYSTEM_PARTITION).unwrap()];
        for (label, ids) in [("dos", vec![]), ("gpt", vec![Guid::from_bytes([4; 16])])] {
            let reader = virtdisk::RawDisk::open(file.path()).unwrap();
            let old = DiskLayout::inspect(&reader, sector).unwrap();
            let (_, plan) = conversion_plan(&reader, &old, &maps, &policy, &ids).unwrap();
            plan.commit(&mut storage).unwrap();
            inspect_tool(file.path(), sector, label, 2048);
            let mut bytes = [0; 4096];
            virtdisk::ReadAt::read_exact_at(&reader, 2048 * u64::from(sector), &mut bytes).unwrap();
            assert_eq!(bytes, [0x5a; 4096]);
            assert_eq!(
                payload_digest(
                    file.path(),
                    2048 * u64::from(sector),
                    2048 * u64::from(sector)
                ),
                before
            );
        }
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    let size = 8u64 * 1024 * 1024 * 1024 * 1024;
    file.as_file().set_len(size).unwrap();
    let mut gpt = GptLayout::initialize(
        Geometry::new(size, 512).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    gpt.create(
        1,
        EFI_SYSTEM_PARTITION,
        Guid::from_bytes([2; 16]),
        LbaRange::new(2048, 4096).unwrap(),
    )
    .unwrap();
    let reader = virtdisk::RawDisk::open(file.path()).unwrap();
    let mut storage = FileStorage::open(file.path()).unwrap();
    initialize_plan(&reader, &DiskLayout::Gpt(gpt))
        .unwrap()
        .commit(&mut storage)
        .unwrap();
    inspect_tool(file.path(), 512, "gpt", 2048);
}
#[test]
fn range_conversions_round_trip_extreme_values() {
    for start in [0, 1, 2048, u32::MAX as u64, u64::MAX - 1] {
        for count in [1, 2, 4096] {
            if let Some(end) = start.checked_add(count) {
                let range = LbaRange::new(start, end).unwrap();
                assert_eq!(range.sectors(), count);
                assert_eq!(range.end() - 1, start + count - 1);
            }
        }
    }
}
#[test]
#[ignore = "requires independent sfdisk and sgdisk"]
fn independent_extended_serialization_and_conversion() {
    use partmgr::conversion::{extended_to_gpt, gpt_to_extended};
    for sector in [512, 4096] {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        let geometry = Geometry::new(64 * 1024 * 1024, sector).unwrap();
        let mut gpt = GptLayout::initialize(geometry, Guid::from_bytes([1; 16]), 128, 128).unwrap();
        for (slot, start) in [(1, 4096), (2, 8192)] {
            gpt.create(
                slot,
                EFI_SYSTEM_PARTITION,
                Guid::from_bytes([slot as u8 + 1; 16]),
                LbaRange::new(start, start + 1024).unwrap(),
            )
            .unwrap();
        }
        let mappings = [TypeMapping::new(0xef, EFI_SYSTEM_PARTITION).unwrap()];
        let policy = ConversionPolicy::new(Guid::from_bytes([7; 16]), 123, BootCodePolicy::Clear);
        let extended = gpt_to_extended(
            &gpt,
            &mappings,
            &policy,
            1,
            LbaRange::new(2048, 10000).unwrap(),
            &[2048, 8000],
        )
        .unwrap();
        let reader = virtdisk::RawDisk::open(file.path()).unwrap();
        let mut storage = FileStorage::open(file.path()).unwrap();
        extended
            .plan_against(&reader)
            .unwrap()
            .commit(&mut storage)
            .unwrap();
        inspect_tool(file.path(), sector, "dos", 4096);
        let reader = virtdisk::RawDisk::open(file.path()).unwrap();
        let inspected = partmgr::extended::ExtendedLayout::inspect(&reader, sector, 128).unwrap();
        assert_eq!(inspected.logical().len(), 2);
        let before: Vec<_> = [4096, 8192]
            .into_iter()
            .map(|start| {
                payload_digest(
                    file.path(),
                    start * u64::from(sector),
                    1024 * u64::from(sector),
                )
            })
            .collect();
        let gpt = extended_to_gpt(
            &inspected,
            &mappings,
            &policy,
            &[Guid::from_bytes([8; 16]), Guid::from_bytes([9; 16])],
        )
        .unwrap();
        initialize_plan(&reader, &DiskLayout::Gpt(gpt))
            .unwrap()
            .commit(&mut storage)
            .unwrap();
        inspect_tool(file.path(), sector, "gpt", 4096);
        for (index, start) in [4096, 8192].into_iter().enumerate() {
            assert_eq!(
                payload_digest(
                    file.path(),
                    start * u64::from(sector),
                    1024 * u64::from(sector)
                ),
                before[index]
            );
        }
    }
}
