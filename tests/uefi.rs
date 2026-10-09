#![cfg(feature = "std")]

use partmgr::{
    guid::Guid,
    layout::LbaRange,
    uefi::{EspAdapter, EspPreparation, HardDriveDevicePath, prepare_esp},
};
#[test]
fn independent_hard_drive_vectors() {
    let range = LbaRange::new(2048, 4096).unwrap();
    let guid: Guid = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();
    let bytes = HardDriveDevicePath::gpt(1, range, guid).unwrap().encode();
    assert_eq!(&bytes[..8], &[4, 1, 42, 0, 1, 0, 0, 0]);
    assert_eq!(&bytes[8..16], &[0, 8, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[16..24], &[0, 8, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        &bytes[24..40],
        &[
            0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff
        ]
    );
    assert_eq!(&bytes[40..], &[2, 2]);
    let mbr = HardDriveDevicePath::mbr(4, range, 0x12345678)
        .unwrap()
        .encode();
    assert_eq!(&mbr[24..28], &[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(&mbr[28..40], &[0; 12]);
    assert_eq!(&mbr[40..], &[1, 1]);
    assert!(HardDriveDevicePath::mbr(5, range, 1).is_err());
    assert!(HardDriveDevicePath::gpt(1, range, Guid::NIL).is_err());
}
struct Adapter {
    stages: Vec<&'static str>,
    fail: bool,
}
impl EspAdapter for Adapter {
    fn prepare_fat(&mut self, _: LbaRange) -> partmgr::io::Result<()> {
        self.stages.push("fat");
        Ok(())
    }
    fn install_boot_files(&mut self, _: LbaRange) -> partmgr::io::Result<()> {
        self.stages.push("boot");
        if self.fail {
            Err(partmgr::io::Error::other("boot"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn preparation_separates_fat_boot_and_firmware() {
    let mut adapter = Adapter {
        stages: Vec::new(),
        fail: true,
    };
    let result = prepare_esp(&mut adapter, LbaRange::new(1, 10).unwrap());
    let error = result.unwrap_err();
    assert_eq!(error.completed(), EspPreparation::FatPrepared);
    assert_eq!(adapter.stages, ["fat", "boot"]);
    adapter.fail = false;
    assert_eq!(
        prepare_esp(&mut adapter, LbaRange::new(1, 10).unwrap()).unwrap(),
        EspPreparation::BootFilesInstalled
    );
}
#[test]
fn configurable_profiles_recognize_created_esp() {
    use partmgr::{
        guid::{EFI_SYSTEM_PARTITION, MICROSOFT_RESERVED},
        layout::{DiskLayout, Geometry, GptLayout},
        uefi::{EspProfile, esp_entries},
    };
    let mut g = GptLayout::initialize(
        Geometry::new(512 * 16384, 512).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    let range = LbaRange::new(2048, 4096).unwrap();
    g.create(1, EFI_SYSTEM_PARTITION, Guid::from_bytes([2; 16]), range)
        .unwrap();
    let layout = DiskLayout::Gpt(g.clone());
    assert_eq!(esp_entries(&layout), vec![(1, range)]);
    assert!(
        EspProfile::linux(1024 * 1024, 1024 * 1024)
            .unwrap()
            .validate(&layout)
            .is_ok()
    );
    assert!(
        EspProfile::linux(2 * 1024 * 1024, 1024 * 1024)
            .unwrap()
            .validate(&layout)
            .is_err()
    );
    assert!(
        EspProfile::windows(1024 * 1024, 1024 * 1024)
            .unwrap()
            .validate(&layout)
            .is_err()
    );
    g.create(
        2,
        MICROSOFT_RESERVED,
        Guid::from_bytes([3; 16]),
        LbaRange::new(4096, 6144).unwrap(),
    )
    .unwrap();
    assert!(
        EspProfile::windows(1024 * 1024, 1024 * 1024)
            .unwrap()
            .validate(&DiskLayout::Gpt(g))
            .is_ok()
    );
}
#[test]
fn explicit_esp_creation_and_logical_recognition() {
    use partmgr::{
        extended::ExtendedLayout,
        layout::{DiskLayout, Geometry, MbrLayout},
        uefi::{create_esp, esp_entries, esp_entries_extended},
    };
    let geometry = Geometry::new(512 * 8192, 512).unwrap();
    let mut m = DiskLayout::Mbr(MbrLayout::initialize(geometry, 1));
    let range = LbaRange::new(2048, 4096).unwrap();
    create_esp(&mut m, 1, Guid::NIL, range).unwrap();
    assert_eq!(esp_entries(&m), vec![(1, range)]);
    let extended = ExtendedLayout::initialize(
        geometry,
        1,
        1,
        LbaRange::new(1024, 6000).unwrap(),
        &[(1024, 0xef, range)],
    )
    .unwrap();
    assert_eq!(esp_entries_extended(&extended), vec![(5, range)]);
}
