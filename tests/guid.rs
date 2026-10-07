use partmgr::guid::{EFI_SYSTEM_PARTITION, GptAttributes, GptName, Guid, MICROSOFT_BASIC_DATA};
#[test]
fn independent_guid_vector() {
    let id: Guid = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();
    assert_eq!(
        id.to_gpt_bytes(),
        [
            0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff
        ]
    );
    assert_eq!(Guid::from_gpt_bytes(id.to_gpt_bytes()), id);
    assert_eq!(id.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
    for bad in [
        "00112233445566778899aabbccddeeff",
        "{00112233-4455-6677-8899-aabbccddeeff}",
        "00112233-4455-6677-8899-aabbccddeefg",
    ] {
        assert!(bad.parse::<Guid>().is_err());
    }
}
#[test]
fn names_are_lossless_and_checked() {
    let mut n = GptName::default();
    n.set(&"😀".repeat(18)).unwrap();
    let before = n.clone();
    assert!(n.set(&"😀".repeat(19)).is_err());
    assert_eq!(n, before);
    let mut raw = [0; 36];
    raw[0] = 0xd800;
    raw[2] = 77;
    let n = GptName::from_raw(raw);
    assert_eq!(n.raw(), &raw);
    assert!(n.to_string().is_err());
}
#[test]
fn attributes_preserve_unknown_bits() {
    let mut a = GptAttributes::from_bits(1 << 40);
    a.set_required(true);
    a.set_no_block_io(true);
    a.set_legacy_boot(true);
    assert_eq!(a.bits(), (1 << 40) | 7);
    assert!(a.set_read_only(EFI_SYSTEM_PARTITION, true).is_err());
    a.set_read_only(MICROSOFT_BASIC_DATA, true).unwrap();
    assert_eq!(a.bits(), (1 << 60) | (1 << 40) | 7);
}
#[test]
fn generated_ids_retry_collisions_and_propagate_entropy_errors() {
    let used: Guid = "00112233-4455-4677-8899-aabbccddeeff".parse().unwrap();
    let mut attempts = 0;
    let id = Guid::generate_unique(&[used], 3, |bytes| {
        attempts += 1;
        *bytes = used.to_bytes();
        if attempts == 2 {
            bytes[15] = 1;
        }
        Ok::<_, std::io::Error>(())
    })
    .unwrap();
    assert_ne!(id, used);
    assert_eq!(attempts, 2);
    assert!(Guid::generate_unique(&[], 1, |_| Err(std::io::Error::other("entropy"))).is_err());
    assert!(Guid::validate_unique(&[Guid::NIL]).is_err());
    assert!(Guid::validate_unique(&[used, used]).is_err());
}
