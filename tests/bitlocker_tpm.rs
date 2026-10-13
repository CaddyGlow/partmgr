#![cfg(feature = "bitlocker-tpm")]

use partmgr::{
    bitlocker::ErrorKind,
    bitlocker_tpm::{Tpm2Protector, UnsealedVmk},
};

fn fixture() -> Vec<u8> {
    let mut datum = vec![0; 302];
    datum[..12].copy_from_slice(&[0x2e, 1, 0, 0, 6, 0, 5, 0, 0x80, 8, 0, 0]);
    datum[12..14].copy_from_slice(&170u16.to_be_bytes());
    let private = &mut datum[14..184];
    private.fill(0x66);
    private[..2].copy_from_slice(&32u16.to_be_bytes());
    private[34..36].copy_from_slice(&16u16.to_be_bytes());
    datum[184..186].copy_from_slice(&78u16.to_be_bytes());
    let public = &mut datum[186..264];
    public[..10].copy_from_slice(&[0, 8, 0, 11, 0, 0, 4, 0x12, 0, 32]);
    // Independently generated with Python hashlib from zero32, PolicyAuthValue,
    // then PolicyPCR + 00000001000b03800800 + 32 bytes of 0x55.
    public[10..42].copy_from_slice(&[
        0xc3, 0xf8, 0x00, 0x39, 0x0c, 0x5f, 0x8a, 0x32, 0xbf, 0xcb, 0x1d, 0x55, 0x61, 0xd6, 0x02,
        0x93, 0x92, 0x78, 0xcc, 0xbd, 0x5a, 0xdd, 0xe5, 0xba, 0x64, 0x79, 0xb7, 0xb7, 0xd4, 0x8c,
        0x54, 0xd0,
    ]);
    public[42..46].copy_from_slice(&[0, 16, 0, 32]);
    public[46..].fill(0x77);
    datum[264..266].copy_from_slice(&32u16.to_be_bytes());
    datum[266..298].fill(0x55);
    datum[298..302].copy_from_slice(&[3, 0x80, 8, 0]);
    datum
}

#[test]
fn parses_observed_shape_with_independently_calculated_complete_policy() {
    let datum = fixture();
    let parsed = Tpm2Protector::parse(0x0100, &datum).unwrap();
    assert_eq!(parsed.private_blob().len(), 170);
    assert_eq!(parsed.public_blob().len(), 78);
    assert_eq!(parsed.pcr_mask(), 0x880);
    assert_eq!(parsed.pcr_selection(), &[0, 0, 0, 1, 0, 11, 3, 0x80, 8, 0]);
    assert_eq!(parsed.pcr_digest(), &[0x55; 32]);
    assert_eq!(&parsed.public_blob()[10..42], parsed.auth_policy());
    assert!(!format!("{parsed:?}").contains("102, 102"));
}

#[test]
fn every_truncation_trailing_byte_and_declared_size_error_is_rejected() {
    let datum = fixture();
    for end in 0..datum.len() {
        assert!(
            Tpm2Protector::parse(0x100, &datum[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut longer = datum.clone();
    longer.push(0);
    assert!(Tpm2Protector::parse(0x100, &longer).is_err());
    for offset in [0, 12, 184, 264] {
        let mut changed = datum.clone();
        changed[offset..offset + 2].copy_from_slice(&[0xff, 0xff]);
        assert!(
            Tpm2Protector::parse(0x100, &changed).is_err(),
            "size {offset}"
        );
    }
}

#[test]
fn refuses_factors_algorithms_versions_and_policy_substitution() {
    let datum = fixture();
    for protection_type in [0, 0x200, 0x500, 0x800, 0x2000] {
        assert_eq!(
            Tpm2Protector::parse(protection_type, &datum)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
    }
    for offset in [6, 186, 188, 191, 194, 228, 230] {
        let mut changed = datum.clone();
        changed[offset] ^= 1;
        assert!(
            Tpm2Protector::parse(0x100, &changed).is_err(),
            "unsupported field {offset}"
        );
    }
    for offset in [196, 266] {
        let mut changed = datum.clone();
        changed[offset] ^= 1;
        assert_eq!(
            Tpm2Protector::parse(0x100, &changed).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }
    let mut changed = datum.clone();
    changed[299] ^= 1;
    assert_eq!(
        Tpm2Protector::parse(0x100, &changed).unwrap_err().kind,
        ErrorKind::InvalidData
    );
    let mut changed = datum;
    changed[11] = 1;
    assert_eq!(
        Tpm2Protector::parse(0x100, &changed).unwrap_err().kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn unsealed_vmk_requires_exact_native_key_record_and_redacts_key() {
    let mut record = vec![0xab; 44];
    record[..12].copy_from_slice(&[44, 0, 5, 0, 1, 0, 0, 0, 3, 0x20, 0, 0]);
    let key = UnsealedVmk::parse(&record).unwrap();
    assert_eq!(key.as_bytes(), &[0xab; 32]);
    assert_eq!(format!("{key:?}"), "UnsealedVmk { .. }");
    record[2] = 0;
    let native_key = UnsealedVmk::parse(&record).unwrap();
    assert_eq!(native_key.as_bytes(), &[0xab; 32]);
    for unsupported_word in [1u16, 2, 3, 4, 6, 0x100, 0xffff] {
        let mut changed = record.clone();
        changed[2..4].copy_from_slice(&unsupported_word.to_le_bytes());
        assert!(UnsealedVmk::parse(&changed).is_err());
    }
    for end in 0..44 {
        assert!(UnsealedVmk::parse(&record[..end]).is_err());
    }
    for offset in 0..12 {
        let mut changed = record.clone();
        changed[offset] ^= 1;
        assert!(
            UnsealedVmk::parse(&changed).is_err(),
            "header field {offset}"
        );
    }
    record.push(0);
    assert!(UnsealedVmk::parse(&record).is_err());
}

#[test]
#[ignore = "requires explicitly supplied private Windows fixture directory"]
fn native_windows_tpm_policy_decodes_without_contacting_a_tpm() {
    let directory =
        std::env::var_os("PARTMGR_BITLOCKER_TPM_EVIDENCE").expect("set fixture directory");
    let metadata =
        std::fs::read(std::path::Path::new(&directory).join("metadata-41943040.bin")).unwrap();
    // The known native fixture's selected TPM property; no secret is printed.
    let parsed = Tpm2Protector::parse(0x100, &metadata[1310..1612]).unwrap();
    assert_eq!(parsed.pcr_mask(), 0x880);
    assert_eq!(parsed.public_blob().len(), 78);
}
