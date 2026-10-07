use partmgr::{
    conversion::{BootCodePolicy, ConversionPolicy, TypeMapping, convert},
    guid::{EFI_SYSTEM_PARTITION, Guid},
    layout::{DiskLayout, Geometry, GptLayout, LbaRange},
};
#[test]
fn explicit_mapping_preserves_payload_ranges_and_requires_ids() {
    let mut g = GptLayout::initialize(
        Geometry::new(512 * 4096, 512).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    let range = LbaRange::new(2048, 3000).unwrap();
    g.create(1, EFI_SYSTEM_PARTITION, Guid::from_bytes([2; 16]), range)
        .unwrap();
    let maps = [TypeMapping::new(0xef, EFI_SYSTEM_PARTITION).unwrap()];
    let p = ConversionPolicy::new(Guid::from_bytes([3; 16]), 123, BootCodePolicy::Clear);
    let m = convert(&DiskLayout::Gpt(g), &maps, &p, &[]).unwrap();
    let DiskLayout::Mbr(ref layout) = m else {
        panic!("expected MBR")
    };
    assert_eq!(layout.entries()[0].range(), range);
    assert!(convert(&m, &maps, &p, &[]).is_err());
    let converted = convert(&m, &maps, &p, &[Guid::from_bytes([4; 16])]).unwrap();
    let DiskLayout::Gpt(g) = converted else {
        panic!("expected GPT")
    };
    assert_eq!(g.entries()[0].range(), Some(range));
    assert!(convert(&m, &[], &p, &[Guid::from_bytes([4; 16])]).is_err());
}
#[test]
fn logical_conversion_requires_explicit_safe_ebr_positions() {
    use partmgr::{
        conversion::{extended_to_gpt, gpt_to_extended},
        extended::ExtendedLayout,
    };
    let geometry = Geometry::new(512 * 16384, 512).unwrap();
    let mut g = GptLayout::initialize(geometry, Guid::from_bytes([1; 16]), 128, 128).unwrap();
    for n in 0..5 {
        g.create(
            n + 1,
            EFI_SYSTEM_PARTITION,
            Guid::from_bytes([n as u8 + 2; 16]),
            LbaRange::new(2048 + u64::from(n) * 2048, 3072 + u64::from(n) * 2048).unwrap(),
        )
        .unwrap();
    }
    let maps = [TypeMapping::new(0xef, EFI_SYSTEM_PARTITION).unwrap()];
    let p = ConversionPolicy::new(Guid::from_bytes([9; 16]), 123, BootCodePolicy::Clear);
    assert!(convert(&DiskLayout::Gpt(g.clone()), &maps, &p, &[]).is_err());
    let extended = gpt_to_extended(
        &g,
        &maps,
        &p,
        1,
        LbaRange::new(1024, 13000).unwrap(),
        &[1024, 4095, 6143, 8191, 10239],
    )
    .unwrap();
    assert_eq!(extended.logical().len(), 5);
    let ids: Vec<_> = (20..25).map(|n| Guid::from_bytes([n; 16])).collect();
    let converted = extended_to_gpt(&extended, &maps, &p, &ids).unwrap();
    assert_eq!(
        converted
            .entries()
            .iter()
            .filter_map(|e| e.range())
            .collect::<Vec<_>>(),
        g.entries()
            .iter()
            .filter_map(|e| e.range())
            .collect::<Vec<_>>()
    );
    assert!(
        gpt_to_extended(
            &g,
            &maps,
            &p,
            1,
            LbaRange::new(2048, 13000).unwrap(),
            &[2048, 4095, 6143, 8191, 10239]
        )
        .is_err()
    );
    let _type_check: ExtendedLayout = extended;
}
struct Image(Vec<u8>);
impl virtdisk::ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
        Ok(())
    }
}
impl partmgr::storage::Storage for Image {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        virtdisk::ReadAt::read_exact_at(self, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> std::io::Result<usize> {
        self.0[o as usize..o as usize + b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn extended_write_round_trip_preserves_independent_payload_hashes() {
    use partmgr::conversion::{extended_to_gpt_plan, gpt_to_extended_plan};
    use sha2::{Digest, Sha256};
    let geometry = Geometry::new(512 * 16384, 512).unwrap();
    let mut g = GptLayout::initialize(geometry, Guid::from_bytes([1; 16]), 128, 128).unwrap();
    let mut image = Image(vec![0; geometry.bytes() as usize]);
    let mut hashes = Vec::new();
    for n in 0..5 {
        let range = LbaRange::new(2048 + u64::from(n) * 2048, 3072 + u64::from(n) * 2048).unwrap();
        g.create(
            n + 1,
            EFI_SYSTEM_PARTITION,
            Guid::from_bytes([n as u8 + 2; 16]),
            range,
        )
        .unwrap();
        let payload = &mut image.0[range.start() as usize * 512..range.end() as usize * 512];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(n as u8);
        }
        hashes.push(Sha256::digest(payload).to_vec());
    }
    partmgr::codec::initialize_plan(&image, &DiskLayout::Gpt(g.clone()))
        .unwrap()
        .commit(&mut image)
        .unwrap();
    let maps = [TypeMapping::new(0xef, EFI_SYSTEM_PARTITION).unwrap()];
    let p = ConversionPolicy::new(
        Guid::from_bytes([9; 16]),
        123,
        BootCodePolicy::Replace(Box::new([0x42; 440])),
    );
    let (extended, plan) = gpt_to_extended_plan(
        &image,
        &g,
        &maps,
        &p,
        1,
        LbaRange::new(1024, 13000).unwrap(),
        &[1024, 4095, 6143, 8191, 10239],
    )
    .unwrap();
    plan.commit(&mut image).unwrap();
    let inspected = partmgr::extended::ExtendedLayout::inspect(&image, 512, 64).unwrap();
    assert_eq!(inspected.logical().len(), 5);
    assert_eq!(&inspected.mbr_sector()[..440], &[0x42; 440]);
    let ids: Vec<_> = (20..25).map(|n| Guid::from_bytes([n; 16])).collect();
    let (_, plan) = extended_to_gpt_plan(&image, &extended, &maps, &p, &ids).unwrap();
    plan.commit(&mut image).unwrap();
    let DiskLayout::Gpt(restored) = DiskLayout::inspect(&image, 512).unwrap() else {
        panic!("expected GPT")
    };
    for (index, entry) in restored
        .entries()
        .iter()
        .filter(|e| e.range().is_some())
        .enumerate()
    {
        let r = entry.range().unwrap();
        assert_eq!(
            Sha256::digest(&image.0[r.start() as usize * 512..r.end() as usize * 512]).to_vec(),
            hashes[index]
        );
    }
    assert_eq!(&image.0[1024 * 512..1025 * 512], &[0; 512]);
}
