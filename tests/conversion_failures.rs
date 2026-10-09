#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    codec::initialize_plan,
    conversion::{
        BootCodePolicy, ConversionPolicy, TypeMapping, conversion_plan, extended_to_gpt_plan,
        gpt_to_extended_plan,
    },
    extended::ExtendedLayout,
    guid::{EFI_SYSTEM_PARTITION, Guid},
    layout::{DiskLayout, Geometry, GptLayout, LbaRange, MbrLayout},
    recovery::RecoveryReport,
    storage::{Barrier, CommitError, Storage, WritePlan, WriteRange},
};
use sha2::{Digest, Sha256};
use virtdisk::ReadAt;
struct Disk {
    bytes: Vec<u8>,
    event: usize,
    fail: Option<usize>,
}
impl ReadAt for Disk {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.bytes[o as usize..o as usize + b.len()]);
        Ok(())
    }
}
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        self.event += 1;
        if self.fail == Some(self.event) {
            return Err(io::Error::other("conversion interruption"));
        }
        self.bytes[o as usize..o as usize + b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.event += 1;
        if self.fail == Some(self.event) {
            Err(io::Error::other("conversion flush"))
        } else {
            Ok(())
        }
    }
}
fn ranges() -> [LbaRange; 3] {
    [
        LbaRange::new(2048, 3072).unwrap(),
        LbaRange::new(4096, 5120).unwrap(),
        LbaRange::new(6144, 7168).unwrap(),
    ]
}
fn disk(sector: u32) -> Disk {
    let mut d = Disk {
        bytes: vec![0; sector as usize * 8192],
        event: 0,
        fail: None,
    };
    for (index, r) in ranges().iter().enumerate() {
        let b =
            &mut d.bytes[r.start() as usize * sector as usize..r.end() as usize * sector as usize];
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(37).wrapping_add(index as u8);
        }
    }
    d
}
fn hashes(d: &Disk, sector: u32) -> Vec<Vec<u8>> {
    ranges()
        .iter()
        .map(|r| {
            Sha256::digest(
                &d.bytes[r.start() as usize * sector as usize..r.end() as usize * sector as usize],
            )
            .to_vec()
        })
        .collect()
}
fn gpt(sector: u32) -> GptLayout {
    let mut g = GptLayout::initialize(
        Geometry::new(u64::from(sector) * 8192, sector).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    for (index, r) in ranges().iter().enumerate() {
        g.create(
            index as u32 + 1,
            EFI_SYSTEM_PARTITION,
            Guid::from_bytes([index as u8 + 2; 16]),
            *r,
        )
        .unwrap();
    }
    g
}
fn mbr(sector: u32) -> MbrLayout {
    let mut m = MbrLayout::initialize(
        Geometry::new(u64::from(sector) * 8192, sector).unwrap(),
        123,
    );
    for (index, r) in ranges().iter().enumerate() {
        m.create(index as u32 + 1, 0xef, *r, false).unwrap();
    }
    m
}
fn extended(sector: u32) -> ExtendedLayout {
    let parts: Vec<_> = ranges()
        .iter()
        .enumerate()
        .map(|(i, r)| ([1024, 4095, 6143][i], 0xef, *r))
        .collect();
    ExtendedLayout::initialize(
        Geometry::new(u64::from(sector) * 8192, sector).unwrap(),
        123,
        1,
        LbaRange::new(1024, 8000).unwrap(),
        &parts,
    )
    .unwrap()
}
fn policy() -> ConversionPolicy {
    ConversionPolicy::new(Guid::from_bytes([9; 16]), 456, BootCodePolicy::Clear)
}
fn mappings() -> [TypeMapping; 1] {
    [TypeMapping::new(0xef, EFI_SYSTEM_PARTITION).unwrap()]
}
fn ids() -> [Guid; 3] {
    [
        Guid::from_bytes([11; 16]),
        Guid::from_bytes([12; 16]),
        Guid::from_bytes([13; 16]),
    ]
}
fn restore(d: &mut Disk, plan: &WritePlan) {
    let mut writes = Vec::new();
    for s in plan.stages() {
        for w in s.writes() {
            let mut current = vec![0; w.expected().len()];
            ReadAt::read_exact_at(d, w.offset(), &mut current).unwrap();
            writes.push(WriteRange::new(w.offset(), current, w.expected().to_vec()).unwrap());
        }
    }
    let restoration = WritePlan::new(
        d.bytes.len() as u64,
        vec![Barrier::new("explicit saved source restoration", writes).unwrap()],
    )
    .unwrap();
    d.fail = None;
    restoration.commit(d).unwrap();
}
#[test]
fn every_basic_conversion_write_flush_failure_preserves_payloads_and_restores_saved_source() {
    for sector in [512, 4096] {
        for from_gpt in [false, true] {
            let mut initial = disk(sector);
            let source = if from_gpt {
                DiskLayout::Gpt(gpt(sector))
            } else {
                DiskLayout::Mbr(mbr(sector))
            };
            initialize_plan(&initial, &source)
                .unwrap()
                .commit(&mut initial)
                .unwrap();
            let before = initial.bytes.clone();
            let expected = hashes(&initial, sector);
            let (_, plan) =
                conversion_plan(&initial, &source, &mappings(), &policy(), &ids()).unwrap();
            let events = plan
                .stages()
                .iter()
                .map(|s| s.writes().len() + 1)
                .sum::<usize>();
            for fail in 1..=events {
                let mut d = Disk {
                    bytes: before.clone(),
                    event: 0,
                    fail: Some(fail),
                };
                let e = plan.commit(&mut d).unwrap_err();
                let CommitError::Interrupted {
                    stage,
                    durability_uncertain,
                    ..
                } = e
                else {
                    panic!("interruption")
                };
                assert!(durability_uncertain);
                assert!(plan.stages().iter().any(|s| s.name() == stage));
                assert_eq!(d.event, fail);
                assert_eq!(hashes(&d, sector), expected);
                if from_gpt {
                    let inspect = DiskLayout::inspect(&d, sector).unwrap();
                    assert!(matches!(inspect, DiskLayout::Gpt(_)) == (fail == 1));
                } else {
                    let inspect = DiskLayout::inspect(&d, sector).unwrap();
                    assert!(matches!(inspect, DiskLayout::Gpt(_)) == (fail == events));
                    let r = RecoveryReport::inspect(&d, sector, &[]).unwrap();
                    assert_eq!(r.backup().is_ok(), fail >= 3);
                    assert_eq!(r.primary().is_ok(), fail >= 6);
                }
                restore(&mut d, &plan);
                assert_eq!(d.bytes, before);
                assert!(DiskLayout::inspect(&d, sector).is_ok());
                assert_eq!(hashes(&d, sector), expected);
            }
        }
    }
}
#[test]
fn every_extended_conversion_write_flush_failure_preserves_payloads_and_restores_saved_source() {
    for sector in [512, 4096] {
        for from_gpt in [false, true] {
            let mut initial = disk(sector);
            let g = gpt(sector);
            let x = extended(sector);
            if from_gpt {
                initialize_plan(&initial, &DiskLayout::Gpt(g.clone()))
                    .unwrap()
                    .commit(&mut initial)
                    .unwrap();
            } else {
                x.plan_against(&initial)
                    .unwrap()
                    .commit(&mut initial)
                    .unwrap();
            }
            let before = initial.bytes.clone();
            let expected = hashes(&initial, sector);
            let plan = if from_gpt {
                gpt_to_extended_plan(
                    &initial,
                    &g,
                    &mappings(),
                    &policy(),
                    1,
                    LbaRange::new(1024, 8000).unwrap(),
                    &[1024, 4095, 6143],
                )
                .unwrap()
                .1
            } else {
                extended_to_gpt_plan(&initial, &x, &mappings(), &policy(), &ids())
                    .unwrap()
                    .1
            };
            let events = plan
                .stages()
                .iter()
                .map(|s| s.writes().len() + 1)
                .sum::<usize>();
            for fail in 1..=events {
                let mut d = Disk {
                    bytes: before.clone(),
                    event: 0,
                    fail: Some(fail),
                };
                let error = plan.commit(&mut d).unwrap_err();
                let CommitError::Interrupted {
                    stage,
                    durability_uncertain,
                    ..
                } = error
                else {
                    panic!("interruption")
                };
                assert!(durability_uncertain);
                assert!(plan.stages().iter().any(|s| s.name() == stage));
                assert_eq!(d.event, fail);
                assert_eq!(hashes(&d, sector), expected);
                if from_gpt {
                    let mbr_published = fail >= 8;
                    if mbr_published {
                        assert!(ExtendedLayout::inspect(&d, sector, 64).is_ok());
                    } else {
                        assert!(matches!(
                            DiskLayout::inspect(&d, sector),
                            Ok(DiskLayout::Gpt(_))
                        ));
                    }
                } else {
                    let gpt_published = fail >= 8;
                    if gpt_published {
                        assert!(matches!(
                            DiskLayout::inspect(&d, sector),
                            Ok(DiskLayout::Gpt(_))
                        ));
                    } else {
                        assert!(ExtendedLayout::inspect(&d, sector, 64).is_ok());
                    }
                    let r = RecoveryReport::inspect(&d, sector, &[]).unwrap();
                    assert_eq!(r.backup().is_ok(), fail >= 3);
                    assert_eq!(r.primary().is_ok(), fail >= 6);
                }
                restore(&mut d, &plan);
                assert_eq!(d.bytes, before);
                if from_gpt {
                    assert!(DiskLayout::inspect(&d, sector).is_ok())
                } else {
                    assert!(ExtendedLayout::inspect(&d, sector, 64).is_ok())
                }
                assert_eq!(hashes(&d, sector), expected);
            }
        }
    }
}
#[test]
fn obsolete_ebr_covered_by_new_gpt_array_receives_one_replacement() {
    for sector in [512, 4096] {
        let mut image = disk(sector);
        let parts: Vec<_> = ranges()
            .iter()
            .enumerate()
            .map(|(i, r)| ([2, 4095, 6143][i], 0xef, *r))
            .collect();
        let old = ExtendedLayout::initialize(
            Geometry::new(u64::from(sector) * 8192, sector).unwrap(),
            123,
            1,
            LbaRange::new(2, 8000).unwrap(),
            &parts,
        )
        .unwrap();
        old.plan_against(&image)
            .unwrap()
            .commit(&mut image)
            .unwrap();
        let payload = hashes(&image, sector);
        let (_, plan) = extended_to_gpt_plan(&image, &old, &mappings(), &policy(), &ids()).unwrap();
        let at_ebr: Vec<_> = plan
            .stages()
            .iter()
            .flat_map(|s| s.writes())
            .filter(|w| {
                w.offset() <= u64::from(sector) * 2
                    && w.offset() + w.replacement().len() as u64 > u64::from(sector) * 2
            })
            .collect();
        assert_eq!(at_ebr.len(), 1);
        assert_eq!(at_ebr[0].offset(), u64::from(sector) * 2);
        let before = image.bytes.clone();
        let events = plan
            .stages()
            .iter()
            .map(|s| s.writes().len() + 1)
            .sum::<usize>();
        for fail in 1..=events {
            let mut interrupted = Disk {
                bytes: before.clone(),
                event: 0,
                fail: Some(fail),
            };
            assert!(matches!(
                plan.commit(&mut interrupted),
                Err(CommitError::Interrupted { .. })
            ));
            assert_eq!(hashes(&interrupted, sector), payload);
            let report = RecoveryReport::inspect(&interrupted, sector, &[]).unwrap();
            assert_eq!(report.backup().is_ok(), fail >= 3);
            assert_eq!(report.primary().is_ok(), fail >= 6);
            if (5..=7).contains(&fail) {
                assert!(ExtendedLayout::inspect(&interrupted, sector, 64).is_err());
            }
            restore(&mut interrupted, &plan);
            assert!(ExtendedLayout::inspect(&interrupted, sector, 64).is_ok());
            assert_eq!(interrupted.bytes, before);
        }

        plan.commit(&mut image).unwrap();
        assert!(matches!(
            DiskLayout::inspect(&image, sector),
            Ok(DiskLayout::Gpt(_))
        ));
        assert_eq!(hashes(&image, sector), payload);
    }
}
