use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_fat_audit::{FatAuditFinding, FatAuditLimits, audit_fat},
};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let bytes = self
            .0
            .get(at..at + out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
}
fn w(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 10000 * 512];
    w(&mut b, 11, 512);
    b[13] = 1;
    w(&mut b, 14, 1);
    b[16] = 2;
    w(&mut b, 17, 512);
    w(&mut b, 19, 10000);
    b[21] = 0xf8;
    w(&mut b, 22, 40);
    w(&mut b, 510, 0xaa55);
    for base in [512, 41 * 512] {
        w(&mut b, base, 0xfff8);
        w(&mut b, base + 2, 0xffff);
    }
    b
}
fn fat(b: &mut [u8], c: usize, v: u16) {
    for base in [512, 41 * 512] {
        w(b, base + c * 2, v);
    }
}
fn file(b: &mut [u8], slot: usize, name: u8, c: u16, size: u32, dir: bool) {
    let at = 81 * 512 + slot * 32;
    b[at..at + 11].fill(b' ');
    b[at] = name;
    b[at + 11] = if dir { 0x10 } else { 0x20 };
    w(b, at + 26, c);
    b[at + 28..at + 32].copy_from_slice(&size.to_le_bytes());
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8_000_000),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> FatAuditLimits {
    FatAuditLimits {
        clusters: 10000,
        entries: 32,
        directory_slots: 64,
        findings: 100,
    }
}
#[test]
fn crosslinks_lost_and_data_only_free_ranges() {
    let mut b = fixture();
    fat(&mut b, 2, 0xffff);
    fat(&mut b, 4, 0xffff);
    file(&mut b, 0, b'A', 2, 1, false);
    file(&mut b, 1, b'B', 2, 1, false);
    let r = resources();
    let report = audit_fat(Arc::new(Image(b)), limits(), &r).unwrap();
    assert!(
        report
            .findings()
            .contains(&FatAuditFinding::CrossLink { cluster: 2 })
    );
    assert!(
        report
            .findings()
            .contains(&FatAuditFinding::LostAllocation { cluster: 4 })
    );
    for range in report.free_ranges() {
        assert!(range.offset >= 113 * 512);
        assert!(range.offset + range.length <= 10000 * 512);
    }
    assert!(r.memory.used() > 0);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn directory_tail_cycle_is_seen_after_namespace_terminator() {
    let mut b = fixture();
    fat(&mut b, 2, 3);
    fat(&mut b, 3, 2);
    file(&mut b, 0, b'D', 2, 0, true);
    let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
    assert!(
        report
            .findings()
            .contains(&FatAuditFinding::Cycle { cluster: 2 })
    );
    assert!(!report.namespace_complete());
}
#[test]
fn dirty_flags_and_mirror_disagreement_are_independent() {
    let mut b = fixture();
    w(&mut b, 514, 0x7fff);
    let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
    assert!(report.findings().contains(&FatAuditFinding::Unclean {
        copy: 0,
        clean: false,
        no_error: true
    }));
    assert!(
        report
            .findings()
            .contains(&FatAuditFinding::MirrorDisagreement {
                cluster: 1,
                copy: 1
            })
    );
}
#[test]
fn bounds_and_cancellation_return_no_report() {
    let b = fixture();
    let mut l = limits();
    l.clusters = 1;
    assert!(audit_fat(Arc::new(Image(b.clone())), l, &resources()).is_err());
    let r = resources();
    r.cancellation.cancel();
    assert!(audit_fat(Arc::new(Image(b)), limits(), &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn short_and_free_chains_are_reported() {
    let mut b = fixture();
    fat(&mut b, 2, 0xffff);
    file(&mut b, 0, b'A', 2, 1024, false);
    file(&mut b, 1, b'B', 3, 512, false);
    let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
    assert!(
        report
            .findings()
            .contains(&FatAuditFinding::LengthMismatch { first_cluster: 2 })
    );
    assert!(report.findings().contains(&FatAuditFinding::InvalidChain {
        cluster: 3,
        value: 0
    }));
    assert!(
        report
            .free_ranges()
            .iter()
            .all(|range| !(range.offset <= 114 * 512 && 114 * 512 < range.offset + range.length))
    );
}
#[test]
fn namespace_directory_self_reference_is_crosslinked() {
    let mut b = fixture();
    fat(&mut b, 2, 0xffff);
    file(&mut b, 0, b'D', 2, 0, true);
    let at = 113 * 512;
    b[at..at + 11].fill(b' ');
    b[at] = b'E';
    b[at + 11] = 0x10;
    w(&mut b, at + 26, 2);
    let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
    assert!(
        report
            .findings()
            .contains(&FatAuditFinding::CrossLink { cluster: 2 })
    );
    assert!(!report.namespace_complete());
}
#[test]
fn zero_finding_budget_does_not_return_partial_report() {
    let mut b = fixture();
    fat(&mut b, 2, 0xffff);
    let mut l = limits();
    l.findings = 0;
    let r = resources();
    assert!(audit_fat(Arc::new(Image(b)), l, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn fat32_root_owns_allocation_and_active_copy_controls_flags() {
    let mut b = vec![0u8; 70000 * 512];
    w(&mut b, 11, 512);
    b[13] = 1;
    w(&mut b, 14, 32);
    b[16] = 2;
    b[21] = 0xf8;
    w(&mut b, 510, 0xaa55);
    for (at, v) in [(32, 70000u32), (36, 600), (44, 2)] {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    w(&mut b, 40, 0x81);
    w(&mut b, 48, 1);
    w(&mut b, 50, 6);
    let base = 632 * 512;
    for (c, v) in [(0, 0x0fff_fff8u32), (1, 0x0bff_ffff), (2, 0x0fff_ffff)] {
        b[base + c * 4..base + c * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let mut l = limits();
    l.clusters = 70000;
    let r = Resources {
        memory: Budget::new(16_000_000),
        cancellation: Cancellation::default(),
    };
    let report = audit_fat(Arc::new(Image(b)), l, &r).unwrap();
    assert!(report.findings().contains(&FatAuditFinding::Unclean {
        copy: 1,
        clean: true,
        no_error: false
    }));
    assert!(!report.findings().iter().any(|f| matches!(
        f,
        FatAuditFinding::LostAllocation { cluster: 2 } | FatAuditFinding::MirrorDisagreement { .. }
    )));
    assert_eq!(report.objects(), 1);
    assert!(report.namespace_complete());
}
#[test]
fn packed_fat12_free_inventory_and_odd_entry_lost_allocation() {
    let mut b = vec![0u8; 2880 * 512];
    w(&mut b, 11, 512);
    b[13] = 1;
    w(&mut b, 14, 1);
    b[16] = 2;
    w(&mut b, 17, 224);
    w(&mut b, 19, 2880);
    b[21] = 0xf8;
    w(&mut b, 22, 9);
    w(&mut b, 510, 0xaa55);
    for base in [512, 10 * 512] {
        b[base..base + 3].copy_from_slice(&[0xf8, 0xff, 0xff]);
        b[base + 4] = 0xf0;
        b[base + 5] = 0xff;
    }
    let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
    assert_eq!(
        report.findings(),
        &[FatAuditFinding::LostAllocation { cluster: 3 }]
    );
    assert_eq!(report.free_ranges()[0].offset, 33 * 512);
    assert_eq!(report.free_ranges()[0].length, 512);
    assert!(report.namespace_complete());
}

#[test]
fn reserved_media_and_entry_one_encoding_are_separate_from_status_and_mirrors() {
    for (entry, value, mask, expected) in [(0, 0xfff0, 0xffff, 0xfff8), (1, 0xfffe, 0x3fff, 0x3fff)]
    {
        let mut b = fixture();
        fat(&mut b, entry, value as u16);
        let r = resources();
        let report = audit_fat(Arc::new(Image(b)), limits(), &r).unwrap();
        assert_eq!(report.findings().len(), 2);
        for copy in 0..2 {
            assert!(
                report
                    .findings()
                    .contains(&FatAuditFinding::InvalidReservedEntry {
                        copy,
                        entry: entry as u8,
                        value,
                        mask,
                        expected
                    })
            );
        }
        assert!(!report.findings().iter().any(|f| matches!(
            f,
            FatAuditFinding::Unclean { .. } | FatAuditFinding::MirrorDisagreement { .. }
        )));
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    let mut b = fixture();
    fat(&mut b, 1, 0x3fff);
    let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
    assert_eq!(report.findings().len(), 2);
    assert!(report.findings().iter().all(|f| matches!(
        f,
        FatAuditFinding::Unclean {
            clean: false,
            no_error: false,
            ..
        }
    )));
    for marker in 0xff8u16..=0xfff {
        let mut b = vec![0; 100 * 512];
        w(&mut b, 11, 512);
        b[13] = 1;
        w(&mut b, 14, 1);
        b[16] = 1;
        w(&mut b, 17, 16);
        w(&mut b, 19, 100);
        b[21] = 0xf8;
        w(&mut b, 22, 1);
        w(&mut b, 510, 0xaa55);
        b[512] = 0xf8;
        b[513] = 0xf | ((marker as u8 & 0xf) << 4);
        b[514] = (marker >> 4) as u8;
        let report = audit_fat(Arc::new(Image(b)), limits(), &resources()).unwrap();
        assert!(
            report.findings().is_empty(),
            "valid FAT12 reserved EOC {marker:x}"
        );
    }
}
