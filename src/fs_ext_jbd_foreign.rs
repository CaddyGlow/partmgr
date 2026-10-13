//! Foreign native redo preflight and private checksumless recovery.
use super::*;
#[cfg(all(test, feature = "std", unix))]
#[path = "fs_ext_jbd_foreign_native.rs"]
mod native;
#[path = "fs_ext_jbd_foreign_recover.rs"]
mod recover;
#[cfg(all(test, feature = "std"))]
#[path = "fs_ext_jbd_foreign_recover_tests.rs"]
mod recover_tests;
use crate::{
    fs_ext_audit::{ExtAuditLimits, ExtAuditReport},
    storage::Storage,
};

/// Independent phase ceilings; memory reservations share the caller's budget.
pub(crate) struct Limits {
    pub(crate) journal_blocks: usize,
    pub(crate) bootstrap_work: usize,
    pub(crate) records: usize,
    pub(crate) scan_work: usize,
    pub(crate) audit: ExtAuditLimits,
}

/// Source-borrowed proof of a complete final-redo audit, never write authority.
/// The caller must enforce the Storage exclusive-access contract throughout.
pub(crate) struct Plan<'a> {
    source: &'a dyn Storage,
    length: u64,
    pub(crate) bootstrap: bootstrap::Bootstrap,
    pub(crate) replay: ReplayPlan,
    pub(crate) audit: ExtAuditReport,
    pub(crate) geometry: super::super::ExtGeometry,
    /// Fresh restart ID, skipping the first unconsumed scan transaction ID.
    pub(crate) restart_sequence: u32,
    /// Only the audit overlay sees this inactive native journal header.
    pub(crate) empty_journal: [u8; 1024],
}
impl Plan<'_> {
    /// Recheck native source controls without modifying the underlying source.
    pub(crate) fn check_source(&self, r: &Resources) -> io::Result<()> {
        r.cancellation.check().map_err(io::Error::other)?;
        if self.source.len()? != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "foreign JBD2 source length changed",
            )));
        }
        let mut primary = [0; 1024];
        let mut journal = [0; 1024];
        self.source.read_exact_at(1024, &mut primary)?;
        self.source
            .read_exact_at(self.bootstrap.physical(0)?, &mut journal)?;
        if primary != self.bootstrap.primary || journal != self.bootstrap.journal {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "foreign JBD2 source controls changed",
            )));
        }
        if self.source.len()? != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "foreign JBD2 source length changed",
            )));
        }
        r.cancellation.check().map_err(io::Error::other)
    }
}

fn active_header(boot: &bootstrap::Bootstrap) -> io::Result<[u8; 1024]> {
    let geometry = boot.geometry;
    geometry.check()?;
    if geometry.start == 0 {
        return Err(invalid(
            "foreign JBD2 preflight requires active native journal",
        ));
    }
    // Bootstrap intentionally tolerates torn publication controls for the owned
    // preparation protocol. Foreign logs have no such repair authority: validate
    // the ORIGINAL dynamic header checksum before normalizing audit-only bytes.
    if !matches!(geometry.checksums, Checksums::None) {
        let mut checked = boot.journal;
        let expected = be32(&checked, 252);
        put32(&mut checked, 252, 0);
        if crc32c(!0, &checked) != expected {
            return Err(invalid("foreign JBD2 active header checksum"));
        }
    }
    let mut empty = boot.journal;
    put32(&mut empty, 28, 0);
    journal_checksum(&geometry, &mut empty);
    original_journal(&geometry, &empty)?;
    Ok(empty)
}

pub(crate) fn preflight<'a>(
    source: &'a dyn Storage,
    scope: u128,
    limits: Limits,
    r: &Resources,
) -> io::Result<Plan<'a>> {
    r.cancellation.check().map_err(io::Error::other)?;
    let length = source.len()?;
    let boot = bootstrap::Bootstrap::read(source, limits.journal_blocks, limits.bootstrap_work, r)?;
    if super::super::u32le(&boot.primary, 96) & 4 == 0 {
        return Err(invalid(
            "foreign JBD2 preflight requires filesystem recovery flag",
        ));
    }
    let mut empty = active_header(&boot)?;
    let replay = scan(
        &boot.geometry,
        limits.records,
        limits.scan_work,
        r,
        |logical, bytes| source.read_exact_at(boot.physical(logical)?, bytes),
        |destination| boot.destination(destination),
    )?;
    // Native recovery skips the first unconsumed transaction ID so old commit
    // records cannot become a new transaction after restarting the log.
    let restart_sequence = replay.next_sequence.wrapping_add(1);
    // Never replace native start/sequence with guesses from an arbitrary slot.
    let (geometry, audit) = overlay::Overlay::new(
        source,
        &replay.blocks,
        boot.geometry.block_bytes,
        Some(overlay::JournalControl {
            physical: boot.physical(0)?,
            original: empty,
            geometry: boot.geometry,
            next_sequence: restart_sequence,
        }),
        r,
    )?
    .verify(scope, limits.audit, Some(&boot))?;
    put32(&mut empty, 24, restart_sequence);
    journal_checksum(&boot.geometry, &mut empty);
    let plan = Plan {
        source,
        length,
        bootstrap: boot,
        replay,
        audit,
        geometry,
        restart_sequence,
        empty_journal: empty,
    };
    plan.check_source(r)?;
    Ok(plan)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> Limits {
        Limits {
            journal_blocks: 1024,
            bootstrap_work: 100000,
            records: 8,
            scan_work: 100000,
            audit: ExtAuditLimits {
                blocks: 2048,
                inodes: 128,
                work: 100000,
                directory_blocks: 8,
                directory_entries: 32,
                findings: 8,
            },
        }
    }
    // Independently assemble footer-free legacy native descriptor/data/commit.
    // Storage write/flush methods panic, proving the entire preflight is read-only.
    fn fixture(destination: u32) -> bootstrap::tests::Owned {
        let mut image = bootstrap::tests::fixture();
        let sb = &mut image.0[1024..2048];
        sb[96..100].copy_from_slice(&6u32.to_le_bytes());
        let mut payload = [0; 1024];
        if destination == 1 {
            payload.copy_from_slice(sb);
            payload[48..52].copy_from_slice(&123456789u32.to_le_bytes());
        }
        let journal = &mut image.0[100 * 1024..101 * 1024];
        put32(journal, 40, 1); // Revoke feature, no checksums or private footer.
        journal[80] = 0;
        put32(journal, 252, 0);
        put32(journal, 28, 1);
        let descriptor = &mut image.0[101 * 1024..102 * 1024];
        header(descriptor, 1, 37);
        put32(descriptor, 12, destination);
        put32(descriptor, 16, 8); // LAST_TAG, first tag includes UUID.
        descriptor[20..36].fill(0x39);
        image.0[102 * 1024..103 * 1024].copy_from_slice(&payload);
        header(&mut image.0[103 * 1024..104 * 1024], 2, 37);
        image
    }
    #[test]
    fn footer_free_native_replay_overlay_audits_without_writes_or_preparation() {
        let r = resources();
        let image = fixture(1);
        let before = image.0.clone();
        let plan = preflight(&image, 18u128 << 64, limits(), &r).unwrap();
        assert_eq!(plan.replay.committed_transactions, 1);
        assert_eq!(plan.replay.next_sequence, 38);
        assert_eq!(plan.replay.blocks.len(), 1);
        assert!(!plan.replay.discarded_tail);
        assert!(plan.audit.is_clean());
        assert_eq!(plan.geometry.block_size, 1024);
        assert_eq!(be32(&plan.empty_journal, 28), 0);
        assert_eq!(plan.restart_sequence, 39);
        assert_eq!(be32(&plan.empty_journal, 24), 39);
        assert_eq!(be32(&plan.bootstrap.journal, 28), 1);
        plan.check_source(&r).unwrap();
        assert_eq!(image.0, before);
        drop(plan);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn foreign_header_requires_real_crc_and_valid_dynamic_geometry() {
        let r = resources();
        let image = bootstrap::tests::fixture();
        let mut boot = bootstrap::Bootstrap::read(&image, 1024, 100000, &r).unwrap();
        boot.geometry.start = 1;
        put32(&mut boot.journal, 28, 1);
        assert!(active_header(&boot).is_err()); // CRC from inactive header is stale.
        journal_checksum(&boot.geometry, &mut boot.journal);
        assert!(active_header(&boot).is_ok());
        boot.geometry.start = boot.geometry.maximum;
        assert!(active_header(&boot).is_err());
        drop(boot);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn native_restart_skips_unconsumed_ids_across_sequence_rollover() {
        for sequence in [u32::MAX - 1, u32::MAX] {
            let mut image = fixture(1);
            for block in [100, 101, 103] {
                let offset = if block == 100 { 24 } else { 8 };
                put32(
                    &mut image.0[block * 1024..(block + 1) * 1024],
                    offset,
                    sequence,
                );
            }
            let r = resources();
            let plan = preflight(&image, 18u128 << 64, limits(), &r).unwrap();
            assert_eq!(plan.replay.next_sequence, sequence.wrapping_add(1));
            assert_eq!(plan.restart_sequence, sequence.wrapping_add(2));
            assert_eq!(be32(&plan.empty_journal, 24), plan.restart_sequence);
            drop(plan);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn active_log_without_commits_still_skips_its_unconsumed_transaction_id() {
        let mut image = fixture(1);
        image.0[101 * 1024..102 * 1024].fill(0);
        let r = resources();
        let plan = preflight(&image, 18u128 << 64, limits(), &r).unwrap();
        assert_eq!(plan.replay.committed_transactions, 0);
        assert!(plan.replay.blocks.is_empty());
        assert_eq!(plan.replay.next_sequence, 37);
        assert_eq!(plan.restart_sequence, 38);
        drop(plan);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn final_control_read_cannot_hide_a_source_length_change() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        struct Changing {
            image: bootstrap::tests::Owned,
            length: AtomicU64,
            armed: AtomicBool,
        }
        impl Storage for Changing {
            fn len(&self) -> io::Result<u64> {
                Ok(self.length.load(Ordering::SeqCst))
            }
            fn read_exact_at(&self, at: u64, bytes: &mut [u8]) -> io::Result<()> {
                self.image.read_exact_at(at, bytes)?;
                if at == 100 * 1024 && self.armed.load(Ordering::SeqCst) {
                    self.length.fetch_sub(1, Ordering::SeqCst);
                }
                Ok(())
            }
            fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
                panic!("foreign preflight attempted a write")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("foreign preflight attempted a flush")
            }
        }
        let image = fixture(1);
        let source = Changing {
            length: AtomicU64::new(image.0.len() as u64),
            image,
            armed: AtomicBool::new(false),
        };
        let r = resources();
        let plan = preflight(&source, 18u128 << 64, limits(), &r).unwrap();
        source.armed.store(true, Ordering::SeqCst);
        let error = plan.check_source(&r).unwrap_err();
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
                .kind,
            ErrorKind::StalePlan
        );
        drop(plan);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn foreign_alias_ownership_cancel_and_phase_ceilings_reject_without_leaks() {
        for destination in [100, 3] {
            let r = resources();
            let image = fixture(destination);
            assert!(preflight(&image, 18u128 << 64, limits(), &r).is_err());
            assert_eq!(r.memory.used(), 0);
        }
        let r = resources();
        let image = fixture(1);
        for phase in 0..4 {
            let mut cap = limits();
            match phase {
                0 => cap.journal_blocks = 1,
                1 => cap.bootstrap_work = 1,
                2 => cap.scan_work = 1,
                _ => cap.audit.work = 1,
            }
            assert!(preflight(&image, 18u128 << 64, cap, &r).is_err());
            assert_eq!(r.memory.used(), 0);
        }
        let tiny = Resources {
            memory: Budget::new(1),
            cancellation: Cancellation::default(),
        };
        assert!(preflight(&image, 18u128 << 64, limits(), &tiny).is_err());
        assert_eq!(tiny.memory.used(), 0);
        r.cancellation.cancel();
        assert!(preflight(&image, 18u128 << 64, limits(), &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
}
