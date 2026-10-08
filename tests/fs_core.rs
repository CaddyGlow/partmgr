use partmgr::fs_core::*;

#[test]
fn retained_transform_reserves_before_work_and_refunds_all_paths() {
    let budget = Budget::new(16);
    let make = || Budgeted::try_new(&budget, 8, || Ok(vec![7u8; 8])).unwrap();
    let value = make()
        .try_map(8, |bytes| {
            assert_eq!(budget.used(), 16);
            Ok((bytes, 42))
        })
        .unwrap();
    assert_eq!(value.get().0, [7; 8]);
    assert_eq!(value.reserved_bytes(), 16);
    drop(value);
    assert_eq!(budget.used(), 0);
    let failed = make().try_map(8, |_| -> Result<()> {
        assert_eq!(budget.used(), 16);
        Err(Error::new(
            ErrorKind::InvalidData,
            "rejected transformation",
        ))
    });
    assert_eq!(failed.unwrap_err().kind, ErrorKind::InvalidData);
    assert_eq!(budget.used(), 0);
    for extra in [9, u64::MAX] {
        let failed = make().try_map(extra, |_| -> Result<()> {
            panic!("closure must not run before sufficient reservation")
        });
        assert_eq!(failed.unwrap_err().kind, ErrorKind::BudgetExhausted);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn native_names_do_not_normalize_or_replace_invalid_sequences() {
    let bytes = NativeName::Bytes(vec![0xff, b'a']);
    let utf16 = NativeName::Utf16(vec![0xd800, 0x0061]);
    assert_eq!(bytes.clone(), NativeName::Bytes(vec![0xff, b'a']));
    assert_eq!(utf16.clone(), NativeName::Utf16(vec![0xd800, 0x0061]));
    assert_eq!(bytes.display_lossy(), "\u{fffd}a");
    assert_eq!(utf16.display_lossy(), "\u{fffd}a");
    assert_ne!(bytes, utf16);
}

#[test]
fn cloned_budget_and_cancellation_share_state() {
    let budget = Budget::new(12);
    let clone = budget.clone();
    let held = budget.reserve(10).unwrap();
    assert_eq!(clone.used(), 10);
    assert_eq!(
        clone.reserve(3).unwrap_err().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(
        clone.reserve(u64::MAX).unwrap_err().kind,
        ErrorKind::BudgetExhausted
    );
    drop(held);
    assert_eq!(clone.used(), 0);
    let cancellation = Cancellation::default();
    let other = cancellation.clone();
    cancellation.cancel();
    assert_eq!(other.check().unwrap_err().kind, ErrorKind::Cancelled);
}

#[test]
fn omitted_capabilities_are_explicitly_unsupported() {
    let profile = CapabilityProfile {
        family: Family::Fat32,
        profile: "contract example".into(),
        operations: vec![(Operation::Recognize, Availability::Supported)],
        durability: "no mutation".into(),
        validation_evidence: vec![],
    };
    assert_eq!(
        profile.availability(Operation::Recognize),
        Availability::Supported
    );
    assert!(matches!(
        profile.availability(Operation::Build),
        Availability::Unsupported { .. }
    ));
}

struct ShortFile {
    identity: ObjectId,
    broken: bool,
}
impl FileRead for ShortFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        4
    }
    fn read_at(&self, offset: u64, buffer: &mut [u8], resources: &Resources) -> Result<usize> {
        resources.cancellation.check()?;
        if self.broken || offset >= 4 || buffer.is_empty() {
            return Ok(0);
        }
        buffer[0] = b"test"[offset as usize];
        Ok(1)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        visitor(LogicalExtent {
            offset: 0,
            length: 4,
            kind: ExtentKind::Data,
        })
    }
}
#[test]
fn whole_file_convenience_handles_short_reads_and_retains_memory_charge() {
    let resources = Resources {
        memory: Budget::new(4),
        cancellation: Cancellation::default(),
    };
    let mut file = ShortFile {
        identity: ObjectId {
            source: 7,
            generation: 0,
            native: vec![1],
        },
        broken: false,
    };
    assert_eq!(
        read_all(&file, 3, &resources).unwrap_err().kind,
        ErrorKind::BudgetExhausted
    );
    let payload = read_all(&file, 4, &resources).unwrap();
    assert_eq!(payload.get().as_slice(), b"test");
    assert_eq!(resources.memory.used(), 4);
    drop(payload);
    file.broken = true;
    assert_eq!(
        read_all(&file, 4, &resources).unwrap_err().kind,
        ErrorKind::InvalidData
    );
    assert_eq!(resources.memory.used(), 0);
}

#[test]
fn budgeted_results_reserve_before_construction_and_refund_on_failure_or_drop() {
    let budget = Budget::new(8);
    let calls = std::cell::Cell::new(0);
    let result = Budgeted::try_new(&budget, 9, || {
        calls.set(calls.get() + 1);
        Ok(vec![1_u8])
    });
    assert_eq!(result.unwrap_err().kind, ErrorKind::BudgetExhausted);
    assert_eq!(calls.get(), 0);
    let result = Budgeted::<Vec<u8>>::try_new(&budget, 8, || {
        assert_eq!(budget.used(), 8);
        Err(Error::new(ErrorKind::InvalidData, "malformed metadata"))
    });
    assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidData);
    assert_eq!(budget.used(), 0);
    let retained = Budgeted::try_new(&budget, 8, || {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(8)
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "metadata allocation failed"))?;
        bytes.extend_from_slice(b"metadata");
        Ok(bytes)
    })
    .unwrap();
    assert_eq!(retained.get(), b"metadata");
    assert_eq!(retained.reserved_bytes(), 8);
    assert_eq!(
        budget.reserve(1).unwrap_err().kind,
        ErrorKind::BudgetExhausted
    );
    drop(retained);
    assert_eq!(budget.used(), 0);
}

struct ChangingFile {
    identities: [ObjectId; 2],
    read: std::sync::atomic::AtomicBool,
    change_identity: bool,
    change_length: bool,
}
impl FileRead for ChangingFile {
    fn identity(&self) -> &ObjectId {
        let changed = self.read.load(std::sync::atomic::Ordering::Acquire);
        &self.identities[usize::from(changed && self.change_identity)]
    }
    fn len(&self) -> u64 {
        let changed = self.read.load(std::sync::atomic::Ordering::Acquire);
        if changed && self.change_length { 5 } else { 4 }
    }
    fn read_at(&self, _: u64, buffer: &mut [u8], _: &Resources) -> Result<usize> {
        buffer.copy_from_slice(b"test");
        self.read.store(true, std::sync::atomic::Ordering::Release);
        Ok(4)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
}

#[test]
fn whole_file_rejects_identity_or_length_changes_and_refunds_memory() {
    for (change_identity, change_length) in [(true, false), (false, true), (true, true)] {
        let file = ChangingFile {
            identities: [
                ObjectId {
                    source: 7,
                    generation: 0,
                    native: vec![1],
                },
                ObjectId {
                    source: 7,
                    generation: 1,
                    native: vec![1],
                },
            ],
            read: std::sync::atomic::AtomicBool::new(false),
            change_identity,
            change_length,
        };
        let resources = Resources {
            memory: Budget::new(4),
            cancellation: Cancellation::default(),
        };
        assert_eq!(
            read_all(&file, 4, &resources).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        assert_eq!(resources.memory.used(), 0);
    }
}

#[test]
fn io_wrapping_retains_nested_framework_category_and_original_cause() {
    for kind in [
        ErrorKind::BudgetExhausted,
        ErrorKind::Cancelled,
        ErrorKind::StalePlan,
        ErrorKind::Unsupported,
    ] {
        let outer = Error::io(
            "decoder boundary",
            std::io::Error::other(Error::new(kind, "original framework cause")),
        );
        assert_eq!(outer.kind, kind);
        assert_eq!(outer.context, "decoder boundary");
        assert_eq!(
            outer
                .source
                .unwrap()
                .get_ref()
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
                .context,
            "original framework cause"
        );
    }
    let outer = Error::io("backend", std::io::Error::other("original backend cause"));
    assert_eq!(outer.kind, ErrorKind::Io);
    assert_eq!(outer.source.unwrap().to_string(), "original backend cause");
}
