use partmgr::fs_core::*;

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
    assert_eq!(payload.bytes, b"test");
    assert_eq!(resources.memory.used(), 4);
    drop(payload);
    file.broken = true;
    assert_eq!(
        read_all(&file, 4, &resources).unwrap_err().kind,
        ErrorKind::InvalidData
    );
    assert_eq!(resources.memory.used(), 0);
}
