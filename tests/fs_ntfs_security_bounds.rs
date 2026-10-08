use partmgr::{fs_core::*, fs_ntfs_security::*};

// Self-relative descriptor with shared owner/group SID and one allow ACE.
// Exhaustive byte substitutions exercise both rejection and accepted views.
#[test]
fn adversarial_descriptor_views_remain_bounded_and_refund() {
    let mut seed = vec![0u8; 60];
    seed[0] = 1;
    seed[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    seed[4..8].copy_from_slice(&20u32.to_le_bytes());
    seed[8..12].copy_from_slice(&20u32.to_le_bytes());
    seed[16..20].copy_from_slice(&32u32.to_le_bytes());
    seed[20..32].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    seed[32..40].copy_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]);
    seed[40..48].copy_from_slice(&[0, 0, 20, 0, 1, 0, 0, 0]);
    seed[48..60].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    let r = Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    };
    let limits = NtfsSecurityLimits {
        bytes: 128,
        aces: 8,
        work: 128,
    };
    drop(NtfsSecurityDescriptor::parse(&seed, limits, &r).unwrap());
    for at in 0..seed.len() {
        for replacement in 0..=255 {
            let mut bytes = seed.clone();
            bytes[at] = replacement;
            if let Ok(d) = NtfsSecurityDescriptor::parse(&bytes, limits, &r) {
                assert_eq!(d.raw(), bytes);
                for sid in [d.owner(), d.group()].into_iter().flatten() {
                    let _ = (sid.raw(), sid.authority(), sid.subauthorities().count());
                }
                for acl in [d.dacl(), d.sacl()] {
                    if let NtfsAclPresence::Present(acl) = acl {
                        assert!(acl.ace_count() <= limits.aces);
                        for ace in acl.aces() {
                            let _ = (
                                ace.raw(),
                                ace.mask(),
                                ace.object_flags(),
                                ace.object_type(),
                                ace.inherited_object_type(),
                                ace.opaque_payload(),
                            );
                            if let Some(sid) = ace.trustee() {
                                let _ = (sid.raw(), sid.authority(), sid.subauthorities().count());
                            }
                        }
                    }
                }
            }
            assert_eq!(r.memory.used(), 0, "byte {at}, replacement {replacement}");
        }
    }
}
