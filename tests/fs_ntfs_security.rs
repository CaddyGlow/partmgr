use partmgr::{fs_core::*, fs_ntfs_security::*};
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> NtfsSecurityLimits {
    NtfsSecurityLimits {
        bytes: 4096,
        aces: 32,
        work: 256,
    }
}
fn word(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes())
}
fn dword(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes())
}
fn sid() -> Vec<u8> {
    vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
}
fn descriptor() -> Vec<u8> {
    let mut b = vec![0; 20];
    b[0] = 1;
    b[1] = 0xa9;
    word(&mut b, 2, 0xd414);
    dword(&mut b, 4, 20);
    dword(&mut b, 8, 20);
    b.extend(sid());
    dword(&mut b, 12, 36);
    b.extend([2, 0, 8, 0, 0, 0, 0, 0]);
    dword(&mut b, 16, 44);
    let mut acl = vec![2, 0, 0, 0, 3, 0, 0, 0];
    let mut ace = vec![1, 0x13, 24, 0, 0x89, 0, 2, 0];
    ace.extend(sid());
    acl.extend(ace);
    acl.extend([0xee, 0xff, 8, 0, 1, 2, 3, 4]);
    let mut callback = vec![9, 0x10, 28, 0, 7, 0, 0, 0];
    callback.extend(sid());
    callback.extend([4, 3, 2, 1]);
    acl.extend(callback);
    let n = acl.len() as u16;
    word(&mut acl, 2, n);
    b.extend(acl);
    b
}
#[test]
fn preserves_owner_group_null_empty_controls_order_unknown_and_callback() {
    let r = resources();
    let raw = descriptor();
    let d = NtfsSecurityDescriptor::parse(&raw, limits(), &r).unwrap();
    assert_eq!(d.raw(), raw);
    assert_eq!(d.control(), 0xd414);
    assert_eq!(d.resource_manager_control(), 0xa9);
    let s = d.owner().unwrap();
    assert_eq!(s.raw(), sid());
    assert_eq!(s.revision(), 1);
    assert_eq!(s.authority(), 5);
    assert_eq!(s.subauthorities().collect::<Vec<_>>(), vec![32, 544]);
    assert_eq!(d.group().unwrap().raw(), s.raw());
    let NtfsAclPresence::Present(a) = d.dacl() else {
        panic!()
    };
    assert_eq!(a.revision(), 2);
    assert_eq!(a.raw().len(), 68);
    let aces: Vec<_> = a.aces().collect();
    assert_eq!(
        aces.iter().map(|a| a.kind()).collect::<Vec<_>>(),
        [1, 0xee, 9]
    );
    assert_eq!(aces[0].flags(), 0x13);
    assert_eq!(aces[0].mask(), Some(0x20089));
    assert_eq!(aces[0].trustee().unwrap().raw(), sid());
    assert_eq!(aces[1].mask(), None);
    assert_eq!(aces[1].opaque_payload(), [1, 2, 3, 4]);
    assert_eq!(aces[2].opaque_payload(), [4, 3, 2, 1]);
    assert_eq!(aces[0].raw().len(), 24);
    assert!(aces[0].object_type().is_none());
    assert!(aces[0].inherited_object_type().is_none());
    let NtfsAclPresence::Present(a) = d.sacl() else {
        panic!()
    };
    assert_eq!(a.ace_count(), 0);
    drop(d);
    assert_eq!(r.memory.used(), 0);
    let mut raw = vec![0; 20];
    raw[0] = 1;
    word(&mut raw, 2, 0x8004);
    let d = NtfsSecurityDescriptor::parse(&raw, limits(), &r).unwrap();
    assert!(matches!(d.dacl(), NtfsAclPresence::Null));
    assert!(matches!(d.sacl(), NtfsAclPresence::Absent));
    drop(d);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_offsets_aces_sids_caps_and_cancellation_refund() {
    let r = resources();
    let base = descriptor();
    for mode in 0..8 {
        let mut b = base.clone();
        match mode {
            0 => dword(&mut b, 4, u32::MAX),
            1 => b[21] = 16,
            2 => word(&mut b, 50, 0xffff),
            3 => word(&mut b, 54, 0),
            4 => word(&mut b, 2, 4),
            5 => dword(&mut b, 16, 21),
            6 => b[44] = 3,
            _ => word(&mut b, 48, 0xffff),
        }
        assert!(
            NtfsSecurityDescriptor::parse(&b, limits(), &r).is_err(),
            "{mode}"
        );
        assert_eq!(r.memory.used(), 0);
    }
    for l in [
        NtfsSecurityLimits {
            bytes: 1,
            ..limits()
        },
        NtfsSecurityLimits {
            aces: 2,
            ..limits()
        },
        NtfsSecurityLimits {
            work: 1,
            ..limits()
        },
    ] {
        assert!(NtfsSecurityDescriptor::parse(&base, l, &r).is_err());
        assert_eq!(r.memory.used(), 0)
    }
    r.cancellation.cancel();
    assert!(NtfsSecurityDescriptor::parse(&base, limits(), &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn object_callback_guids_and_ignored_acl_offsets_remain_exact() {
    let r = resources();
    let mut raw = vec![0; 20];
    raw[0] = 1;
    word(&mut raw, 2, 0x8004);
    dword(&mut raw, 12, u32::MAX);
    dword(&mut raw, 16, 20);
    let mut acl = vec![4, 0, 72, 0, 1, 0, 0, 0];
    let mut ace = vec![11, 0x1f, 64, 0, 0x77, 0, 0, 0, 3, 0, 0, 0];
    ace.extend([0x12; 16]);
    ace.extend([0x34; 16]);
    ace.extend(sid());
    ace.extend([0xde, 0xad, 0xbe, 0xef]);
    acl.extend(ace);
    raw.extend(acl);
    let d = NtfsSecurityDescriptor::parse(&raw, limits(), &r).unwrap();
    assert_eq!(d.raw(), raw);
    assert!(matches!(d.sacl(), NtfsAclPresence::Absent));
    let NtfsAclPresence::Present(a) = d.dacl() else {
        panic!()
    };
    let ace = a.aces().next().unwrap();
    assert_eq!(ace.object_flags(), Some(3));
    assert_eq!(ace.object_type().unwrap(), [0x12; 16]);
    assert_eq!(ace.inherited_object_type().unwrap(), [0x34; 16]);
    assert_eq!(ace.opaque_payload(), [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(ace.trustee().unwrap().authority(), 5);
    drop(d);
    assert_eq!(r.memory.used(), 0);
    for end in 0..raw.len() {
        assert!(NtfsSecurityDescriptor::parse(&raw[..end], limits(), &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    let mut malformed = raw;
    dword(&mut malformed, 36, 4);
    assert!(NtfsSecurityDescriptor::parse(&malformed, limits(), &r).is_err());
}
