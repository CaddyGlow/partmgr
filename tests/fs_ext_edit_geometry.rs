#![cfg(feature = "std")]

#[path = "fixtures/ext2_clean.rs"]
mod independent;
use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditState, ExtEditor},
    fs_undo::UndoLimits,
    storage::Storage,
};
const BASE: usize = 4096;
struct Memory {
    bytes: Vec<u8>,
    writes: usize,
    arm: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    fail_length: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    cancel_commit: Option<Cancellation>,
}
impl Memory {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            writes: 0,
            arm: None,
            fail_length: None,
            cancel_commit: None,
        }
    }
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        if self
            .fail_length
            .as_ref()
            .is_some_and(|armed| armed.replace(false))
        {
            return Err(io::Error::other("late committed geometry length fault"));
        }
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.bytes.get(512..520) == Some(b"PMFSUNDO".as_slice())
            && self.bytes.get(524) == Some(&2)
        {
            if let Some(arm) = &self.arm {
                arm.set(true);
            }
            if let Some(token) = &self.cancel_commit {
                token.cancel();
            }
        }
        Ok(())
    }
}
fn container() -> Vec<u8> {
    let mut image = independent::fixture();
    image[1028..1032].copy_from_slice(&48u32.to_le_bytes());
    image[1036..1040].copy_from_slice(&39u32.to_le_bytes());
    image[2060..2062].copy_from_slice(&39u16.to_le_bytes());
    for bit in 47..8192 {
        image[3072 + bit / 8] |= 1 << (bit % 8);
    }
    let mut b = vec![0xa5; BASE + 66 * 1024 + BASE];
    b[BASE..BASE + image.len()].copy_from_slice(&image);
    b[BASE + image.len()..BASE + 66 * 1024].fill(0x63);
    b[BASE + 66 * 1024..].fill(0x5a);
    b
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    }
}
fn l() -> ExtEditLimits {
    ExtEditLimits {
        audit: ExtAuditLimits {
            blocks: 128,
            inodes: 16,
            work: 65536,
            directory_blocks: 4,
            directory_entries: 32,
            findings: 32,
        },
        file_blocks: 32,
        directory_entries: 32,
        affected_bytes: 8192,
        work: 1_000_000,
        undo: UndoLimits {
            patches: 64,
            body_bytes: 32768,
        },
    }
}
fn binding() -> ExtEditBinding {
    ExtEditBinding {
        volume: [3; 32],
        generation: 7,
    }
}
fn region() -> ExtEditRegion {
    ExtEditRegion {
        offset: BASE as u64,
        length: 66 * 1024,
    }
}
fn open(bytes: Vec<u8>, r: &Resources) -> partmgr::fs_core::Result<ExtEditor<Memory, Memory>> {
    ExtEditor::open(
        Memory::new(bytes),
        Memory::new(vec![0; 65536]),
        region(),
        binding(),
        l(),
        r,
    )
}
#[test]
fn grows_actual_geometry_and_invalidates_old_handles_without_changing_payload_or_container() {
    let r = resources();
    let original = container();
    let mut editor = open(original.clone(), &r).unwrap();
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let (batch, report) = editor.plan_grow_filesystem(60, &r).unwrap();
    assert_eq!(
        (
            report.old_blocks,
            report.new_blocks,
            report.added_free_blocks
        ),
        (48, 60, 12)
    );
    assert_eq!(report.groups, 1);
    assert!(batch.resize_report().is_none());
    assert_eq!(batch.stage_lengths(), &[1, 1, 2, 1]);
    editor.commit(batch, [0x91; 16], &r).unwrap();
    assert_eq!(editor.geometry().blocks(), 60);
    assert!(editor.audit().unwrap().is_clean());
    assert_eq!(
        editor.read_at(&file, 0, &mut [0; 1], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    drop(file);
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let mut payload = [0; 1024];
    assert_eq!(editor.read_at(&file, 0, &mut payload, &r).unwrap(), 1024);
    assert_eq!(payload, [73; 1024]);
    drop(file);
    let (storage, journal, state) = editor.into_stores();
    assert_eq!(state, ExtEditState::Ready);
    assert_eq!(storage.bytes.len(), original.len());
    assert_eq!(&storage.bytes[..BASE], &original[..BASE]);
    assert_eq!(
        &storage.bytes[BASE + 60 * 1024..],
        &original[BASE + 60 * 1024..]
    );
    assert_eq!(
        u32::from_le_bytes(storage.bytes[BASE + 1036..BASE + 1040].try_into().unwrap()),
        51
    );
    for bit in 47..59 {
        assert_eq!(storage.bytes[BASE + 3072 + bit / 8] & (1 << (bit % 8)), 0);
    }
    for bit in 59..8192 {
        assert_ne!(storage.bytes[BASE + 3072 + bit / 8] & (1 << (bit % 8)), 0);
    }
    drop(storage);
    drop(journal);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn same_last_group_boundary_is_allowed_and_shrink_new_group_and_region_overrun_reject() {
    let r = resources();
    let mut editor = open(container(), &r).unwrap();
    for blocks in [47, 48, 66, u32::MAX] {
        assert!(editor.plan_grow_filesystem(blocks, &r).is_err());
    }
    let (batch, report) = editor.plan_grow_filesystem(65, &r).unwrap();
    assert_eq!(report.added_free_blocks, 17);
    editor.commit(batch, [0x92; 16], &r).unwrap();
    assert_eq!(editor.geometry().blocks(), 65);
    assert!(editor.plan_grow_filesystem(66, &r).is_err());
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn stale_growth_batch_is_rejected_after_another_growth_without_writes() {
    let r = resources();
    let mut editor = open(container(), &r).unwrap();
    let (stale, _) = editor.plan_grow_filesystem(55, &r).unwrap();
    let (fresh, _) = editor.plan_grow_filesystem(60, &r).unwrap();
    editor.commit(fresh, [0x93; 16], &r).unwrap();
    let error = editor.commit(stale, [0x94; 16], &r).unwrap_err();
    assert!(!error.target_may_have_changed);
    assert_eq!(error.source.kind, ErrorKind::StalePlan);
    assert_eq!(editor.geometry().blocks(), 60);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
// Raw independently authored four-group fixture. No builder or growth encoder.
fn multigroup(bs: usize, sparse: bool) -> (Vec<u8>, u32, u32, Vec<usize>) {
    let first = usize::from(bs == 1024);
    let old = first + 3 * 64 + 48;
    let new = first + 3 * 64 + 60;
    let mut image = vec![0u8; (first + 4 * 64) * bs];
    let mut descriptors = vec![0u8; bs];
    let table_blocks = 2048usize.div_ceil(bs);
    let mut free_total = 0;
    let mut backups = Vec::new();
    let mut root_block = 0;
    let mut file_block = 0;
    let mut table0 = 0;
    for group in 0..4 {
        let start = first + group * 64;
        let backup = !sparse || matches!(group, 0 | 1 | 3);
        if group != 0 && backup {
            backups.push(group);
        }
        let bitmap = start + if backup { 2 } else { 0 };
        let ibitmap = bitmap + 1;
        let table = bitmap + 2;
        let metadata = if backup { 2 } else { 0 } + 2 + table_blocks;
        let allocated = metadata + if group == 0 { 2 } else { 0 };
        let available = if group == 3 { 48 } else { 64 };
        let free = available - allocated;
        free_total += free;
        let at = group * 32;
        put32(&mut descriptors, at, bitmap as u32);
        put32(&mut descriptors, at + 4, ibitmap as u32);
        put32(&mut descriptors, at + 8, table as u32);
        put16(&mut descriptors, at + 12, free as u16);
        put16(&mut descriptors, at + 14, if group == 0 { 5 } else { 16 });
        put16(&mut descriptors, at + 16, u16::from(group == 0));
        descriptors[at + 20] = 0xa0 + group as u8;
        image[bitmap * bs..(bitmap + 1) * bs].fill(255);
        for bit in allocated..available {
            image[bitmap * bs + bit / 8] &= !(1 << (bit % 8));
        }
        image[ibitmap * bs..(ibitmap + 1) * bs].fill(255);
        for bit in if group == 0 { 11 } else { 0 }..16 {
            image[ibitmap * bs + bit / 8] &= !(1 << (bit % 8));
        }
        if group == 0 {
            table0 = table;
            root_block = start + metadata;
            file_block = root_block + 1;
        }
    }
    let mut sb = [0u8; 1024];
    put32(&mut sb, 0, 64);
    put32(&mut sb, 4, old as u32);
    put32(&mut sb, 12, free_total as u32);
    put32(&mut sb, 16, 53);
    put32(&mut sb, 20, first as u32);
    put32(&mut sb, 24, (bs / 1024).trailing_zeros());
    put32(&mut sb, 28, (bs / 1024).trailing_zeros());
    put32(&mut sb, 32, 64);
    put32(&mut sb, 36, 64);
    put32(&mut sb, 40, 16);
    put16(&mut sb, 56, 0xef53);
    put16(&mut sb, 58, 1);
    put32(&mut sb, 76, 1);
    put32(&mut sb, 84, 11);
    put16(&mut sb, 88, 128);
    put32(&mut sb, 96, 2);
    put32(&mut sb, 100, u32::from(sparse));
    sb[104..120].fill(0x39);
    image[1024..2048].copy_from_slice(&sb);
    image[(first + 1) * bs..(first + 2) * bs].copy_from_slice(&descriptors);
    for &group in &backups {
        let at = (first + group * 64) * bs;
        let mut copy = sb;
        put16(&mut copy, 90, group as u16);
        put32(&mut copy, 12, free_total as u32 - 7);
        copy[200] = 0x6b;
        image[at..at + 1024].copy_from_slice(&copy);
        image[at + bs..at + 2 * bs].copy_from_slice(&descriptors);
    }
    let root = table0 * bs + 128;
    let file = table0 * bs + 10 * 128;
    for (at, mode, block) in [(root, 0x41ed, root_block), (file, 0x81a4, file_block)] {
        put16(&mut image, at, mode);
        put32(&mut image, at + 4, bs as u32);
        put16(&mut image, at + 26, 2);
        put32(&mut image, at + 28, (bs / 512) as u32);
        put32(&mut image, at + 40, block as u32);
    }
    for (off, ino, len, name, kind) in [
        (0, 2, 12, b".".as_slice(), 2),
        (12, 2, 12, b"..".as_slice(), 2),
        (24, 11, 16, b"x".as_slice(), 1),
        (40, 11, bs - 40, b"alias".as_slice(), 1),
    ] {
        let at = root_block * bs + off;
        put32(&mut image, at, ino);
        put16(&mut image, at + 4, len as u16);
        image[at + 6] = name.len() as u8;
        image[at + 7] = kind;
        image[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }
    image[file_block * bs..(file_block + 1) * bs].fill(73);
    let mut container = vec![0xa5; BASE + image.len() + BASE];
    container[BASE..BASE + image.len()].copy_from_slice(&image);
    (container, old as u32, new as u32, backups)
}
fn large_limits() -> ExtEditLimits {
    let mut cap = l();
    cap.audit.blocks = 512;
    cap.audit.inodes = 128;
    cap.audit.work = 1_000_000;
    cap.affected_bytes = 65536;
    cap.work = 1_000_000;
    cap.undo.body_bytes = 131072;
    cap.undo.patches = 128;
    cap
}
#[test]
fn multigroup_growth_updates_all_native_backups_and_preserves_opaque_bytes_all_block_sizes() {
    for bs in [1024usize, 2048, 4096] {
        for sparse in [false, true] {
            let r = resources();
            let (original, old, new, backups) = multigroup(bs, sparse);
            let length = original.len() - 2 * BASE;
            let mut editor = ExtEditor::open(
                Memory::new(original.clone()),
                Memory::new(vec![0; 262144]),
                ExtEditRegion {
                    offset: BASE as u64,
                    length: length as u64,
                },
                binding(),
                large_limits(),
                &r,
            )
            .unwrap();
            let (batch, report) = editor.plan_grow_filesystem(new, &r).unwrap();
            assert_eq!(report.old_blocks, old);
            assert_eq!(report.added_free_blocks, 12);
            assert_eq!(report.backup_groups, backups.len() as u32);
            editor.commit(batch, [0x71; 16], &r).unwrap();
            assert_eq!(editor.geometry().blocks(), new);
            assert!(editor.audit().unwrap().is_clean());
            let (target, journal, state) = editor.into_stores();
            assert_eq!(state, ExtEditState::Ready);
            let first = usize::from(bs == 1024);
            let total = get32(&original, BASE + 1036) + 12;
            assert_eq!(get32(&target.bytes, BASE + 1028), new);
            assert_eq!(get32(&target.bytes, BASE + 1036), total);
            for group in backups {
                let at = BASE + (first + group * 64) * bs;
                assert_eq!(get32(&target.bytes, at + 4), new);
                assert_eq!(get32(&target.bytes, at + 12), total);
                assert_eq!(get16(&target.bytes, at + 90), group as u16);
                assert_eq!(target.bytes[at + 200], 0x6b);
                let d = at + bs + 3 * 32;
                assert_eq!(get16(&target.bytes, d + 12), get16(&original, d + 12) + 12);
                assert_eq!(target.bytes[d + 20], original[d + 20]);
            }
            assert_eq!(&target.bytes[..BASE], &original[..BASE]);
            assert_eq!(
                &target.bytes[BASE + new as usize * bs..],
                &original[BASE + new as usize * bs..]
            );
            drop(target);
            drop(journal);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn growth_phase_limits_refuse_without_target_or_undo_writes() {
    for mode in 0..5 {
        let r = resources();
        let original = container();
        let mut cap = l();
        match mode {
            0 => cap.work = 1,
            1 => cap.affected_bytes = 1,
            2 => cap.undo.patches = 1,
            3 => cap.undo.body_bytes = 1,
            _ => cap.work = 80,
        };
        let editor = ExtEditor::open(
            Memory::new(original.clone()),
            Memory::new(vec![0; 65536]),
            region(),
            binding(),
            cap,
            &r,
        )
        .unwrap();
        assert!(editor.plan_grow_filesystem(60, &r).is_err());
        let (target, journal, _) = editor.into_stores();
        assert_eq!(target.writes, 0);
        assert_eq!(journal.writes, 0);
        assert_eq!(target.bytes, original);
        drop(target);
        drop(journal);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn committed_growth_refresh_failure_or_cancellation_requires_cold_recovery() {
    for cancel in [false, true] {
        let r = resources();
        let armed = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut target = Memory::new(container());
        if !cancel {
            target.fail_length = Some(armed.clone());
        }
        let mut journal = Memory::new(vec![0; 65536]);
        journal.arm = Some(armed);
        if cancel {
            journal.cancel_commit = Some(r.cancellation.clone());
        }
        let mut editor = ExtEditor::open(target, journal, region(), binding(), l(), &r).unwrap();
        let (batch, _) = editor.plan_grow_filesystem(60, &r).unwrap();
        let failure = editor.commit(batch, [0x76; 16], &r).unwrap_err();
        assert!(failure.target_may_have_changed);
        assert_eq!(editor.state(), ExtEditState::NeedsRecovery);
        assert_eq!(editor.geometry().blocks(), 48);
        let (target, mut journal, _) = editor.into_stores();
        journal.arm = None;
        journal.cancel_commit = None;
        let fresh = resources();
        let recovered = ExtEditor::recover_open(
            target,
            journal,
            region(),
            partmgr::fs_undo::UndoBinding {
                volume: binding().volume,
                generation: binding().generation,
                transaction: [0x76; 16],
            },
            l(),
            &fresh,
        )
        .unwrap();
        assert_eq!(recovered.geometry().blocks(), 60);
        assert_eq!(recovered.state(), ExtEditState::Ready);
        let file = recovered
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &fresh)
            .unwrap();
        assert_eq!(
            recovered.read_at(&file, 0, &mut [0; 1024], &fresh).unwrap(),
            1024
        );
        drop(file);
        drop(recovered);
        assert_eq!(fresh.memory.used(), 0);
        assert_eq!(r.memory.used(), 0);
    }
}
struct ZeroAppend(partmgr::fs_core::ObjectId);
impl partmgr::fs_core::FileRead for ZeroAppend {
    fn identity(&self) -> &partmgr::fs_core::ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        47 * 1024
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let n = (self.len().saturating_sub(at)).min(out.len() as u64) as usize;
        out[..n].fill(0);
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(partmgr::fs_core::LogicalExtent) -> partmgr::fs_core::Result<()>,
    ) -> partmgr::fs_core::Result<()> {
        Ok(())
    }
}
#[test]
fn admitted_tail_blocks_can_be_allocated_zeroed_and_written_through_owned_handles() {
    let r = resources();
    let mut cap = l();
    cap.file_blocks = 64;
    cap.affected_bytes = 131072;
    cap.undo.body_bytes = 262144;
    cap.undo.patches = 256;
    cap.audit.work = 1_000_000;
    cap.work = 20_000;
    let mut editor = ExtEditor::open(
        Memory::new(container()),
        Memory::new(vec![0; 524288]),
        region(),
        binding(),
        cap,
        &r,
    )
    .unwrap();
    let (batch, _) = editor.plan_grow_filesystem(60, &r).unwrap();
    editor.commit(batch, [0x81; 16], &r).unwrap();
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let input = ZeroAppend(partmgr::fs_core::ObjectId {
        source: 999,
        generation: 1,
        native: vec![1],
    });
    let batch = editor.plan_extend(&file, &input, &r).unwrap();
    drop(file);
    editor.commit(batch, [0x82; 16], &r).unwrap();
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert_eq!(file.len(), 48 * 1024);
    let mut bytes = [1; 1024];
    assert_eq!(
        editor.read_at(&file, 47 * 1024, &mut bytes, &r).unwrap(),
        1024
    );
    assert_eq!(bytes, [0; 1024]);
    let batch = editor
        .plan_replace(
            &[partmgr::fs_ext_edit::ExtReplacement {
                file: &file,
                offset: 47 * 1024,
                bytes: &[0x52; 1024],
            }],
            &r,
        )
        .unwrap();
    drop(file);
    editor.commit(batch, [0x83; 16], &r).unwrap();
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    editor.read_at(&file, 47 * 1024, &mut bytes, &r).unwrap();
    assert_eq!(bytes, [0x52; 1024]);
    drop(file);
    let (target, journal, state) = editor.into_stores();
    assert_eq!(state, ExtEditState::Ready);
    let inode = BASE + 5 * 1024 + 10 * 128;
    let indirect = get32(&target.bytes, inode + 40 + 12 * 4) as usize;
    let last = get32(&target.bytes, BASE + indirect * 1024 + 35 * 4) as usize;
    assert!((48..60).contains(&last));
    assert_eq!(
        &target.bytes[BASE + last * 1024..BASE + (last + 1) * 1024],
        &[0x52; 1024]
    );
    drop(target);
    drop(journal);
    assert_eq!(r.memory.used(), 0);
}
