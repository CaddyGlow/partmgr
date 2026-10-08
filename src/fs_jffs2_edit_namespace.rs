//! Private operation-specific namespace intents using the shared NOR transaction engine.
use super::*;
/// Explicit native metadata for a newly created object; no source metadata is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Jffs2CreateMetadata {
    /// Native permissions, limited to 0777; object type is chosen by the create method.
    pub permissions: u16,
    /// Native 16-bit user ID.
    pub uid: u16,
    /// Native 16-bit group ID.
    pub gid: u16,
    /// Unsigned Unix access seconds.
    pub accessed: u32,
    /// Unsigned Unix modification seconds; also updates the parent entry timestamp.
    pub modified: u32,
    /// Unsigned Unix change seconds.
    pub changed: u32,
}
fn entry<'a>(parent: &'a Jffs2Inode, name: &[u8]) -> Option<&'a crate::fs_jffs2::Jffs2Entry> {
    parent
        .children
        .binary_search_by(|e| e.name.as_slice().cmp(name))
        .ok()
        .map(|at| &parent.children[at])
}
fn next(parent: &Jffs2Inode) -> Result<u32> {
    parent
        .namespace_version()
        .checked_add(1)
        .ok_or_else(|| cap("JFFS2 namespace version overflow"))
}
impl<F: FlashStorage> Jffs2Editor<F> {
    fn parent(&self, id: &ObjectId) -> Result<&Jffs2Inode> {
        let p = inode(&self.decoded, self.number(id)?)?;
        if self.decoded.endian.dword(&p.raw, 20) & 0xf000 != 0x4000 {
            return Err(invalid(
                "JFFS2 namespace parent must be a reachable directory",
            ));
        }
        Ok(p)
    }
    fn create(
        &self,
        parent: &ObjectId,
        name: &[u8],
        kind: u32,
        payload: &[u8],
        metadata: Jffs2CreateMetadata,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        if metadata.permissions > 0o777 {
            return Err(invalid("JFFS2 create permission profile"));
        }
        if kind == 0x8000 && payload.len() > self.limits.file_bytes {
            return Err(cap("JFFS2 create regular-file payload cap"));
        }
        if kind == 0xa000 && (payload.is_empty() || payload.len() > 254 || payload.contains(&0)) {
            return Err(invalid(
                "JFFS2 create symlink requires exact 1..254 non-NUL target bytes",
            ));
        }
        let lease = self.limits.reserve(r)?;
        let p = self.parent(parent)?;
        if entry(p, name).is_some() {
            return Err(invalid("JFFS2 create destination already exists"));
        }
        let number = self
            .inode_floor
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 create inode overflow"))?;
        let e = self.decoded.endian;
        let mut raw = [0; 68];
        put(e, &mut raw, 20, kind | u32::from(metadata.permissions));
        word(e, &mut raw, 24, metadata.uid);
        word(e, &mut raw, 26, metadata.gid);
        put(e, &mut raw, 32, metadata.accessed);
        put(e, &mut raw, 36, metadata.modified);
        put(e, &mut raw, 40, metadata.changed);
        let prototype = Jffs2Inode {
            number,
            version: 1,
            raw,
            map: Vec::new(),
            children: Vec::new(),
            deleted: Vec::new(),
            synthetic: false,
            dir_time: None,
            header_offset: None,
            namespace_version: 1,
        };
        let records = vec![
            file_node(e, &prototype, number, 1, payload, None)?,
            dirent(
                e,
                p.number,
                number,
                next(p)?,
                metadata.modified,
                match kind {
                    0x4000 => 4,
                    0x8000 => 8,
                    0xa000 => 10,
                    _ => unreachable!(),
                },
                name,
            )?,
        ];
        let slots = allocate(&self.decoded, records, None, self.limits)?;
        self.plan(slots, None, Jffs2EditOperation::Create, lease, r)
    }
    /// Create one complete bounded regular file under explicit native metadata.
    /// An existing destination is refused, including a source-visible hardlink name.
    pub fn create_file(
        &self,
        parent: &ObjectId,
        name: &[u8],
        payload: &[u8],
        metadata: Jffs2CreateMetadata,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.create(parent, name, 0x8000, payload, metadata, r)
    }
    /// Create an empty directory with explicit native metadata and a fresh native inode.
    pub fn create_directory(
        &self,
        parent: &ObjectId,
        name: &[u8],
        metadata: Jffs2CreateMetadata,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.create(parent, name, 0x4000, b"", metadata, r)
    }
    /// Create one unfollowed symlink with exact byte target and explicit native metadata.
    pub fn create_symlink(
        &self,
        parent: &ObjectId,
        name: &[u8],
        target: &[u8],
        metadata: Jffs2CreateMetadata,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.create(parent, name, 0xa000, target, metadata, r)
    }
    /// Add one absent native name for a reachable regular file or symlink, preserving inode.
    /// Directory hardlinks are rejected; the symlink target is never followed.
    pub fn link(
        &self,
        object: &ObjectId,
        parent: &ObjectId,
        name: &[u8],
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        let lease = self.limits.reserve(r)?;
        let number = self.number(object)?;
        let old = inode(&self.decoded, number)?;
        let kind = self.decoded.endian.dword(&old.raw, 20) & 0xf000;
        if kind == 0x4000 {
            return Err(invalid("JFFS2 directory hardlinks are forbidden"));
        }
        let p = self.parent(parent)?;
        if entry(p, name).is_some() {
            return Err(invalid("JFFS2 hardlink destination exists"));
        }
        let slots = allocate(
            &self.decoded,
            vec![dirent(
                self.decoded.endian,
                p.number,
                number,
                next(p)?,
                timestamp,
                if kind == 0xa000 { 10 } else { 8 },
                name,
            )?],
            None,
            self.limits,
        )?;
        self.plan(slots, None, Jffs2EditOperation::Link, lease, r)
    }
    /// Publish one deletion tombstone, retaining any remaining hardlinks.
    /// Nonempty directory removal and root removal are rejected.
    pub fn unlink(
        &self,
        parent: &ObjectId,
        name: &[u8],
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        let lease = self.limits.reserve(r)?;
        let p = self.parent(parent)?;
        let ent = entry(p, name).ok_or_else(|| invalid("JFFS2 unlink source name absent"))?;
        let old = inode(&self.decoded, ent.inode)?;
        if old.number == 1
            || self.decoded.endian.dword(&old.raw, 20) & 0xf000 == 0x4000
                && !old.children.is_empty()
        {
            return Err(invalid("JFFS2 root/nonempty-directory unlink forbidden"));
        }
        let slots = allocate(
            &self.decoded,
            vec![dirent(
                self.decoded.endian,
                p.number,
                0,
                next(p)?,
                timestamp,
                ent.file_type,
                name,
            )?],
            None,
            self.limits,
        )?;
        self.plan(slots, None, Jffs2EditOperation::Unlink, lease, r)
    }
    /// Rename or move one existing name to an absent destination while retaining native inode.
    /// Destination publishes before the final source tombstone; interrupted transactions
    /// require bound-intent recovery before strict reopening, not native mount atomicity.
    pub fn rename(
        &self,
        source_parent: &ObjectId,
        source_name: &[u8],
        destination_parent: &ObjectId,
        destination_name: &[u8],
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        let lease = self.limits.reserve(r)?;
        let old_parent = self.parent(source_parent)?;
        let new_parent = self.parent(destination_parent)?;
        let ent = entry(old_parent, source_name)
            .ok_or_else(|| invalid("JFFS2 rename source name absent"))?;
        if ent.inode == 1 || entry(new_parent, destination_name).is_some() {
            return Err(invalid("JFFS2 rename root/existing destination forbidden"));
        }
        let destination_version = next(new_parent)?;
        let deletion_version = if old_parent.number == new_parent.number {
            destination_version
                .checked_add(1)
                .ok_or_else(|| cap("JFFS2 rename source version overflow"))?
        } else {
            next(old_parent)?
        };
        let slots = allocate(
            &self.decoded,
            vec![
                dirent(
                    self.decoded.endian,
                    new_parent.number,
                    ent.inode,
                    destination_version,
                    timestamp,
                    ent.file_type,
                    destination_name,
                )?,
                dirent(
                    self.decoded.endian,
                    old_parent.number,
                    0,
                    deletion_version,
                    timestamp,
                    ent.file_type,
                    source_name,
                )?,
            ],
            None,
            self.limits,
        )?;
        self.plan(slots, None, Jffs2EditOperation::Rename, lease, r)
    }
}
struct Change<'a> {
    parent: u32,
    name: &'a [u8],
    inode: u32,
    kind: u8,
    version: u32,
    time: u32,
}
fn parsed<'a>(i: &'a Intent, index: usize) -> Result<Change<'a>> {
    let b = &i
        .slots
        .get(index)
        .ok_or_else(|| invalid("JFFS2 missing namespace record"))?
        .bytes;
    let e = i.endian;
    if b.len() < 40 || e.word(b, 2) != 0xe001 {
        return Err(invalid("JFFS2 namespace intent dirent type"));
    }
    let n = b[28] as usize;
    if n == 0 || n > 254 || b.len() != ((40 + n + 3) & !3) || e.dword(b, 4) as usize != 40 + n {
        return Err(invalid("JFFS2 namespace intent dirent bounds"));
    }
    Ok(Change {
        parent: e.dword(b, 12),
        name: &b[40..40 + n],
        inode: e.dword(b, 20),
        kind: b[29],
        version: e.dword(b, 16),
        time: e.dword(b, 24),
    })
}
fn reachable<'a>(d: &'a Decoded, a: &Jffs2AuditReport, n: u32) -> Result<&'a Jffs2Inode> {
    let at = d
        .inodes
        .binary_search_by_key(&n, |i| i.number)
        .map_err(|_| invalid("JFFS2 namespace absent inode"))?;
    if !a.reachable[at] {
        return Err(invalid(
            "JFFS2 namespace intent references unreachable inode",
        ));
    }
    Ok(&d.inodes[at])
}
fn parent<'a>(d: &'a Decoded, a: &Jffs2AuditReport, n: u32) -> Result<&'a Jffs2Inode> {
    let p = reachable(d, a, n)?;
    if d.endian.dword(&p.raw, 20) & 0xf000 != 0x4000 {
        return Err(invalid("JFFS2 namespace intent parent type"));
    }
    Ok(p)
}
fn absent(p: &Jffs2Inode, name: &[u8]) -> Result<()> {
    if entry(p, name).is_some() {
        return Err(invalid("JFFS2 namespace destination collision"));
    }
    Ok(())
}
fn matches_change(ch: &Change<'_>, ent: &crate::fs_jffs2::Jffs2Entry) -> bool {
    ch.inode == ent.inode && ch.kind == ent.file_type
}
fn unchanged_lists(
    old: &[crate::fs_jffs2::Jffs2Entry],
    new: &[crate::fs_jffs2::Jffs2Entry],
    number: u32,
    changes: &[Change<'_>],
) -> Result<()> {
    let changed = |name: &[u8]| changes.iter().any(|c| c.parent == number && c.name == name);
    let mut a = old.iter().filter(|e| !changed(&e.name));
    let mut b = new.iter().filter(|e| !changed(&e.name));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ok(()),
            (Some(x), Some(y))
                if x.name == y.name && x.inode == y.inode && x.file_type == y.file_type => {}
            _ => return Err(invalid("JFFS2 namespace intent changed an unrelated name")),
        }
    }
}
pub(super) fn validate(
    i: &Intent,
    b: &Decoded,
    a: &Jffs2AuditReport,
    c: &Decoded,
    ca: &Jffs2AuditReport,
    l: Jffs2EditLimits,
) -> Result<()> {
    let e = i.endian;
    let mut changes = Vec::new();
    changes
        .try_reserve_exact(2)
        .map_err(|_| cap("JFFS2 namespace change allocation"))?;
    let mut new_object = None;
    let mut removed = None;
    match i.operation {
        Jffs2EditOperation::Create => {
            if i.slots.len() != 2 {
                return Err(invalid("JFFS2 create intent record count"));
            }
            let bytes = &i.slots[0].bytes;
            if bytes.len() < 68 || e.word(bytes, 2) != 0xe002 {
                return Err(invalid("JFFS2 create intent inode type"));
            }
            let n = i
                .inode_floor
                .checked_add(1)
                .ok_or_else(|| cap("JFFS2 create intent inode overflow"))?;
            let size = e.dword(bytes, 28) as usize;
            let encoded = e.dword(bytes, 48) as usize;
            let kind = e.dword(bytes, 20) & 0xf000;
            if ![0x4000, 0x8000, 0xa000].contains(&kind)
                || e.dword(bytes, 20) & 0xfff > 0o777
                || e.dword(bytes, 12) != n
                || e.dword(bytes, 16) != 1
                || e.dword(bytes, 44) != 0
                || e.dword(bytes, 52) as usize != size
                || if kind == 0x8000 {
                    !compression_edit::data_shape(
                        i.compression,
                        bytes[56],
                        encoded,
                        size,
                        l.file_bytes,
                    )
                } else {
                    bytes[56] != 0 || encoded != size
                }
                || bytes[57] != 0
                || e.word(bytes, 58) != 0
                || bytes.len() != ((68 + encoded + 3) & !3)
                || e.dword(bytes, 4) as usize != 68 + encoded
                || kind == 0x4000 && size != 0
                || kind == 0x8000 && size > l.file_bytes
                || kind == 0xa000 && !(1..=254).contains(&size)
            {
                return Err(invalid("JFFS2 create exact inode semantic profile"));
            }
            let ch = parsed(i, 1)?;
            let p = parent(b, a, ch.parent)?;
            absent(p, ch.name)?;
            if ch.inode != n
                || ch.kind
                    != match kind {
                        0x4000 => 4,
                        0x8000 => 8,
                        _ => 10,
                    }
                || ch.version != next(p)?
                || ch.time != e.dword(bytes, 36)
            {
                return Err(invalid("JFFS2 create publication semantics"));
            }
            new_object = Some(n);
            changes.push(ch);
        }
        Jffs2EditOperation::Link => {
            if i.slots.len() != 1 {
                return Err(invalid("JFFS2 link intent record count"));
            }
            let ch = parsed(i, 0)?;
            let p = parent(b, a, ch.parent)?;
            absent(p, ch.name)?;
            let target = reachable(b, a, ch.inode)?;
            let kind = e.dword(&target.raw, 20) & 0xf000;
            if kind == 0x4000
                || ch.kind != if kind == 0xa000 { 10 } else { 8 }
                || ch.version != next(p)?
            {
                return Err(invalid("JFFS2 link intent semantic profile"));
            }
            changes.push(ch);
        }
        Jffs2EditOperation::Unlink => {
            if i.slots.len() != 1 {
                return Err(invalid("JFFS2 unlink intent record count"));
            }
            let ch = parsed(i, 0)?;
            let p = parent(b, a, ch.parent)?;
            let ent =
                entry(p, ch.name).ok_or_else(|| invalid("JFFS2 unlink intent source absent"))?;
            let old = reachable(b, a, ent.inode)?;
            if ch.inode != 0
                || ch.kind != ent.file_type
                || ch.version != next(p)?
                || old.number == 1
                || e.dword(&old.raw, 20) & 0xf000 == 0x4000 && !old.children.is_empty()
            {
                return Err(invalid("JFFS2 unlink intent semantic profile"));
            }
            let refs = b
                .inodes
                .iter()
                .enumerate()
                .filter(|(at, _)| a.reachable[*at])
                .flat_map(|(_, p)| &p.children)
                .filter(|ent| ent.inode == old.number)
                .count();
            if refs == 1 {
                removed = Some(old.number);
            }
            changes.push(ch);
        }
        Jffs2EditOperation::Rename => {
            if i.slots.len() != 2 {
                return Err(invalid("JFFS2 rename intent record count"));
            }
            let dst = parsed(i, 0)?;
            let src = parsed(i, 1)?;
            let dp = parent(b, a, dst.parent)?;
            let sp = parent(b, a, src.parent)?;
            absent(dp, dst.name)?;
            let ent =
                entry(sp, src.name).ok_or_else(|| invalid("JFFS2 rename intent source absent"))?;
            let expected = if dp.number == sp.number {
                next(dp)?
                    .checked_add(1)
                    .ok_or_else(|| cap("JFFS2 rename intent version overflow"))?
            } else {
                next(sp)?
            };
            if ent.inode == 1
                || dst.inode != ent.inode
                || dst.kind != ent.file_type
                || src.inode != 0
                || src.kind != ent.file_type
                || dst.time != src.time
                || dst.version != next(dp)?
                || src.version != expected
            {
                return Err(invalid(
                    "JFFS2 rename intent publication/tombstone semantics",
                ));
            }
            changes.push(dst);
            changes.push(src);
        }
        _ => return Err(invalid("JFFS2 unexpected namespace intent operation")),
    }
    if c.inodes.len() != b.inodes.len() + usize::from(new_object.is_some()) {
        return Err(invalid("JFFS2 namespace changed unrelated inode inventory"));
    }
    for (at, old) in b.inodes.iter().enumerate() {
        let new = inode(c, old.number)?;
        if old.raw != new.raw {
            return Err(invalid(
                "JFFS2 namespace changed existing native inode metadata",
            ));
        }
        unchanged_lists(&old.children, &new.children, old.number, &changes)?;
        unchanged_lists(&old.deleted, &new.deleted, old.number, &changes)?;
        let new_at = c
            .inodes
            .binary_search_by_key(&old.number, |i| i.number)
            .unwrap();
        let expected = a.reachable[at] && removed != Some(old.number);
        if ca.reachable[new_at] != expected {
            return Err(invalid(
                "JFFS2 namespace lost reachability or formed a detached directory cycle",
            ));
        }
    }
    if let Some(n) = new_object {
        let at = c
            .inodes
            .binary_search_by_key(&n, |i| i.number)
            .map_err(|_| invalid("JFFS2 created inode absent"))?;
        if !ca.reachable[at] {
            return Err(invalid("JFFS2 created inode not reachable"));
        }
    }
    for ch in &changes {
        let p = inode(c, ch.parent)?;
        if ch.inode == 0 {
            if entry(p, ch.name).is_some()
                || !p
                    .deleted
                    .iter()
                    .any(|ent| ent.name == ch.name && matches_change(ch, ent))
            {
                return Err(invalid("JFFS2 final deletion tombstone absent"));
            }
        } else if !entry(p, ch.name).is_some_and(|ent| matches_change(ch, ent)) {
            return Err(invalid("JFFS2 final namespace publication absent"));
        }
    }
    Ok(())
}
