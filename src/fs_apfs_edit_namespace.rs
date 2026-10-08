//! Exact sensitive native namespace and bounded data projections for native COW.
use super::*;

/// Native metadata supplied explicitly for newly authored APFS objects.
#[derive(Clone, Copy, Debug)]
pub struct ApfsCreateMetadata {
    /// Permission bits, without file-type bits; supported range is 0..=0o777.
    pub permissions: u16,
    /// Native UID.
    pub uid: u32,
    /// Native GID.
    pub gid: u32,
    /// Native nanoseconds since Unix epoch, used for all four inode times and directory addition.
    pub timestamp: u64,
}
/// A projected native mutation using the same retained-history publication protocol as range replacement.
pub type ApfsMutationPlan = ApfsRangePlan;

struct InlineInput {
    bytes: Vec<u8>,
    binding: (ObjectId, u64),
}
struct ResourceEdit {
    name: Option<Vec<u8>>,
    offset: u64,
    eof: u64,
    truncate: bool,
    replace: bool,
}
type Fields = Vec<(u8, u8, Vec<u8>)>;
fn key(id: u64, kind: u64) -> Vec<u8> {
    ((kind << 60) | id).to_le_bytes().to_vec()
}
fn name_key(parent: u64, name: &[u8]) -> Vec<u8> {
    let mut k = key(parent, 9);
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name);
    k.push(0);
    k
}
fn xattr_name(name: &[u8]) -> Result<()> {
    if name.is_empty()
        || name.len() > 821
        || name.contains(&0)
        || std::str::from_utf8(name).is_err()
    {
        return Err(invalid("APFS native xattr name bounds"));
    }
    if name == b"com.apple.ResourceFork"
        || name == b"com.apple.FinderInfo"
        || name == b"com.apple.decmpfs"
        || name == b"com.apple.system.Security"
        || name.starts_with(b"com.apple.fs.")
    {
        return Err(unavailable(
            "APFS special xattr requires dedicated semantics",
        ));
    }
    Ok(())
}
fn xattr_key(file: u64, name: &[u8]) -> Vec<u8> {
    let mut k = key(file, 4);
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name);
    k.push(0);
    k
}
fn increment_generation(catalog: &mut Records, file: u64) -> Result<()> {
    let at = inode_index(catalog, file)?;
    let raw = &mut catalog[at].1;
    let generation = u32le(raw, 64)
        .checked_add(1)
        .ok_or_else(|| budget("APFS xattr generation"))?;
    d(raw, 64, generation);
    Ok(())
}
fn name_valid(name: &[u8]) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name.contains(&0)
        || name.contains(&b'/')
        || name == b"."
        || name == b".."
        || std::str::from_utf8(name).is_err()
    {
        return Err(invalid("APFS exact native UTF8 name"));
    }
    Ok(())
}
pub(super) fn fields(raw: &[u8]) -> Fields {
    let count = u16::from_le_bytes(raw[92..94].try_into().unwrap()) as usize;
    let mut at = 96 + count * 4;
    (0..count)
        .map(|i| {
            let p = 96 + i * 4;
            let n = u16::from_le_bytes(raw[p + 2..p + 4].try_into().unwrap()) as usize;
            let out = (raw[p], raw[p + 1], raw[at..at + n].to_vec());
            at += n.next_multiple_of(8);
            out
        })
        .collect()
}
fn put_fields(raw: &mut Vec<u8>, fields: Fields) -> Result<()> {
    let used = fields.iter().try_fold(0usize, |a, f| {
        a.checked_add(f.2.len().next_multiple_of(8))
            .ok_or_else(|| budget("APFS native xfield bytes"))
    })?;
    if fields.len() > u16::MAX as usize
        || used > u16::MAX as usize
        || fields
            .iter()
            .any(|f| f.2.is_empty() || f.2.len() > u16::MAX as usize)
    {
        return Err(budget("APFS native xfield bounds"));
    }
    raw.truncate(92);
    let size = 96 + fields.len() * 4 + used;
    raw.try_reserve_exact(size - 92)
        .map_err(|_| budget("APFS native inode projection"))?;
    raw.resize(size, 0);
    w(raw, 92, fields.len() as u16);
    w(raw, 94, used as u16);
    let mut at = 96 + fields.len() * 4;
    for (i, (kind, flags, value)) in fields.into_iter().enumerate() {
        let p = 96 + i * 4;
        raw[p] = kind;
        raw[p + 1] = flags;
        w(raw, p + 2, value.len() as u16);
        raw[at..at + value.len()].copy_from_slice(&value);
        at += value.len().next_multiple_of(8);
    }
    Ok(())
}
fn field_set(fs: &mut Fields, kind: u8, flags: u8, value: Option<Vec<u8>>) {
    if let Some(i) = fs.iter().position(|f| f.0 == kind) {
        if let Some(value) = value {
            fs[i].2 = value;
        } else {
            fs.remove(i);
        }
    } else if let Some(value) = value {
        fs.push((kind, flags, value));
    }
}
fn inode_index(catalog: &Records, id: u64) -> Result<usize> {
    catalog
        .iter()
        .position(|r| u64le(&r.0, 0) == ((3u64 << 60) | id))
        .ok_or_else(|| invalid("APFS projected inode absent"))
}
fn drec(id: u64, time: u64, directory: bool, sibling: Option<u64>) -> Vec<u8> {
    let mut v = vec![0; 18];
    q(&mut v, 0, id);
    q(&mut v, 8, time);
    w(&mut v, 16, if directory { 4 } else { 8 });
    if let Some(s) = sibling {
        v.extend_from_slice(&[1, 0, 8, 0, 1, 2, 8, 0]);
        v.extend_from_slice(&s.to_le_bytes());
    }
    v
}
fn occurrence(catalog: &Records, parent: u64, name: &[u8]) -> Result<usize> {
    let k = name_key(parent, name);
    catalog
        .iter()
        .position(|r| r.0 == k)
        .ok_or_else(|| invalid("APFS native occurrence absent"))
}
fn collision(catalog: &Records, parent: u64, name: &[u8]) -> Result<()> {
    if catalog.iter().any(|r| r.0 == name_key(parent, name)) {
        return Err(invalid("APFS native name collision"));
    }
    Ok(())
}
fn next_id(next: &mut u64) -> Result<u64> {
    let id = *next;
    if !(16..0x0fffffffffffffff).contains(&id) {
        return Err(budget("APFS native object identity exhausted"));
    }
    *next = next
        .checked_add(1)
        .ok_or_else(|| budget("APFS native object identity exhausted"))?;
    Ok(id)
}
fn links(catalog: &mut Records, id: u64, next: &mut u64) -> Result<()> {
    let mut occurrences: Vec<(usize, u64, Vec<u8>, Option<u64>)> = catalog
        .iter()
        .enumerate()
        .filter(|(_, r)| u64le(&r.0, 0) >> 60 == 9 && u64le(&r.1, 0) == id)
        .map(|(i, r)| {
            (
                i,
                u64le(&r.0, 0) & 0x0fffffffffffffff,
                r.0[10..r.0.len() - 1].to_vec(),
                if r.1.len() == 34 {
                    Some(u64le(&r.1, 26))
                } else {
                    None
                },
            )
        })
        .collect();
    if occurrences.is_empty() {
        return Err(invalid("APFS projected regular file has no names"));
    }
    let index = inode_index(catalog, id)?;
    let mut raw = catalog[index].1.clone();
    let mut fs = fields(&raw);
    if occurrences.len() > 1 {
        for entry in &mut occurrences {
            if entry.3.is_none() {
                entry.3 = Some(next_id(next)?);
            }
        }
    }
    // Preserve existing native sibling IDs, including the last remaining sibling.
    let primary = occurrences.iter().min_by_key(|e| e.3.unwrap_or(0)).unwrap();
    q(&mut raw, 0, primary.1);
    d(
        &mut raw,
        56,
        u32::try_from(occurrences.len()).map_err(|_| budget("APFS native link count"))?,
    );
    let mut name = primary.2.clone();
    name.push(0);
    field_set(&mut fs, 4, 2, Some(name));
    if fs.iter().any(|f| f.0 == 7) {
        field_set(&mut fs, 7, 32, primary.3.map(|s| s.to_le_bytes().to_vec()));
    }
    put_fields(&mut raw, fs)?;
    catalog[index].1 = raw;
    for entry in &occurrences {
        let old = &catalog[entry.0].1;
        catalog[entry.0].1 = drec(id, u64le(old, 8), false, entry.3);
    }
    catalog.retain(|r| {
        !(u64le(&r.0, 0) >> 60 == 5 && u64le(&r.0, 0) & 0x0fffffffffffffff == id
            || u64le(&r.0, 0) >> 60 == 12 && u64le(&r.1, 0) == id)
    });
    for (_, parent, name, sibling) in occurrences {
        if let Some(s) = sibling {
            let mut k = key(id, 5);
            k.extend_from_slice(&s.to_le_bytes());
            let mut v = parent.to_le_bytes().to_vec();
            v.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
            v.extend_from_slice(&name);
            v.push(0);
            catalog.push((k, v));
            catalog.push((key(s, 12), id.to_le_bytes().to_vec()));
        }
    }
    Ok(())
}
fn directory_counts(catalog: &mut Records) -> Result<()> {
    let mut counts = BTreeMap::<u64, u32>::new();
    for (k, _) in catalog.iter().filter(|r| u64le(&r.0, 0) >> 60 == 9) {
        let count = counts.entry(u64le(k, 0) & 0x0fffffffffffffff).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| budget("APFS directory children exhausted"))?;
    }
    for (k, v) in catalog.iter_mut().filter(|r| u64le(&r.0, 0) >> 60 == 3) {
        if u16::from_le_bytes(v[80..82].try_into().unwrap()) & 0xf000 == 0x4000 {
            d(
                v,
                56,
                counts
                    .get(&(u64le(k, 0) & 0x0fffffffffffffff))
                    .copied()
                    .unwrap_or(0),
            );
        }
    }
    Ok(())
}
struct Empty {
    id: ObjectId,
}
impl FileRead for Empty {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        0
    }
    fn read_at(&self, _: u64, _: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        Ok(0)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()
    }
}
struct EmbeddedGrowth {
    id: ObjectId,
    bytes: Vec<u8>,
    length: u64,
}
impl FileRead for EmbeddedGrowth {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, offset: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let count = out
            .len()
            .min(self.length.saturating_sub(offset).min(usize::MAX as u64) as usize);
        out[..count].fill(0);
        if offset < (self.bytes.len() as u64) {
            let start = offset as usize;
            let copy = count.min(self.bytes.len() - start);
            out[..copy].copy_from_slice(&self.bytes[start..start + copy]);
        }
        Ok(count)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        if self.length != 0 {
            visitor(LogicalExtent {
                offset: 0,
                length: self.length,
                kind: ExtentKind::Data,
            })?;
        }
        Ok(())
    }
}
struct Base {
    binding: Option<(ObjectId, u64)>,
    catalog: Records,
    free: Vec<u64>,
    lease: Reservation,
    next: u64,
    files: u64,
    dirs: u64,
}
impl<S: Storage> ApfsEditor<S> {
    /// Create a source- and generation-bound identity for a directory.
    pub fn directory_identity(&self, inode: u64, r: &Resources) -> Result<ObjectId> {
        self.revalidate(r)?;
        if self
            .volume
            .inner
            .nodes
            .get(&inode)
            .is_none_or(|n| !n.directory)
        {
            return Err(invalid("APFS owned directory absent"));
        }
        Ok(ObjectId {
            source: self.scope,
            generation: self.generation,
            native: inode.to_be_bytes().to_vec(),
        })
    }
    /// Enumerate copied exact native names with owned identities bound to the current generation.
    pub fn directory(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<DirectoryEntry>>> {
        self.revalidate(r)?;
        let inode = self.own_node(id, true)?;
        let node = &self.volume.inner.nodes[&inode];
        let charge = (node.entries.len() as u64)
            .checked_mul(2048)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| budget("APFS owned directory memory"))?;
        Budgeted::try_new(&self.snapshot.work.resources.memory, charge, || {
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(node.entries.len())
                .map_err(|_| budget("APFS owned directory index"))?;
            for entry in &node.entries {
                r.cancellation.check()?;
                self.snapshot.work.resources.cancellation.check()?;
                self.snapshot.work.charge(1)?;
                entries.push(DirectoryEntry {
                    name: NativeName::Bytes(entry.name.clone()),
                    object: ObjectId {
                        source: self.scope,
                        generation: self.generation,
                        native: entry.inode.to_be_bytes().to_vec(),
                    },
                    kind: if self.volume.inner.nodes[&entry.inode].directory {
                        ObjectKind::Directory
                    } else {
                        ObjectKind::File
                    },
                });
            }
            Ok(entries)
        })
    }
    fn own_node(&self, id: &ObjectId, directory: bool) -> Result<u64> {
        if id.source != self.scope || id.generation != self.generation || id.native.len() != 8 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS owned foreign/stale identity",
            ));
        }
        let inode = u64::from_be_bytes(id.native[..].try_into().unwrap());
        let node = self
            .volume
            .inner
            .nodes
            .get(&inode)
            .ok_or_else(|| invalid("APFS owned inode absent"))?;
        if node.directory != directory || inode < 2 || inode == 3 {
            return Err(invalid("APFS mutation object/profile"));
        }
        if u32le(&node.raw, 68) != 0 {
            return Err(unavailable("APFS BSD write/security flags"));
        }
        Ok(inode)
    }
    fn namespace_base(&self, r: &Resources) -> Result<Base> {
        if self.recovery_required {
            return Err(Error::new(
                ErrorKind::InterruptedWrite,
                "APFS native recovery required",
            ));
        }
        self.revalidate(r)?;
        self.generation
            .checked_add(2)
            .ok_or_else(|| budget("APFS owned generation exhausted"))?;
        let c = self.volume.container();
        let blocks = c.checkpoint().blocks;
        if c.checkpoint().volumes.len() != 1 || blocks > 127 * 32768 {
            return Err(unavailable(
                "APFS initial COW single-volume/direct two-CIB profile",
            ));
        }
        for node in self.volume.inner.nodes.values() {
            for stream in &node.streams {
                if !matches!(
                    stream.kind,
                    StreamKind::Data | StreamKind::ResourceFork | StreamKind::Named(_)
                ) && stream.inline.is_none()
                {
                    return Err(unavailable("APFS COW external resource stream"));
                }
            }
        }
        let charge = blocks
            .checked_mul(1024)
            .and_then(|n| n.checked_add((self.limits.metadata_blocks as u64).checked_mul(8192)?))
            .ok_or_else(|| budget("APFS COW reservation overflow"))?;
        let lease = self.snapshot.work.resources.memory.reserve(charge)?;
        self.snapshot.work.charge(
            self.limits
                .read
                .work
                .checked_add(
                    blocks
                        .checked_mul(64)
                        .ok_or_else(|| budget("APFS COW work"))?,
                )
                .ok_or_else(|| budget("APFS COW work"))?,
        )?;
        let mut work = Work {
            limits: self.limits.read,
            used: 0,
        };
        let (vmap, _) = index::omap(c, u64le(&self.volume.inner.header, 128), &mut work, r)?;
        let catalog = records(
            c,
            u64le(&self.volume.inner.header, 136),
            0,
            TreeKind::Filesystem,
            Some(&vmap),
            &mut work,
            r,
        )?;
        records(
            c,
            u64le(&self.volume.inner.header, 144),
            0x40000000,
            TreeKind::Extent,
            None,
            &mut work,
            r,
        )?;
        if !records(
            c,
            u64le(&self.volume.inner.header, 152),
            0x40000000,
            TreeKind::Snapshot,
            None,
            &mut work,
            r,
        )?
        .is_empty()
        {
            return Err(unavailable("APFS COW snapshot mutation"));
        }
        for address in [
            c.checkpoint().object_map,
            u64le(&self.volume.inner.header, 128),
        ] {
            let h = self.copied(address)?;
            records(
                c,
                u64le(&h, 48),
                0x40000000,
                TreeKind::Omap,
                None,
                &mut work,
                r,
            )?;
        }
        self.snapshot.work.charge(work.used)?;
        Ok(Base {
            binding: None,
            catalog,
            free: self.free_blocks()?,
            lease,
            next: u64le(&self.volume.inner.header, 176),
            files: u64le(&self.volume.inner.header, 184),
            dirs: u64le(&self.volume.inner.header, 192),
        })
    }
    fn empty_input(&self) -> Arc<dyn FileRead> {
        Arc::new(Empty {
            id: ObjectId {
                source: self.scope,
                generation: self.generation,
                native: b"metadata-only".to_vec(),
            },
        })
    }
    fn namespace_finish(
        &self,
        base: Base,
        payload: Vec<Payload>,
        input: Arc<dyn FileRead>,
        eof: u64,
        zero_from: Option<u64>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        self.namespace_finish_at(base, payload, input, (0, eof), zero_from, r)
    }
    fn namespace_finish_at(
        &self,
        mut base: Base,
        payload: Vec<Payload>,
        input: Arc<dyn FileRead>,
        range: (u64, u64),
        zero_from: Option<u64>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let (offset, eof) = range;
        directory_counts(&mut base.catalog)?;
        self.assemble(
            Projection {
                binding: base.binding,
                catalog: base.catalog,
                payload,
                input,
                offset,
                eof,
                zero_from,
                lease: base.lease,
                resources: r.clone(),
                counters: Some((base.next, base.files, base.dirs)),
                reclamation: None,
            },
            r,
        )
    }
    /// Publish a projected file/namespace mutation with the retained native recovery anchor.
    pub fn commit_mutation(
        &mut self,
        plan: ApfsMutationPlan,
        anchor: &ApfsRecoveryAnchor,
        r: &Resources,
    ) -> Result<ApfsEditReceipt> {
        self.commit_range(plan, anchor, r)
    }
    /// Create a regular file from deferred DATA, preserving validated whole-block source holes.
    pub fn plan_create(
        &self,
        parent: &ObjectId,
        name: &[u8],
        input: Arc<dyn FileRead>,
        metadata: ApfsCreateMetadata,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        self.plan_create_inner(parent, name, Some(input), metadata, r)
    }
    /// Create an empty native directory with explicit metadata.
    pub fn plan_create_directory(
        &self,
        parent: &ObjectId,
        name: &[u8],
        metadata: ApfsCreateMetadata,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        self.plan_create_inner(parent, name, None, metadata, r)
    }
    fn plan_create_inner(
        &self,
        parent: &ObjectId,
        name: &[u8],
        input: Option<Arc<dyn FileRead>>,
        m: ApfsCreateMetadata,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let parent = self.own_node(parent, true)?;
        name_valid(name)?;
        collision(&base.catalog, parent, name)?;
        if m.permissions & !0o777 != 0 {
            return Err(invalid("APFS explicit creation permission bits"));
        }
        let id = next_id(&mut base.next)?;
        let directory = input.is_none();
        let mut raw = vec![0; 96];
        q(&mut raw, 0, parent);
        q(&mut raw, 8, id);
        for p in [16, 24, 32, 40] {
            q(&mut raw, p, m.timestamp);
        }
        d(&mut raw, 56, u32::from(!directory));
        d(&mut raw, 72, m.uid);
        d(&mut raw, 76, m.gid);
        w(
            &mut raw,
            80,
            m.permissions | if directory { 0x4000 } else { 0x8000 },
        );
        let mut n = name.to_vec();
        n.push(0);
        put_fields(&mut raw, vec![(4, 2, n)])?;
        base.catalog.push((key(id, 3), raw));
        base.catalog.push((
            name_key(parent, name),
            drec(id, m.timestamp, directory, None),
        ));
        let (payload, input, eof) = if let Some(input) = input {
            base.files = base
                .files
                .checked_add(1)
                .ok_or_else(|| budget("APFS file count"))?;
            base.catalog.push((key(id, 6), 1u32.to_le_bytes().to_vec()));
            let eof = input.len();
            let payload = self.author_data(&mut base, id, &input, r)?;
            (payload, input, eof)
        } else {
            base.dirs = base
                .dirs
                .checked_add(1)
                .ok_or_else(|| budget("APFS directory count"))?;
            (Vec::new(), self.empty_input(), 0)
        };
        self.namespace_finish(base, payload, input, eof, None, r)
    }
    /// Replace an existing regular DATA stream, retaining native metadata, names and inline resource fork.
    pub fn plan_replace(
        &self,
        id: &ObjectId,
        input: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        let eof = input.len();
        let payload = self.author_data(&mut base, file, &input, r)?;
        self.namespace_finish(base, payload, input, eof, None, r)
    }
    fn author_data(
        &self,
        base: &mut Base,
        id: u64,
        input: &Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<Vec<Payload>> {
        if input.identity().native.len() > 4096 {
            return Err(budget("APFS source identity cap"));
        }
        let identity = input.identity().clone();
        let eof = input.len();
        let count = eof.div_ceil(BLOCK as u64);
        if count > self.limits.read.blocks || count > base.free.len().saturating_sub(8) as u64 {
            return Err(budget("APFS new DATA block cap"));
        }
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(count as usize + 1)
            .map_err(|_| budget("APFS deferred source extents"))?;
        let mut end = 0;
        input.visit_extents(r, &mut |extent| {
            self.snapshot.work.resources.cancellation.check()?;
            r.cancellation.check()?;
            self.snapshot.work.charge(1)?;
            if input.identity() != &identity || input.len() != eof {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS indexed source changed",
                ));
            }
            if extent.offset != end || extent.length == 0 || extent.kind == ExtentKind::Unwritten {
                return Err(invalid("APFS source extent coverage/kind"));
            }
            end = end
                .checked_add(extent.length)
                .filter(|n| *n <= eof)
                .ok_or_else(|| invalid("APFS source extent range"))?;
            if extents.len() == count as usize + 1 {
                return Err(budget("APFS source extent count"));
            }
            extents.push(extent);
            Ok(())
        })?;
        if end != eof || input.identity() != &identity || input.len() != eof {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS complete source extent binding",
            ));
        }
        base.binding = Some((identity, eof));
        let data_id = detach_data_stream(&mut base.catalog, id, &mut base.next)?;
        base.catalog.retain(|r| {
            !(u64le(&r.0, 0) >> 60 == 8 && u64le(&r.0, 0) & 0x0fffffffffffffff == data_id)
        });
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(count as usize)
            .map_err(|_| budget("APFS payload recipes"))?;
        let mut sparse = 0;
        let mut extent_index = 0;
        for logical in (0..count).map(|n| n * BLOCK as u64) {
            r.cancellation.check()?;
            self.snapshot.work.charge(1)?;
            while extent_index < extents.len()
                && extents[extent_index].offset + extents[extent_index].length <= logical
            {
                extent_index += 1;
            }
            let stop = (logical + BLOCK as u64).min(eof);
            let hole = extents.get(extent_index).is_some_and(|e| {
                e.kind == ExtentKind::Hole && e.offset <= logical && e.offset + e.length >= stop
            });
            let physical = if hole {
                sparse += BLOCK as u64;
                0
            } else {
                let physical = base.free[payload.len()];
                payload.push(Payload {
                    logical,
                    physical,
                    previous: 0,
                });
                physical
            };
            let mut k = key(data_id, 8);
            k.extend_from_slice(&logical.to_le_bytes());
            let mut v = vec![0; 24];
            q(&mut v, 0, BLOCK as u64);
            q(&mut v, 8, physical);
            base.catalog.push((k, v));
        }
        self.update_data_inode(
            &mut base.catalog,
            id,
            eof,
            count * BLOCK as u64,
            sparse,
            eof,
        )?;
        Ok(payload)
    }
    fn update_data_inode(
        &self,
        catalog: &mut Records,
        id: u64,
        eof: u64,
        allocated: u64,
        sparse: u64,
        written: u64,
    ) -> Result<()> {
        let i = inode_index(catalog, id)?;
        let raw = &mut catalog[i].1;
        let mut fs = fields(raw);
        let mut data = fs
            .iter()
            .find(|f| f.0 == 8)
            .map_or_else(|| vec![0; 40], |f| f.2.clone());
        q(&mut data, 0, eof);
        q(&mut data, 8, allocated);
        let old = u64le(&data, 24);
        q(
            &mut data,
            24,
            old.checked_add(written)
                .ok_or_else(|| budget("APFS byte-write counter"))?,
        );
        field_set(&mut fs, 8, 32, Some(data));
        field_set(
            &mut fs,
            13,
            40,
            if sparse == 0 {
                None
            } else {
                Some(sparse.to_le_bytes().to_vec())
            },
        );
        let flags = u64le(raw, 48);
        q(
            raw,
            48,
            if sparse == 0 {
                flags & !0x200
            } else {
                flags | 0x200
            },
        );
        let generation = u32le(raw, 64)
            .checked_add(1)
            .ok_or_else(|| budget("APFS write generation"))?;
        d(raw, 64, generation);
        put_fields(raw, fs)
    }
    /// Set bounded embedded user xattr bytes, retiring an old external mapping.
    /// Existing embedded reserved flag8 survives replacement; it is never created.
    pub fn plan_set_xattr(
        &self,
        id: &ObjectId,
        name: &[u8],
        value: &[u8],
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        xattr_name(name)?;
        if value.len() > 3804 {
            return Err(unavailable("APFS external generic xattr authoring"));
        }
        let mut base = self.namespace_base(r)?;
        let file = self.own_xattr_node(id)?;
        let k = xattr_key(file, name);
        let old = base.catalog.iter().find(|record| record.0 == k);
        let mut flags = old.map_or(2, |record| {
            u16::from_le_bytes(record.1[..2].try_into().unwrap())
        });
        if flags == 1 {
            flags = 2;
        }
        if !matches!(flags, 2 | 10) {
            return Err(unavailable("APFS non-user-embedded xattr mutation"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(value.len() + 4)
            .map_err(|_| budget("APFS embedded xattr bytes"))?;
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value);
        base.catalog.retain(|record| record.0 != k);
        base.catalog.push((k, bytes));
        increment_generation(&mut base.catalog, file)?;
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
    /// Replace a user xattr with a dense deferred external stream.
    pub fn plan_replace_xattr_stream(
        &self,
        id: &ObjectId,
        name: &[u8],
        input: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        xattr_name(name)?;
        let base = self.namespace_base(r)?;
        let file = self.own_xattr_node(id)?;
        let eof = input.len();
        self.external_resource(
            base,
            file,
            input,
            ResourceEdit {
                name: Some(name.to_vec()),
                offset: 0,
                eof,
                truncate: false,
                replace: true,
            },
            r,
        )
    }
    /// Replace bytes within an existing external user xattr, retaining its EOF.
    pub fn plan_range_xattr_stream(
        &self,
        id: &ObjectId,
        name: &[u8],
        offset: u64,
        input: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        xattr_name(name)?;
        let base = self.namespace_base(r)?;
        let file = self.own_xattr_node(id)?;
        let kind = StreamKind::Named(NativeName::Bytes(name.to_vec()));
        let old = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|s| s.kind == kind)
            .ok_or_else(|| invalid("APFS external xattr absent"))?;
        if input.is_empty()
            || offset
                .checked_add(input.len())
                .is_none_or(|end| end > old.length)
        {
            return Err(invalid("APFS external xattr range"));
        }
        self.external_resource(
            base,
            file,
            input,
            ResourceEdit {
                name: Some(name.to_vec()),
                offset,
                eof: old.length,
                truncate: false,
                replace: false,
            },
            r,
        )
    }
    /// Change an existing external user xattr EOF; growth is initialized to zero.
    pub fn plan_truncate_xattr_stream(
        &self,
        id: &ObjectId,
        name: &[u8],
        eof: u64,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        xattr_name(name)?;
        let base = self.namespace_base(r)?;
        let file = self.own_xattr_node(id)?;
        let kind = StreamKind::Named(NativeName::Bytes(name.to_vec()));
        if !self.volume.inner.nodes[&file]
            .streams
            .iter()
            .any(|s| s.kind == kind)
        {
            return Err(invalid("APFS external xattr absent"));
        }
        self.external_resource(
            base,
            file,
            self.empty_input(),
            ResourceEdit {
                name: Some(name.to_vec()),
                offset: 0,
                eof,
                truncate: true,
                replace: false,
            },
            r,
        )
    }
    /// Remove a present user xattr, retiring its external allocation if present.
    pub fn plan_remove_xattr(
        &self,
        id: &ObjectId,
        name: &[u8],
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        xattr_name(name)?;
        let mut base = self.namespace_base(r)?;
        let file = self.own_xattr_node(id)?;
        let k = xattr_key(file, name);
        let record = base
            .catalog
            .iter()
            .find(|record| record.0 == k)
            .ok_or_else(|| invalid("APFS xattr absent"))?;
        if !matches!(
            u16::from_le_bytes(record.1[..2].try_into().unwrap()),
            1 | 2 | 10
        ) {
            return Err(unavailable("APFS non-user-embedded xattr removal"));
        }
        base.catalog.retain(|record| record.0 != k);
        increment_generation(&mut base.catalog, file)?;
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
    fn own_xattr_node(&self, id: &ObjectId) -> Result<u64> {
        let raw: [u8; 8] = id
            .native
            .as_slice()
            .try_into()
            .map_err(|_| invalid("APFS xattr identity length"))?;
        let file = u64::from_be_bytes(raw);
        let directory = self
            .volume
            .inner
            .nodes
            .get(&file)
            .ok_or_else(|| invalid("APFS xattr object absent"))?
            .directory;
        self.own_node(id, directory)
    }
    /// Replace or create an embedded native resource fork (at most 3804 bytes).
    /// Inline bytes are metadata: bounded input is read during planning, while
    /// its immutable identity/length and cancellation binding survive commit.
    pub fn plan_replace_resource_fork(
        &self,
        id: &ObjectId,
        input: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        if input.len() > 3804 {
            let base = self.namespace_base(r)?;
            let file = self.own_node(id, false)?;
            let eof = input.len();
            return self.external_resource(
                base,
                file,
                input,
                ResourceEdit {
                    name: None,
                    offset: 0,
                    eof,
                    truncate: false,
                    replace: true,
                },
                r,
            );
        }
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        let inline = self.resource_input(&input, r)?;
        base.binding = Some(inline.binding);
        self.project_resource(&mut base.catalog, file, inline.bytes)?;
        self.namespace_finish(base, Vec::new(), input, 0, None, r)
    }
    /// Replace an existing resource-fork range without changing its EOF.
    pub fn plan_range_resource_fork(
        &self,
        id: &ObjectId,
        offset: u64,
        input: Arc<dyn FileRead>,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        if input.is_empty() {
            return Err(invalid("APFS empty resource-fork range"));
        }
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        if let Some(stream) = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|s| s.kind == StreamKind::ResourceFork && s.inline.is_none())
        {
            let end = offset
                .checked_add(input.len())
                .filter(|end| *end <= stream.length)
                .ok_or_else(|| invalid("APFS resource range exceeds EOF"))?;
            if end == offset {
                return Err(invalid("APFS empty resource range"));
            }
            return self.external_resource(
                base,
                file,
                input,
                ResourceEdit {
                    name: None,
                    offset,
                    eof: stream.length,
                    truncate: false,
                    replace: false,
                },
                r,
            );
        }
        let mut bytes = self.inline_resource(file)?;
        let end = offset
            .checked_add(input.len())
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| invalid("APFS resource-fork range exceeds unchanged EOF"))?;
        let inline = self.resource_input(&input, r)?;
        if inline.binding.1 != end - offset {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS resource-fork range input length changed",
            ));
        }
        bytes[offset as usize..end as usize].copy_from_slice(&inline.bytes);
        base.binding = Some(inline.binding);
        self.project_resource(&mut base.catalog, file, bytes)?;
        self.namespace_finish(base, Vec::new(), input, 0, None, r)
    }
    /// Change an embedded resource-fork EOF, zeroing newly exposed bytes.
    /// Zero EOF retains a present empty native resource fork.
    pub fn plan_truncate_resource_fork(
        &self,
        id: &ObjectId,
        eof: u64,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        if self.volume.inner.nodes[&file]
            .streams
            .iter()
            .any(|s| s.kind == StreamKind::ResourceFork && s.inline.is_none())
        {
            return self.external_resource(
                base,
                file,
                self.empty_input(),
                ResourceEdit {
                    name: None,
                    offset: 0,
                    eof,
                    truncate: true,
                    replace: false,
                },
                r,
            );
        }
        if eof > 3804 {
            let bytes = self.inline_resource(file)?;
            let input: Arc<dyn FileRead> = Arc::new(EmbeddedGrowth {
                id: id.clone(),
                bytes,
                length: eof,
            });
            return self.external_resource(
                base,
                file,
                input,
                ResourceEdit {
                    name: None,
                    offset: 0,
                    eof,
                    truncate: false,
                    replace: true,
                },
                r,
            );
        }
        let mut bytes = self.inline_resource(file)?;
        if eof == bytes.len() as u64 {
            return Err(invalid("APFS unchanged resource-fork EOF"));
        }
        bytes
            .try_reserve_exact((eof as usize).saturating_sub(bytes.len()))
            .map_err(|_| budget("APFS bounded resource-fork projection"))?;
        bytes.resize(eof as usize, 0);
        self.project_resource(&mut base.catalog, file, bytes)?;
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
    fn external_resource(
        &self,
        mut base: Base,
        file: u64,
        input: Arc<dyn FileRead>,
        edit: ResourceEdit,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let ResourceEdit {
            name,
            offset,
            eof,
            truncate,
            replace,
        } = edit;
        let count = eof.div_ceil(BLOCK as u64);
        if count > self.limits.read.blocks || count > base.free.len().saturating_sub(8) as u64 {
            return Err(budget("APFS resource allocation cap"));
        }
        if input.identity().native.len() > 4096 {
            return Err(budget("APFS resource identity cap"));
        }
        let kind = match &name {
            Some(name) => StreamKind::Named(NativeName::Bytes(name.clone())),
            None => StreamKind::ResourceFork,
        };
        let old = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|s| s.kind == kind);
        if truncate && old.is_none_or(|s| s.length == eof) {
            return Err(invalid("APFS unchanged resource EOF"));
        }
        let old_eof = old.map_or(0, |s| s.length);
        let stream_id = match old.filter(|s| s.inline.is_none()) {
            Some(s) => s.id,
            None => next_id(&mut base.next)?,
        };
        let input_length = input.len();
        let binding = (input.identity().clone(), input_length);
        let end = offset
            .checked_add(input_length)
            .filter(|end| *end <= eof)
            .ok_or_else(|| invalid("APFS external resource input range"))?;
        base.binding = Some(binding);
        base.catalog.retain(|record| {
            !(u64le(&record.0, 0) >> 60 == 8
                && u64le(&record.0, 0) & 0x0fffffffffffffff == stream_id)
        });
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(count as usize)
            .map_err(|_| budget("APFS resource recipes"))?;
        for logical in (0..count).map(|n| n * BLOCK as u64) {
            r.cancellation.check()?;
            self.snapshot.work.charge(1)?;
            let previous = old
                .and_then(|s| {
                    s.runs
                        .iter()
                        .find(|run| run.logical <= logical && logical < run.logical + run.length)
                })
                .map_or(0, |run| {
                    run.physical + (logical - run.logical) / BLOCK as u64
                });
            let changed = replace
                || previous == 0
                || (!truncate && logical < end && logical + BLOCK as u64 > offset)
                || (truncate && logical + BLOCK as u64 > old_eof.min(eof));
            let physical = if changed {
                let physical = base.free[payload.len()];
                payload.push(Payload {
                    logical,
                    physical,
                    previous: if replace { 0 } else { previous },
                });
                physical
            } else {
                previous
            };
            let mut k = key(stream_id, 8);
            k.extend_from_slice(&logical.to_le_bytes());
            let mut v = vec![0; 24];
            q(&mut v, 0, BLOCK as u64);
            q(&mut v, 8, physical);
            base.catalog.push((k, v));
        }
        let mut k = key(file, 4);
        let mut native_name = name
            .clone()
            .unwrap_or_else(|| b"com.apple.ResourceFork".to_vec());
        native_name.push(0);
        let name = native_name.as_slice();
        k.extend_from_slice(&(name.len() as u16).to_le_bytes());
        k.extend_from_slice(name);
        let old_value = base
            .catalog
            .iter()
            .find(|record| record.0 == k)
            .map(|record| record.1.clone());
        if old_value
            .as_ref()
            .is_some_and(|v| u16::from_le_bytes(v[..2].try_into().unwrap()) & 8 != 0)
        {
            return Err(unavailable("APFS reserved xattr flag external conversion"));
        }
        let mut value = vec![0; 52];
        w(&mut value, 0, 1);
        let header_size = old_value
            .as_ref()
            .filter(|v| v.len() == 52 && u16::from_le_bytes(v[..2].try_into().unwrap()) == 1)
            .map_or(48, |v| u16::from_le_bytes(v[2..4].try_into().unwrap()));
        w(&mut value, 2, header_size);
        q(&mut value, 4, stream_id);
        q(&mut value, 12, eof);
        q(&mut value, 20, count * BLOCK as u64);
        let written = old_value
            .as_ref()
            .filter(|v| v.len() == 52 && u16::from_le_bytes(v[..2].try_into().unwrap()) == 1)
            .map_or(0, |v| u64le(v, 36));
        q(
            &mut value,
            36,
            written
                .checked_add(input_length)
                .ok_or_else(|| budget("APFS resource write counter"))?,
        );
        if let Some(v) = old_value
            .as_ref()
            .filter(|v| v.len() == 52 && u16::from_le_bytes(v[..2].try_into().unwrap()) == 1)
        {
            q(&mut value, 44, u64le(v, 44));
        }
        base.catalog.retain(|record| record.0 != k);
        base.catalog.push((k, value));
        let at = inode_index(&base.catalog, file)?;
        let raw = &mut base.catalog[at].1;
        if name == b"com.apple.ResourceFork\0" {
            let flags = (u64le(raw, 48) | 0x4000) & !0x8000;
            q(raw, 48, flags);
        }
        let generation = u32le(raw, 64)
            .checked_add(1)
            .ok_or_else(|| budget("APFS resource generation"))?;
        d(raw, 64, generation);
        self.namespace_finish_at(
            base,
            payload,
            input,
            (offset, eof),
            if truncate {
                Some(old_eof.min(eof))
            } else {
                None
            },
            r,
        )
    }
    /// Remove a present resource fork, distinct from truncating it to zero.
    pub fn plan_remove_resource_fork(
        &self,
        id: &ObjectId,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        if !self.volume.inner.nodes[&file]
            .streams
            .iter()
            .any(|s| s.kind == StreamKind::ResourceFork)
        {
            return Err(invalid("APFS resource fork absent"));
        }
        base.catalog.retain(|record| {
            !(u64le(&record.0, 0) == (4u64 << 60 | file)
                && record.0[10..] == *b"com.apple.ResourceFork\0")
        });
        let at = inode_index(&base.catalog, file)?;
        let raw = &mut base.catalog[at].1;
        let flags = (u64le(raw, 48) & !0x4000) | 0x8000;
        q(raw, 48, flags);
        let generation = u32le(raw, 64)
            .checked_add(1)
            .ok_or_else(|| budget("APFS resource-fork write generation"))?;
        d(raw, 64, generation);
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
    fn inline_resource(&self, file: u64) -> Result<Vec<u8>> {
        let stream = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|stream| stream.kind == StreamKind::ResourceFork)
            .ok_or_else(|| invalid("APFS resource fork absent"))?;
        let bytes = stream
            .inline
            .as_ref()
            .ok_or_else(|| unavailable("APFS external resource-fork mutation"))?;
        if bytes.len() > 3804 {
            return Err(invalid("APFS native embedded resource-fork limit"));
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(bytes.len())
            .map_err(|_| budget("APFS resource-fork copy"))?;
        copy.extend_from_slice(bytes);
        Ok(copy)
    }
    fn resource_input(&self, input: &Arc<dyn FileRead>, r: &Resources) -> Result<InlineInput> {
        self.snapshot.work.resources.cancellation.check()?;
        r.cancellation.check()?;
        let length = input.len();
        if length > 3804 || input.identity().native.len() > 4096 {
            return Err(budget("APFS bounded resource-fork input"));
        }
        let identity = input.identity().clone();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length as usize)
            .map_err(|_| budget("APFS resource-fork metadata input"))?;
        bytes.resize(length as usize, 0);
        let mut done = 0;
        while done < bytes.len() {
            self.snapshot.work.resources.cancellation.check()?;
            r.cancellation.check()?;
            if input.identity() != &identity || input.len() != length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "APFS resource-fork input changed",
                ));
            }
            self.snapshot.work.charge((bytes.len() - done) as u64)?;
            let count = input.read_at(done as u64, &mut bytes[done..], r)?;
            if count == 0 || count > bytes.len() - done {
                return Err(Error::io(
                    "APFS resource-fork short input",
                    io::ErrorKind::UnexpectedEof.into(),
                ));
            }
            done += count;
        }
        self.snapshot.work.resources.cancellation.check()?;
        r.cancellation.check()?;
        if input.identity() != &identity || input.len() != length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "APFS resource-fork input changed",
            ));
        }
        Ok(InlineInput {
            bytes,
            binding: (identity, length),
        })
    }
    fn project_resource(&self, catalog: &mut Records, file: u64, bytes: Vec<u8>) -> Result<()> {
        if bytes.len() > 3804 {
            return Err(invalid("APFS native embedded resource-fork limit"));
        }
        let mut resource_key = key(file, 4);
        let name = b"com.apple.ResourceFork\0";
        resource_key.extend_from_slice(&(name.len() as u16).to_le_bytes());
        resource_key.extend_from_slice(name);
        let mut value = Vec::new();
        value
            .try_reserve_exact(4 + bytes.len())
            .map_err(|_| budget("APFS embedded resource-fork record"))?;
        value.extend_from_slice(&2u16.to_le_bytes());
        value.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        value.extend_from_slice(&bytes);
        if let Some(record) = catalog.iter_mut().find(|record| record.0 == resource_key) {
            record.1 = value;
        } else {
            catalog
                .try_reserve(1)
                .map_err(|_| budget("APFS resource-fork catalog entry"))?;
            catalog.push((resource_key, value));
        }
        let at = inode_index(catalog, file)?;
        let raw = &mut catalog[at].1;
        if name == b"com.apple.ResourceFork\0" {
            let flags = (u64le(raw, 48) | 0x4000) & !0x8000;
            q(raw, 48, flags);
        }
        let generation = u32le(raw, 64)
            .checked_add(1)
            .ok_or_else(|| budget("APFS resource-fork write generation"))?;
        d(raw, 64, generation);
        Ok(())
    }
    /// Change DATA EOF, retaining old history and zeroing any newly exposed boundary bytes.
    pub fn plan_truncate(
        &self,
        id: &ObjectId,
        eof: u64,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        let stream = self.volume.inner.nodes[&file]
            .streams
            .iter()
            .find(|s| s.kind == StreamKind::Data)
            .ok_or_else(|| invalid("APFS DATA absent"))?;
        if eof == stream.length {
            return Err(invalid("APFS unchanged truncate length"));
        }
        let count = eof.div_ceil(BLOCK as u64);
        if count > self.limits.read.blocks {
            return Err(budget("APFS truncate DATA cap"));
        }
        let data_id = detach_data_stream(&mut base.catalog, file, &mut base.next)?;
        base.catalog.retain(|r| {
            !(u64le(&r.0, 0) >> 60 == 8 && u64le(&r.0, 0) & 0x0fffffffffffffff == data_id)
        });
        let mut payload = Vec::new();
        let mut sparse = 0;
        for logical in (0..count).map(|n| n * BLOCK as u64) {
            r.cancellation.check()?;
            self.snapshot.work.charge(1)?;
            let old = stream
                .runs
                .iter()
                .find(|s| s.logical <= logical && logical < s.logical + s.length);
            let mut physical = if logical >= stream.length {
                0
            } else {
                old.map_or(0, |s| {
                    if s.physical == 0 {
                        0
                    } else {
                        s.physical + (logical - s.logical) / BLOCK as u64
                    }
                })
            };
            let boundary = physical != 0
                && (logical < eof && eof < logical + BLOCK as u64
                    || logical < stream.length
                        && stream.length < logical + BLOCK as u64
                        && eof > stream.length);
            if boundary {
                if payload.len() + 8 >= base.free.len() {
                    return Err(budget("APFS truncate physical cap"));
                }
                let previous = physical;
                physical = base.free[payload.len()];
                payload.push(Payload {
                    logical,
                    physical,
                    previous,
                });
            }
            if physical == 0 {
                sparse += BLOCK as u64;
            }
            let mut k = key(data_id, 8);
            k.extend_from_slice(&logical.to_le_bytes());
            let mut v = vec![0; 24];
            q(&mut v, 0, BLOCK as u64);
            q(&mut v, 8, physical);
            base.catalog.push((k, v));
        }
        self.update_data_inode(
            &mut base.catalog,
            file,
            eof,
            count * BLOCK as u64,
            sparse,
            0,
        )?;
        self.namespace_finish(
            base,
            payload,
            self.empty_input(),
            eof,
            Some(eof.min(stream.length)),
            r,
        )
    }
    /// Add an exact native regular-file alias, maintaining sibling identities and link counts.
    pub fn plan_hardlink(
        &self,
        id: &ObjectId,
        parent: &ObjectId,
        name: &[u8],
        timestamp: u64,
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let file = self.own_node(id, false)?;
        let parent = self.own_node(parent, true)?;
        name_valid(name)?;
        collision(&base.catalog, parent, name)?;
        base.catalog
            .push((name_key(parent, name), drec(file, timestamp, false, None)));
        links(&mut base.catalog, file, &mut base.next)?;
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
    /// Rename or move one native occurrence, refusing destination collisions and directory cycles.
    pub fn plan_rename(
        &self,
        parent: &ObjectId,
        name: &[u8],
        new_parent: &ObjectId,
        new_name: &[u8],
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let parent = self.own_node(parent, true)?;
        let new_parent = self.own_node(new_parent, true)?;
        name_valid(name)?;
        name_valid(new_name)?;
        collision(&base.catalog, new_parent, new_name)?;
        let at = occurrence(&base.catalog, parent, name)?;
        let id = u64le(&base.catalog[at].1, 0);
        if id == 3 {
            return Err(invalid("APFS private directory immutable"));
        }
        let node = self
            .volume
            .inner
            .nodes
            .get(&id)
            .ok_or_else(|| invalid("APFS rename target absent"))?;
        if u32le(&node.raw, 68) != 0 {
            return Err(unavailable("APFS BSD rename flags"));
        }
        if node.directory {
            let mut cursor = new_parent;
            let mut seen = BTreeSet::new();
            loop {
                self.snapshot.work.charge(1)?;
                r.cancellation.check()?;
                if cursor == id || !seen.insert(cursor) {
                    return Err(invalid("APFS directory move cycle"));
                }
                if cursor == 2 {
                    break;
                }
                let ancestor = self
                    .volume
                    .inner
                    .nodes
                    .get(&cursor)
                    .ok_or_else(|| invalid("APFS directory parent absent"))?;
                cursor = u64le(&ancestor.raw, 0);
                if seen.len() > self.limits.read.records {
                    return Err(budget("APFS move ancestry cap"));
                }
            }
        }
        base.catalog[at].0 = name_key(new_parent, new_name);
        if node.directory {
            let i = inode_index(&base.catalog, id)?;
            q(&mut base.catalog[i].1, 0, new_parent);
            let mut fs = fields(&base.catalog[i].1);
            let mut name = new_name.to_vec();
            name.push(0);
            field_set(&mut fs, 4, 2, Some(name));
            put_fields(&mut base.catalog[i].1, fs)?;
        } else {
            links(&mut base.catalog, id, &mut base.next)?;
        }
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
    /// Remove one occurrence; last-link DATA retirement is native, and directories must be empty.
    pub fn plan_unlink(
        &self,
        parent: &ObjectId,
        name: &[u8],
        r: &Resources,
    ) -> Result<ApfsMutationPlan> {
        let mut base = self.namespace_base(r)?;
        let parent = self.own_node(parent, true)?;
        name_valid(name)?;
        let at = occurrence(&base.catalog, parent, name)?;
        let id = u64le(&base.catalog[at].1, 0);
        if id == 2 || id == 3 {
            return Err(invalid("APFS root/private directory immutable"));
        }
        let node = &self.volume.inner.nodes[&id];
        if u32le(&node.raw, 68) != 0 {
            return Err(unavailable("APFS BSD unlink flags"));
        }
        if node.directory && !node.entries.is_empty() {
            return Err(invalid("APFS directory not empty"));
        }
        base.catalog.remove(at);
        let remaining = base
            .catalog
            .iter()
            .any(|r| u64le(&r.0, 0) >> 60 == 9 && u64le(&r.1, 0) == id);
        if remaining {
            links(&mut base.catalog, id, &mut base.next)?;
        } else {
            base.catalog.retain(|r| {
                !(u64le(&r.0, 0) & 0x0fffffffffffffff == id
                    && matches!(u64le(&r.0, 0) >> 60, 3..=5)
                    || u64le(&r.0, 0) >> 60 == 12 && u64le(&r.1, 0) == id)
            });
            if node.directory {
                base.dirs = base
                    .dirs
                    .checked_sub(1)
                    .ok_or_else(|| invalid("APFS directory counter"))?;
            } else {
                base.files = base
                    .files
                    .checked_sub(1)
                    .ok_or_else(|| invalid("APFS file counter"))?;
            }
        }
        self.namespace_finish(base, Vec::new(), self.empty_input(), 0, None, r)
    }
}
