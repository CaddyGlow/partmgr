//! Fresh native allocation and B-tree layout, without a source image.
use super::*;
use std::collections::BTreeMap;
pub(super) struct Payload {
    pub input: usize,
    pub logical: u64,
    pub physical: u64,
}
pub(super) struct ForkPatch {
    pub input: usize,
    pub block: u64,
    pub offset: usize,
    pub length: usize,
}
pub(super) struct Layout {
    pub raw_bitmaps: Vec<u64>,
    pub metadata: BTreeMap<u64, Vec<u8>>,
    pub payload: Vec<Payload>,
    pub forks: Vec<ForkPatch>,
    pub allocated: u64,
    pub volume_allocated: u64,
}
#[derive(Clone, Copy)]
struct Geometry {
    capacity: ApfsCheckpointCapacity,
    data_base: u64,
    metadata_base: u64,
    pool_base: u64,
    prefix: u64,
    chunks: u64,
}
impl Geometry {
    fn new(capacity: ApfsCheckpointCapacity, blocks: u64) -> Self {
        let data_base = 1 + u64::from(capacity.descriptor_blocks);
        let metadata_base = data_base + u64::from(capacity.data_blocks);
        let pool_base = metadata_base + 24;
        let chunks = blocks.div_ceil(32768);
        let prefix = pool_base + 3 * (chunks + 1);
        Self {
            capacity,
            data_base,
            metadata_base,
            pool_base,
            prefix,
            chunks,
        }
    }
    fn at(self, old: u64) -> u64 {
        match old {
            9..=16 => self.data_base + old - 9,
            17..=40 => self.metadata_base + old - 17,
            41..=46 => self.pool_base + old - 41,
            _ => old,
        }
    }
}
struct Alloc {
    geometry: Geometry,
    blocks: u64,
    next: u64,
    virtual_id: u64,
    metadata: BTreeMap<u64, Vec<u8>>,
    used: Vec<bool>,
    forks: Vec<ForkPatch>,
}
impl Alloc {
    fn at(&self, old: u64) -> u64 {
        self.geometry.at(old)
    }
    fn physical(&mut self, work: &mut Work, r: &Resources) -> Result<u64> {
        work.tick(1, r)?;
        if self.next >= self.blocks {
            return Err(budget("APFS target has insufficient blocks"));
        }
        let at = self.next;
        self.next += 1;
        self.used[at as usize] = true;
        Ok(at)
    }
    fn put(&mut self, at: u64, b: Vec<u8>) -> Result<()> {
        if at >= self.blocks || b.len() != BLOCK || self.metadata.insert(at, b).is_some() {
            return Err(invalid("APFS duplicate metadata allocation"));
        }
        Ok(())
    }
    fn page(&mut self, at: u64, f: NodeFields, records: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let leaf = f.level == 0;
        let b = node(f, records)?;
        let end = BLOCK
            - if u16::from_le_bytes(b[32..34].try_into().unwrap()) & 1 != 0 {
                40
            } else {
                0
            };
        for (i, (k, v)) in records.iter().enumerate() {
            let header = u64::from_le_bytes(k[..8].try_into().unwrap());
            if leaf && header >> 60 == 4 && k.get(10..) == Some(b"com.apple.ResourceFork\0") {
                let id = header & 0x0fff_ffff_ffff_ffff;
                let t = 56 + i * 8;
                let reverse = u16::from_le_bytes(b[t + 4..t + 6].try_into().unwrap()) as usize;
                self.forks.push(ForkPatch {
                    input: usize::try_from(id - 15).map_err(|_| budget("APFS fork index"))?,
                    block: at,
                    offset: end - reverse + 4,
                    length: v.len() - 4,
                });
            }
        }
        self.put(at, b)
    }
    fn tree(
        &mut self,
        format: (u64, u64, u32, u32),
        records: Records,
        work: &mut Work,
        r: &Resources,
    ) -> Result<Vec<(u64, u64)>> {
        let (root, id, storage, subtype) = format;
        let fixed = if subtype == 11 { Some((16, 16)) } else { None };
        let maxk = records.iter().map(|x| x.0.len()).max().unwrap_or(0);
        let maxv = records.iter().map(|x| x.1.len()).max().unwrap_or(0);
        let count = records.len() as u64;
        let size = |rs: &[(Vec<u8>, Vec<u8>)]| {
            rs.iter()
                .map(|(k, v)| k.len() + v.len() + if fixed.is_some() { 4 } else { 8 })
                .sum::<usize>()
        };
        let mut mappings = vec![(id, root)];
        if size(&records) <= BLOCK - 96 {
            work.tick(BLOCK as u64, r)?;
            self.page(
                root,
                NodeFields {
                    id,
                    storage,
                    subtype,
                    level: 0,
                    root: true,
                    fixed,
                    totals: (count, 1, maxk, maxv),
                },
                &records,
            )?;
            return Ok(mappings);
        }
        let mut records = records;
        let mut level = 0u16;
        let mut nodes = 1u64;
        loop {
            work.tick(records.len() as u64, r)?;
            if level >= 8 {
                return Err(budget("APFS authored B-tree depth"));
            }
            let mut parents = Vec::new();
            let mut start = 0;
            while start < records.len() {
                let mut end = start;
                let mut occupied = 0;
                while end < records.len() {
                    let cost = records[end].0.len()
                        + records[end].1.len()
                        + if fixed.is_some() { 4 } else { 8 };
                    if cost > BLOCK - 96 {
                        return Err(unsupported("APFS record exceeds supported native node"));
                    }
                    if occupied + cost > BLOCK - 96 {
                        break;
                    }
                    occupied += cost;
                    end += 1;
                }
                let at = self.physical(work, r)?;
                let child = if storage == 0 {
                    let n = self.virtual_id;
                    self.virtual_id += 1;
                    n
                } else {
                    at
                };
                if storage == 0 {
                    mappings.push((child, at));
                }
                work.tick(BLOCK as u64, r)?;
                self.page(
                    at,
                    NodeFields {
                        id: child,
                        storage,
                        subtype,
                        level,
                        root: false,
                        fixed,
                        totals: (0, 0, 0, 0),
                    },
                    &records[start..end],
                )?;
                parents.push((records[start].0.clone(), child.to_le_bytes().to_vec()));
                nodes += 1;
                start = end;
            }
            level += 1;
            if size(&parents) <= BLOCK - 96 {
                work.tick(BLOCK as u64, r)?;
                self.page(
                    root,
                    NodeFields {
                        id,
                        storage,
                        subtype,
                        level,
                        root: true,
                        fixed,
                        totals: (count, nodes, maxk, maxv),
                    },
                    &parents,
                )?;
                return Ok(mappings);
            }
            records = parents;
        }
    }
}
fn object_map(id: u64, tree: u64, manually_managed: bool) -> Result<Vec<u8>> {
    let mut b = object(id, 0x4000000b, 0)?;
    d(&mut b, 32, u32::from(manually_managed));
    d(&mut b, 40, 0x40000002);
    d(&mut b, 44, 0x40000002);
    q(&mut b, 48, tree);
    seal(&mut b);
    Ok(b)
}
fn map_records(mappings: &[(u64, u64)]) -> Records {
    let mut records = Vec::new();
    for &(id, at) in mappings {
        let mut k = id.to_le_bytes().to_vec();
        k.extend_from_slice(&1u64.to_le_bytes());
        let mut v = vec![0; 16];
        d(&mut v, 4, BLOCK as u32);
        q(&mut v, 8, at);
        records.push((k, v));
    }
    records.sort_by_key(|x| u64::from_le_bytes(x.0[..8].try_into().unwrap()));
    records
}
fn native_inode(index: usize) -> u64 {
    if index == 0 { 2 } else { index as u64 + 15 }
}
pub(super) fn construct(
    inv: &Inventory,
    o: &ApfsBuildOptions,
    capacity: ApfsCheckpointCapacity,
    r: &Resources,
    work: &mut Work,
) -> Result<Layout> {
    let blocks = o.image_bytes / BLOCK as u64;
    if !o.image_bytes.is_multiple_of(BLOCK as u64)
        || !(256..=131073).contains(&blocks)
        || blocks > o.limits.blocks
    {
        return Err(invalid(
            "APFS authoring single-CIB geometry outside profile",
        ));
    }
    if o.volume_label.is_empty()
        || o.volume_label.len() > 255
        || o.volume_label.contains(&0)
        || std::str::from_utf8(&o.volume_label).is_err()
    {
        return Err(invalid("APFS native volume label"));
    }
    let geometry = Geometry::new(capacity, blocks);
    if geometry.prefix >= blocks {
        return Err(budget("APFS native reserved capacity exceeds image"));
    }
    let mut used = Vec::new();
    used.try_reserve_exact(blocks as usize)
        .map_err(|_| budget("APFS allocation map"))?;
    used.resize(blocks as usize, false);
    used[..geometry.prefix as usize].fill(true);
    let mut a = Alloc {
        geometry,
        blocks,
        next: geometry.prefix,
        virtual_id: 2048,
        metadata: BTreeMap::new(),
        used,
        forks: Vec::new(),
    };
    let record_cap = o
        .limits
        .objects
        .checked_mul(4)
        .and_then(|n| n.checked_add(o.limits.occurrences.checked_mul(3)?))
        .and_then(|n| n.checked_add(usize::try_from(o.limits.blocks).ok()?))
        .ok_or_else(|| budget("APFS record capacity overflow"))?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_cap)
        .map_err(|_| budget("APFS catalog record allocation"))?;
    let mut physical = Vec::new();
    physical
        .try_reserve_exact(o.limits.blocks as usize)
        .map_err(|_| budget("APFS physical record allocation"))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(o.limits.blocks as usize)
        .map_err(|_| budget("APFS deferred payload map allocation"))?;
    let mut aliases = vec![Vec::new(); inv.inputs.len()];
    for (parent, input) in inv.inputs.iter().enumerate() {
        for (name, &child) in input.children.iter().map(|(n, c)| (n, c)) {
            aliases[child].push((parent, name.clone()));
        }
    }
    let defaults = inv.defaults;
    for (id, name) in [(2, b"root".as_slice()), (3, b"private-dir".as_slice())] {
        records.push(directory(1, id, name, true, defaults.timestamp, None)?);
    }
    records.push((
        key(3, 3),
        inode(
            1,
            3,
            b"private-dir",
            InodeFields {
                mode: 0x4000 | defaults.directory_permissions,
                uid: defaults.uid,
                gid: defaults.gid,
                timestamp: defaults.timestamp,
                links: 0,
                stream: None,
                sparse: 0,
                resource: false,
            },
        )?,
    ));
    let mut sibling = 16u64
        .checked_add(inv.inputs.len() as u64)
        .ok_or_else(|| budget("APFS sibling ID overflow"))?;
    let (mut files, mut directories) = (0u64, 0u64);
    let mut logical_blocks = 0u64;
    for (index, input) in inv.inputs.iter().enumerate() {
        work.tick(1, r)?;
        let id = native_inode(index);
        let mut allocated = 0;
        let mut sparse = 0;
        if input.directory {
            directories += u64::from(index != 0);
        } else {
            files += 1;
        }
        let size = input.data.as_ref().map_or(0, |f| f.len());
        if !input.directory {
            let mut at = 0u64;
            let mut extent_index = 0;
            while at < size {
                work.tick(1, r)?;
                logical_blocks = logical_blocks
                    .checked_add(1)
                    .ok_or_else(|| budget("APFS logical block map overflow"))?;
                if logical_blocks > o.limits.blocks {
                    return Err(budget("APFS total logical block map ceiling"));
                }
                let length = (size - at).min(BLOCK as u64);
                allocated += BLOCK as u64;
                while extent_index < input.extents.len()
                    && input.extents[extent_index].offset + input.extents[extent_index].length <= at
                {
                    extent_index += 1;
                }
                let hole = input.extents.get(extent_index).is_some_and(|e| {
                    matches!(e.kind, ExtentKind::Hole)
                        && e.offset <= at
                        && e.offset + e.length >= at + length
                });
                let block = if hole {
                    sparse += BLOCK as u64;
                    0
                } else {
                    let block = a.physical(work, r)?;

                    payload.push(Payload {
                        input: index,
                        logical: at,
                        physical: block,
                    });
                    block
                };
                let mut k = key(id, 8);
                k.extend_from_slice(&at.to_le_bytes());
                let mut v = zero(24)?;
                q(&mut v, 0, BLOCK as u64);
                q(&mut v, 8, block);
                records.push((k, v));
                if block != 0 {
                    let mut v = zero(20)?;
                    q(&mut v, 0, (1u64 << 60) | 1);
                    q(&mut v, 8, id);
                    d(&mut v, 16, 1);
                    physical.push((key(block, 2), v));
                }
                at = at
                    .checked_add(BLOCK as u64)
                    .ok_or_else(|| budget("APFS payload length overflow"))?;
            }
            records.push((key(id, 6), 1u32.to_le_bytes().to_vec()));
        }
        let fork_length = input.fork.as_ref().map_or(0, |f| f.len());
        if fork_length > 2048 {
            return Err(unsupported(
                "APFS resource fork exceeds initial embedded authoring profile",
            ));
        }
        let resource = input.fork.is_some();
        if resource {
            let mut value = zero(4 + fork_length as usize)?;
            w(&mut value, 0, 2);
            w(&mut value, 2, fork_length as u16);
            records.push((name_key(id, 4, b"com.apple.ResourceFork")?, value));
        }
        let primary_parent = if index == 0 {
            1
        } else {
            native_inode(input.parent)
        };
        let links = if input.directory {
            input.children.len() as u32
        } else {
            aliases[index].len() as u32
        };
        records.push((
            key(id, 3),
            inode(
                primary_parent,
                id,
                &input.primary,
                InodeFields {
                    mode: if input.directory {
                        0x4000 | defaults.directory_permissions
                    } else {
                        0x8000 | defaults.file_permissions
                    },
                    uid: defaults.uid,
                    gid: defaults.gid,
                    timestamp: defaults.timestamp,
                    links,
                    stream: if input.directory {
                        None
                    } else {
                        Some((size, allocated, id))
                    },
                    sparse,
                    resource,
                },
            )?,
        ));
        for (parent, name) in &aliases[index] {
            let parent = native_inode(*parent);
            let link = if !input.directory && aliases[index].len() > 1 {
                let link = sibling;
                sibling += 1;
                Some(link)
            } else {
                None
            };
            records.push(directory(
                parent,
                id,
                name,
                input.directory,
                defaults.timestamp,
                link,
            )?);
            if let Some(link) = link {
                let mut k = key(id, 5);
                k.extend_from_slice(&link.to_le_bytes());
                let mut v = parent.to_le_bytes().to_vec();
                v.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
                v.extend_from_slice(name);
                v.push(0);
                records.push((k, v));
                records.push((key(link, 12), id.to_le_bytes().to_vec()));
            }
        }
    }
    for n in [records.len(), physical.len()] {
        let n = n as u64;
        work.tick(
            n.checked_mul(u64::from(n.max(1).ilog2()) + 1)
                .ok_or_else(|| budget("APFS sorting work overflow"))?,
            r,
        )?;
    }
    records.sort_by(|a, b| compare(&a.0, &b.0));
    physical.sort_by(|a, b| compare(&a.0, &b.0));
    let catalog = a.tree((a.at(22), 1027, 0, 14), records, work, r)?;
    a.tree((a.at(23), a.at(23), 0x40000000, 15), physical, work, r)?;
    a.tree((a.at(24), a.at(24), 0x40000000, 16), Vec::new(), work, r)?;
    a.tree(
        (a.at(21), a.at(21), 0x40000000, 11),
        map_records(&catalog),
        work,
        r,
    )?;
    a.tree(
        (a.at(18), a.at(18), 0x40000000, 11),
        map_records(&[(1026, a.at(19))]),
        work,
        r,
    )?;
    a.put(a.at(17), object_map(a.at(17), a.at(18), true)?)?;
    a.put(a.at(20), object_map(a.at(20), a.at(21), false)?)?;
    let volume_allocated = a
        .metadata
        .keys()
        .filter(|&&at| (20..=24).any(|old| at == a.at(old)) || at >= a.geometry.prefix)
        .count() as u64
        + payload.len() as u64;
    let mut vol = object(1026, 13, 0)?;
    vol[32..36].copy_from_slice(b"APSB");
    q(&mut vol, 40, 2);
    q(&mut vol, 88, volume_allocated);
    w(&mut vol, 96, 5);
    d(&mut vol, 104, 6);
    w(&mut vol, 112, 1);
    d(&mut vol, 116, 2);
    d(&mut vol, 120, 0x40000002);
    d(&mut vol, 124, 0x40000002);
    q(&mut vol, 128, a.at(20));
    q(&mut vol, 136, 1027);
    q(&mut vol, 144, a.at(23));
    q(&mut vol, 152, a.at(24));
    q(&mut vol, 176, sibling.max(16));
    q(&mut vol, 184, files);
    q(&mut vol, 192, directories);
    vol[240..256].copy_from_slice(&o.volume_uuid);
    q(&mut vol, 264, 1);
    vol[272..279].copy_from_slice(b"partmgr");
    q(&mut vol, 304, defaults.timestamp);
    q(&mut vol, 312, 1);
    vol[704..704 + o.volume_label.len()].copy_from_slice(&o.volume_label);
    d(&mut vol, 960, 16);
    seal(&mut vol);
    a.put(a.at(19), vol)?;
    let allocated = a.used.iter().filter(|x| **x).count() as u64;
    superblock(&mut a, o, allocated, work, r)?;
    let mut raw_bitmaps = Vec::new();
    raw_bitmaps
        .try_reserve_exact(a.geometry.chunks as usize + 1)
        .map_err(|_| budget("APFS raw bitmap index"))?;
    raw_bitmaps.push(a.at(25));
    for chunk in 0..a.geometry.chunks {
        raw_bitmaps.push(a.geometry.pool_base + if chunk == 0 { 0 } else { chunk + 1 });
    }
    Ok(Layout {
        raw_bitmaps,
        metadata: a.metadata,
        payload,
        forks: a.forks,
        allocated,
        volume_allocated,
    })
}
fn superblock(
    a: &mut Alloc,
    o: &ApfsBuildOptions,
    allocated: u64,
    work: &mut Work,
    r: &Resources,
) -> Result<()> {
    work.tick(a.geometry.prefix * BLOCK as u64, r)?;
    let main_queue_limit = match 1 + (a.blocks - 1) / 4544 {
        2 => 3,
        n => n,
    };
    let mut nx = object(1, 0x80000001, 0)?;
    nx[32..36].copy_from_slice(b"NXSB");
    d(&mut nx, 36, BLOCK as u32);
    q(&mut nx, 40, a.blocks);
    q(&mut nx, 64, 2);
    nx[72..88].copy_from_slice(&o.container_uuid);
    q(&mut nx, 88, a.virtual_id.max(1030));
    q(&mut nx, 96, 2);
    d(&mut nx, 104, a.geometry.capacity.descriptor_blocks);
    d(&mut nx, 108, a.geometry.capacity.data_blocks);
    q(&mut nx, 112, 1);
    q(&mut nx, 120, a.geometry.data_base);
    d(&mut nx, 128, 2);
    d(&mut nx, 132, 4);
    d(&mut nx, 140, 2);
    d(&mut nx, 148, 4);
    q(&mut nx, 152, 1024);
    q(&mut nx, 160, a.at(17));
    q(&mut nx, 168, 1025);
    d(&mut nx, 180, a.blocks.div_ceil(131072).min(100) as u32);
    q(&mut nx, 184, 1026);
    q(&mut nx, 1312, (main_queue_limit << 32) | (4u64 << 16) | 1);
    seal(&mut nx);
    a.put(0, nx.clone())?;
    a.put(2, nx)?;
    let mut cp = object(1, 0x4000000c, 0)?;
    d(&mut cp, 32, 1);
    d(&mut cp, 36, 4);
    for (i, (kind, sub, id, at)) in [
        (0x80000011, 0, 1025, 9),
        (0x80000005, 0, 1024, 10),
        (0x80000002, 9, 1028, 11),
        (0x80000002, 9, 1029, 12),
    ]
    .into_iter()
    .enumerate()
    {
        let p = 40 + 40 * i;
        d(&mut cp, p, kind);
        d(&mut cp, p + 4, sub);
        d(&mut cp, p + 8, BLOCK as u32);
        q(&mut cp, p + 24, id);
        q(&mut cp, p + 32, a.at(at));
    }
    seal(&mut cp);
    a.put(1, cp)?;
    let mut reaper = object(1025, 0x80000011, 0)?;
    q(&mut reaper, 32, 1);
    d(&mut reaper, 64, 1);
    d(&mut reaper, 108, (BLOCK - 112) as u32);
    seal(&mut reaper);
    a.put(a.at(9), reaper)?;
    let mut sm = object(1024, 0x80000005, 0)?;
    d(&mut sm, 32, BLOCK as u32);
    d(&mut sm, 36, 32768);
    d(&mut sm, 40, 126);
    d(&mut sm, 44, 507);
    q(&mut sm, 48, a.blocks);
    q(&mut sm, 56, a.geometry.chunks);
    d(&mut sm, 64, 1);
    q(&mut sm, 72, a.blocks - allocated);
    d(&mut sm, 80, 384);
    d(&mut sm, 148, 16);
    q(&mut sm, 152, 3 * (a.geometry.chunks + 1));
    d(&mut sm, 160, 1);
    d(&mut sm, 164, 16);
    q(&mut sm, 168, a.at(25));
    q(&mut sm, 176, a.at(41));
    q(&mut sm, 208, 1028);
    q(&mut sm, 248, 1029);
    w(&mut sm, 224, 1);
    w(&mut sm, 264, main_queue_limit as u16);
    w(&mut sm, 320, 1);
    w(&mut sm, 322, 15);
    d(&mut sm, 324, 336);
    d(&mut sm, 328, 344);
    d(&mut sm, 332, 352);
    q(&mut sm, 336, 1);
    for i in 0..16 {
        w(
            &mut sm,
            352 + i * 2,
            if i == 0 || i == 15 {
                u16::MAX
            } else {
                (i + 1) as u16
            },
        );
    }
    q(&mut sm, 384, a.at(42));
    seal(&mut sm);
    a.put(a.at(10), sm)?;
    for (at, id) in [(11, 1028), (12, 1029)] {
        a.put(
            a.at(at),
            node(
                NodeFields {
                    id,
                    storage: 0x80000000,
                    subtype: 9,
                    level: 0,
                    root: true,
                    fixed: Some((16, 8)),
                    totals: (0, 1, 16, 8),
                },
                &[],
            )?,
        )?;
    }
    let mut ip = zero(BLOCK)?;
    for block in 0..a.geometry.chunks + 1 {
        ip[block as usize / 8] |= 1 << (block % 8);
    }
    a.put(a.at(25), ip)?;
    let mut cib = object(a.at(42), 0x40000007, 0)?;
    d(&mut cib, 36, a.geometry.chunks as u32);
    for chunk in 0..a.geometry.chunks {
        let start = chunk * 32768;
        let count = (a.blocks - start).min(32768);
        let address = a.geometry.pool_base + if chunk == 0 { 0 } else { chunk + 1 };
        let mut bitmap = zero(BLOCK)?;
        let mut used = 0;
        for relative in 0..count {
            if a.used[(start + relative) as usize] {
                bitmap[relative as usize / 8] |= 1 << (relative % 8);
                used += 1;
            }
        }
        a.put(address, bitmap)?;
        let at = 40 + chunk as usize * 32;
        q(&mut cib, at, 1);
        q(&mut cib, at + 8, start);
        d(&mut cib, at + 16, count as u32);
        d(&mut cib, at + 20, (count - used) as u32);
        q(&mut cib, at + 24, address);
    }
    seal(&mut cib);
    a.put(a.at(42), cib)?;
    Ok(())
}
