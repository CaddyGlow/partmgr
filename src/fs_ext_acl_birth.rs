//! Source-derived atomic namespace birth and native ACL inheritance.
use super::*;
#[derive(Clone, Copy)]
pub(in super::super) struct Request<'a> {
    pub name: &'a [u8],
    pub directory: bool,
    pub mode: u16,
    pub umask: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime: u32,
    pub mtime: u32,
    pub inode_generation: u32,
    pub payload: &'a [u8],
}
pub(in super::super) fn encode(
    request: Request<'_>,
    maximum: usize,
    r: &Resources,
) -> io::Result<(Vec<u8>, Reservation)> {
    let name_length = u32::try_from(request.name.len())
        .ok()
        .filter(|length| *length <= 255)
        .ok_or_else(|| unsupported("ACL birth name format ceiling"))?;
    let size = 40usize
        .checked_add(request.name.len())
        .and_then(|n| n.checked_add(request.payload.len()))
        .filter(|n| *n <= maximum)
        .ok_or_else(|| unsupported("ACL birth intent ceiling"))?;
    let lease = r.memory.reserve(size as u64).map_err(io::Error::other)?;
    let mut value = Vec::new();
    value.try_reserve_exact(size).map_err(io::Error::other)?;
    if value.capacity() > size {
        return Err(unsupported("ACL birth intent capacity"));
    }
    r.cancellation.check().map_err(io::Error::other)?;
    value.extend_from_slice(&request.mode.to_le_bytes());
    value.extend_from_slice(&request.umask.to_le_bytes());
    for n in [
        request.uid,
        request.gid,
        request.atime,
        request.mtime,
        request.inode_generation,
        name_length,
    ] {
        value.extend_from_slice(&n.to_le_bytes());
    }
    value.extend_from_slice(&(request.payload.len() as u64).to_le_bytes());
    value.extend_from_slice(&u32::from(request.directory).to_le_bytes());
    value.extend_from_slice(request.name);
    value.extend_from_slice(request.payload);
    r.cancellation.check().map_err(io::Error::other)?;
    Ok((value, lease))
}
pub(in super::super) fn decode(value: &[u8]) -> io::Result<Request<'_>> {
    if value.len() < 40 {
        return Err(invalid("ACL birth intent header"));
    }
    let name = u32le(value, 24) as usize;
    let payload = usize::try_from(u64::from_le_bytes(
        value[28..36].try_into().map_err(io::Error::other)?,
    ))
    .map_err(io::Error::other)?;
    let end = 40usize
        .checked_add(name)
        .and_then(|n| n.checked_add(payload))
        .filter(|n| *n == value.len())
        .ok_or_else(|| invalid("ACL birth intent lengths"))?;
    let directory = match u32le(value, 36) {
        0 => false,
        1 => true,
        _ => return Err(invalid("ACL birth intent type")),
    };
    Ok(Request {
        mode: u16le(value, 0),
        umask: u16le(value, 2),
        uid: u32le(value, 4),
        gid: u32le(value, 8),
        atime: u32le(value, 12),
        mtime: u32le(value, 16),
        inode_generation: u32le(value, 20),
        directory,
        name: &value[40..40 + name],
        payload: &value[40 + name..end],
    })
}
pub(in super::super) fn intent(
    path: &[NativeName],
    value: &[u8],
    ctime: u32,
    maximum: usize,
    r: &Resources,
) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"partmgr-acl-exact-intent-v4");
    hash.update([5]);
    hash.update(ctime.to_le_bytes());
    hash.update(0u16.to_le_bytes());
    hash.update((path.len() as u64).to_le_bytes());
    let mut size = value.len();
    for component in path {
        r.cancellation.check().map_err(io::Error::other)?;
        let NativeName::Bytes(name) = component else {
            return Err(unsupported("ACL birth native path"));
        };
        size = size
            .checked_add(name.len() + 8)
            .filter(|n| *n <= maximum)
            .ok_or_else(|| unsupported("ACL birth intent ceiling"))?;
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
    }
    if size > maximum {
        return Err(unsupported("ACL birth intent ceiling"));
    }
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(hash.finalize().into())
}
fn inode_offset(decoder: &ExtDecoder<Slice<'_>>, number: u32) -> io::Result<usize> {
    let g = decoder.geometry();
    let table = decoder.group((number - 1) / g.inodes_per_group)?[2];
    usize::try_from(
        u64::from(table) * u64::from(g.block_size)
            + u64::from((number - 1) % g.inodes_per_group) * 128,
    )
    .map_err(io::Error::other)
}
fn fresh_block(
    decoder: &ExtDecoder<Slice<'_>>,
    audit: &crate::fs_ext_audit::ExtAuditReport,
    source: &[u8],
    homes: &mut Vec<Home>,
    limits: Limits,
    work: &mut Work<'_>,
) -> io::Result<u32> {
    let bs = decoder.geometry().block_size as usize;
    for range in audit.free_ranges() {
        for at in (range.offset..range.offset + range.length).step_by(bs) {
            work.charge(
                homes
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| unsupported("ACL birth free scan work"))?,
            )?;
            let block = u32::try_from(at / bs as u64).map_err(io::Error::other)?;
            if homes.iter().any(|home| home.block == block) {
                continue;
            }
            patch(homes, source, block, bs, limits.records)?.fill(0);
            bitmap(decoder, homes, source, block, true, limits.records, work)?;
            return Ok(block);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::StorageFull,
        "ACL birth no audited free block",
    ))
}
fn record(bytes: &mut [u8], at: usize, inode: u32, size: usize, name: &[u8], kind: u8) {
    put32(bytes, at, inode);
    bytes[at + 4..at + 6].copy_from_slice(&(size as u16).to_le_bytes());
    bytes[at + 6] = name.len() as u8;
    bytes[at + 7] = kind;
    bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
}
fn reserve_encoding(work: &mut Work<'_>, maximum: usize) -> io::Result<()> {
    work.charge(
        maximum
            .checked_mul(5)
            .ok_or_else(|| unsupported("ACL birth encoding work overflow"))?,
    )
}
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn plan(
    storage: &dyn Storage,
    scope: u128,
    generation: u64,
    path: &[NativeName],
    request: Request<'_>,
    ctime: u32,
    limits: Limits,
    r: &Resources,
) -> io::Result<Plan> {
    let mut work = Work {
        used: 0,
        maximum: limits.work,
        r,
    };
    work.charge(1)?;
    let length = storage.len()?;
    if length > limits.source_bytes {
        return Err(unsupported("xattr source snapshot byte ceiling"));
    }
    let size = usize::try_from(length).map_err(io::Error::other)?;
    // Refuse before O(source) initialization, with a checked envelope for capture,
    // prospective copy, and both separately bounded complete ownership audits.
    let path_work = limits
        .audit
        .directory_blocks
        .checked_mul(MAX + 16)
        .and_then(|n| {
            limits
                .directory_entries
                .checked_mul(256)
                .and_then(|e| n.checked_add(e))
        })
        .and_then(|n| n.checked_add(MAX * 258 * 2))
        .and_then(|n| n.checked_mul(limits.path_depth))
        .ok_or_else(|| unsupported("xattr path work envelope overflow"))?;
    let envelope = size
        .checked_mul(9)
        .and_then(|v| {
            limits
                .audit
                .work
                .checked_mul(2)
                .and_then(|a| v.checked_add(a))
        })
        .and_then(|v| {
            limits
                .encoding
                .work
                .checked_mul(5)
                .and_then(|n| v.checked_add(n))
        })
        .and_then(|v| v.checked_add(path_work))
        .ok_or_else(|| unsupported("xattr planning work envelope overflow"))?;
    if envelope > limits.work {
        return Err(unsupported("xattr planning work envelope ceiling"));
    }
    let source_lease = r.memory.reserve(length).map_err(io::Error::other)?;
    let mut source = Vec::new();
    source.try_reserve_exact(size).map_err(io::Error::other)?;
    if source.capacity() > size {
        return Err(unsupported("xattr source snapshot capacity"));
    }
    work.charge(size)?;
    source.resize(size, 0);
    for (at, chunk) in source.chunks_mut(65536).enumerate() {
        work.charge(chunk.len())?;
        storage.read_exact_at(at as u64 * 65536, chunk)?;
        r.cancellation.check().map_err(io::Error::other)?;
    }
    if storage.len()? != length {
        return Err(invalid("xattr source length changed while capturing"));
    }
    r.cancellation.check().map_err(io::Error::other)?;
    work.charge(size)?;
    let decoder = ExtDecoder::open_reader(Slice(&source), scope, r, true)?;
    let g = decoder.geometry();
    let bs = g.block_size as usize;
    if g.modern.is_some()
        || g.extent_profile
        || g.inode_size != 128
        || !g.has_journal
        || !g.external_xattrs
        || length != u64::from(g.blocks) * bs as u64
    {
        return Err(unsupported(
            "xattr COW requires complete classic journal EXT_ATTR volume",
        ));
    }
    if path.len() > limits.path_depth {
        return Err(unsupported("xattr path depth ceiling"));
    }
    work.charge(limits.audit.work)?;
    let audit = audit_decoder(&decoder, limits.audit, r).map_err(io::Error::other)?;
    if !audit.is_clean() {
        return Err(invalid(
            "xattr COW requires complete clean original ownership",
        ));
    }
    let mut number = 2;
    for name in path {
        work.charge(1)?;
        let NativeName::Bytes(name) = name else {
            return Err(unsupported("xattr path native bytes required"));
        };
        if name.is_empty()
            || name.len() > 255
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(invalid("xattr path component"));
        }
        work.charge(
            limits
                .audit
                .directory_blocks
                .checked_mul(bs + 16)
                .and_then(|n| {
                    limits
                        .directory_entries
                        .checked_mul(256)
                        .and_then(|e| n.checked_add(e))
                })
                .and_then(|n| n.checked_add(bs * 258 * 2))
                .ok_or_else(|| unsupported("xattr path decoder work overflow"))?,
        )?;
        let entries = decoder.directory(
            number,
            limits.audit.directory_blocks,
            limits.directory_entries,
            r,
        )?;
        let entry = entries
            .entries()
            .iter()
            .find(|e| matches!(&e.name,NativeName::Bytes(n)if n==name))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "xattr path absent"))?;
        number = entry.inode;
    }
    work.charge(bs * 259)?;
    let inode = decoder.inode(number, r)?;
    if !matches!(inode.mode() & 0xf000, 0x8000 | 0x4000)
        || number == g.journal_inode
        || u32le(inode.raw_metadata(), 32) != 0
    {
        return Err(unsupported(
            "xattr user namespace requires ordinary classic file/directory",
        ));
    }
    if inode.mode() & 0xf000 != 0x4000 || u32le(inode.raw_metadata(), 32) != 0 || !g.filetype {
        return Err(unsupported(
            "ACL birth requires ordinary filetype directory",
        ));
    }
    if request.name.is_empty()
        || request.name.len() > 255
        || matches!(request.name, b"." | b"..")
        || request.name.contains(&0)
        || request.name.contains(&b'/')
        || request.umask & !0o777 != 0
        || request.mode & 0xf000 != if request.directory { 0x4000 } else { 0x8000 }
        || (request.directory && !request.payload.is_empty())
    {
        return Err(invalid("ACL birth exact native request"));
    }
    work.charge(
        limits
            .audit
            .directory_entries
            .checked_mul(256)
            .ok_or_else(|| unsupported("ACL birth directory work"))?,
    )?;
    let directory = decoder.directory(
        number,
        limits.audit.directory_blocks,
        limits.directory_entries,
        r,
    )?;
    if directory
        .entries()
        .iter()
        .any(|entry| matches!(&entry.name,NativeName::Bytes(name) if name==request.name))
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "ACL birth existing child",
        ));
    }
    // Reserve nested observation/decode/preparation/container allowances in
    // the SAME aggregate as scans, prospective audit and the final guard.
    // The upfront envelope is admission; it does not consume this allowance.
    reserve_encoding(&mut work, limits.encoding.work)?;
    let parent_ea = u32le(inode.raw_metadata(), 104);
    let parent_view = if parent_ea == 0 {
        None
    } else {
        let at = parent_ea as usize * bs;
        Some(xattr::observe(
            &source[at..at + bs],
            0,
            true,
            xattr::ObservationLimits {
                bytes: bs,
                entries: limits.encoding.entries,
                value_bytes: limits.encoding.value_bytes,
                work: limits.encoding.work,
            },
            r,
        )?)
    };
    let default = parent_view.as_ref().and_then(|view| {
        view.entries()
            .find(|entry| entry.index == 3 && entry.name.is_empty())
            .map(|entry| entry.value)
    });
    let acl = default
        .map(|bytes| {
            acl::decode(
                bytes,
                acl::Limits {
                    bytes: limits.encoding.value_bytes,
                    entries: limits.encoding.entries,
                    work: limits.encoding.work,
                },
                r,
            )
        })
        .transpose()?;
    let prepared = acl_write::prepare(
        acl_write::Request::Inherit {
            parent_default: acl.as_ref(),
            umask: request.umask,
        },
        if request.directory {
            acl_semantics::ChildKind::Directory
        } else {
            acl_semantics::ChildKind::Regular
        },
        request.mode,
        acl_write::Limits {
            bytes: limits.encoding.value_bytes,
            entries: limits.encoding.entries,
            work: limits.encoding.work,
        },
        r,
    )?;
    let encoded = acl_container::rewrite(
        None,
        bs,
        &prepared,
        acl_container::Limits {
            entries: limits.encoding.entries,
            value_bytes: limits.encoding.value_bytes,
            work: limits.encoding.work,
        },
        r,
    )?;
    let home_bytes = limits
        .records
        .checked_mul(core::mem::size_of::<Home>())
        .ok_or_else(|| unsupported("ACL birth home envelope"))?;
    let homes_lease = r
        .memory
        .reserve(home_bytes as u64)
        .map_err(io::Error::other)?;
    let mut homes = Vec::new();
    homes
        .try_reserve_exact(limits.records)
        .map_err(io::Error::other)?;
    if homes.capacity() > limits.records {
        return Err(unsupported("ACL birth home capacity"));
    }
    // The original complete audit proves every bitmap-clear slot has no owner.
    let first_inode = u32le(&source, 1024 + 84).max(11);
    let mut child = None;
    for candidate in first_inode..=g.inodes {
        work.charge(1)?;
        let group = (candidate - 1) / g.inodes_per_group;
        let bit = (candidate - 1) % g.inodes_per_group;
        let map = decoder.group(group)?[1];
        if source[map as usize * bs + (bit / 8) as usize] & (1 << (bit % 8)) == 0 {
            child = Some(candidate);
            break;
        }
    }
    let child = child.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::StorageFull,
            "ACL birth no audited free inode",
        )
    })?;
    let group = (child - 1) / g.inodes_per_group;
    let bit = (child - 1) % g.inodes_per_group;
    let inode_map = decoder.group(group)?[1];
    let b = patch(&mut homes, &source, inode_map, bs, limits.records)?;
    b[(bit / 8) as usize] |= 1 << (bit % 8);
    let descriptor = (u64::from(g.first) + 1) * bs as u64 + u64::from(group) * 32;
    let b = patch(
        &mut homes,
        &source,
        (descriptor / bs as u64) as u32,
        bs,
        limits.records,
    )?;
    let inside = (descriptor % bs as u64) as usize;
    let free = u16le(b, inside + 14)
        .checked_sub(1)
        .ok_or_else(|| invalid("ACL birth free inode count"))?;
    b[inside + 14..inside + 16].copy_from_slice(&free.to_le_bytes());
    if request.directory {
        let count = u16le(b, inside + 16)
            .checked_add(1)
            .ok_or_else(|| invalid("ACL birth directory count"))?;
        b[inside + 16..inside + 18].copy_from_slice(&count.to_le_bytes());
    }
    let primary = patch(
        &mut homes,
        &source,
        u32::from(bs == 1024),
        bs,
        limits.records,
    )?;
    let inside = 1024 % bs;
    let free = u32le(primary, inside + 16)
        .checked_sub(1)
        .ok_or_else(|| invalid("ACL birth primary free inode count"))?;
    put32(primary, inside + 16, free);
    let external = if let Some(block) = encoded.block.as_ref() {
        let external = fresh_block(&decoder, &audit, &source, &mut homes, limits, &mut work)?;
        patch(&mut homes, &source, external, bs, limits.records)?.copy_from_slice(block.bytes());
        external
    } else {
        0
    };
    let length = if request.directory {
        bs
    } else {
        request.payload.len()
    };
    let blocks = length.div_ceil(bs);
    if blocks > 12 {
        return Err(unsupported("ACL birth direct initial mapping ceiling"));
    }
    let mut raw = [0u8; 128];
    raw[..2].copy_from_slice(&prepared.mode.to_le_bytes());
    raw[2..4].copy_from_slice(&(request.uid as u16).to_le_bytes());
    raw[24..26].copy_from_slice(&(request.gid as u16).to_le_bytes());
    raw[120..122].copy_from_slice(&((request.uid >> 16) as u16).to_le_bytes());
    raw[122..124].copy_from_slice(&((request.gid >> 16) as u16).to_le_bytes());
    put32(
        &mut raw,
        4,
        u32::try_from(length).map_err(io::Error::other)?,
    );
    put32(&mut raw, 8, request.atime);
    put32(&mut raw, 12, ctime);
    put32(&mut raw, 16, request.mtime);
    raw[26..28].copy_from_slice(&if request.directory { 2u16 } else { 1u16 }.to_le_bytes());
    put32(&mut raw, 100, request.inode_generation);
    put32(&mut raw, 104, external);
    for logical in 0..blocks {
        work.charge(bs)?;
        let block = fresh_block(&decoder, &audit, &source, &mut homes, limits, &mut work)?;
        put32(&mut raw, 40 + logical * 4, block);
        let bytes = patch(&mut homes, &source, block, bs, limits.records)?;
        if request.directory {
            record(bytes, 0, child, 12, b".", 2);
            record(bytes, 12, number, bs - 12, b"..", 2);
        } else {
            let at = logical * bs;
            let count = (request.payload.len() - at).min(bs);
            bytes[..count].copy_from_slice(&request.payload[at..at + count]);
        }
    }
    let sectors = (blocks as u32 + u32::from(external != 0))
        .checked_mul(g.block_size / 512)
        .ok_or_else(|| invalid("ACL birth sector count"))?;
    put32(&mut raw, 28, sectors);
    let at = inode_offset(&decoder, child)?;
    let previous_generation = u32le(&source, at + 100);
    if previous_generation.checked_add(1) != Some(request.inode_generation) {
        return Err(invalid(
            "ACL birth requested generation must advance exact free inode slot",
        ));
    }
    patch(&mut homes, &source, (at / bs) as u32, bs, limits.records)?[at % bs..at % bs + 128]
        .copy_from_slice(&raw);
    // Insert into one existing leaf, or append a direct directory leaf. Parent
    // source/default, free candidates and all namespace neighbors stay guarded.
    let map_parent = decoder.file_map(number, limits.audit.directory_blocks, r, false)?;
    let needed = (8 + request.name.len()).next_multiple_of(4);
    let mut inserted = false;
    for extent in &map_parent.extents {
        let super::super::ExtentKind::Data(physical) = extent.kind else {
            return Err(invalid("ACL birth sparse parent directory"));
        };
        for relative in (0..extent.length).step_by(bs) {
            work.charge(bs)?;
            let block =
                u32::try_from((physical + relative) / bs as u64).map_err(io::Error::other)?;
            let old = &source[block as usize * bs..(block as usize + 1) * bs];
            let mut at = 0;
            while at < bs {
                let size = u16le(old, at + 4) as usize;
                let occupied = u32le(old, at) != 0;
                let used = if occupied {
                    (8 + old[at + 6] as usize).next_multiple_of(4)
                } else {
                    0
                };
                if size < 8 || !size.is_multiple_of(4) || at + size > bs || used > size {
                    return Err(invalid("ACL birth parent entry framing"));
                }
                if size - used >= needed {
                    let bytes = patch(&mut homes, &source, block, bs, limits.records)?;
                    if occupied {
                        bytes[at + 4..at + 6].copy_from_slice(&(used as u16).to_le_bytes());
                    }
                    let target = at + used;
                    record(
                        bytes,
                        target,
                        child,
                        size - used,
                        request.name,
                        if request.directory { 2 } else { 1 },
                    );
                    inserted = true;
                    break;
                }
                at += size;
            }
            if inserted {
                break;
            }
        }
        if inserted {
            break;
        }
    }
    let parent_at = inode_offset(&decoder, number)?;
    let parent_block = (parent_at / bs) as u32;
    let parent_inside = parent_at % bs;
    if !inserted {
        if !inode.len().is_multiple_of(bs as u64)
            || inode.len() / bs as u64 >= 12
            || inode.raw_metadata()[88..100].iter().any(|b| *b != 0)
        {
            return Err(unsupported("ACL birth parent direct growth ceiling"));
        }
        let block = fresh_block(&decoder, &audit, &source, &mut homes, limits, &mut work)?;
        record(
            patch(&mut homes, &source, block, bs, limits.records)?,
            0,
            child,
            bs,
            request.name,
            if request.directory { 2 } else { 1 },
        );
        let home = patch(&mut homes, &source, parent_block, bs, limits.records)?;
        let raw = &mut home[parent_inside..parent_inside + 128];
        let logical = (inode.len() / bs as u64) as usize;
        if u32le(raw, 40 + logical * 4) != 0 {
            return Err(invalid("ACL birth parent growth pointer"));
        }
        put32(raw, 40 + logical * 4, block);
        let length = u32le(raw, 4)
            .checked_add(g.block_size)
            .ok_or_else(|| invalid("ACL birth parent size"))?;
        put32(raw, 4, length);
        let sectors = u32le(raw, 28)
            .checked_add(g.block_size / 512)
            .ok_or_else(|| invalid("ACL birth parent sectors"))?;
        put32(raw, 28, sectors);
    }
    let home = patch(&mut homes, &source, parent_block, bs, limits.records)?;
    let raw = &mut home[parent_inside..parent_inside + 128];
    put32(raw, 12, ctime);
    put32(raw, 16, ctime);
    if request.directory {
        let links = u16le(raw, 26)
            .checked_add(1)
            .ok_or_else(|| invalid("ACL birth parent link count"))?;
        raw[26..28].copy_from_slice(&links.to_le_bytes());
    }
    work.charge(bs * 259)?;
    let journal_inode = decoder.inode(g.journal_inode, r)?;
    let journal_count =
        usize::try_from(journal_inode.len() / bs as u64).map_err(io::Error::other)?;
    work.charge(
        journal_count
            .checked_mul(journal_count)
            .ok_or_else(|| unsupported("xattr journal alias work overflow"))?,
    )?;
    let journal_lease = r
        .memory
        .reserve(
            journal_count
                .checked_mul(4)
                .ok_or_else(|| unsupported("xattr journal map overflow"))? as u64,
        )
        .map_err(io::Error::other)?;
    let mut journal = Vec::new();
    journal
        .try_reserve_exact(journal_count)
        .map_err(io::Error::other)?;
    if journal.capacity() > journal_count {
        return Err(unsupported("xattr journal map capacity"));
    }
    work.charge(
        journal_count
            .checked_mul(bs + 16)
            .ok_or_else(|| unsupported("xattr journal decoder work overflow"))?,
    )?;
    let map = decoder.file_map(g.journal_inode, journal_count, r, false)?;
    for e in &map.extents {
        work.charge(1)?;
        let super::super::ExtentKind::Data(at) = e.kind else {
            return Err(invalid("xattr journal mapping must be dense data"));
        };
        if !at.is_multiple_of(bs as u64)
            || !e.length.is_multiple_of(bs as u64)
            || e.offset != journal.len() as u64 * bs as u64
        {
            return Err(invalid("xattr journal mapping framing"));
        }
        for relative in (0..e.length).step_by(bs) {
            work.charge(1)?;
            let block = u32::try_from((at + relative) / bs as u64).map_err(io::Error::other)?;
            if journal.len() >= journal_count || journal.contains(&block) {
                return Err(invalid("xattr journal mapping alias/length"));
            }
            journal.push(block);
        }
    }
    if journal_inode.is_empty() || !journal_inode.len().is_multiple_of(bs as u64) {
        return Err(invalid("xattr original journal length"));
    }
    if journal.len() != journal_count {
        return Err(invalid("xattr original journal coverage"));
    }
    work.charge(2048)?;
    let primary: &[u8; 1024] = source[1024..2048].try_into().map_err(io::Error::other)?;
    let journal_at = journal[0] as usize * bs;
    let header: &[u8; 1024] = source[journal_at..journal_at + 1024]
        .try_into()
        .map_err(io::Error::other)?;
    super::super::jbd::xattr::clean_geometry(primary, header, journal.len())?;
    let physical = (homes.len() as u64)
        .checked_mul(bs as u64)
        .ok_or_else(|| unsupported("ACL birth physical ceiling"))?;
    if physical > limits.affected_bytes {
        return Err(unsupported("ACL birth affected home ceiling"));
    }
    work.charge(
        size.checked_mul(3)
            .ok_or_else(|| unsupported("ACL birth prospective work"))?,
    )?;
    let (mut prospective, _lease) = copy(&source, r)?;
    for home in &homes {
        work.charge(bs)?;
        let at = home.block as usize * bs;
        prospective[at..at + bs].copy_from_slice(&home.replacement[..bs]);
    }
    work.charge(limits.audit.work)?;
    let next = ExtDecoder::open_reader(Slice(&prospective), scope, r, true)?;
    let proof = audit_decoder(&next, limits.audit, r).map_err(io::Error::other)?;
    if !proof.is_clean() {
        return Err(invalid("ACL birth complete prospective ownership audit"));
    }
    drop((proof, next, directory, parent_view));
    drop((audit, map, decoder));
    // Native scan_owned exposes redo in destination order. Seal ORIGINAL homes
    // in the same canonical order so cold reconstruction is byte-exact.
    work.charge(
        homes
            .len()
            .checked_mul(homes.len())
            .ok_or_else(|| unsupported("xattr canonical home ordering work overflow"))?,
    )?;
    homes.sort_unstable_by_key(|home| home.block);
    let intent_ceiling = limits
        .path_depth
        .checked_mul(259)
        .and_then(|n| n.checked_add(255))
        .and_then(|n| n.checked_add(limits.encoding.value_bytes))
        .and_then(|n| n.checked_add(request.payload.len()))
        .ok_or_else(|| unsupported("xattr sealed intent ceiling overflow"))?;
    work.charge(
        limits
            .path_depth
            .checked_mul(8)
            .and_then(|n| n.checked_add(intent_ceiling))
            .and_then(|n| n.checked_add(64))
            .ok_or_else(|| unsupported("xattr intent work overflow"))?,
    )?;
    let intent = intent_digest(path, Operation::Create(request), ctime, intent_ceiling, r)?;
    work.charge(size)?;
    use sha2::{Digest, Sha256};
    let mut original_hash = Sha256::new();
    original_hash.update(b"partmgr-acl-exact-plan-source-v4");
    for chunk in source.chunks(65536) {
        r.cancellation.check().map_err(io::Error::other)?;
        original_hash.update(chunk);
    }
    r.cancellation.check().map_err(io::Error::other)?;
    let original_digest = original_hash.finalize().into();
    let result = Plan {
        scope,
        generation,
        block_bytes: bs,
        source,
        homes,
        journal,
        inode: child,
        old_external: 0,
        new_external: external,
        changed: true,
        intent,
        original_digest,
        _source: source_lease,
        _homes: homes_lease,
        _journal: journal_lease,
    };
    result.check_source(storage, false, limits.work.saturating_sub(work.used), r)?;
    r.cancellation.check().map_err(io::Error::other)?;
    Ok(result)
}

#[cfg(test)]
mod work_tests {
    use super::*;
    #[test]
    fn nested_encoding_reservation_consumes_exact_aggregate_and_refuses_one_below() {
        let r = Resources {
            memory: crate::fs_core::Budget::new(64),
            cancellation: Default::default(),
        };
        let mut exact = Work {
            used: 5,
            maximum: 43,
            r: &r,
        };
        reserve_encoding(&mut exact, 7).unwrap();
        assert_eq!(exact.used, 40);
        exact.charge(3).unwrap();
        assert!(exact.charge(1).is_err());
        let mut below = Work {
            used: 5,
            maximum: 39,
            r: &r,
        };
        assert!(reserve_encoding(&mut below, 7).is_err());
        assert_eq!(below.used, 5);
        assert!(reserve_encoding(&mut below, usize::MAX).is_err());
        assert_eq!(r.memory.used(), 0);
    }
}
