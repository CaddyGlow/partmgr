//! Exact byte rename within an existing checksum-protected linear directory.
use super::inode_writer::patch_inode;
use super::*;
use crate::fs_core::NativeName;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(in super::super) struct Create<'a> {
    pub(in super::super) parent: &'a [NativeName],
    pub(in super::super) name: &'a [u8],
    pub(in super::super) metadata: &'a crate::fs_ext_edit::ExtCreateMetadata,
    pub(in super::super) payload: &'a [u8],
    pub(in super::super) directory: bool,
}

pub(in super::super) struct Delete<'a> {
    pub(in super::super) parent: &'a [NativeName],
    pub(in super::super) name: &'a [u8],
    pub(in super::super) deletion_time: u32,
}

pub(in super::super) fn delete(
    decoder: &ExtStorageDecoder<'_>,
    audit: &ExtAuditReport,
    request: Delete<'_>,
    limits: ExtEditLimits,
    resources: &Resources,
) -> io::Result<Plan> {
    name(request.name)?;
    if request.deletion_time < decoder.geometry.inodes {
        return Err(unsupported(
            "native deletion time aliases orphan inode-number domain",
        ));
    }
    let mut context = Context::new(decoder, audit, limits, resources)?;
    let parent = directory(&mut context, request.parent)?;
    let entries = decoder.directory(
        parent,
        limits.audit.directory_blocks,
        limits.directory_entries,
        resources,
    )?;
    let entry = entries
        .entries()
        .iter()
        .find(|entry| matches!(&entry.name,NativeName::Bytes(bytes) if bytes == request.name))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "native ext delete source"))?;
    let inode = decoder.inode(entry.inode, resources)?;
    let is_directory = inode.mode & 0xf000 == 0x4000;
    let proof = decoder.geometry.modern.as_ref().unwrap();
    if inode.number < 11
        || inode.number == proof.orphan_inode
        || (!is_directory && inode.mode & 0xf000 != 0x8000)
        || super::super::super::u32le(&inode.raw, 32) & 0x30 != 0
    {
        return Err(unsupported(
            "modern delete requires ordinary mutable file/directory",
        ));
    }
    if is_directory {
        let child = decoder.directory(
            inode.number,
            limits.audit.directory_blocks,
            limits.directory_entries,
            resources,
        )?;
        for entry in child.entries() {
            context.tick(1)?;
            match &entry.name {
                NativeName::Bytes(bytes) if bytes == b"." && entry.inode == inode.number => {}
                NativeName::Bytes(bytes) if bytes == b".." && entry.inode == parent => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::DirectoryNotEmpty,
                        "native ext directory is not empty",
                    ));
                }
            }
        }
    }
    let links = super::super::super::u16le(&inode.raw, 26);
    if is_directory || links == 1 {
        let decoded = context.allocation_map(&inode)?;
        for allocation in &decoded.allocations {
            for relative in 0..allocation.blocks {
                context.release(allocation.physical + relative)?;
            }
        }
        for &physical in &decoded.metadata {
            context.release(physical)?;
        }
        let external = super::super::super::u32le(&inode.raw, 104);
        if external != 0 {
            let bs = decoder.geometry.block_size as usize;
            let mut block = [0; MAX_BLOCK];
            decoder.read_exact_at(u64::from(external) * bs as u64, &mut block[..bs])?;
            proof.checksums.xattr(u64::from(external), &block[..bs])?;
            let references = super::super::super::u32le(&block, 4)
                .checked_sub(1)
                .ok_or_else(|| invalid("native xattr reference underflow"))?;
            if references == 0 {
                context.release(external)?;
            } else {
                block[4..8].copy_from_slice(&references.to_le_bytes());
                if proof.checksums.has_metadata() {
                    block[16..20].fill(0);
                    let checksum = super::super::super::checksum::crc32c(
                        super::super::super::checksum::crc32c(
                            proof.checksums.seed,
                            &u64::from(external).to_le_bytes(),
                        ),
                        &block[..bs],
                    );
                    block[16..20].copy_from_slice(&checksum.to_le_bytes());
                }
                context.patch(u64::from(external) * bs as u64, &block[..bs])?;
            }
        }
        context.release_inode(inode.number, is_directory)?;
        patch_inode(&mut context, &inode, |bytes| {
            bytes[4..8].fill(0);
            bytes[108..112].fill(0);
            bytes[28..32].fill(0);
            bytes[116..118].fill(0);
            bytes[26..28].fill(0);
            bytes[20..24].copy_from_slice(&request.deletion_time.to_le_bytes());
            bytes[40..100].fill(0);
            bytes[104..108].fill(0);
            Ok(())
        })?;
    } else {
        patch_inode(&mut context, &inode, |bytes| {
            bytes[26..28].copy_from_slice(&(links - 1).to_le_bytes());
            Ok(())
        })?;
    }
    edit_entry(
        &mut context,
        parent,
        EntryEdit::Remove {
            inode: inode.number,
            name: request.name,
        },
    )?;
    if is_directory {
        let parent_inode = decoder.inode(parent, resources)?;
        patch_inode(&mut context, &parent_inode, |bytes| {
            let links = super::super::super::u16le(bytes, 26)
                .checked_sub(1)
                .filter(|n| *n >= 2)
                .ok_or_else(|| invalid("native parent link-count underflow"))?;
            bytes[26..28].copy_from_slice(&links.to_le_bytes());
            Ok(())
        })?;
    }
    context.finish()
}

pub(in super::super) fn create(
    decoder: &ExtStorageDecoder<'_>,
    audit: &ExtAuditReport,
    request: Create<'_>,
    limits: ExtEditLimits,
    resources: &Resources,
) -> io::Result<Plan> {
    name(request.name)?;
    let mut context = Context::new(decoder, audit, limits, resources)?;
    let parent = directory(&mut context, request.parent)?;
    let entries = decoder.directory(
        parent,
        limits.audit.directory_blocks,
        limits.directory_entries,
        resources,
    )?;
    for entry in entries.entries() {
        context.tick(1)?;
        if matches!(&entry.name,NativeName::Bytes(bytes) if bytes == request.name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native ext create collision",
            ));
        }
    }
    let bs = decoder.geometry.block_size as usize;
    if request.directory && !request.payload.is_empty() {
        return Err(invalid(
            "directory creation cannot discard supplied payload",
        ));
    }
    let count = if request.directory {
        1
    } else {
        request.payload.len().div_ceil(bs)
    };
    if count > limits.file_blocks {
        return Err(budget("modern creation payload block ceiling"));
    }
    let mut raw = request.metadata.raw;
    if super::super::super::u16le(&raw, 0) & 0xf000
        != if request.directory { 0x4000 } else { 0x8000 }
        || raw[4..8] != [0; 4]
        || raw[20..24] != [0; 4]
        || raw[26..32] != [0; 6]
        || raw[40..104] != [0; 64]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "modern creation managed inode fields",
        ));
    }
    let (number, generation) = context.allocate_inode(request.directory)?;
    raw[26..28].copy_from_slice(&(if request.directory { 2u16 } else { 1 }).to_le_bytes());
    raw[100..104].copy_from_slice(&generation.to_le_bytes());
    let mut inode = ExtInode::decode_raw(number, raw)?;
    inode.raw[32..36].copy_from_slice(
        &(if decoder.geometry.uses_extents() {
            0x80000u32
        } else {
            0
        })
        .to_le_bytes(),
    );
    inode.extra_size = decoder.geometry.minimum_extra_size;
    inode.extra[..2].copy_from_slice(&inode.extra_size.to_le_bytes());
    let mut allocations = Vec::<super::super::super::extent::ExtentAllocation>::new();
    allocations
        .try_reserve_exact(count)
        .map_err(|_| budget("modern create extent rows"))?;
    if allocations.capacity() > count {
        return Err(budget("modern create extent capacity"));
    }
    if request.directory {
        let physical = context.allocate()?;
        let mut block = [0; MAX_BLOCK];
        let proof = decoder.geometry.modern.as_ref().unwrap();
        let usable = bs
            - if proof.checksums.has_metadata() {
                12
            } else {
                0
            };
        for (at, owner, length, name) in [
            (0, number, 12, b".".as_slice()),
            (12, parent, usable - 12, b"..".as_slice()),
        ] {
            block[at..at + 4].copy_from_slice(&owner.to_le_bytes());
            block[at + 4..at + 6].copy_from_slice(&(length as u16).to_le_bytes());
            block[at + 6] = name.len() as u8;
            block[at + 7] = 2;
            block[at + 8..at + 8 + name.len()].copy_from_slice(name);
        }
        proof
            .checksums
            .stamp_directory_leaf(number, generation, &mut block[..bs])?;
        context.patch(u64::from(physical) * bs as u64, &block[..bs])?;
        allocations.push(super::super::super::extent::ExtentAllocation {
            logical: 0,
            physical,
            blocks: 1,
            unwritten: false,
        });
    }
    for (logical, chunk) in request.payload.chunks(bs).enumerate() {
        let physical = context.allocate()?;
        let mut block = [0; MAX_BLOCK];
        block[..chunk.len()].copy_from_slice(chunk);
        context.patch(u64::from(physical) * bs as u64, &block[..bs])?;
        if let Some(previous) = allocations.last_mut()
            && previous.logical + u64::from(previous.blocks) == logical as u64
            && previous.physical + previous.blocks == physical
            && previous.blocks < 32768
        {
            previous.blocks += 1;
            continue;
        }
        allocations.push(super::super::super::extent::ExtentAllocation {
            logical: logical as u64,
            physical,
            blocks: 1,
            unwritten: false,
        });
    }
    write_inode(
        &mut context,
        &inode,
        if request.directory {
            bs as u64
        } else {
            request.payload.len() as u64
        },
        &allocations,
    )?;
    edit_entry(
        &mut context,
        parent,
        EntryEdit::Insert {
            inode: number,
            name: request.name,
            kind: if request.directory { 2 } else { 1 },
        },
    )?;
    if request.directory {
        let parent_inode = decoder.inode(parent, resources)?;
        patch_inode(&mut context, &parent_inode, |bytes| {
            let links = super::super::super::u16le(bytes, 26);
            if links < 2 {
                return Err(unsupported(
                    "native directory link-count sentinel cannot be guessed",
                ));
            }
            let links = links
                .checked_add(1)
                .ok_or_else(|| budget("native parent directory link count"))?;
            bytes[26..28].copy_from_slice(&links.to_le_bytes());
            Ok(())
        })?;
    }
    context.finish()
}

fn name(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| matches!(b, 0 | b'/'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native ext name",
        ));
    }
    Ok(())
}

fn directory(context: &mut Context<'_, '_>, path: &[NativeName]) -> io::Result<u32> {
    let mut number = 2;
    for component in path {
        context.tick(1)?;
        let NativeName::Bytes(bytes) = component else {
            return Err(unsupported("ext parent path requires native bytes"));
        };
        name(bytes)?;
        let entries = context.decoder.directory(
            number,
            context.limits.audit.directory_blocks,
            context.limits.directory_entries,
            context.resources,
        )?;
        number = entries
            .entries()
            .iter()
            .find(|entry| entry.name == *component)
            .map(|entry| entry.inode)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ext parent path"))?;
        if context.decoder.inode(number, context.resources)?.mode & 0xf000 != 0x4000 {
            return Err(unsupported(
                "ext parent path does not follow special objects",
            ));
        }
    }
    Ok(number)
}

pub(in super::super) struct Rename<'a> {
    pub(in super::super) source: &'a [NativeName],
    pub(in super::super) old_name: &'a [u8],
    pub(in super::super) destination: &'a [NativeName],
    pub(in super::super) new_name: &'a [u8],
}

pub(in super::super) fn rename(
    decoder: &ExtStorageDecoder<'_>,
    audit: &ExtAuditReport,
    request: Rename<'_>,
    limits: ExtEditLimits,
    resources: &Resources,
) -> io::Result<Plan> {
    let Rename {
        source,
        old_name,
        destination,
        new_name,
    } = request;
    name(old_name)?;
    name(new_name)?;
    let mut context = Context::new(decoder, audit, limits, resources)?;
    let parent = directory(&mut context, source)?;
    let destination = directory(&mut context, destination)?;
    if destination != parent {
        return move_file(context, parent, old_name, destination, new_name);
    }
    let inode = decoder.inode(parent, resources)?;
    if inode.mode & 0xf000 != 0x4000 || super::super::super::u32le(&inode.raw, 32) & 0x30 != 0 {
        return Err(unsupported(
            "modern rename requires mutable linear directory",
        ));
    }
    let entries = decoder.directory(
        parent,
        limits.audit.directory_blocks,
        limits.directory_entries,
        resources,
    )?;
    let mut object = None;
    for entry in entries.entries() {
        context.tick(1)?;
        let NativeName::Bytes(bytes) = &entry.name else {
            return Err(invalid("decoded ext name representation"));
        };
        if bytes == new_name {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native ext rename collision",
            ));
        }
        if bytes == old_name {
            object = Some(entry.inode);
        }
    }
    let object = object
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "native ext rename source"))?;
    if super::super::super::u32le(&decoder.inode(object, resources)?.raw, 32) & 0x30 != 0 {
        return Err(unsupported("native ext immutable/append object rename"));
    }
    if super::super::super::u32le(&inode.raw, 32) & 0x1000 != 0 {
        super::htree::edit(
            &mut context,
            &inode,
            EntryEdit::Rename {
                inode: object,
                old: old_name,
                new: new_name,
            },
        )?;
        return context.finish();
    }
    let map = decoder.file_map(parent, limits.audit.directory_blocks, resources, false)?;
    let bs = decoder.geometry.block_size as usize;
    let proof = decoder.geometry.modern.as_ref().unwrap();
    for extent in &map.extents {
        let crate::fs_file::ExtentKind::Data(physical) = extent.kind else {
            return Err(invalid("native ext directory cannot contain sparse blocks"));
        };
        for relative in (0..extent.length).step_by(bs) {
            context.tick(bs)?;
            let offset = physical + relative;
            let mut block = [0; MAX_BLOCK];
            decoder.read_exact_at(offset, &mut block[..bs])?;
            let tail = proof
                .checksums
                .directory_leaf(parent, inode.generation, &block[..bs])?;
            let mut at = 0;
            while at < tail {
                if tail - at < 8 {
                    return Err(invalid("native ext rename truncated record"));
                }
                let length = usize::from(super::super::super::u16le(&block, at + 4));
                let count = usize::from(block[at + 6]);
                if length < 8
                    || !length.is_multiple_of(4)
                    || at + length > tail
                    || count > length - 8
                {
                    return Err(invalid("native ext rename record bounds"));
                }
                if super::super::super::u32le(&block, at) == object
                    && &block[at + 8..at + 8 + count] == old_name
                {
                    if new_name.len() > length - 8 {
                        return Err(unsupported("modern rename directory slot growth pending"));
                    }
                    block[at + 6] = new_name.len() as u8;
                    block[at + 8..at + length].fill(0);
                    block[at + 8..at + 8 + new_name.len()].copy_from_slice(new_name);
                    proof.checksums.stamp_directory_leaf(
                        parent,
                        inode.generation,
                        &mut block[..bs],
                    )?;
                    context.patch(offset, &block[..bs])?;
                    return context.finish();
                }
                at += length;
            }
        }
    }
    Err(invalid("native ext audited rename entry disappeared"))
}

#[derive(Clone, Copy)]
pub(super) enum EntryEdit<'a> {
    Rename {
        inode: u32,
        old: &'a [u8],
        new: &'a [u8],
    },
    Reparent {
        old: u32,
        new: u32,
    },
    Remove {
        inode: u32,
        name: &'a [u8],
    },
    Insert {
        inode: u32,
        name: &'a [u8],
        kind: u8,
    },
}
fn edit_entry(context: &mut Context<'_, '_>, parent: u32, edit: EntryEdit<'_>) -> io::Result<()> {
    let decoder = context.decoder;
    let inode = decoder.inode(parent, context.resources)?;
    if inode.mode & 0xf000 != 0x4000 || super::super::super::u32le(&inode.raw, 32) & 0x30 != 0 {
        return Err(unsupported("modern move requires mutable linear directory"));
    }
    if super::super::super::u32le(&inode.raw, 32) & 0x1000 != 0 {
        return super::htree::edit(context, &inode, edit);
    }
    let map = decoder.file_map(
        parent,
        context.limits.audit.directory_blocks,
        context.resources,
        false,
    )?;
    let bs = decoder.geometry.block_size as usize;
    let proof = decoder.geometry.modern.as_ref().unwrap();
    for extent in &map.extents {
        let crate::fs_file::ExtentKind::Data(physical) = extent.kind else {
            return Err(invalid("native ext directory sparse allocation"));
        };
        for relative in (0..extent.length).step_by(bs) {
            context.tick(bs)?;
            let mut block = [0; MAX_BLOCK];
            decoder.read_exact_at(physical + relative, &mut block[..bs])?;
            let tail = proof
                .checksums
                .directory_leaf(parent, inode.generation, &block[..bs])?;
            let mut at = 0;
            while at < tail {
                if tail - at < 8 {
                    return Err(invalid("native ext move truncated record"));
                }
                let length = usize::from(super::super::super::u16le(&block, at + 4));
                let count = usize::from(block[at + 6]);
                let existing = super::super::super::u32le(&block, at);
                if length < 8
                    || !length.is_multiple_of(4)
                    || at + length > tail
                    || count > length - 8
                {
                    return Err(invalid("native ext move record bounds"));
                }
                let changed = match edit {
                    EntryEdit::Rename { .. } => {
                        return Err(invalid("linear directory received indexed rename"));
                    }
                    EntryEdit::Reparent { old, new } => {
                        if existing == old && &block[at + 8..at + 8 + count] == b".." {
                            block[at..at + 4].copy_from_slice(&new.to_le_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    EntryEdit::Remove { inode, name } => {
                        if existing == inode && &block[at + 8..at + 8 + count] == name {
                            block[at..at + 4].fill(0);
                            true
                        } else {
                            false
                        }
                    }
                    EntryEdit::Insert { inode, name, kind } => {
                        let used = if existing == 0 {
                            0
                        } else {
                            (8 + count).next_multiple_of(4)
                        };
                        let needed = (8 + name.len()).next_multiple_of(4);
                        if length - used >= needed {
                            if used != 0 {
                                block[at + 4..at + 6].copy_from_slice(&(used as u16).to_le_bytes());
                            }
                            let begin = at + used;
                            block[begin..at + length].fill(0);
                            block[begin..begin + 4].copy_from_slice(&inode.to_le_bytes());
                            block[begin + 4..begin + 6]
                                .copy_from_slice(&((length - used) as u16).to_le_bytes());
                            block[begin + 6] = name.len() as u8;
                            block[begin + 7] = kind;
                            block[begin + 8..begin + 8 + name.len()].copy_from_slice(name);
                            true
                        } else {
                            false
                        }
                    }
                };
                if changed {
                    proof.checksums.stamp_directory_leaf(
                        parent,
                        inode.generation,
                        &mut block[..bs],
                    )?;
                    context.patch(physical + relative, &block[..bs])?;
                    return Ok(());
                }
                at += length;
            }
        }
    }
    match edit {
        EntryEdit::Insert {
            inode: object,
            name,
            kind,
        } => grow_directory(context, &inode, object, name, kind),
        EntryEdit::Rename { .. } => Err(invalid("linear directory received indexed rename")),
        EntryEdit::Remove { .. } => Err(invalid("audited native ext removal entry disappeared")),
        EntryEdit::Reparent { .. } => Err(invalid("audited native parent entry disappeared")),
    }
}

fn grow_directory(
    context: &mut Context<'_, '_>,
    inode: &ExtInode,
    object: u32,
    name: &[u8],
    kind: u8,
) -> io::Result<()> {
    let decoder = context.decoder;
    let bs = decoder.geometry.block_size as usize;
    let logical = inode.length / bs as u64;
    if logical >= context.limits.audit.directory_blocks as u64
        || logical >= context.limits.file_blocks as u64
    {
        return Err(budget("modern directory growth block ceiling"));
    }
    let decoded = context.allocation_map(inode)?;
    let mut rows = Vec::new();
    let count = decoded
        .allocations
        .len()
        .checked_add(1)
        .ok_or_else(|| budget("modern directory extent count"))?;
    rows.try_reserve_exact(count)
        .map_err(|_| budget("modern directory extent allocation"))?;
    if rows.capacity() > count {
        return Err(budget("modern directory extent capacity"));
    }
    for allocation in &decoded.allocations {
        context.tick(1)?;
        if allocation.unwritten || allocation.logical + u64::from(allocation.blocks) > logical {
            return Err(unsupported(
                "modern directory preallocation cannot be reinterpreted",
            ));
        }
        rows.push(super::super::super::extent::ExtentAllocation {
            logical: allocation.logical,
            physical: allocation.physical,
            blocks: allocation.blocks,
            unwritten: allocation.unwritten,
        });
    }
    for &physical in &decoded.metadata {
        context.release(physical)?;
    }
    let physical = context.allocate()?;
    rows.push(super::super::super::extent::ExtentAllocation {
        logical,
        physical,
        blocks: 1,
        unwritten: false,
    });
    let mut block = [0; MAX_BLOCK];
    let proof = decoder.geometry.modern.as_ref().unwrap();
    let usable = bs
        - if proof.checksums.has_metadata() {
            12
        } else {
            0
        };
    block[..4].copy_from_slice(&object.to_le_bytes());
    block[4..6].copy_from_slice(&(usable as u16).to_le_bytes());
    block[6] = name.len() as u8;
    block[7] = kind;
    block[8..8 + name.len()].copy_from_slice(name);
    proof
        .checksums
        .stamp_directory_leaf(inode.number, inode.generation, &mut block[..bs])?;
    context.patch(u64::from(physical) * bs as u64, &block[..bs])?;
    let length = inode
        .length
        .checked_add(bs as u64)
        .ok_or_else(|| budget("modern directory size overflow"))?;
    write_inode(context, inode, length, &rows)
}

fn move_file(
    mut context: Context<'_, '_>,
    source: u32,
    old_name: &[u8],
    destination: u32,
    new_name: &[u8],
) -> io::Result<Plan> {
    let entries = context.decoder.directory(
        source,
        context.limits.audit.directory_blocks,
        context.limits.directory_entries,
        context.resources,
    )?;
    let object = entries
        .entries()
        .iter()
        .find(|entry| matches!(&entry.name, NativeName::Bytes(bytes) if bytes == old_name))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "native ext move source"))?;
    let inode = context.decoder.inode(object.inode, context.resources)?;
    let is_directory = inode.mode & 0xf000 == 0x4000;
    if (!is_directory && inode.mode & 0xf000 != 0x8000)
        || inode.number < 11
        || inode.number
            == context
                .decoder
                .geometry
                .modern
                .as_ref()
                .unwrap()
                .orphan_inode
        || super::super::super::u32le(&inode.raw, 32) & 0x30 != 0
    {
        return Err(unsupported(
            "modern cross-directory move requires ordinary mutable file/directory",
        ));
    }
    if is_directory {
        let mut ancestor = destination;
        let mut complete = false;
        for _ in 0..context.limits.audit.inodes {
            context.tick(1)?;
            if ancestor == inode.number {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "native directory move would create ancestry cycle",
                ));
            }
            if ancestor == 2 {
                complete = true;
                break;
            }
            let parents = context.decoder.directory(
                ancestor,
                context.limits.audit.directory_blocks,
                context.limits.directory_entries,
                context.resources,
            )?;
            ancestor = parents
                .entries()
                .iter()
                .find(|entry| matches!(&entry.name,NativeName::Bytes(bytes) if bytes==b".."))
                .ok_or_else(|| invalid("native destination parent reference absent"))?
                .inode;
        }
        if !complete {
            return Err(budget("native directory move ancestry ceiling"));
        }
    }
    let destination_entries = context.decoder.directory(
        destination,
        context.limits.audit.directory_blocks,
        context.limits.directory_entries,
        context.resources,
    )?;
    for entry in destination_entries.entries() {
        context.tick(1)?;
        if matches!(&entry.name, NativeName::Bytes(bytes) if bytes == new_name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native ext move destination collision",
            ));
        }
    }
    let kind = object
        .file_type
        .ok_or_else(|| unsupported("modern move native file type absent"))?;
    edit_entry(
        &mut context,
        destination,
        EntryEdit::Insert {
            inode: object.inode,
            name: new_name,
            kind,
        },
    )?;
    edit_entry(
        &mut context,
        source,
        EntryEdit::Remove {
            inode: object.inode,
            name: old_name,
        },
    )?;
    if is_directory {
        edit_entry(
            &mut context,
            inode.number,
            EntryEdit::Reparent {
                old: source,
                new: destination,
            },
        )?;
        for (number, increment) in [(source, false), (destination, true)] {
            let parent = context.decoder.inode(number, context.resources)?;
            patch_inode(&mut context, &parent, |bytes| {
                let links = super::super::super::u16le(bytes, 26);
                if links < 2 {
                    return Err(unsupported("native parent link-count sentinel"));
                }
                let changed = if increment {
                    links.checked_add(1)
                } else {
                    links.checked_sub(1).filter(|n| *n >= 2)
                }
                .ok_or_else(|| invalid("native moved-directory parent link-count bounds"))?;
                bytes[26..28].copy_from_slice(&changed.to_le_bytes());
                Ok(())
            })?;
        }
    }
    context.finish()
}
