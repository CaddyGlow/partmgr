//! Staged complete fresh HFS+/HFSX layout; publication and owned editing are separate.
use super::metadata_builder::{self, CatalogMetadata};
use super::{
    TreeKind, allocation_builder::FreshAllocation, bad, budget, catalog_key, catalog_tree,
    fork_builder, keyed_tree, vector,
};
use crate::fs_core::{FileRead, Resources, Result};
#[cfg(all(test, feature = "std"))]
use crate::fs_core::{LogicalExtent, ObjectId, Reservation};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(super) struct DirectorySource<'a> {
    pub(super) metadata: Option<&'a CatalogMetadata>,
    pub(super) parent: u32,
    pub(super) name: &'a [u16],
}

pub(super) struct FileSource<'a> {
    pub(super) metadata: Option<&'a CatalogMetadata>,
    pub(super) parent: u32,
    pub(super) name: &'a [u16],
    pub(super) data: &'a dyn FileRead,
    pub(super) resource: Option<&'a dyn FileRead>,
}

#[cfg(all(test, feature = "std"))]
pub(super) fn empty_volume(
    block_size: u32,
    blocks: u32,
    binary: bool,
    name: &[u16],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    fresh_volume(block_size, blocks, binary, name, None, r)
}

#[cfg(all(test, feature = "std"))]
pub(super) fn fresh_volume(
    block_size: u32,
    blocks: u32,
    binary: bool,
    name: &[u16],
    file: Option<FileSource<'_>>,
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    fresh_files(block_size, blocks, binary, name, file.as_slice(), r)
}

#[cfg(all(test, feature = "std"))]
pub(super) fn fresh_files(
    block_size: u32,
    blocks: u32,
    binary: bool,
    name: &[u16],
    files: &[FileSource<'_>],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    fresh_tree(block_size, blocks, binary, name, &[], files, r)
}

#[cfg(all(test, feature = "std"))]
pub(super) fn fresh_tree(
    block_size: u32,
    blocks: u32,
    binary: bool,
    name: &[u16],
    directories: &[DirectorySource<'_>],
    files: &[FileSource<'_>],
    r: &Resources,
) -> Result<(Vec<u8>, Reservation)> {
    let length = u64::from(block_size) * u64::from(blocks);
    let capacity = usize::try_from(length).map_err(|_| budget("HFS+ volume buffer length"))?;
    let lease = r.memory.reserve(length)?;
    let mut image = vector(capacity)?;
    image.resize(capacity, 0);
    emit_tree(
        TreeSource {
            root_metadata: None,
            block_size,
            blocks,
            binary,
            name,
            directories,
            files,
        },
        r,
        &mut |at, bytes| {
            let at = usize::try_from(at).map_err(|_| bad("HFS+ memory sink offset"))?;
            let end = at
                .checked_add(bytes.len())
                .ok_or_else(|| bad("HFS+ memory sink bounds"))?;
            image
                .get_mut(at..end)
                .ok_or_else(|| bad("HFS+ memory sink bounds"))?
                .copy_from_slice(bytes);
            Ok(())
        },
    )?;
    Ok((image, lease))
}

pub(super) struct TreeSource<'a> {
    pub(super) root_metadata: Option<&'a CatalogMetadata>,
    pub(super) block_size: u32,
    pub(super) blocks: u32,
    pub(super) binary: bool,
    pub(super) name: &'a [u16],
    pub(super) directories: &'a [DirectorySource<'a>],
    pub(super) files: &'a [FileSource<'a>],
}

fn emit_bytes(
    at: u64,
    bytes: &[u8],
    r: &Resources,
    emit: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut offset = at;
    for chunk in bytes.chunks(65536) {
        r.cancellation.check()?;
        emit(offset, chunk)?;
        offset = offset
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| bad("HFS+ staging output overflow"))?;
    }
    Ok(())
}

// Writes only to caller-owned unpublished staging. Successful emission does not
// flush, publish, or authorize mutation of an existing filesystem.
pub(super) fn emit_tree(
    source: TreeSource<'_>,
    r: &Resources,
    emit: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
) -> Result<u64> {
    let TreeSource {
        root_metadata,
        block_size,
        blocks,
        binary,
        name,
        directories,
        files,
    } = source;
    r.cancellation.check()?;
    let directory_count =
        u32::try_from(directories.len()).map_err(|_| budget("HFS+ directory count"))?;
    let entries = directories
        .len()
        .checked_add(files.len())
        .ok_or_else(|| budget("HFS+ object count"))?;
    let object_count = u32::try_from(entries).map_err(|_| budget("HFS+ object count"))?;
    let first_file = directory_count
        .checked_add(16)
        .ok_or_else(|| budget("HFS+ directory CNIDs"))?;
    let _graph_charge = r.memory.reserve(
        (entries as u64)
            .checked_mul(512)
            .ok_or_else(|| budget("HFS+ tree inventory charge"))?,
    )?;
    if (directories.len() as u64)
        .checked_mul(entries as u64)
        .is_none_or(|work| work > 1 << 20)
    {
        return Err(budget("HFS+ directory accounting work ceiling"));
    }
    let mut graph_work = 0u64;
    for directory in directories {
        let mut parent = directory.parent;
        let mut depth = 0usize;
        while parent != 2 {
            r.cancellation.check()?;
            graph_work += 1;
            if graph_work > 1 << 20 {
                return Err(budget("HFS+ directory parent work ceiling"));
            }
            if parent < 16 || parent >= first_file || depth >= directories.len() {
                return Err(bad("HFS+ directory parent graph"));
            }
            parent = directories[(parent - 16) as usize].parent;
            depth += 1;
        }
    }
    if files
        .iter()
        .any(|file| file.parent != 2 && !(16..first_file).contains(&file.parent))
    {
        return Err(bad("HFS+ file parent graph"));
    }
    let file_count = u32::try_from(files.len()).map_err(|_| budget("HFS+ fresh file count"))?;
    let next_cnid = object_count
        .checked_add(16)
        .ok_or_else(|| budget("HFS+ CNID capacity"))?;
    let inventory = entries
        .checked_mul(2)
        .ok_or_else(|| budget("HFS+ inventory capacity"))?;
    if name.is_empty() || name.len() > 127 || name.iter().any(|u| *u == 0 || *u == 47) {
        return Err(bad("HFS+ staged volume name profile"));
    }
    let mut allocation = FreshAllocation::plan(block_size, blocks, r)?;
    // Native B-tree nodes must span whole allocation blocks when those blocks
    // exceed the tree's minimum node size.
    let extent_node = block_size.max(1024);
    let catalog_node = block_size.max(4096);
    let extent_bytes = u64::from(extent_node) * 2;
    let catalog_nodes = if entries <= 1 {
        2
    } else {
        object_count
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or_else(|| budget("HFS+ catalog node capacity"))?
    };
    let catalog_bytes = u64::from(catalog_node) * u64::from(catalog_nodes);
    let extent = allocation.allocate(extent_bytes.div_ceil(u64::from(block_size)) as u32, r)?;
    let catalog = allocation.allocate(catalog_bytes.div_ceil(u64::from(block_size)) as u32, r)?;
    let geometry = allocation.geometry();
    let mut payloads = Vec::new();
    let mut file_records = Vec::new();
    let mut file_leases = Vec::new();
    let _file_scratch = r.memory.reserve(
        (entries as u64)
            .checked_mul(512)
            .ok_or_else(|| budget("HFS+ inventory charge"))?,
    )?;
    payloads
        .try_reserve_exact(inventory)
        .map_err(|_| budget("HFS+ deferred payload inventory"))?;
    file_records
        .try_reserve_exact(inventory)
        .map_err(|_| budget("HFS+ file record inventory"))?;
    file_leases
        .try_reserve_exact(
            entries
                .checked_mul(6)
                .ok_or_else(|| budget("HFS+ lease inventory capacity"))?,
        )
        .map_err(|_| budget("HFS+ file reservation inventory"))?;
    for (position, source) in files.iter().enumerate() {
        let cnid = first_file + position as u32;
        if source.name.is_empty()
            || source.name.len() > 255
            || source.name.iter().any(|unit| *unit == 0 || *unit == 47)
        {
            return Err(bad("HFS+ staged file name profile"));
        }
        let mut body = [0; 248];
        body[..2].copy_from_slice(&2u16.to_be_bytes());
        body[2..4].copy_from_slice(&2u16.to_be_bytes());
        body[8..12].copy_from_slice(&cnid.to_be_bytes());
        metadata_builder::apply(&mut body, false, source.metadata)?;
        for (index, input) in [Some(source.data), source.resource].into_iter().enumerate() {
            let length = input.map_or(0, FileRead::len);
            let count = u32::try_from(length.div_ceil(u64::from(block_size)))
                .map_err(|_| budget("HFS+ fresh payload block count"))?;
            let runs = if count == 0 {
                None
            } else {
                Some(allocation.allocate(count, r)?)
            };
            let fork = fork_builder::plan(cnid, index == 1, length, geometry, runs.as_slice(), r)?;
            if !fork.overflow.is_empty() {
                return Err(bad(
                    "HFS+ fresh contiguous fork unexpectedly needs overflow",
                ));
            }
            body[88 + index * 80..168 + index * 80].copy_from_slice(&fork.header);
            if let (Some(input), Some(run)) = (input, runs) {
                file_leases.push(r.memory.reserve(input.identity().native.len() as u64)?);
                payloads.push((input, input.identity().clone(), length, run));
            }
        }
        let (mut record, lease) = catalog_key(source.parent, source.name, binary, r)?;
        file_leases.push(lease);
        file_leases.push(r.memory.reserve(248)?);
        record
            .try_reserve_exact(248)
            .map_err(|_| budget("HFS+ fresh file record allocation"))?;
        record.extend_from_slice(&body);
        file_records.push(record);
        let (mut thread, lease) = catalog_key(cnid, &[], binary, r)?;
        file_leases.push(lease);
        file_leases.push(r.memory.reserve((10 + source.name.len() * 2) as u64)?);
        thread
            .try_reserve_exact(10 + source.name.len() * 2)
            .map_err(|_| budget("HFS+ fresh file thread allocation"))?;
        thread.extend_from_slice(&4u16.to_be_bytes());
        thread.extend_from_slice(&[0; 2]);
        thread.extend_from_slice(&source.parent.to_be_bytes());
        thread.extend_from_slice(&(source.name.len() as u16).to_be_bytes());
        for unit in source.name {
            thread.extend_from_slice(&unit.to_be_bytes());
        }
        file_records.push(thread);
    }
    for (position, source) in directories.iter().enumerate() {
        r.cancellation.check()?;
        if source.name.is_empty()
            || source.name.len() > 255
            || source.name.iter().any(|u| *u == 0 || *u == 47)
        {
            return Err(bad("HFS+ directory name profile"));
        }
        let cnid = 16 + position as u32;
        let subdirectories = directories
            .iter()
            .filter(|entry| entry.parent == cnid)
            .count() as u32;
        let children =
            subdirectories + files.iter().filter(|entry| entry.parent == cnid).count() as u32;
        let mut body = [0; 88];
        body[..2].copy_from_slice(&1u16.to_be_bytes());
        body[2..4].copy_from_slice(&(if binary { 16u16 } else { 0u16 }).to_be_bytes());
        body[4..8].copy_from_slice(&children.to_be_bytes());
        body[8..12].copy_from_slice(&cnid.to_be_bytes());
        metadata_builder::apply(&mut body, true, source.metadata)?;
        if binary {
            body[84..88].copy_from_slice(&subdirectories.to_be_bytes());
        }
        let (mut record, lease) = catalog_key(source.parent, source.name, binary, r)?;
        file_leases.push(lease);
        file_leases.push(r.memory.reserve(88)?);
        record
            .try_reserve_exact(88)
            .map_err(|_| budget("HFS+ directory record allocation"))?;
        record.extend_from_slice(&body);
        file_records.push(record);
        let (mut thread, lease) = catalog_key(cnid, &[], binary, r)?;
        file_leases.push(lease);
        file_leases.push(r.memory.reserve((10 + source.name.len() * 2) as u64)?);
        thread
            .try_reserve_exact(10 + source.name.len() * 2)
            .map_err(|_| budget("HFS+ directory thread allocation"))?;
        thread.extend_from_slice(&3u16.to_be_bytes());
        thread.extend_from_slice(&[0; 2]);
        thread.extend_from_slice(&source.parent.to_be_bytes());
        thread.extend_from_slice(&(source.name.len() as u16).to_be_bytes());
        for unit in source.name {
            thread.extend_from_slice(&unit.to_be_bytes());
        }
        file_records.push(thread);
    }
    let bitmap_fork = fork_builder::plan(
        6,
        false,
        allocation.bitmap().len() as u64,
        geometry,
        &[allocation.bitmap_extent()],
        r,
    )?;
    let extent_fork = fork_builder::plan(3, false, extent_bytes, geometry, &[extent], r)?;
    let catalog_fork = fork_builder::plan(4, false, catalog_bytes, geometry, &[catalog], r)?;
    let (mut root, root_lease) = catalog_key(1, name, binary, r)?;
    let body_charge = r.memory.reserve((88 + 10 + 2 * name.len()) as u64)?;
    let mut folder = [0; 88];
    folder[..2].copy_from_slice(&1u16.to_be_bytes());
    folder[2..4].copy_from_slice(&(if binary { 16u16 } else { 0u16 }).to_be_bytes());
    folder[8..12].copy_from_slice(&2u32.to_be_bytes());
    let root_directories = directories.iter().filter(|entry| entry.parent == 2).count() as u32;
    let root_children =
        root_directories + files.iter().filter(|entry| entry.parent == 2).count() as u32;
    folder[4..8].copy_from_slice(&root_children.to_be_bytes());
    if binary {
        folder[84..88].copy_from_slice(&root_directories.to_be_bytes());
    }
    metadata_builder::apply(&mut folder, true, root_metadata)?;
    root.try_reserve_exact(folder.len())
        .map_err(|_| budget("HFS+ root record allocation"))?;
    root.extend_from_slice(&folder);
    let (mut thread, thread_lease) = catalog_key(2, &[], binary, r)?;
    thread
        .try_reserve_exact(10 + name.len() * 2)
        .map_err(|_| budget("HFS+ root thread allocation"))?;
    thread.extend_from_slice(&3u16.to_be_bytes());
    thread.extend_from_slice(&[0; 2]);
    thread.extend_from_slice(&1u32.to_be_bytes());
    thread.extend_from_slice(&(name.len() as u16).to_be_bytes());
    for unit in name {
        thread.extend_from_slice(&unit.to_be_bytes());
    }
    let record_count = inventory
        .checked_add(2)
        .ok_or_else(|| budget("HFS+ record count"))?;
    let _key_charge = r.memory.reserve(
        (record_count as u64)
            .checked_mul(2048)
            .ok_or_else(|| budget("HFS+ key inventory charge"))?,
    )?;
    let mut ordered = vector(record_count)?;
    for record in [&root, &thread].into_iter().chain(file_records.iter()) {
        let end = usize::from(super::super::be16(record, 0)) + 2;
        ordered.push((
            super::super::key(&record[2..end], 0, binary)?,
            record.as_slice(),
        ));
    }
    ordered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut records = vector(record_count)?;
    records.extend(ordered.iter().map(|(_, record)| *record));
    let (catalog_tree, catalog_lease) = catalog_tree(
        catalog_node as usize,
        catalog_nodes,
        64,
        binary,
        &records,
        r,
    )?;
    let (extent_tree, extent_lease) =
        keyed_tree(extent_node as usize, 2, 64, TreeKind::Extents, &[], r)?;
    let length = u64::from(block_size) * u64::from(blocks);
    let _buffer_charge = r.memory.reserve(65536)?;
    let mut buffer = vector(65536)?;
    buffer.resize(65536, 0);
    let mut cleared = 0u64;
    while cleared < length {
        r.cancellation.check()?;
        let count = (length - cleared).min(buffer.len() as u64) as usize;
        emit(cleared, &buffer[..count])?;
        cleared += count as u64;
    }
    emit_bytes(
        u64::from(allocation.bitmap_extent().0) * u64::from(block_size),
        allocation.bitmap(),
        r,
        emit,
    )?;
    emit_bytes(
        u64::from(extent.0) * u64::from(block_size),
        &extent_tree,
        r,
        emit,
    )?;
    emit_bytes(
        u64::from(catalog.0) * u64::from(block_size),
        &catalog_tree,
        r,
        emit,
    )?;
    for (input, identity, length, (start, _)) in payloads {
        let mut offset = 0u64;
        while offset < length {
            r.cancellation.check()?;
            if input.len() != length || input.identity() != &identity {
                return Err(bad("HFS+ deferred payload source changed"));
            }
            let count = usize::try_from((length - offset).min(65536)).unwrap();
            let at = u64::from(start) * u64::from(block_size) + offset;
            let actual = input.read_at(offset, &mut buffer[..count], r)?;
            if actual == 0 || actual > count {
                return Err(bad("HFS+ deferred payload invalid read count"));
            }
            r.cancellation.check()?;
            emit(at, &buffer[..actual])?;
            offset += actual as u64;
        }
        if input.len() != length || input.identity() != &identity {
            return Err(bad("HFS+ deferred payload source changed"));
        }
    }
    let mut header = [0; 512];
    header[..2].copy_from_slice(&(if binary { 0x4858u16 } else { 0x482bu16 }).to_be_bytes());
    header[2..4].copy_from_slice(&(if binary { 5u16 } else { 4u16 }).to_be_bytes());
    header[4..8].copy_from_slice(&0x100u32.to_be_bytes());
    header[8..12].copy_from_slice(b"pmgr");
    let clump = block_size
        .checked_mul(4)
        .ok_or_else(|| bad("HFS+ staged clump size"))?;
    header[72..80].copy_from_slice(&1u64.to_be_bytes());
    for (at, value) in [
        (56, clump),
        (60, clump),
        (40, block_size),
        (44, blocks),
        (48, allocation.free_blocks()),
        (32, file_count),
        (36, directory_count),
        (64, next_cnid),
        (68, 1),
    ] {
        header[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
    header[112..192].copy_from_slice(&bitmap_fork.header);
    header[192..272].copy_from_slice(&extent_fork.header);
    header[272..352].copy_from_slice(&catalog_fork.header);
    r.cancellation.check()?;
    emit_bytes(1024, &header, r, emit)?;
    emit_bytes(length - 1024, &header, r, emit)?;
    drop((
        allocation,
        bitmap_fork,
        extent_fork,
        catalog_fork,
        root,
        root_lease,
        thread,
        thread_lease,
        body_charge,
        catalog_tree,
        catalog_lease,
        extent_tree,
        extent_lease,
    ));
    Ok(length)
}

#[cfg(feature = "std")]
#[test]
fn complete_empty_fresh_layout_reopens_with_clean_ownership_and_refunds() {
    use crate::platform::{io, sync::Arc};
    use crate::{
        fs_core::{Budget, Cancellation},
        fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
        fs_hfsplus_audit::{HfsPlusAuditLimits, audit_hfsplus},
    };
    struct Bytes(Vec<u8>);
    impl crate::io::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let end = at
                .checked_add(out.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            out.copy_from_slice(
                self.0
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    for (size, blocks) in [(512, 2048), (4096, 256)] {
        for binary in [false, true] {
            let r = Resources {
                memory: Budget::new(8 << 20),
                cancellation: Cancellation::default(),
            };
            let name: Vec<_> = "Volume".encode_utf16().collect();
            let (image, lease) = empty_volume(size, blocks, binary, &name, &r).unwrap();
            assert_eq!(
                &image[1024..1536],
                &image[image.len() - 1024..image.len() - 512]
            );
            let volume = HfsPlusVolume::open(
                Arc::new(Bytes(image)),
                HfsPlusReadLimits {
                    blocks,
                    nodes: 8,
                    records: 4,
                    extents: 8,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            let audit = audit_hfsplus(
                &volume,
                HfsPlusAuditLimits {
                    blocks,
                    objects: 4,
                    depth: 2,
                    findings: 4,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            assert!(
                audit.is_clean() && audit.is_complete(),
                "{:?}",
                audit.findings()
            );
            drop((audit, volume, lease));
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[cfg(all(test, feature = "std"))]
struct Model {
    id: ObjectId,
    bytes: Vec<u8>,
}
#[cfg(all(test, feature = "std"))]
impl FileRead for Model {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let at = usize::try_from(at).map_err(|_| bad("model offset"))?;
        let n = out.len().min(3).min(self.bytes.len().saturating_sub(at));
        out[..n].copy_from_slice(&self.bytes[at..at + n]);
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(feature = "std")]
#[test]
fn populated_fresh_layout_streams_short_reads_and_preserves_both_forks() {
    use crate::platform::{io, sync::Arc};
    use crate::{
        fs_core::{Budget, Cancellation, NativeName, StreamKind},
        fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
        fs_hfsplus_audit::{HfsPlusAuditLimits, audit_hfsplus},
    };
    struct Bytes(Vec<u8>);
    impl crate::io::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let end = at
                .checked_add(out.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            out.copy_from_slice(
                self.0
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    let data = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
        bytes: (0..65553).map(|i| (i * 31 % 251) as u8).collect(),
    };
    let resource = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![2],
        },
        bytes: b"resource fork!".to_vec(),
    };
    let name: Vec<_> = "payload".encode_utf16().collect();
    for (size, blocks) in [(512, 2048), (4096, 256)] {
        for binary in [false, true] {
            let r = Resources {
                memory: Budget::new(8 << 20),
                cancellation: Cancellation::default(),
            };
            let (image, lease) = fresh_volume(
                size,
                blocks,
                binary,
                &"Volume".encode_utf16().collect::<Vec<_>>(),
                Some(FileSource {
                    metadata: None,
                    parent: 2,
                    name: &name,
                    data: &data,
                    resource: Some(&resource),
                }),
                &r,
            )
            .unwrap();
            let volume = HfsPlusVolume::open(
                Arc::new(Bytes(image)),
                HfsPlusReadLimits {
                    blocks,
                    nodes: 8,
                    records: 8,
                    extents: 8,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            let audit = audit_hfsplus(
                &volume,
                HfsPlusAuditLimits {
                    blocks,
                    objects: 4,
                    depth: 2,
                    findings: 4,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            assert!(
                audit.is_clean() && audit.is_complete(),
                "{:?}",
                audit.findings()
            );
            let id = volume
                .lookup(&[NativeName::Utf16(name.clone())], &r)
                .unwrap();
            for (kind, expected) in [
                (StreamKind::Data, &data.bytes),
                (StreamKind::ResourceFork, &resource.bytes),
            ] {
                let fork = volume.open_fork(&id, &kind, &r).unwrap();
                assert_eq!(fork.len(), expected.len() as u64);
                let mut actual = vec![0; expected.len()];
                assert_eq!(fork.read_at(0, &mut actual, &r).unwrap(), actual.len());
                assert_eq!(&actual, expected);
            }
            let tree = crate::fs_hfsplus_tree::HfsPlusTreeSource::inventory(
                volume,
                HfsPlusAuditLimits {
                    blocks,
                    objects: 4,
                    depth: 2,
                    findings: 4,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            let plan = super::builder_inventory::Plan::new(
                Arc::new(tree),
                crate::fs_copy::CopyLimits {
                    objects: 4,
                    pages: 8,
                    page_entries: 1,
                },
                crate::fs_copy::CopyNamePolicy::StrictUtf8,
                super::builder_inventory::MetadataPolicy::ContentOnlyDefaults,
                binary,
                &r,
            )
            .unwrap();
            assert_eq!(plan.outcomes().len(), 20);
            assert!(plan.outcomes().iter().all(|outcome| matches!(
                outcome.decision,
                crate::fs_core::Preservation::Transform { .. }
            )));
            let copy_lease = r
                .memory
                .reserve(u64::from(size) * u64::from(blocks))
                .unwrap();
            let mut copied = vec![0; size as usize * blocks as usize];
            plan.emit(
                size,
                blocks,
                &"Copied".encode_utf16().collect::<Vec<_>>(),
                &r,
                &mut |at, bytes| {
                    let at = at as usize;
                    copied[at..at + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();
            let copied_volume = HfsPlusVolume::open(
                Arc::new(Bytes(copied)),
                HfsPlusReadLimits {
                    blocks,
                    nodes: 8,
                    records: 8,
                    extents: 8,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            let copied_id = copied_volume
                .lookup(&[NativeName::Utf16(name.clone())], &r)
                .unwrap();
            for (kind, expected) in [
                (StreamKind::Data, &data.bytes),
                (StreamKind::ResourceFork, &resource.bytes),
            ] {
                let fork = copied_volume.open_fork(&copied_id, &kind, &r).unwrap();
                let mut actual = vec![0; expected.len()];
                assert_eq!(fork.read_at(0, &mut actual, &r).unwrap(), actual.len());
                assert_eq!(&actual, expected);
            }
            drop((audit, plan, copied_volume, copy_lease, lease));
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn multiple_file_catalog_order_collisions_and_budget_refunds() {
    use crate::fs_core::{Budget, Cancellation};
    let data = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
        bytes: (0..2049).map(|i| (i * 31 % 251) as u8).collect(),
    };
    let names: Vec<Vec<u16>> = (0..48)
        .rev()
        .map(|i| format!("payload-{i:03}").encode_utf16().collect())
        .collect();
    let files: Vec<_> = names
        .iter()
        .map(|name| FileSource {
            metadata: None,
            parent: 2,
            name,
            data: &data,
            resource: Some(&data),
        })
        .collect();
    let label: Vec<_> = "Volume".encode_utf16().collect();
    for binary in [false, true] {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let (image, lease) = fresh_files(4096, 256, binary, &label, &files, &r).unwrap();
        let catalog = u32::from_be_bytes(image[1312..1316].try_into().unwrap()) as usize * 4096;
        assert!(u16::from_be_bytes(image[catalog + 14..catalog + 16].try_into().unwrap()) > 1);
        drop((image, lease));
        assert_eq!(r.memory.used(), 0);
        let lower: Vec<_> = "a".encode_utf16().collect();
        let upper: Vec<_> = "A".encode_utf16().collect();
        let collision = [
            FileSource {
                metadata: None,
                parent: 2,
                name: &lower,
                data: &data,
                resource: None,
            },
            FileSource {
                metadata: None,
                parent: 2,
                name: &upper,
                data: &data,
                resource: None,
            },
        ];
        let result = fresh_files(4096, 256, binary, &label, &collision, &r);
        assert_eq!(result.is_ok(), binary);
        drop(result);
        assert_eq!(r.memory.used(), 0);
        let identical = [
            FileSource {
                metadata: None,
                parent: 2,
                name: &lower,
                data: &data,
                resource: None,
            },
            FileSource {
                metadata: None,
                parent: 2,
                name: &lower,
                data: &data,
                resource: None,
            },
        ];
        assert!(fresh_files(4096, 256, binary, &label, &identical, &r).is_err());
        assert_eq!(r.memory.used(), 0);
        r.cancellation.cancel();
        assert!(fresh_files(4096, 256, binary, &label, &files, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
}

#[cfg(feature = "std")]
#[test]
fn streamed_large_layout_bounded_memory_sink_failures_and_refunds() {
    use crate::fs_core::{Budget, Cancellation};
    let r = Resources {
        memory: Budget::new(256 << 10),
        cancellation: Cancellation::default(),
    };
    let name: Vec<_> = "Streamed".encode_utf16().collect();
    let source = || TreeSource {
        root_metadata: None,
        block_size: 4096,
        blocks: 32768,
        binary: true,
        name: &name,
        directories: &[],
        files: &[],
    };
    let mut calls = 0;
    let mut peak = 0;
    let length = emit_tree(source(), &r, &mut |at, bytes| {
        assert!(bytes.len() <= 65536);
        assert!(at + bytes.len() as u64 <= 128 << 20);
        peak = peak.max(r.memory.used());
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(length, 128 << 20);
    assert!(calls > 2048 && peak < 256 << 10);
    assert_eq!(r.memory.used(), 0);
    let mut calls = 0;
    let error = emit_tree(source(), &r, &mut |_, _| {
        calls += 1;
        if calls == 3 {
            return Err(bad("injected staging failure"));
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.context, "injected staging failure");
    assert_eq!(calls, 3);
    assert_eq!(r.memory.used(), 0);
    let mut calls = 0;
    r.cancellation.cancel();
    assert!(
        emit_tree(source(), &r, &mut |_, _| {
            calls += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls, 0);
    assert_eq!(r.memory.used(), 0);
}

#[cfg(feature = "std")]
#[test]
fn staged_cancellation_during_payload_read_and_between_headers() {
    use crate::fs_core::{Budget, Cancellation, ErrorKind};
    struct Cancelling {
        id: ObjectId,
    }
    impl FileRead for Cancelling {
        fn identity(&self) -> &ObjectId {
            &self.id
        }
        fn len(&self) -> u64 {
            3
        }
        fn read_at(&self, _: u64, bytes: &mut [u8], r: &Resources) -> Result<usize> {
            let count = bytes.len().min(3);
            bytes[..count].fill(0xa5);
            r.cancellation.cancel();
            Ok(count)
        }
        fn visit_extents(
            &self,
            _: &Resources,
            _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
        ) -> Result<()> {
            Ok(())
        }
    }
    let name: Vec<_> = "Volume".encode_utf16().collect();
    let filename: Vec<_> = "file".encode_utf16().collect();
    let input = Cancelling {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
    };
    let files = [FileSource {
        metadata: None,
        parent: 2,
        name: &filename,
        data: &input,
        resource: None,
    }];
    let r = Resources {
        memory: Budget::new(256 << 10),
        cancellation: Cancellation::default(),
    };
    let mut payload_writes = 0;
    let mut headers = 0;
    let error = emit_tree(
        TreeSource {
            root_metadata: None,
            block_size: 4096,
            blocks: 256,
            binary: false,
            name: &name,
            directories: &[],
            files: &files,
        },
        &r,
        &mut |_, bytes| {
            if bytes.iter().all(|b| *b == 0xa5) {
                payload_writes += 1;
            }
            if bytes.len() == 512 && bytes.starts_with(b"H+") {
                headers += 1;
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert_eq!((payload_writes, headers), (0, 0));
    assert_eq!(r.memory.used(), 0);
    let r = Resources {
        memory: Budget::new(256 << 10),
        cancellation: Cancellation::default(),
    };
    let mut header_offsets = Vec::new();
    let error = emit_tree(
        TreeSource {
            root_metadata: None,
            block_size: 4096,
            blocks: 256,
            binary: false,
            name: &name,
            directories: &[],
            files: &[],
        },
        &r,
        &mut |at, bytes| {
            if bytes.len() == 512 && bytes.starts_with(b"H+") {
                header_offsets.push(at);
                r.cancellation.cancel();
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert_eq!(header_offsets, vec![1024]);
    assert_eq!(r.memory.used(), 0);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native streamed HFS+/HFSX gate with 128MiB images and 256KiB builder budget"]
fn native_streamed_large_volume_and_deferred_forks() {
    use crate::fs_core::{Budget, Cancellation, Error};
    use crate::platform::{fs, os::unix::fs::FileExt, path::PathBuf, process::Command};
    use sha2::{Digest, Sha256};
    struct Generated {
        id: ObjectId,
    }
    impl FileRead for Generated {
        fn identity(&self) -> &ObjectId {
            &self.id
        }
        fn len(&self) -> u64 {
            (16 << 20) + 17
        }
        fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
            r.cancellation.check()?;
            let count = out
                .len()
                .min(997)
                .min(self.len().saturating_sub(at) as usize);
            for (i, b) in out[..count].iter_mut().enumerate() {
                *b = ((at + i as u64) * 31 % 251) as u8;
            }
            Ok(count)
        }
        fn visit_extents(
            &self,
            _: &Resources,
            _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
        ) -> Result<()> {
            Ok(())
        }
    }
    let output = PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_STREAMED_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let data = Generated {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
    };
    let resource = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![2],
        },
        bytes: b"resource fork!".to_vec(),
    };
    let name: Vec<_> = "payload".encode_utf16().collect();
    let volume: Vec<_> = "Streamed".encode_utf16().collect();
    let files = [FileSource {
        metadata: None,
        parent: 2,
        name: &name,
        data: &data,
        resource: Some(&resource),
    }];
    let mut receipt = String::new();
    for tool in [checker, icat] {
        receipt.push_str(&format!(
            "tool={tool} sha256={:x}\n",
            Sha256::digest(fs::read(tool).unwrap())
        ));
    }
    for binary in [false, true] {
        let label = if binary { "hfsx" } else { "hfsplus" };
        let path = output.join(format!("{label}.img"));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(128 << 20).unwrap();
        let r = Resources {
            memory: Budget::new(256 << 10),
            cancellation: Cancellation::default(),
        };
        let mut peak = 0;
        let mut calls = 0;
        let length = emit_tree(
            TreeSource {
                root_metadata: None,
                block_size: 4096,
                blocks: 32768,
                binary,
                name: &volume,
                directories: &[],
                files: &files,
            },
            &r,
            &mut |at, bytes| {
                assert!(bytes.len() <= 65536);
                peak = peak.max(r.memory.used());
                calls += 1;
                file.write_all_at(bytes, at)
                    .map_err(|e| Error::io("HFS+ staged native sink", e))
            },
        )
        .unwrap();
        file.sync_all().unwrap();
        assert_eq!(length, 128 << 20);
        assert_eq!(r.memory.used(), 0);
        assert!(peak < 256 << 10);
        let before = Sha256::digest(fs::read(&path).unwrap());
        let check = Command::new(checker)
            .arg("-fn")
            .arg(&path)
            .output()
            .unwrap();
        fs::write(output.join(format!("{label}-fsck.stdout")), &check.stdout).unwrap();
        fs::write(output.join(format!("{label}-fsck.stderr")), &check.stderr).unwrap();
        assert!(check.status.success(), "{check:?}");
        assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
        for (id, expected) in [
            (
                "16",
                (0..data.len())
                    .map(|i| (i * 31 % 251) as u8)
                    .collect::<Vec<_>>(),
            ),
            ("16-4353-1", resource.bytes.clone()),
        ] {
            let result = Command::new(icat)
                .args(["-f", "hfs"])
                .arg(&path)
                .arg(id)
                .output()
                .unwrap();
            fs::write(
                output.join(format!("{label}-icat-{id}.stdout")),
                &result.stdout,
            )
            .unwrap();
            fs::write(
                output.join(format!("{label}-icat-{id}.stderr")),
                &result.stderr,
            )
            .unwrap();
            assert!(result.status.success());
            assert_eq!(result.stdout, expected);
        }
        assert_eq!(Sha256::digest(fs::read(&path).unwrap()), before);
        receipt.push_str(&format!("case={label} bytes={length} peak_budget={peak} writes={calls} image_sha256={before:x}\n"));
    }
    receipt.push_str("status=passed\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}

#[cfg(feature = "std")]
#[test]
fn directory_parent_graph_forward_references_cycles_and_refunds() {
    use crate::fs_core::{Budget, Cancellation, ErrorKind};
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let label: Vec<_> = "Volume".encode_utf16().collect();
    let first: Vec<_> = "first".encode_utf16().collect();
    let second: Vec<_> = "second".encode_utf16().collect();
    for parents in [[16, 2], [17, 16], [99, 2]] {
        let dirs = [
            DirectorySource {
                metadata: None,
                parent: parents[0],
                name: &first,
            },
            DirectorySource {
                metadata: None,
                parent: parents[1],
                name: &second,
            },
        ];
        let error = fresh_tree(4096, 256, true, &label, &dirs, &[], &r).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidData);
        assert_eq!(r.memory.used(), 0);
    }
    let dirs = [
        DirectorySource {
            metadata: None,
            parent: 17,
            name: &first,
        },
        DirectorySource {
            metadata: None,
            parent: 2,
            name: &second,
        },
    ];
    let (image, lease) = fresh_tree(4096, 256, true, &label, &dirs, &[], &r).unwrap();
    assert_eq!(u32::from_be_bytes(image[1060..1064].try_into().unwrap()), 2);
    drop((image, lease));
    assert_eq!(r.memory.used(), 0);
    let data = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
        bytes: vec![1],
    };
    let files = [FileSource {
        metadata: None,
        parent: 99,
        name: &first,
        data: &data,
        resource: None,
    }];
    assert!(fresh_tree(4096, 256, true, &label, &dirs, &files, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native empty HFS+/HFSX formatter gate requires fresh evidence and fsck tools"]
fn native_empty_fresh_volume_checker_and_space_accounting() {
    native_fresh_volume_gate(0, false);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native populated HFS+/HFSX formatter gate"]
fn native_populated_fresh_volume_complete_fork_models() {
    native_fresh_volume_gate(1, false);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native multiple-file indexed HFS+/HFSX formatter gate"]
fn native_multiple_fresh_volume_indexed_catalog_and_forks() {
    native_fresh_volume_gate(48, false);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native nested HFS+/HFSX formatter gate"]
fn native_nested_fresh_volume_directory_graph_and_forks() {
    native_fresh_volume_gate(48, true);
}

#[cfg(all(test, feature = "std", target_os = "linux"))]
fn native_fresh_volume_gate(file_count: usize, nested: bool) {
    let populated = file_count > 0;
    use crate::fs_core::{Budget, Cancellation};
    use crate::platform::{fs, path::PathBuf, process::Command};
    use sha2::{Digest, Sha256};
    let output = PathBuf::from(
        crate::platform::env::var_os(if nested {
            "PARTMGR_HFSPLUS_NESTED_EVIDENCE"
        } else if file_count > 1 {
            "PARTMGR_HFSPLUS_MULTIPLE_EVIDENCE"
        } else if populated {
            "PARTMGR_HFSPLUS_POPULATED_EVIDENCE"
        } else {
            "PARTMGR_HFSPLUS_EMPTY_EVIDENCE"
        })
        .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let fsstat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/fsstat";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let data = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
        bytes: (0..if file_count > 1 { 2049 } else { 65553 })
            .map(|i| (i * 31 % 251) as u8)
            .collect(),
    };
    let resource = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![2],
        },
        bytes: b"resource fork!".to_vec(),
    };
    let names: Vec<Vec<u16>> = (0..file_count)
        .rev()
        .map(|i| format!("payload-{i:03}").encode_utf16().collect())
        .collect();
    let files: Vec<_> = names
        .iter()
        .map(|name| FileSource {
            metadata: None,
            parent: if nested { 17 } else { 2 },
            name,
            data: &data,
            resource: Some(&resource),
        })
        .collect();
    let directory_names: Vec<Vec<u16>> = ["BOX", "INNER", "EMPTY"]
        .iter()
        .map(|name| name.encode_utf16().collect())
        .collect();
    let directories = [
        DirectorySource {
            metadata: None,
            parent: 2,
            name: &directory_names[0],
        },
        DirectorySource {
            metadata: None,
            parent: 16,
            name: &directory_names[1],
        },
        DirectorySource {
            metadata: None,
            parent: 2,
            name: &directory_names[2],
        },
    ];
    let selected = if nested { directories.as_slice() } else { &[] };
    let first_file = 16 + selected.len();
    let mut receipt = String::new();
    for tool in [checker, fsstat, icat] {
        receipt.push_str(&format!(
            "tool={tool} sha256={:x}\n",
            Sha256::digest(fs::read(tool).unwrap())
        ));
    }
    for (size, blocks) in [(512, 2048), (4096, 256)] {
        for binary in [false, true] {
            let label = format!("{}-b{size}", if binary { "hfsx" } else { "hfsplus" });
            let r = Resources {
                memory: Budget::new(8 << 20),
                cancellation: Cancellation::default(),
            };
            let (bytes, lease) = fresh_tree(
                size,
                blocks,
                binary,
                &"NativeVolume".encode_utf16().collect::<Vec<_>>(),
                selected,
                &files,
                &r,
            )
            .unwrap();
            let path = output.join(format!("{label}.img"));
            fs::write(&path, &bytes).unwrap();
            for (suffix, tool, args) in [
                ("fsck", checker, vec!["-fn"]),
                ("fsstat", fsstat, vec!["-f", "hfs"]),
            ] {
                let result = Command::new(tool).args(&args).arg(&path).output().unwrap();
                fs::write(
                    output.join(format!("{label}-{suffix}.stdout")),
                    &result.stdout,
                )
                .unwrap();
                fs::write(
                    output.join(format!("{label}-{suffix}.stderr")),
                    &result.stderr,
                )
                .unwrap();
                assert!(result.status.success(), "{label} {suffix} {result:?}");
                let text = String::from_utf8_lossy(&result.stdout);
                if suffix == "fsck" {
                    assert!(text.contains("appears to be OK"), "{text}");
                } else {
                    let free = u32::from_be_bytes(bytes[1072..1076].try_into().unwrap());
                    assert!(
                        text.contains(&format!("Number of Free Blocks: {free}")),
                        "{text}"
                    );
                    assert!(text.contains("NativeVolume"), "{text}");
                }
            }
            if populated {
                for object in first_file..first_file + file_count {
                    for (id, expected) in [
                        (object.to_string(), &data.bytes),
                        (format!("{object}-4353-1"), &resource.bytes),
                    ] {
                        let result = Command::new(icat)
                            .args(["-f", "hfs"])
                            .arg(&path)
                            .arg(&id)
                            .output()
                            .unwrap();
                        fs::write(
                            output.join(format!("{label}-icat-{id}.stdout")),
                            &result.stdout,
                        )
                        .unwrap();
                        fs::write(
                            output.join(format!("{label}-icat-{id}.stderr")),
                            &result.stderr,
                        )
                        .unwrap();
                        assert!(result.status.success());
                        assert_eq!(&result.stdout, expected);
                    }
                }
            }
            assert_eq!(fs::read(&path).unwrap(), bytes);
            receipt.push_str(&format!(
                "case={label} image_sha256={:x} bytes={} free_blocks={}\n",
                Sha256::digest(&bytes),
                bytes.len(),
                u32::from_be_bytes(bytes[1072..1076].try_into().unwrap())
            ));
            drop((bytes, lease));
            assert_eq!(r.memory.used(), 0);
        }
    }
    receipt.push_str("status=passed\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native common-tree HFS+/HFSX capture requires immutable native input artifacts"]
fn native_common_tree_nested_capture_complete_forks() {
    use crate::platform::{
        fs, io, os::unix::fs::FileExt, path::PathBuf, process::Command, sync::Arc,
    };
    use crate::{
        fs_core::{Budget, Cancellation, Error},
        fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
        fs_hfsplus_audit::HfsPlusAuditLimits,
        fs_hfsplus_tree::HfsPlusTreeSource,
    };
    use sha2::{Digest, Sha256};
    struct Input {
        file: fs::File,
        length: u64,
    }
    impl crate::io::ReadAt for Input {
        fn len(&self) -> u64 {
            self.length
        }
        fn read_exact_at(&self, at: u64, bytes: &mut [u8]) -> io::Result<()> {
            if self.file.metadata()?.len() != self.length {
                return Err(io::Error::other("source length changed"));
            }
            self.file.read_exact_at(bytes, at)
        }
    }
    let output = PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_CAPTURE_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let inputs = PathBuf::from("/data/cache/partmgr-hfsplus-nested-native-v1");
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let fls = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/fls";
    let mut receipt = String::new();
    for tool in [checker, icat, fls] {
        receipt.push_str(&format!(
            "tool={tool} sha256={:x}\n",
            Sha256::digest(fs::read(tool).unwrap())
        ));
    }
    for (size, blocks) in [(512, 2048), (4096, 256)] {
        for binary in [false, true] {
            let label = format!("{}-b{size}", if binary { "hfsx" } else { "hfsplus" });
            let input_path = inputs.join(format!("{label}.img"));
            let input_hash = Sha256::digest(fs::read(&input_path).unwrap());
            let r = Resources {
                memory: Budget::new(8 << 20),
                cancellation: Cancellation::default(),
            };
            let volume = HfsPlusVolume::open(
                Arc::new(Input {
                    file: fs::File::open(&input_path).unwrap(),
                    length: 1 << 20,
                }),
                HfsPlusReadLimits {
                    blocks,
                    nodes: 256,
                    records: 128,
                    extents: 256,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            let tree = HfsPlusTreeSource::inventory(
                volume,
                HfsPlusAuditLimits {
                    blocks,
                    objects: 64,
                    depth: 8,
                    findings: 8,
                    work: 1 << 20,
                },
                &r,
            )
            .unwrap();
            let plan = super::builder_inventory::Plan::new(
                Arc::new(tree),
                crate::fs_copy::CopyLimits {
                    objects: 64,
                    pages: 256,
                    page_entries: 1,
                },
                crate::fs_copy::CopyNamePolicy::StrictUtf8,
                super::builder_inventory::MetadataPolicy::ContentOnlyDefaults,
                binary,
                &r,
            )
            .unwrap();
            assert_eq!(plan.outcomes().len(), 520);
            let mut decisions = String::new();
            for outcome in plan.outcomes() {
                decisions.push_str(&format!(
                    "object={:?} class={} decision={:?}\n",
                    outcome.object, outcome.class, outcome.decision
                ));
            }
            fs::write(
                output.join(format!("{label}-metadata-decisions.txt")),
                decisions,
            )
            .unwrap();
            let path = output.join(format!("{label}.img"));
            let file = fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.set_len(1 << 20).unwrap();
            plan.emit(
                size,
                blocks,
                &"Captured".encode_utf16().collect::<Vec<_>>(),
                &r,
                &mut |at, bytes| {
                    file.write_all_at(bytes, at)
                        .map_err(|e| Error::io("HFS+ captured staging sink", e))
                },
            )
            .unwrap();
            file.sync_all().unwrap();
            let before = Sha256::digest(fs::read(&path).unwrap());
            let check = Command::new(checker)
                .arg("-fn")
                .arg(&path)
                .output()
                .unwrap();
            fs::write(output.join(format!("{label}-fsck.stdout")), &check.stdout).unwrap();
            fs::write(output.join(format!("{label}-fsck.stderr")), &check.stderr).unwrap();
            assert!(check.status.success(), "{check:?}");
            assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
            let listing = Command::new(fls)
                .args(["-r", "-f", "hfs"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(listing.status.success());
            fs::write(output.join(format!("{label}-fls.stdout")), &listing.stdout).unwrap();
            fs::write(output.join(format!("{label}-fls.stderr")), &listing.stderr).unwrap();
            let text = String::from_utf8_lossy(&listing.stdout);
            for entry in ["d/d 16:\tBOX", "+ d/d 18:\tINNER", "d/d 17:\tEMPTY"] {
                assert!(text.contains(entry), "{text}");
            }
            for i in 0..48 {
                assert!(text.contains(&format!("++ r/r {}:\tpayload-{i:03}", 19 + i)));
            }
            for object in 19..67 {
                for (id, expected) in [
                    (
                        object.to_string(),
                        (0..2049).map(|i| (i * 31 % 251) as u8).collect::<Vec<_>>(),
                    ),
                    (format!("{object}-4353-1"), b"resource fork!".to_vec()),
                ] {
                    let result = Command::new(icat)
                        .args(["-f", "hfs"])
                        .arg(&path)
                        .arg(&id)
                        .output()
                        .unwrap();
                    fs::write(
                        output.join(format!("{label}-icat-{id}.stdout")),
                        &result.stdout,
                    )
                    .unwrap();
                    fs::write(
                        output.join(format!("{label}-icat-{id}.stderr")),
                        &result.stderr,
                    )
                    .unwrap();
                    assert!(result.status.success());
                    assert_eq!(result.stdout, expected);
                }
            }
            assert_eq!(Sha256::digest(fs::read(&input_path).unwrap()), input_hash);
            assert_eq!(Sha256::digest(fs::read(&path).unwrap()), before);
            receipt.push_str(&format!("case={label} input={} input_sha256={input_hash:x} image_sha256={before:x} objects=52 metadata_decisions=520\n",input_path.display()));
            drop(plan);
            assert_eq!(r.memory.used(), 0);
        }
    }
    receipt.push_str("status=passed\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}

#[cfg(all(test, feature = "std"))]
fn typed_metadata_volume(binary: bool, r: &Resources) -> Result<(Vec<u8>, Reservation)> {
    let root = CatalogMetadata {
        uid: 42,
        gid: 43,
        permissions: 0o750,
        created: 2082844801,
        modified: 2082931201,
        attributes_modified: 2082931202,
        accessed: 2083017600,
        backup: 2083104000,
    };
    let directory = CatalogMetadata {
        uid: 500,
        gid: 600,
        permissions: 0o711,
        ..root
    };
    let file = CatalogMetadata {
        uid: 1001,
        gid: 1002,
        permissions: 0o640,
        ..root
    };
    let dirname: Vec<_> = "DIR".encode_utf16().collect();
    let filename: Vec<_> = "payload".encode_utf16().collect();
    let label: Vec<_> = "Typed".encode_utf16().collect();
    let data = Model {
        id: ObjectId {
            source: 1,
            generation: 1,
            native: vec![1],
        },
        bytes: b"typed metadata payload".to_vec(),
    };
    let directories = [DirectorySource {
        metadata: Some(&directory),
        parent: 2,
        name: &dirname,
    }];
    let files = [FileSource {
        metadata: Some(&file),
        parent: 16,
        name: &filename,
        data: &data,
        resource: None,
    }];
    let lease = r.memory.reserve(1 << 20)?;
    let mut image = vec![0; 1 << 20];
    emit_tree(
        TreeSource {
            root_metadata: Some(&root),
            block_size: 4096,
            blocks: 256,
            binary,
            name: &label,
            directories: &directories,
            files: &files,
        },
        r,
        &mut |at, bytes| {
            let at = at as usize;
            image[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        },
    )?;
    Ok((image, lease))
}

#[cfg(feature = "std")]
#[test]
fn typed_metadata_root_directory_file_roundtrip_and_invalid_mode() {
    use crate::platform::{io, sync::Arc};
    use crate::{
        fs_core::{Budget, Cancellation, MetadataField, NativeName},
        fs_hfsplus::{HfsPlusReadLimits, HfsPlusVolume},
    };
    struct Bytes(Vec<u8>);
    impl crate::io::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let end = at
                .checked_add(out.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            out.copy_from_slice(
                self.0
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    for binary in [false, true] {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let (image, lease) = typed_metadata_volume(binary, &r).unwrap();
        let volume = HfsPlusVolume::open(
            Arc::new(Bytes(image)),
            HfsPlusReadLimits {
                blocks: 256,
                nodes: 16,
                records: 16,
                extents: 16,
                work: 1 << 20,
            },
            &r,
        )
        .unwrap();
        for (path, uid, gid, mode) in [
            (Vec::<&str>::new(), 42u32, 43u32, 0x41e8u32),
            (vec!["DIR"], 500, 600, 0x41c9),
            (vec!["DIR", "payload"], 1001, 1002, 0x81a0),
        ] {
            let names: Vec<_> = path
                .iter()
                .map(|name| NativeName::Utf16(name.encode_utf16().collect()))
                .collect();
            let id = volume.lookup(&names, &r).unwrap();
            let metadata = volume.metadata(&id, &r).unwrap();
            let m = metadata.get();
            let owner: Vec<_> = uid
                .to_be_bytes()
                .into_iter()
                .chain(gid.to_be_bytes())
                .collect();
            assert_eq!(m.owner, MetadataField::Known(owner));
            assert_eq!(m.mode, MetadataField::Known(mode));
            let typed = metadata_builder::from_native_hfs(m, mode & 0xf000 == 0x4000).unwrap();
            assert_eq!(
                (typed.uid, typed.gid, typed.permissions),
                (uid, gid, (mode & 0o7777) as u16)
            );
            assert_eq!(typed.attributes_modified, 2082931202);
            assert_eq!(typed.backup, 2083104000);
            let mut inconsistent = m.clone();
            inconsistent.owner = MetadataField::Known(vec![0; 8]);
            assert!(
                metadata_builder::from_native_hfs(&inconsistent, mode & 0xf000 == 0x4000).is_err()
            );
            let mut inconsistent = m.clone();
            if let MetadataField::Known(time) = &mut inconsistent.created {
                time.ticks += 1;
            }
            assert!(
                metadata_builder::from_native_hfs(&inconsistent, mode & 0xf000 == 0x4000).is_err()
            );
            for (field, value) in [
                (&m.created, 2082844801i128),
                (&m.modified, 2082931201),
                (&m.accessed, 2083017600),
            ] {
                let MetadataField::Known(time) = field else {
                    panic!("native date missing")
                };
                assert_eq!(time.ticks, value);
                assert_eq!(time.ticks_per_second, 1);
                assert_eq!(
                    time.epoch,
                    "1904-01-01 00:00:00 GMT; native unsigned seconds"
                );
            }
            let (_, MetadataField::Opaque { bytes, .. }) = m
                .attributes
                .iter()
                .find(|(name, _)| name == &NativeName::Bytes(b"hfs.catalog-record".to_vec()))
                .unwrap()
            else {
                panic!("catalog bytes missing")
            };
            assert_eq!(
                u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
                2082931202
            );
            assert_eq!(
                u32::from_be_bytes(bytes[28..32].try_into().unwrap()),
                2083104000
            );
        }
        let tree = crate::fs_hfsplus_tree::HfsPlusTreeSource::inventory(
            volume,
            crate::fs_hfsplus_audit::HfsPlusAuditLimits {
                blocks: 256,
                objects: 8,
                depth: 4,
                findings: 8,
                work: 1 << 20,
            },
            &r,
        )
        .unwrap();
        let plan = super::builder_inventory::Plan::new(
            Arc::new(tree),
            crate::fs_copy::CopyLimits {
                objects: 8,
                pages: 8,
                page_entries: 1,
            },
            crate::fs_copy::CopyNamePolicy::StrictUtf8,
            super::builder_inventory::MetadataPolicy::NativeHfsCatalogFields,
            binary,
            &r,
        )
        .unwrap();
        assert_eq!(
            plan.outcomes()
                .iter()
                .filter(|o| matches!(o.decision, crate::fs_core::Preservation::Preserve))
                .count(),
            15
        );
        let copy_lease = r.memory.reserve(1 << 20).unwrap();
        let mut copied = vec![0; 1 << 20];
        plan.emit(
            4096,
            256,
            &"MetadataCopy".encode_utf16().collect::<Vec<_>>(),
            &r,
            &mut |at, bytes| {
                let at = at as usize;
                copied[at..at + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
        let copied = HfsPlusVolume::open(
            Arc::new(Bytes(copied)),
            HfsPlusReadLimits {
                blocks: 256,
                nodes: 16,
                records: 16,
                extents: 16,
                work: 1 << 20,
            },
            &r,
        )
        .unwrap();
        for (parts, uid, gid, permissions) in [
            (vec![], 42, 43, 0o750),
            (vec!["DIR"], 500, 600, 0o711),
            (vec!["DIR", "payload"], 1001, 1002, 0o640),
        ] {
            let names: Vec<_> = parts
                .iter()
                .map(|p| NativeName::Utf16(p.encode_utf16().collect()))
                .collect();
            let id = copied.lookup(&names, &r).unwrap();
            let metadata = copied.metadata(&id, &r).unwrap();
            let typed = metadata_builder::from_native_hfs(metadata.get(), parts.len() < 2).unwrap();
            assert_eq!(
                (typed.uid, typed.gid, typed.permissions),
                (uid, gid, permissions)
            );
            assert_eq!(
                (
                    typed.created,
                    typed.modified,
                    typed.attributes_modified,
                    typed.accessed,
                    typed.backup
                ),
                (2082844801, 2082931201, 2082931202, 2083017600, 2083104000)
            );
        }
        drop((copied, plan, lease, copy_lease));
        assert_eq!(r.memory.used(), 0);
    }
    let mut body = [0x55; 248];
    let before = body;
    let invalid = CatalogMetadata {
        uid: 1,
        gid: 2,
        permissions: 0x8000,
        created: 0,
        modified: 0,
        attributes_modified: 0,
        accessed: 0,
        backup: 0,
    };
    assert!(metadata_builder::apply(&mut body, false, Some(&invalid)).is_err());
    assert_eq!(body, before);
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native typed HFS+/HFSX catalog metadata gate"]
fn native_typed_catalog_metadata_and_payload() {
    use crate::fs_core::{Budget, Cancellation};
    use crate::platform::{fs, io, path::PathBuf, process::Command, sync::Arc};
    use sha2::{Digest, Sha256};
    struct Bytes(Vec<u8>);
    impl crate::io::ReadAt for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, at: u64, bytes: &mut [u8]) -> io::Result<()> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let end = at
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("overflow"))?;
            bytes.copy_from_slice(
                self.0
                    .get(at..end)
                    .ok_or_else(|| io::Error::other("bounds"))?,
            );
            Ok(())
        }
    }
    impl crate::storage::Storage for Bytes {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, bytes: &mut [u8]) -> io::Result<()> {
            crate::io::ReadAt::read_exact_at(self, at, bytes)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let at = usize::try_from(at).map_err(io::Error::other)?;
            let n = bytes.len().min(997);
            let end = at
                .checked_add(n)
                .ok_or_else(|| io::Error::other("overflow"))?;
            self.0
                .get_mut(at..end)
                .ok_or_else(|| io::Error::other("bounds"))?
                .copy_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("staging must not flush"))
        }
    }
    let output = PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_TYPED_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let istat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let mut receipt = String::new();
    for tool in [checker, istat, icat] {
        receipt.push_str(&format!(
            "tool={tool} sha256={:x}\n",
            Sha256::digest(fs::read(tool).unwrap())
        ));
    }
    for binary in [false, true] {
        let label = if binary { "hfsx" } else { "hfsplus" };
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let (image, lease) = typed_metadata_volume(binary, &r).unwrap();
        let source_path = output.join(format!("{label}-source.img"));
        fs::write(&source_path, &image).unwrap();
        let source_hash = Sha256::digest(&image);
        let volume = super::super::HfsPlusVolume::open(
            Arc::new(Bytes(image)),
            super::super::HfsPlusReadLimits {
                blocks: 256,
                nodes: 16,
                records: 16,
                extents: 16,
                work: 1 << 20,
            },
            &r,
        )
        .unwrap();
        let tree = crate::fs_hfsplus_tree::HfsPlusTreeSource::inventory(
            volume,
            crate::fs_hfsplus_audit::HfsPlusAuditLimits {
                blocks: 256,
                objects: 8,
                depth: 4,
                findings: 8,
                work: 1 << 20,
            },
            &r,
        )
        .unwrap();
        use crate::fs_hfsplus_builder::*;
        let plan = HfsPlusBuildPlan::prepare(
            Arc::new(tree),
            HfsPlusBuildOptions {
                allocation_block_bytes: 4096,
                blocks: 256,
                case: if binary {
                    HfsPlusBuildCase::BinaryUtf16
                } else {
                    HfsPlusBuildCase::AsciiFold
                },
                volume_name: "Typed".encode_utf16().collect(),
                limits: crate::fs_copy::CopyLimits {
                    objects: 8,
                    pages: 8,
                    page_entries: 1,
                },
                names: crate::fs_copy::CopyNamePolicy::StrictUtf8,
                metadata: HfsPlusBuildMetadata::NativeHfsCatalogFields,
            },
            &r,
        )
        .unwrap();
        assert_eq!(
            plan.metadata_outcomes()
                .iter()
                .filter(|o| matches!(o.decision, crate::fs_core::Preservation::Preserve))
                .count(),
            15
        );
        let copy_lease = r.memory.reserve(1 << 20).unwrap();
        let mut target = Bytes(vec![0; 1 << 20]);
        plan.emit(&mut target, &r).unwrap();
        let image = target.0;
        assert_eq!(Sha256::digest(fs::read(&source_path).unwrap()), source_hash);
        drop(plan);
        let path = output.join(format!("{label}.img"));
        fs::write(&path, &image).unwrap();
        let result = Command::new(checker)
            .arg("-fn")
            .arg(&path)
            .output()
            .unwrap();
        fs::write(output.join(format!("{label}-fsck.stdout")), &result.stdout).unwrap();
        fs::write(output.join(format!("{label}-fsck.stderr")), &result.stderr).unwrap();
        assert!(result.status.success(), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("appears to be OK"));
        for (object, uid, gid) in [(2, 42, 43), (16, 500, 600), (17, 1001, 1002)] {
            let result = Command::new(istat)
                .env("TZ", "UTC")
                .args(["-f", "hfs"])
                .arg(&path)
                .arg(object.to_string())
                .output()
                .unwrap();
            fs::write(
                output.join(format!("{label}-istat-{object}.stdout")),
                &result.stdout,
            )
            .unwrap();
            fs::write(
                output.join(format!("{label}-istat-{object}.stderr")),
                &result.stderr,
            )
            .unwrap();
            assert!(result.status.success());
            let text = String::from_utf8_lossy(&result.stdout);
            assert!(
                text.contains(&format!("uid / gid: {uid} / {gid}")),
                "{text}"
            );
            let mode = match object {
                2 => "drwxr-x---",
                16 => "drwx--x--x",
                _ => "rrw-r-----",
            };
            assert!(text.contains(&format!("Mode:\t{mode}")), "{text}");
            for date in [
                "1970-01-01 00:00:01",
                "1970-01-02 00:00:01",
                "1970-01-02 00:00:02",
                "1970-01-03 00:00:00",
                "1970-01-04 00:00:00",
            ] {
                assert!(text.contains(date), "{text}");
            }
        }
        let result = Command::new(icat)
            .args(["-f", "hfs"])
            .arg(&path)
            .arg("17")
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"typed metadata payload");
        fs::write(
            output.join(format!("{label}-icat-17.stdout")),
            &result.stdout,
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), image);
        receipt.push_str(&format!(
            "case={label} image_sha256={:x}\n",
            Sha256::digest(&image)
        ));
        drop((image, lease, copy_lease));
        assert_eq!(r.memory.used(), 0);
    }
    receipt.push_str("status=passed\n");
    fs::write(output.join("receipt.txt"), receipt).unwrap();
}
