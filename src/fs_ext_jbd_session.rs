//! Staged owned native journal session; mutable storage never becomes ReadAt.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::sync::atomic::{AtomicU64, Ordering};
use crate::{
    fs_core::{Budget, Cancellation, ObjectId},
    fs_ext_audit::ExtAuditLimits,
    storage::Storage,
};
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) audit: ExtAuditLimits,
    pub(crate) file_blocks: usize,
    pub(crate) affected_blocks: usize,
    pub(crate) affected_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    Ready,
    NeedsRecovery,
}
pub(crate) struct File {
    pub(crate) identity: ObjectId,
    inode: super::super::ExtInode,
    map: super::super::ExtDecodedFileMap,
    _reservation: Reservation,
}
impl File {
    pub(crate) fn inode_number(&self) -> u32 {
        self.inode.number()
    }
}
pub(crate) enum Operation<'a> {
    CreateFile {
        parent: &'a [crate::fs_core::NativeName],
        name: &'a [u8],
        metadata: &'a crate::fs_ext_edit::ExtCreateMetadata,
        payload: &'a [u8],
    },
    CreateDirectory {
        parent: &'a [crate::fs_core::NativeName],
        name: &'a [u8],
        metadata: &'a crate::fs_ext_edit::ExtCreateMetadata,
    },
    Rename {
        source: &'a [crate::fs_core::NativeName],
        name: &'a [u8],
        destination: &'a [crate::fs_core::NativeName],
        new_name: &'a [u8],
    },
    Delete {
        parent: &'a [crate::fs_core::NativeName],
        name: &'a [u8],
        deletion_time: u32,
    },
    Extend {
        file: &'a File,
        input: &'a dyn crate::fs_core::FileRead,
    },
    Truncate {
        file: &'a File,
        length: u64,
    },
}
enum OperationPlan {
    Classic(crate::fs_ext_edit::ExtEditBatch),
    Modern(modern_plan::Plan),
}
impl OperationPlan {
    fn patches(&self) -> &[crate::storage::WriteRange] {
        match self {
            Self::Classic(plan) => plan.patches(),
            Self::Modern(plan) => &plan.patches,
        }
    }
}
pub(crate) struct Session<S: Storage> {
    storage: S,
    scope: u128,
    generation: u64,
    state: State,
    length: u64,
    volume_length: u64,
    limits: Limits,
    memory: Budget,
}
impl<S: Storage> Session<S> {
    pub(crate) fn open(storage: S, limits: Limits, r: &Resources) -> io::Result<Self> {
        let serial = NEXT_SESSION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| budget("native ext session identity exhausted"))?;
        let scope = (18u128 << 64) | u128::from(serial);
        let length = storage.len()?;
        let (decoder, proof) = super::super::ExtDecoder::open_native_clean(&storage, scope, r)?;
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, r)
            .map_err(io::Error::other)?;
        if !audit.is_clean() {
            return Err(invalid(
                "native ext session requires complete clean ownership audit",
            ));
        }
        let volume_length =
            u64::from(decoder.geometry.blocks) * u64::from(decoder.geometry.block_size);
        if storage.len()? != length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "native ext opening source length changed",
            )));
        }
        drop((decoder, proof, audit));
        Ok(Self {
            storage,
            scope,
            generation: 0,
            state: State::Ready,
            length,
            volume_length,
            limits,
            memory: r.memory.clone(),
        })
    }
    fn resources(&self, cancellation: &Cancellation) -> Resources {
        Resources {
            memory: self.memory.clone(),
            cancellation: cancellation.clone(),
        }
    }
    fn ready(&self, cancellation: &Cancellation) -> io::Result<()> {
        cancellation.check().map_err(io::Error::other)?;
        if self.state != State::Ready {
            return Err(io::Error::other(Error::new(
                ErrorKind::UncertainDurability,
                "native ext session requires recovery and reinspection",
            )));
        }
        if self.storage.len()? != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "native ext session storage length changed",
            )));
        }
        Ok(())
    }
    fn handle(&self, file: &File, cancellation: &Cancellation) -> io::Result<()> {
        self.ready(cancellation)?;
        if file.identity.source != self.scope || file.identity.generation != self.generation {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "foreign or invalidated native ext file handle",
            )));
        }
        Ok(())
    }
    pub(crate) fn file(&self, number: u32, cancellation: &Cancellation) -> io::Result<File> {
        self.ready(cancellation)?;
        let r = self.resources(cancellation);
        let reservation = r
            .memory
            .reserve((crate::platform::mem::size_of::<File>() + 512) as u64)
            .map_err(io::Error::other)?;
        let (decoder, proof) =
            super::super::ExtDecoder::open_native_clean(&self.storage, self.scope, &r)?;
        let inode = decoder.inode(number, &r)?;
        if inode.mode() & 0xf000 != 0x8000
            || number < 11
            || decoder
                .geometry
                .modern
                .as_ref()
                .is_some_and(|proof| proof.orphan_inode == number)
        {
            return Err(unsupported(
                "native ext file handle requires ordinary regular file",
            ));
        }
        let map = decoder.file_map(number, self.limits.file_blocks, &r, false)?;
        let mut identity = decoder.identity(number, &r)?;
        identity.generation = self.generation;
        drop(proof);
        Ok(File {
            identity,
            inode,
            map,
            _reservation: reservation,
        })
    }
    pub(crate) fn file_at(
        &self,
        path: &[crate::fs_core::NativeName],
        cancellation: &Cancellation,
    ) -> io::Result<File> {
        self.ready(cancellation)?;
        if path.is_empty() || path.len() > self.limits.audit.work {
            return Err(budget("native ext file path ceiling"));
        }
        let r = self.resources(cancellation);
        let (decoder, proof) =
            super::super::ExtDecoder::open_native_clean(&self.storage, self.scope, &r)?;
        let mut number = 2;
        let mut work = 0usize;
        for name in path {
            cancellation.check().map_err(io::Error::other)?;
            if !matches!(name, crate::fs_core::NativeName::Bytes(bytes) if !bytes.is_empty() && bytes.len() <= 255 && bytes != b"." && bytes != b".." && !bytes.contains(&0) && !bytes.contains(&b'/'))
            {
                return Err(unsupported(
                    "native ext file path requires exact bounded byte names",
                ));
            }
            let directory = decoder.directory(
                number,
                self.limits.audit.directory_blocks,
                self.limits.audit.directory_entries,
                &r,
            )?;
            work = work
                .checked_add(directory.entries().len() + 1)
                .filter(|work| *work <= self.limits.audit.work)
                .ok_or_else(|| budget("native ext file path work ceiling"))?;
            number = directory
                .entries()
                .iter()
                .find(|entry| &entry.name == name)
                .ok_or_else(|| invalid("native ext file path absent"))?
                .inode;
        }
        drop((decoder, proof));
        self.file(number, cancellation)
    }
    pub(crate) fn read_at(
        &self,
        file: &File,
        at: u64,
        out: &mut [u8],
        cancellation: &Cancellation,
    ) -> io::Result<usize> {
        self.handle(file, cancellation)?;
        let r = self.resources(cancellation);
        super::super::read_indexed_map(&file.map, at, out, &r, |physical, bytes| {
            if physical
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.volume_length)
            {
                return Err(invalid("native ext indexed read outside declared volume"));
            }
            self.ready(cancellation)?;
            self.storage.read_exact_at(physical, bytes)
        })
    }
    pub(crate) fn replace(
        &mut self,
        file: &File,
        offset: u64,
        bytes: &[u8],
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.handle(file, cancellation)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= file.map.length)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "native ext range exceeds existing file",
                )
            })?;
        if bytes.is_empty() {
            return Ok(());
        }
        if super::super::u32le(&file.inode.raw, 32) & 0x30 != 0 {
            return Err(unsupported("native ext immutable/append-only file"));
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| budget("native ext generation exhausted"))?;
        let r = self.resources(cancellation);
        let (decoder, proof) =
            super::super::ExtDecoder::open_native_clean(&self.storage, self.scope, &r)?;
        let block_bytes = proof.geometry.block_bytes;
        let blocks =
            usize::try_from((end - 1) / block_bytes as u64 - offset / block_bytes as u64 + 1)
                .map_err(|_| budget("native ext range block count overflow"))?;
        let affected = blocks
            .checked_mul(block_bytes)
            .filter(|n| *n as u64 <= self.limits.affected_bytes)
            .ok_or_else(|| budget("native ext affected byte ceiling"))?;
        if blocks > self.limits.affected_blocks {
            return Err(budget("native ext affected block ceiling"));
        }
        let reservation = r
            .memory
            .reserve(
                blocks
                    .checked_mul(crate::platform::mem::size_of::<ReplayBlock>())
                    .ok_or_else(|| budget("native ext range reservation overflow"))?
                    as u64,
            )
            .map_err(io::Error::other)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(blocks)
            .map_err(|_| budget("native ext range allocation"))?;
        if records.capacity() > blocks {
            return Err(budget("native ext range allocator capacity"));
        }
        let mut position = offset;
        while position < end {
            cancellation.check().map_err(io::Error::other)?;
            let logical = position / block_bytes as u64 * block_bytes as u64;
            let index = file
                .map
                .extents
                .partition_point(|e| e.offset <= logical)
                .checked_sub(1)
                .ok_or_else(|| invalid("native ext range map gap"))?;
            let extent = &file.map.extents[index];
            let super::super::ExtentKind::Data(physical) = extent.kind else {
                return Err(unsupported(
                    "native ext range replacement requires initialized allocated data",
                ));
            };
            let physical = physical
                .checked_add(logical - extent.offset)
                .ok_or_else(|| invalid("native ext range physical overflow"))?;
            if !physical.is_multiple_of(block_bytes as u64)
                || logical >= extent.offset + extent.length
            {
                return Err(invalid("native ext range map alignment"));
            }
            let mut data = [0; MAX_BLOCK];
            self.storage
                .read_exact_at(physical, &mut data[..block_bytes])?;
            let count = (end - position).min(block_bytes as u64 - (position - logical)) as usize;
            let inside = (position - logical) as usize;
            let input = (position - offset) as usize;
            data[inside..inside + count].copy_from_slice(&bytes[input..input + count]);
            records.push(ReplayBlock {
                destination: u32::try_from(physical / block_bytes as u64)
                    .map_err(|_| unsupported("native ext range high physical block"))?,
                bytes: data,
            });
            position += count as u64;
        }
        debug_assert_eq!(affected, records.len() * block_bytes);
        drop((decoder, proof));
        // Once the transaction may write, invalidate all handles conservatively;
        // any failure requires recovery through this same exclusive owner.
        self.generation = next_generation;
        self.state = State::NeedsRecovery;
        transaction::commit(
            &mut self.storage,
            self.scope,
            self.limits.audit,
            self.limits.affected_blocks,
            self.limits.affected_bytes,
            &records,
            &r,
        )?;
        drop((records, reservation));
        self.state = State::Ready;
        Ok(())
    }
    // Reviewable filesystem operations only; callers cannot submit physical offsets.
    pub(crate) fn operate(
        &mut self,
        operation: Operation<'_>,
        mut planning: crate::fs_ext_edit::ExtEditLimits,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.ready(cancellation)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| budget("native ext generation exhausted"))?;
        if let Operation::Extend { file, .. } | Operation::Truncate { file, .. } = &operation {
            self.handle(file, cancellation)?;
        }
        let r = self.resources(cancellation);
        planning.audit = self.limits.audit;
        planning.file_blocks = self.limits.file_blocks;
        planning.affected_bytes = planning.affected_bytes.min(self.limits.affected_bytes);
        let (decoder, proof) =
            super::super::ExtDecoder::open_native_clean(&self.storage, self.scope, &r)?;
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, self.limits.audit, &r)
            .map_err(io::Error::other)?;
        let batch =
            if decoder.geometry().modern.is_some() {
                match operation {
                    Operation::Extend { file, input } => OperationPlan::Modern(
                        modern_plan::extend(&decoder, &audit, &file.inode, input, planning, &r)?,
                    ),
                    Operation::Truncate { file, length } => OperationPlan::Modern(
                        modern_plan::truncate(&decoder, &audit, &file.inode, length, planning, &r)?,
                    ),
                    Operation::CreateFile {
                        parent,
                        name,
                        metadata,
                        payload,
                    } => OperationPlan::Modern(modern_plan::create(
                        &decoder,
                        &audit,
                        modern_plan::Create {
                            parent,
                            name,
                            metadata,
                            payload,
                            directory: false,
                        },
                        planning,
                        &r,
                    )?),
                    Operation::CreateDirectory {
                        parent,
                        name,
                        metadata,
                    } => OperationPlan::Modern(modern_plan::create(
                        &decoder,
                        &audit,
                        modern_plan::Create {
                            parent,
                            name,
                            metadata,
                            payload: &[],
                            directory: true,
                        },
                        planning,
                        &r,
                    )?),
                    Operation::Delete {
                        parent,
                        name,
                        deletion_time,
                    } => OperationPlan::Modern(modern_plan::delete(
                        &decoder,
                        &audit,
                        modern_plan::Delete {
                            parent,
                            name,
                            deletion_time,
                        },
                        planning,
                        &r,
                    )?),
                    Operation::Rename {
                        source,
                        name,
                        destination,
                        new_name,
                    } => OperationPlan::Modern(modern_plan::rename(
                        &decoder,
                        &audit,
                        modern_plan::Rename {
                            source,
                            old_name: name,
                            destination,
                            new_name,
                        },
                        planning,
                        &r,
                    )?),
                }
            } else {
                let context = crate::fs_ext_edit::allocation::PlanningContext::native(
                    &self.storage,
                    decoder.geometry(),
                    &audit,
                    (self.scope, self.generation),
                    planning,
                    &r,
                )
                .map_err(io::Error::other)?;
                let batch = match operation {
                    Operation::CreateFile {
                        parent,
                        name,
                        metadata,
                        payload,
                    } => {
                        let directory = context
                            .open_directory(parent, &r)
                            .map_err(io::Error::other)?;
                        context.plan_create_file(&directory, name, metadata, payload, &r)
                    }
                    Operation::CreateDirectory {
                        parent,
                        name,
                        metadata,
                    } => {
                        let directory = context
                            .open_directory(parent, &r)
                            .map_err(io::Error::other)?;
                        context.plan_create_directory(&directory, name, metadata, &r)
                    }
                    Operation::Rename {
                        source,
                        name,
                        destination,
                        new_name,
                    } => {
                        let source = context
                            .open_directory(source, &r)
                            .map_err(io::Error::other)?;
                        let destination = context
                            .open_directory(destination, &r)
                            .map_err(io::Error::other)?;
                        context.plan_rename(&source, name, &destination, new_name, &r)
                    }
                    Operation::Delete {
                        parent,
                        name,
                        deletion_time,
                    } => {
                        let directory = context
                            .open_directory(parent, &r)
                            .map_err(io::Error::other)?;
                        context.plan_delete(&directory, name, deletion_time, &r)
                    }
                    Operation::Extend { file, input } => {
                        let file = context
                            .file_handle(file.inode.number(), &r)
                            .map_err(io::Error::other)?;
                        context.plan_extend(&file, input, &r)
                    }
                    Operation::Truncate { file, length } => {
                        let file = context
                            .file_handle(file.inode.number(), &r)
                            .map_err(io::Error::other)?;
                        context.plan_truncate(&file, length, &r)
                    }
                }
                .map_err(io::Error::other)?;
                OperationPlan::Classic(batch)
            };
        let block_bytes = proof.geometry.block_bytes;
        // Charge and allocate the maximum bounded full-block projection before reading it.
        let charge = self
            .limits
            .affected_blocks
            .checked_mul(crate::platform::mem::size_of::<ReplayBlock>())
            .ok_or_else(|| budget("native operation record accounting"))?;
        let reservation = r.memory.reserve(charge as u64).map_err(io::Error::other)?;
        let mut records: Vec<ReplayBlock> = Vec::new();
        records
            .try_reserve_exact(self.limits.affected_blocks)
            .map_err(|_| budget("native operation record allocation"))?;
        if records.capacity() > self.limits.affected_blocks {
            return Err(budget("native operation record capacity"));
        }
        for patch in batch.patches() {
            cancellation.check().map_err(io::Error::other)?;
            let end = patch
                .offset()
                .checked_add(patch.expected().len() as u64)
                .filter(|end| *end <= self.volume_length)
                .ok_or_else(|| invalid("native operation patch bounds"))?;
            let mut at = patch.offset();
            while at < end {
                let destination = u32::try_from(at / block_bytes as u64)
                    .map_err(|_| unsupported("native operation high block"))?;
                let index =
                    match records.binary_search_by_key(&destination, |record| record.destination) {
                        Ok(index) => index,
                        Err(index) => {
                            if records.len() == self.limits.affected_blocks {
                                return Err(budget("native operation affected block ceiling"));
                            }
                            let mut record = ReplayBlock {
                                destination,
                                bytes: [0; MAX_BLOCK],
                            };
                            self.storage.read_exact_at(
                                u64::from(destination) * block_bytes as u64,
                                &mut record.bytes[..block_bytes],
                            )?;
                            records.insert(index, record);
                            index
                        }
                    };
                let inside = (at % block_bytes as u64) as usize;
                let input = (at - patch.offset()) as usize;
                let count = (end - at).min((block_bytes - inside) as u64) as usize;
                let record = &mut records[index];
                if record.bytes[inside..inside + count] != patch.expected()[input..input + count] {
                    return Err(io::Error::other(Error::new(
                        ErrorKind::StalePlan,
                        "native operation expected bytes changed",
                    )));
                }
                record.bytes[inside..inside + count]
                    .copy_from_slice(&patch.replacement()[input..input + count]);
                at += count as u64;
            }
        }
        // The native controller owns the transient RECOVER fence, not the classic planner.
        let superblock = if block_bytes == 1024 { 1 } else { 0 };
        if let Ok(index) = records.binary_search_by_key(&superblock, |record| record.destination) {
            let inside = 1024 % block_bytes;
            let features = super::super::u32le(&records[index].bytes, inside + 96) | 4;
            records[index].bytes[inside + 96..inside + 100]
                .copy_from_slice(&features.to_le_bytes());
            if decoder.geometry().modern.is_some() {
                let checksum = super::super::checksum::crc32c(
                    !0,
                    &records[index].bytes[inside..inside + 1020],
                );
                records[index].bytes[inside + 1020..inside + 1024]
                    .copy_from_slice(&checksum.to_le_bytes());
            }
        }
        self.ready(cancellation)?;
        drop(batch);
        drop((decoder, proof, audit));
        self.generation = next_generation;
        self.state = State::NeedsRecovery;
        transaction::commit(
            &mut self.storage,
            self.scope,
            self.limits.audit,
            self.limits.affected_blocks,
            self.limits.affected_bytes,
            &records,
            &r,
        )?;
        drop((records, reservation));
        self.state = State::Ready;
        Ok(())
    }
    pub(crate) fn recover(&mut self, cancellation: &Cancellation) -> io::Result<()> {
        cancellation.check().map_err(io::Error::other)?;
        if self.storage.len()? != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "native ext recovery source length changed",
            )));
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| budget("native ext recovery generation exhausted"))?;
        let r = self.resources(cancellation);
        self.state = State::NeedsRecovery;
        recovery::recover(
            &mut self.storage,
            self.scope,
            self.limits.audit,
            self.limits
                .affected_blocks
                .checked_add(1)
                .ok_or_else(|| budget("native ext recovery record ceiling overflow"))?,
            &r,
        )?;
        self.generation = next_generation;
        self.state = State::Ready;
        Ok(())
    }
    pub(crate) fn into_storage(self) -> (S, State) {
        (self.storage, self.state)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::platform::cell::Cell;
    struct Owned {
        bytes: Vec<u8>,
        writes: usize,
        fail_write: bool,
        reads: Cell<usize>,
        last_read: Cell<Option<(u64, usize)>>,
    }
    impl Storage for Owned {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.reads.set(self.reads.get() + 1);
            self.last_read.set(Some((at, out.len())));
            let at = at as usize;
            out.copy_from_slice(
                self.bytes
                    .get(at..at + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail_write {
                return Err(io::Error::other("session injected write failure"));
            }
            let at = at as usize;
            self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn le(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn short(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Owned {
        let mut bytes = bootstrap::tests::fixture().0;
        // Independently add inode11/data31 and its exact byte-name directory
        // entry to the independently assembled classic journal layout.
        le(&mut bytes, 1024 + 12, 996);
        le(&mut bytes, 1024 + 16, 117);
        short(&mut bytes, 2048 + 12, 996);
        short(&mut bytes, 2048 + 14, 117);
        bytes[3 * 1024 + 30 / 8] |= 1 << (30 % 8);
        bytes[4 * 1024 + 10 / 8] |= 1 << (10 % 8);
        let inode = 5 * 1024 + 10 * 128;
        short(&mut bytes, inode, 0o100600);
        le(&mut bytes, inode + 4, 128);
        short(&mut bytes, inode + 26, 1);
        le(&mut bytes, inode + 28, 2);
        le(&mut bytes, inode + 40, 31);
        short(&mut bytes, 30 * 1024 + 16, 12);
        let entry = 30 * 1024 + 24;
        le(&mut bytes, entry, 11);
        short(&mut bytes, entry + 4, 1000);
        bytes[entry + 6] = 4;
        bytes[entry + 7] = 1;
        bytes[entry + 8..entry + 12].copy_from_slice(b"file");
        bytes[31 * 1024..32 * 1024].fill(0xa5);
        for (index, byte) in bytes[31 * 1024..31 * 1024 + 128].iter_mut().enumerate() {
            *byte = index as u8;
        }
        Owned {
            bytes,
            writes: 0,
            fail_write: false,
            reads: Cell::new(0),
            last_read: Cell::new(None),
        }
    }
    fn fixture_256() -> Owned {
        let mut source = fixture();
        // Independent 128->256 layout assembly: relocate the inode table away
        // from directory/data/journal blocks, then author native extension bytes.
        let old = source.bytes[5 * 1024..21 * 1024].to_vec();
        source.bytes[5 * 1024..21 * 1024].fill(0);
        for number in 0..128 {
            let at = 64 * 1024 + number * 256;
            source.bytes[at..at + 128].copy_from_slice(&old[number * 128..(number + 1) * 128]);
            if source.bytes[at..at + 2] != [0, 0] {
                short(&mut source.bytes, at + 128, 32);
                le(&mut source.bytes, at + 136, (123456789 << 2) | 1);
                le(&mut source.bytes, at + 144, 0x12345678);
                le(&mut source.bytes, at + 152, 0xa17e0007);
            }
        }
        for physical in 5..21 {
            let bit = physical - 1;
            source.bytes[3 * 1024 + bit / 8] &= !(1 << (bit % 8));
        }
        for physical in 64..96 {
            let bit = physical - 1;
            source.bytes[3 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
        le(&mut source.bytes, 2048 + 8, 64);
        short(&mut source.bytes, 1024 + 88, 256);
        short(&mut source.bytes, 1024 + 348, 32);
        short(&mut source.bytes, 1024 + 350, 32);
        le(&mut source.bytes, 1024 + 12, 980);
        short(&mut source.bytes, 2048 + 12, 980);
        source
    }
    fn limits() -> Limits {
        Limits {
            audit: ExtAuditLimits {
                blocks: 2048,
                inodes: 128,
                work: 100000,
                directory_blocks: 8,
                directory_entries: 32,
                findings: 8,
            },
            file_blocks: 8,
            affected_blocks: 8,
            affected_bytes: 32 * 1024,
        }
    }
    struct Input {
        identity: ObjectId,
        bytes: Vec<u8>,
    }
    impl crate::fs_core::FileRead for Input {
        fn identity(&self) -> &ObjectId {
            &self.identity
        }
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(
            &self,
            offset: u64,
            out: &mut [u8],
            r: &Resources,
        ) -> crate::fs_core::Result<usize> {
            r.cancellation.check()?;
            let at = usize::try_from(offset).unwrap_or(usize::MAX);
            let count = out.len().min(37).min(self.bytes.len().saturating_sub(at));
            if count > 0 {
                out[..count].copy_from_slice(&self.bytes[at..at + count]);
            }
            Ok(count)
        }
        fn visit_extents(
            &self,
            r: &Resources,
            visitor: &mut dyn FnMut(crate::fs_core::LogicalExtent) -> crate::fs_core::Result<()>,
        ) -> crate::fs_core::Result<()> {
            r.cancellation.check()?;
            visitor(crate::fs_core::LogicalExtent {
                offset: 0,
                length: self.len(),
                kind: crate::fs_core::ExtentKind::Data,
            })
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn same_owner_native_journal_classic_allocation_and_namespace_plans() {
        exercise_classic_operations(false);
    }
    #[cfg(feature = "std")]
    #[test]
    fn same_owner_native_journal_extended_classic_allocation_and_namespace_plans() {
        exercise_classic_operations(true);
    }
    fn exercise_classic_operations(extended: bool) {
        use crate::{
            fs_core::NativeName,
            fs_ext_edit::{ExtCreateMetadata, ExtEditLimits},
            fs_undo::UndoLimits,
        };
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let mut limits = limits();
        limits.file_blocks = 256;
        limits.affected_blocks = 256;
        limits.affected_bytes = 1 << 20;
        let planning = ExtEditLimits {
            audit: limits.audit,
            file_blocks: 256,
            directory_entries: 32,
            affected_bytes: 1 << 20,
            work: 100000,
            undo: UndoLimits {
                patches: 1024,
                body_bytes: 4 << 20,
            },
        };
        let mut session =
            Session::open(if extended { fixture_256() } else { fixture() }, limits, &r).unwrap();
        let old = session
            .file_at(&[NativeName::Bytes(b"file".to_vec())], &r.cancellation)
            .unwrap();
        assert_eq!(old.inode_number(), 11);
        let metadata = ExtCreateMetadata::zeroed(0o100640);
        let payload: Vec<u8> = (0..4097).map(|index| (index * 17 + 3) as u8).collect();
        session
            .operate(
                Operation::CreateFile {
                    parent: &[],
                    name: b"new\xff",
                    metadata: &metadata,
                    payload: &payload,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        assert!(
            session
                .read_at(&old, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        let number = {
            let (decoder, proof) = super::super::super::ExtDecoder::open_native_clean(
                &session.storage,
                session.scope,
                &r,
            )
            .unwrap();
            let directory = decoder.directory(2, 8, 32, &r).unwrap();
            let number = directory
                .entries()
                .iter()
                .find(
                    |entry| matches!(&entry.name, NativeName::Bytes(bytes) if bytes == b"new\xff"),
                )
                .unwrap()
                .inode;
            drop((directory, decoder, proof));
            number
        };
        let file = session.file(number, &r.cancellation).unwrap();
        let input = Input {
            identity: ObjectId {
                source: 999,
                generation: 7,
                native: vec![1],
            },
            bytes: (0..11000).map(|index| (index * 31 + 9) as u8).collect(),
        };
        session
            .operate(
                Operation::Extend {
                    file: &file,
                    input: &input,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        drop(file);
        let file = session.file(number, &r.cancellation).unwrap();
        let mut expected = payload.clone();
        expected.extend_from_slice(&input.bytes);
        let mut actual = vec![0; expected.len()];
        assert_eq!(
            session
                .read_at(&file, 0, &mut actual, &r.cancellation)
                .unwrap(),
            actual.len()
        );
        assert_eq!(actual, expected);
        session
            .operate(
                Operation::Truncate {
                    file: &file,
                    length: 513,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        drop(file);
        let writes = session.storage.writes;
        let generation = session.generation;
        assert!(
            session
                .operate(
                    Operation::Delete {
                        parent: &[],
                        name: b"new\xff",
                        deletion_time: 42
                    },
                    planning,
                    &r.cancellation
                )
                .is_err()
        );
        assert_eq!(session.storage.writes, writes);
        assert_eq!(session.generation, generation);
        assert_eq!(session.state, State::Ready);
        let metadata = ExtCreateMetadata::zeroed(0o40750);
        session
            .operate(
                Operation::CreateDirectory {
                    parent: &[],
                    name: b"dir",
                    metadata: &metadata,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        let dir = [NativeName::Bytes(b"dir".to_vec())];
        session
            .operate(
                Operation::Rename {
                    source: &[],
                    name: b"new\xff",
                    destination: &dir,
                    new_name: b"moved\xfe",
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        assert!(
            session
                .operate(
                    Operation::Delete {
                        parent: &[],
                        name: b"dir",
                        deletion_time: 1234567
                    },
                    planning,
                    &r.cancellation
                )
                .is_err()
        );
        assert_eq!(session.state, State::Ready);
        let file = session.file(number, &r.cancellation).unwrap();
        let mut actual = [0; 513];
        assert_eq!(
            session
                .read_at(&file, 0, &mut actual, &r.cancellation)
                .unwrap(),
            513
        );
        assert_eq!(&actual, &payload[..513]);
        session
            .operate(
                Operation::Delete {
                    parent: &dir,
                    name: b"moved\xfe",
                    deletion_time: 1234567,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        session
            .operate(
                Operation::Delete {
                    parent: &[],
                    name: b"dir",
                    deletion_time: 1234568,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        assert_eq!(session.generation, 7);
        if extended {
            let before = fixture_256().bytes;
            for number in [2usize, 8, 11] {
                let at = 64 * 1024 + (number - 1) * 256 + 128;
                assert_eq!(&session.storage.bytes[at..at + 128], &before[at..at + 128]);
            }
            let at = 64 * 1024 + (number as usize - 1) * 256 + 128;
            assert_eq!(super::super::super::u16le(&session.storage.bytes, at), 32);
            assert!(
                session.storage.bytes[at + 2..at + 128]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        drop((file, old, session));
        assert_eq!(r.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn extended_classic_existing_tails_exact_replace_extend_truncate_and_refunds() {
        use crate::{fs_ext_edit::ExtEditLimits, fs_undo::UndoLimits};
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let mut limits = limits();
        limits.file_blocks = 64;
        limits.affected_blocks = 64;
        limits.affected_bytes = 1 << 20;
        let planning = ExtEditLimits {
            audit: limits.audit,
            file_blocks: 64,
            directory_entries: 32,
            affected_bytes: 1 << 20,
            work: 100000,
            undo: UndoLimits {
                patches: 1024,
                body_bytes: 4 << 20,
            },
        };
        let storage = fixture_256();
        let at = 64 * 1024 + 10 * 256;
        let native = storage.bytes[at..at + 256].to_vec();
        let mut expected: Vec<u8> = (0..128).collect();
        let mut owner = Session::open(storage, limits, &r).unwrap();
        let file = owner.file(11, &r.cancellation).unwrap();
        let replacement: Vec<u8> = expected[13..77].iter().map(|b| b ^ 0x57).collect();
        owner
            .replace(&file, 13, &replacement, &r.cancellation)
            .unwrap();
        expected[13..77].copy_from_slice(&replacement);
        assert_eq!(&owner.storage.bytes[at..at + 256], &native);
        assert!(
            owner
                .read_at(&file, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(file);
        let input = Input {
            identity: ObjectId {
                source: 888,
                generation: 1,
                native: vec![8],
            },
            bytes: (0..13000).map(|n| (n * 31 + n / 47) as u8).collect(),
        };
        for step in 0..2 {
            let file = owner.file(11, &r.cancellation).unwrap();
            if step == 0 {
                owner
                    .operate(
                        Operation::Extend {
                            file: &file,
                            input: &input,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
                expected.extend_from_slice(&input.bytes);
            } else {
                owner
                    .operate(
                        Operation::Truncate {
                            file: &file,
                            length: 513,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
                expected.truncate(513);
            }
            assert_eq!(&owner.storage.bytes[at + 128..at + 256], &native[128..]);
            assert!(
                owner
                    .read_at(&file, 0, &mut [0; 1], &r.cancellation)
                    .is_err()
            );
            drop(file);
            let current = owner.file(11, &r.cancellation).unwrap();
            let mut actual = vec![0; expected.len()];
            assert_eq!(
                owner
                    .read_at(&current, 0, &mut actual, &r.cancellation)
                    .unwrap(),
                actual.len()
            );
            assert_eq!(actual, expected);
            drop(current);
        }
        drop(owner);
        assert_eq!(r.memory.used(), 0);
    }
    #[cfg(feature = "std")]
    #[test]
    fn owned_native_operations_every_write_barrier_torn_restart_old_or_new() {
        exercise_operation_restart(false);
    }
    #[cfg(feature = "std")]
    #[test]
    fn owned_extended_native_operations_every_write_barrier_torn_restart_old_or_new() {
        exercise_operation_restart(true);
    }
    fn exercise_operation_restart(extended: bool) {
        use crate::{
            fs_core::NativeName,
            fs_ext_edit::{ExtCreateMetadata, ExtEditLimits},
            fs_undo::UndoLimits,
        };
        use recovery::tests::Fault;
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let mut limits = limits();
        limits.file_blocks = 64;
        limits.affected_blocks = 64;
        limits.affected_bytes = 1 << 20;
        let planning = ExtEditLimits {
            audit: limits.audit,
            file_blocks: 64,
            directory_entries: 32,
            affected_bytes: 1 << 20,
            work: 100000,
            undo: UndoLimits {
                patches: 1024,
                body_bytes: 4 << 20,
            },
        };
        let directory = ExtCreateMetadata::zeroed(0o40750);
        let regular = ExtCreateMetadata::zeroed(0o100640);
        let dir = [NativeName::Bytes(b"dir".to_vec())];
        let input = Input {
            identity: ObjectId {
                source: 777,
                generation: 1,
                native: vec![1],
            },
            bytes: vec![0x39; 13000],
        };
        for case in 0..7 {
            let mut initial =
                Session::open(if extended { fixture_256() } else { fixture() }, limits, &r)
                    .unwrap();
            if case == 4 || case == 6 {
                initial
                    .operate(
                        Operation::CreateDirectory {
                            parent: &[],
                            name: b"dir",
                            metadata: &directory,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
            }
            let (storage, state) = initial.into_storage();
            assert_eq!(state, State::Ready);
            let image = storage.bytes;
            let make = |immediate, failed_flush_persists, torn, cut| Fault {
                visible: image.clone(),
                durable: image.clone(),
                events: 0,
                cut,
                immediate,
                failed_flush_persists,
                torn,
            };
            let perform = |session: &mut Session<Fault>| {
                let file = session.file(11, &r.cancellation).unwrap();
                let operation = match case {
                    0 => Operation::CreateFile {
                        parent: &[],
                        name: b"new\xff",
                        metadata: &regular,
                        payload: &[0x52; 1501],
                    },
                    1 => Operation::CreateDirectory {
                        parent: &[],
                        name: b"new\xfe",
                        metadata: &directory,
                    },
                    2 => Operation::Extend {
                        file: &file,
                        input: &input,
                    },
                    3 => Operation::Truncate {
                        file: &file,
                        length: 17,
                    },
                    4 => Operation::Rename {
                        source: &[],
                        name: b"file",
                        destination: &dir,
                        new_name: b"moved\xfd",
                    },
                    5 => Operation::Delete {
                        parent: &[],
                        name: b"file",
                        deletion_time: 1234567,
                    },
                    6 => Operation::Delete {
                        parent: &[],
                        name: b"dir",
                        deletion_time: 1234568,
                    },
                    _ => unreachable!(),
                };
                session.operate(operation, planning, &r.cancellation)
            };
            let mut success =
                Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
            perform(&mut success).unwrap();
            let (success, state) = success.into_storage();
            assert_eq!(state, State::Ready);
            let events = success.events;
            assert!(events > 24);
            for immediate in [false, true] {
                for failed_flush_persists in [false, true] {
                    for torn in [false, true] {
                        for cut in 1..=events {
                            let mut session = Session::open(
                                make(immediate, failed_flush_persists, torn, cut),
                                limits,
                                &r,
                            )
                            .unwrap();
                            assert!(perform(&mut session).is_err(), "case={case} cut={cut}");
                            assert_eq!(session.state, State::NeedsRecovery);
                            assert_eq!(r.memory.used(), 0);
                            // Process restart loses volatile writes; recovery reauthorizes this owned storage.
                            let (mut target, _) = session.into_storage();
                            target.visible.clone_from(&target.durable);
                            target.cut = usize::MAX;
                            recovery::recover(
                                &mut target,
                                18u128 << 64,
                                limits.audit,
                                limits.affected_blocks + 1,
                                &r,
                            )
                            .unwrap();
                            let same_home = |expected: &[u8]| {
                                target.durable[..100 * 1024] == expected[..100 * 1024]
                                    && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                            };
                            assert!(
                                same_home(&image) || same_home(&success.durable),
                                "partial home case={case} cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                            );
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn owned_scope_generation_ranges_uncertainty_reinspection_limits_and_refunds() {
        let r = Resources {
            memory: Budget::new(8 << 20),
            cancellation: Cancellation::default(),
        };
        let original = fixture().bytes;
        let mut session = Session::open(fixture(), limits(), &r).unwrap();
        let file = session.file(11, &r.cancellation).unwrap();
        assert_eq!(file.identity.source >> 64, 18);
        let setup_reads = session.storage.reads.get();
        assert!(setup_reads > 10);
        // Setup/indexing is charged separately. Repeated/random payload requests
        // issue exactly one mapped data read, with no superblock/GDT/inode/JBD IO.
        for attempt in 0..128usize {
            let offset = (attempt * 37) % 128;
            let mut bytes = [0; 16];
            let before = session.storage.reads.get();
            let count = session
                .read_at(&file, offset as u64, &mut bytes, &r.cancellation)
                .unwrap();
            let expected = (128 - offset).min(bytes.len());
            assert_eq!(count, expected);
            assert_eq!(
                &bytes[..count],
                &original[31 * 1024 + offset..31 * 1024 + offset + count]
            );
            assert_eq!(session.storage.reads.get(), before + 1);
            assert_eq!(
                session.storage.last_read.get(),
                Some(((31 * 1024 + offset) as u64, count))
            );
        }
        let payload_reads = session.storage.reads.get();
        assert_eq!(
            session
                .read_at(&file, 128, &mut [0; 16], &r.cancellation)
                .unwrap(),
            0
        );
        assert_eq!(
            session.read_at(&file, 0, &mut [], &r.cancellation).unwrap(),
            0
        );
        assert_eq!(session.storage.reads.get(), payload_reads);
        let mut out = [0; 16];
        assert_eq!(
            session
                .read_at(&file, 120, &mut out, &r.cancellation)
                .unwrap(),
            8
        );
        assert_eq!(&out[..8], &original[31 * 1024 + 120..31 * 1024 + 128]);
        assert_eq!(
            session
                .read_at(&file, 128, &mut out, &r.cancellation)
                .unwrap(),
            0
        );
        assert!(
            session
                .replace(&file, 127, &[1, 2], &r.cancellation)
                .is_err()
        );
        assert_eq!(session.storage.writes, 0);
        let foreign = Session::open(fixture(), limits(), &r).unwrap();
        let foreign_file = foreign.file(11, &r.cancellation).unwrap();
        assert_ne!(foreign_file.identity.source, file.identity.source);
        assert!(
            session
                .read_at(&foreign_file, 0, &mut out, &r.cancellation)
                .is_err()
        );
        session
            .replace(&file, 23, &[0x71; 70], &r.cancellation)
            .unwrap();
        assert!(
            session
                .read_at(&file, 0, &mut out, &r.cancellation)
                .is_err()
        );
        let current = session.file(11, &r.cancellation).unwrap();
        assert_eq!(current.identity.generation, 1);
        assert_eq!(current.identity.source, file.identity.source);
        assert_eq!(
            session
                .read_at(&current, 23, &mut out, &r.cancellation)
                .unwrap(),
            16
        );
        assert_eq!(out, [0x71; 16]);
        let mut expected = original;
        expected[31 * 1024 + 23..31 * 1024 + 93].fill(0x71);
        assert_eq!(session.storage.bytes[..100 * 1024], expected[..100 * 1024]);
        assert_eq!(
            session.storage.bytes[1124 * 1024..],
            expected[1124 * 1024..]
        );
        session.storage.fail_write = true;
        assert!(session.replace(&current, 0, &[9], &r.cancellation).is_err());
        assert_eq!(session.state, State::NeedsRecovery);
        assert!(session.file(11, &r.cancellation).is_err());
        assert!(
            session
                .read_at(&current, 0, &mut out, &r.cancellation)
                .is_err()
        );
        session.storage.fail_write = false;
        session.recover(&r.cancellation).unwrap();
        assert_eq!(session.state, State::Ready);
        assert!(
            session
                .read_at(&current, 0, &mut out, &r.cancellation)
                .is_err()
        );
        let renewed = session.file(11, &r.cancellation).unwrap();
        assert_eq!(renewed.identity.generation, 3);
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let writes = session.storage.writes;
        assert!(session.replace(&renewed, 0, &[1], &cancellation).is_err());
        assert_eq!(session.storage.writes, writes);
        assert_eq!(session.state, State::Ready);
        session.storage.bytes.push(0);
        assert!(
            session
                .read_at(&renewed, 0, &mut out, &r.cancellation)
                .is_err()
        );
        assert!(session.recover(&r.cancellation).is_err());
        assert_eq!(session.storage.writes, writes);
        session.storage.bytes.pop();
        session.generation = u64::MAX;
        let exhausted = session.file(11, &r.cancellation).unwrap();
        assert!(
            session
                .replace(&exhausted, 0, &[1], &r.cancellation)
                .is_err()
        );
        assert_eq!(session.storage.writes, writes);
        assert_eq!(session.state, State::Ready);
        assert!(session.recover(&r.cancellation).is_err());
        assert_eq!(session.storage.writes, writes);
        drop((
            file,
            current,
            renewed,
            exhausted,
            foreign_file,
            foreign,
            session,
        ));
        assert_eq!(r.memory.used(), 0);
        let mut capped = limits();
        capped.affected_bytes = 0;
        let mut session = Session::open(fixture(), capped, &r).unwrap();
        let file = session.file(11, &r.cancellation).unwrap();
        assert!(session.replace(&file, 0, &[1], &r.cancellation).is_err());
        assert_eq!(session.storage.writes, 0);
        assert_eq!(session.state, State::Ready);
        let (storage, state) = session.into_storage();
        assert_eq!(state, State::Ready);
        drop((file, storage));
        assert_eq!(r.memory.used(), 0);
    }
}
