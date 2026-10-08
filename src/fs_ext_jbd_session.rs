//! Staged owned native journal session; mutable storage never becomes ReadAt.
use super::*;
use crate::{
    fs_core::{Budget, Cancellation, ObjectId},
    fs_ext_audit::ExtAuditLimits,
    storage::Storage,
};
use std::sync::atomic::{AtomicU64, Ordering};
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
            .reserve((std::mem::size_of::<File>() + 512) as u64)
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
                    .checked_mul(std::mem::size_of::<ReplayBlock>())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
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
        let mut expected = original.clone();
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
