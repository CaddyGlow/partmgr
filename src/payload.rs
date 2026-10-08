//! Recoverable payload copying and filesystem resize ordering.
//!
//! Copying requires exclusive disk access and a separate recovery medium with
//! capacity for a complete disk snapshot plus 256 bytes. RAM usage is bounded by
//! the chosen chunk size. Retain that medium until the containing layout commits.
use crate::platform::io;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::storage::Storage;
use sha2::{Digest, Sha256};
const SNAPSHOT: u64 = 256;
fn invalid(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn exact(s: &mut dyn Storage, mut o: u64, mut b: &[u8]) -> io::Result<()> {
    while !b.is_empty() {
        let n = s.write_at(o, b)?;
        if n == 0 || n > b.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "invalid short write",
            ));
        }
        o += n as u64;
        b = &b[n..];
    }
    Ok(())
}
fn number(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
/// Durable progress from a recoverable copy.
#[derive(Debug, PartialEq, Eq)]
pub enum CopyOutcome {
    /// All copied bytes were durably flushed and verified.
    Complete,
    /// Cancellation occurred at a durable chunk boundary.
    Cancelled {
        /// Bytes durably copied.
        copied: u64,
    },
}
/// Immutable copy description backed by a full independent source snapshot.
#[derive(Clone, Debug)]
pub struct CopyOperation {
    length: u64,
    source: u64,
    destination: u64,
    count: u64,
    chunk: usize,
}
#[derive(Clone)]
struct Record {
    progress: u64,
    pending: u64,
    sequence: u64,
    hash: [u8; 32],
}
impl CopyOperation {
    /// Snapshot the entire disk before destructive writes. Recovery storage must
    /// be independent and exclusively held; this method never modifies the disk.
    pub fn prepare(
        disk: &dyn Storage,
        recovery: &mut dyn Storage,
        source: u64,
        destination: u64,
        count: u64,
        chunk: usize,
    ) -> io::Result<Self> {
        let length = disk.len()?;
        let op = Self {
            length,
            source,
            destination,
            count,
            chunk,
        };
        op.validate()?;
        if recovery.len()?
            < length
                .checked_add(SNAPSHOT)
                .ok_or_else(|| invalid("snapshot overflow"))?
        {
            return Err(invalid("recovery medium too small"));
        }
        // Invalidate both old journal slots before writing a new snapshot.
        exact(recovery, 0, &[0; 256])?;
        recovery.flush()?;
        let mut hash = Sha256::new();
        let mut b = vec![0; chunk];
        let mut offset = 0;
        while offset < length {
            let n = (length - offset).min(chunk as u64) as usize;
            disk.read_exact_at(offset, &mut b[..n])?;
            hash.update(&b[..n]);
            exact(recovery, SNAPSHOT + offset, &b[..n])?;
            offset += n as u64;
        }
        recovery.flush()?;
        let r = Record {
            progress: 0,
            pending: 0,
            sequence: 0,
            hash: hash.finalize().into(),
        };
        op.save(recovery, &r)?;
        Ok(op)
    }
    fn validate(&self) -> io::Result<()> {
        if self.chunk == 0
            || self.chunk > 16 * 1024 * 1024
            || self.count == 0
            || self
                .source
                .checked_add(self.count)
                .is_none_or(|n| n > self.length)
            || self
                .destination
                .checked_add(self.count)
                .is_none_or(|n| n > self.length)
        {
            return Err(invalid("invalid copy geometry or chunk size"));
        }
        Ok(())
    }
    fn encode(&self, r: &Record) -> [u8; 128] {
        let mut b = [0; 128];
        b[..8].copy_from_slice(b"PMCOPY01");
        for (i, n) in [
            self.length,
            self.source,
            self.destination,
            self.count,
            r.progress,
            r.pending,
            r.sequence,
        ]
        .iter()
        .enumerate()
        {
            b[8 + i * 8..16 + i * 8].copy_from_slice(&n.to_le_bytes());
        }
        b[64..96].copy_from_slice(&r.hash);
        let digest = Sha256::digest(&b[..96]);
        b[96..].copy_from_slice(&digest);
        b
    }
    fn save(&self, s: &mut dyn Storage, r: &Record) -> io::Result<()> {
        exact(s, (r.sequence % 2) * 128, &self.encode(r))?;
        s.flush()
    }
    fn read(s: &dyn Storage, chunk: usize) -> io::Result<(Self, Record)> {
        let mut best = None;
        for slot in 0..2 {
            let mut b = [0; 128];
            s.read_exact_at(slot * 128, &mut b)?;
            if &b[..8] != b"PMCOPY01" || Sha256::digest(&b[..96])[..] != b[96..] {
                continue;
            }
            let op = Self {
                length: number(&b, 8),
                source: number(&b, 16),
                destination: number(&b, 24),
                count: number(&b, 32),
                chunk,
            };
            op.validate()?;
            let r = Record {
                progress: number(&b, 40),
                pending: number(&b, 48),
                sequence: number(&b, 56),
                hash: b[64..96].try_into().unwrap(),
            };
            if r.progress > op.count || r.pending > op.count - r.progress {
                return Err(invalid("invalid recovery progress"));
            }
            if best
                .as_ref()
                .is_none_or(|(_, old): &(Self, Record)| r.sequence > old.sequence)
            {
                best = Some((op, r));
            }
        }
        best.ok_or_else(|| invalid("no intact recovery record"))
    }
    /// Reload an intact journal and verify its complete snapshot digest.
    pub fn load(s: &dyn Storage, chunk: usize) -> io::Result<Self> {
        let (op, r) = Self::read(s, chunk)?;
        op.verify_snapshot(s, &r)?;
        Ok(op)
    }
    /// Commit a containing layout only after durable, independently verified
    /// payload completion. The caller retains exclusive access while the
    /// supplied metadata commit runs. Recovery storage must remain available
    /// if that commit reports an interruption.
    pub fn commit_layout<T, S: Storage + ?Sized>(
        &self,
        disk: &mut S,
        recovery: &dyn Storage,
        commit: impl FnOnce(&mut S) -> io::Result<T>,
    ) -> io::Result<T> {
        let (operation, record) = Self::read(recovery, self.chunk)?;
        if (
            operation.length,
            operation.source,
            operation.destination,
            operation.count,
        ) != (self.length, self.source, self.destination, self.count)
            || record.progress != self.count
            || record.pending != 0
        {
            return Err(invalid("payload prerequisite incomplete or mismatched"));
        }
        self.verify_snapshot(recovery, &record)?;
        self.verify_disk(disk, recovery, &record)?;
        commit(disk)
    }
    fn verify_snapshot(&self, s: &dyn Storage, r: &Record) -> io::Result<()> {
        let mut hash = Sha256::new();
        let mut b = vec![0; self.chunk];
        let mut o = 0;
        while o < self.length {
            let n = (self.length - o).min(self.chunk as u64) as usize;
            s.read_exact_at(SNAPSHOT + o, &mut b[..n])?;
            hash.update(&b[..n]);
            o += n as u64;
        }
        if hash.finalize()[..] != r.hash {
            return Err(invalid("corrupt recovery snapshot"));
        }
        Ok(())
    }
    fn verify_disk<S: Storage + ?Sized>(
        &self,
        disk: &S,
        s: &dyn Storage,
        r: &Record,
    ) -> io::Result<()> {
        if disk.len()? != self.length {
            return Err(invalid("changed disk geometry"));
        }
        let mut actual = vec![0; self.chunk];
        let mut old = vec![0; self.chunk];
        let mut o = 0;
        while o < self.length {
            let n = (self.length - o).min(self.chunk as u64) as usize;
            disk.read_exact_at(o, &mut actual[..n])?;
            s.read_exact_at(SNAPSHOT + o, &mut old[..n])?;
            let mut wanted = old[..n].to_vec();
            let changed_start = o.max(self.destination);
            let changed_end = (o + n as u64).min(self.destination + r.progress + r.pending);
            if changed_start < changed_end {
                let start = (changed_start - o) as usize;
                let end = (changed_end - o) as usize;
                s.read_exact_at(
                    SNAPSHOT + self.source + changed_start - self.destination,
                    &mut wanted[start..end],
                )?;
            }
            for i in 0..n {
                let pos = o + i as u64;
                let pending = pos >= self.destination + r.progress
                    && pos < self.destination + r.progress + r.pending;
                if actual[i] != wanted[i] && (!pending || actual[i] != old[i]) {
                    return Err(invalid("changed disk outside durable copy state"));
                }
            }
            o += n as u64;
        }
        Ok(())
    }
    /// Copy from the durable snapshot. `continue_copy` receives copied and total
    /// bytes before each fresh chunk; false cancels at a safe boundary. A pending
    /// interrupted chunk is completed before cancellation is considered. I/O errors may
    /// leave a pending chunk; reloading and rerunning safely rewrites that chunk.
    pub fn run(
        &self,
        disk: &mut dyn Storage,
        s: &mut dyn Storage,
        mut continue_copy: impl FnMut(u64, u64) -> bool,
    ) -> io::Result<CopyOutcome> {
        let (op, mut r) = Self::read(s, self.chunk)?;
        if (op.length, op.source, op.destination, op.count)
            != (self.length, self.source, self.destination, self.count)
        {
            return Err(invalid("different recovery operation"));
        }
        self.verify_snapshot(s, &r)?;
        self.verify_disk(disk, s, &r)?;
        let mut b = vec![0; self.chunk];
        while r.progress < self.count {
            if r.pending == 0 && !continue_copy(r.progress, self.count) {
                return Ok(CopyOutcome::Cancelled { copied: r.progress });
            }
            let n = if r.pending > 0 {
                r.pending
            } else {
                (self.count - r.progress).min(self.chunk as u64)
            };
            if n > self.chunk as u64 {
                return Err(invalid("resume chunk smaller than pending chunk"));
            }
            if r.pending == 0 {
                r.pending = n;
                r.sequence = r
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("journal sequence overflow"))?;
                self.save(s, &r)?;
            }
            s.read_exact_at(SNAPSHOT + self.source + r.progress, &mut b[..n as usize])?;
            exact(disk, self.destination + r.progress, &b[..n as usize])?;
            disk.flush()?;
            let mut actual = vec![0; n as usize];
            disk.read_exact_at(self.destination + r.progress, &mut actual)?;
            if actual != b[..n as usize] {
                return Err(invalid("copy verification failed"));
            }
            r.progress += n;
            r.pending = 0;
            r.sequence = r
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("journal sequence overflow"))?;
            self.save(s, &r)?;
        }
        Ok(CopyOutcome::Complete)
    }
}
/// Filesystem operations are separate from partition metadata operations.
pub trait FilesystemResize {
    /// Shrink the filesystem and durably complete its work.
    fn shrink(&mut self, new_bytes: u64) -> io::Result<()>;
    /// Grow the filesystem within an already enlarged partition.
    fn grow(&mut self, new_bytes: u64) -> io::Result<()>;
}
/// Grow the containing partition successfully before growing its filesystem.
/// Filesystem failure leaves the larger containing partition in place.
pub fn grow_filesystem(
    adapter: &mut dyn FilesystemResize,
    new_bytes: u64,
    commit_boundary: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    commit_boundary()?;
    adapter.grow(new_bytes)
}
/// Complete filesystem shrink before committing a smaller containing partition.
/// Boundary failure leaves the smaller filesystem in the larger partition.
pub fn shrink_filesystem(
    adapter: &mut dyn FilesystemResize,
    new_bytes: u64,
    commit_boundary: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    adapter.shrink(new_bytes)?;
    commit_boundary()
}
