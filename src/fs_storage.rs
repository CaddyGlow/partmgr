//! Owned, bounded mutable storage for filesystem editors.
//!
//! A session keeps its backend private until it is dropped. Backend locks can
//! be advisory: callers must exclude mounted access and external writers, and
//! keep backing parents immutable. No immutable `virtdisk::ReadAt` contract is
//! implemented, and no resize or snapshot-management capability is exposed.
use crate::storage::Storage;
use std::{fmt, io};

/// Backend sector facts. Unknown geometry remains `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectorGeometry {
    /// Logical sector size; independent of filesystem block size.
    pub logical: Option<u32>,
    /// Physical sector size; does not imply atomic writes.
    pub physical: Option<u32>,
}
impl SectorGeometry {
    /// Validate supplied facts without guessing missing values.
    pub fn new(logical: Option<u32>, physical: Option<u32>) -> io::Result<Self> {
        if [logical, physical].into_iter().flatten().any(|n| n == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero sector size",
            ));
        }
        Ok(Self { logical, physical })
    }
}

/// A write or durability barrier failed after mutation could have occurred.
///
/// The source retains the backend failure; no byte count or rollback is inferred
/// from an error. Even a successful flush cannot prove a failed write was complete.
#[derive(Debug)]
pub struct UncertainMutation {
    operation: &'static str,
    source: io::Error,
}
impl UncertainMutation {
    /// Backend operation that failed.
    pub fn operation(&self) -> &'static str {
        self.operation
    }
}
impl fmt::Display for UncertainMutation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed; mutation/durability uncertain: {}",
            self.operation, self.source
        )
    }
}
impl std::error::Error for UncertainMutation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// An owned fixed region of an exclusive backend.
///
/// Construction validates byte bounds, not filesystem or partition correctness.
/// The entire parent stays owned, so management operations cannot be invoked
/// through this adapter. `flush` delegates the backend's durability promise;
/// publication-directory durability remains an orchestration responsibility.
pub struct BoundedSession<S> {
    backend: S,
    start: u64,
    length: u64,
    parent_length: u64,
    geometry: SectorGeometry,
    uncertain: bool,
}
impl<S: Storage> BoundedSession<S> {
    /// Consume the backend, retaining its lock throughout the session lifetime.
    pub fn new(backend: S, start: u64, length: u64, geometry: SectorGeometry) -> io::Result<Self> {
        let geometry = SectorGeometry::new(geometry.logical, geometry.physical)?;
        let parent_length = backend.len()?;
        if start
            .checked_add(length)
            .is_none_or(|end| end > parent_length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session exceeds backend",
            ));
        }
        Ok(Self {
            backend,
            start,
            length,
            parent_length,
            geometry,
            uncertain: false,
        })
    }
    /// Report sector facts without advertising atomicity.
    pub fn geometry(&self) -> SectorGeometry {
        self.geometry
    }
    /// Whether any mutation or flush has failed in this session.
    ///
    /// Sticky until drop; recovery and reinspection must decide actual consistency.
    pub fn mutation_uncertain(&self) -> bool {
        self.uncertain
    }
    fn absolute(&self, offset: u64, count: u64) -> io::Result<u64> {
        if offset
            .checked_add(count)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operation exceeds session",
            ));
        }
        if self.backend.len()? != self.parent_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "backend geometry changed during session",
            ));
        }
        self.start
            .checked_add(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "session offset overflow"))
    }
    fn failed(&mut self, operation: &'static str, source: io::Error) -> io::Error {
        self.uncertain = true;
        io::Error::new(source.kind(), UncertainMutation { operation, source })
    }
    /// Zero a bounded range using constant scratch space, without implicit flush.
    ///
    /// The whole range is checked before the first write. Failure after any
    /// accepted write can leave partially zeroed bytes.
    pub fn zero_at(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.absolute(offset, length)?;
        let zeros = [0u8; 64 * 1024];
        let mut done = 0;
        while done < length {
            let count = (length - done).min(zeros.len() as u64) as usize;
            let written = match self.write_at(offset + done, &zeros[..count]) {
                Ok(written) => written,
                Err(error) if done != 0 && !self.uncertain => {
                    return Err(self.failed("zero", error));
                }
                Err(error) => return Err(error),
            };
            if written == 0 {
                return Err(self.failed("zero", io::ErrorKind::WriteZero.into()));
            }
            done += written as u64;
        }
        Ok(())
    }
}
impl<S: Storage> Storage for BoundedSession<S> {
    fn len(&self) -> io::Result<u64> {
        self.absolute(0, 0)?;
        Ok(self.length)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let absolute = self.absolute(offset, out.len() as u64)?;
        self.backend.read_exact_at(absolute, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let absolute = self.absolute(offset, bytes.len() as u64)?;
        match self.backend.write_at(absolute, bytes) {
            Ok(n) if n <= bytes.len() => Ok(n),
            Ok(_) => Err(self.failed(
                "write",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "backend returned excessive write count",
                ),
            )),
            Err(error) => Err(self.failed("write", error)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Err(error) = self.absolute(0, 0) {
            return Err(self.failed("flush", error));
        }
        self.backend
            .flush()
            .map_err(|error| self.failed("flush", error))
    }
}

/// Immutable bounded region retaining source provenance and shared read budgets.
///
/// This is separate from editor sessions. The caller must keep the backing
/// source stable for every deferred read; a read-only handle alone is insufficient.
pub use virtdisk::DiskView as ImmutableRegion;
