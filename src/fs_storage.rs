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

use virtdisk::{Capability, ImageOperation, ImageWriter, InspectImage, WriteAt};

struct WriterStorage(ImageWriter);
impl Storage for WriterStorage {
    fn len(&self) -> io::Result<u64> {
        Ok(WriteAt::len(&self.0))
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_all_at(at, bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        WriteAt::flush(&self.0)
    }
}
/// Owns a writer and fixed bounded region without exposing management or writer aliases.
///
/// Locks may be advisory. Callers must exclude mounted access and external writers,
/// keep every backing parent immutable, and own later publication/directory sync.
/// This mutable session does not implement immutable ReadAt.
pub struct ImageWriterSession {
    region: BoundedSession<WriterStorage>,
}
impl ImageWriterSession {
    /// Consume an already explicitly opened writer and inspect actual handle capabilities.
    /// Supplied sector facts fill unknown values; conflicting known facts reject.
    /// Construction validates bounds but does not authorize filesystem mutation.
    pub fn new(
        writer: ImageWriter,
        start: u64,
        length: u64,
        supplied: SectorGeometry,
    ) -> io::Result<Self> {
        let facts = writer.inspection();
        for operation in [
            ImageOperation::Read,
            ImageOperation::Write,
            ImageOperation::Flush,
        ] {
            if facts.capabilities.get(operation) != Capability::Supported {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "writer handle lacks a required session operation",
                ));
            }
        }
        let supplied = SectorGeometry::new(supplied.logical, supplied.physical)?;
        fn fact(known: Option<u32>, supplied: Option<u32>) -> io::Result<Option<u32>> {
            if let (Some(known), Some(supplied)) = (known, supplied)
                && known != supplied
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "supplied sector geometry conflicts with writer inspection",
                ));
            }
            Ok(known.or(supplied))
        }
        let geometry = SectorGeometry::new(
            fact(facts.geometry.logical_sector_size, supplied.logical)?,
            fact(facts.geometry.physical_sector_size, supplied.physical)?,
        )?;
        Ok(Self {
            region: BoundedSession::new(WriterStorage(writer), start, length, geometry)?,
        })
    }
    /// Actual or explicitly supplied sector facts; no atomic-write promise is inferred.
    pub fn geometry(&self) -> SectorGeometry {
        self.region.geometry()
    }
    /// Sticky uncertainty after a write or durability barrier error.
    pub fn mutation_uncertain(&self) -> bool {
        self.region.mutation_uncertain()
    }
    /// Zero a fully prevalidated range with bounded scratch, without implicit flush.
    pub fn zero(&mut self, at: u64, length: u64) -> io::Result<()> {
        self.region.zero_at(at, length)
    }
}
impl Storage for ImageWriterSession {
    fn len(&self) -> io::Result<u64> {
        self.region.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.region.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.region.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.region.flush()
    }
}

#[cfg(test)]
mod faults {
    use super::*;
    use virtdisk::{Image, ImageFormat, ReadAt};
    struct FaultWriter {
        inner: WriterStorage,
        partial: bool,
        fail_flush: bool,
    }
    impl Storage for FaultWriter {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read_exact_at(at, out)
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            if self.partial {
                self.inner.write_at(at, &bytes[..bytes.len() / 2])?;
                return Err(io::Error::other(
                    "injected error after partial real writer mutation",
                ));
            }
            self.inner.write_at(at, bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::other("injected durability barrier failure"));
            }
            self.inner.flush()
        }
    }
    #[test]
    fn partial_mutation_and_flush_failure_retain_actual_writer_and_sticky_uncertainty() {
        for partial in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("fault.raw");
            let writer = ImageWriter::create(&path, ImageFormat::Raw, 8192).unwrap();
            let fault = FaultWriter {
                inner: WriterStorage(writer),
                partial,
                fail_flush: !partial,
            };
            let mut session =
                BoundedSession::new(fault, 4096, 512, SectorGeometry::default()).unwrap();
            if partial {
                assert!(session.write_at(0, &[7; 100]).is_err());
            } else {
                assert_eq!(session.write_at(0, &[7; 100]).unwrap(), 100);
                assert!(session.flush().is_err());
            }
            assert!(session.mutation_uncertain());
            assert!(ImageWriter::open(&path, ImageFormat::Raw).is_err());
            let mut bytes = [0; 100];
            session.read_exact_at(0, &mut bytes).unwrap();
            assert_eq!(&bytes[..50], &[7; 50]);
            assert_eq!(&bytes[50..], if partial { &[0; 50] } else { &[7; 50] });
            if partial {
                session.flush().unwrap();
                assert!(session.mutation_uncertain());
            }
            drop(session);
            let reopened = Image::open(&path, Some(ImageFormat::Raw)).unwrap();
            reopened.read_exact_at(4096, &mut bytes).unwrap();
            assert_eq!(&bytes[..50], &[7; 50]);
        }
    }
}
