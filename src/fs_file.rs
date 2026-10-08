//! Reusable, immutable handles for already validated uncompressed extent maps.
//!
//! Engines must establish ownership, source stability, and profile validity before
//! constructing a handle. Construction validates ranges, not filesystem ownership.
//! The retained source carries provenance and shared read accounting. No payload
//! is decoded during construction; lookup uses a binary search over a bounded map.
use std::{io, sync::Arc};
use virtdisk::ReadAt;

/// Meaning of one logical file range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentKind {
    /// Bytes stored at this offset in the bounded source.
    Data(u64),
    /// An unallocated sparse range that reads as zero.
    Hole,
    /// Allocated but uninitialized storage that must read as zero.
    Unwritten,
}

/// A nonempty logical extent, in file byte coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileExtent {
    /// Starting file byte offset.
    pub offset: u64,
    /// Byte length.
    pub length: u64,
    /// Storage mapping or zero semantics.
    pub kind: ExtentKind,
}

/// Indexed file mapping bound to one immutable source.
///
/// Clones share the validated index and source; unrelated reads have no shared
/// file cursor here. Any serialization inside the backend remains its limitation.
#[derive(Clone)]
pub struct ExtentFile {
    source: Arc<dyn ReadAt>,
    map: ExtentMap,
}

/// Source-independent checked index. Wrappers establish source stability and ownership.
#[derive(Clone)]
pub(crate) struct ExtentMap {
    length: u64,
    extents: Arc<[FileExtent]>,
}
impl ExtentMap {
    /// Validate a complete ordered map and coalesce physically adjacent ranges.
    ///
    /// `max_extents` bounds the input index, including ranges later coalesced.
    /// Gaps must be declared explicitly as holes. The caller's input allocation
    /// precedes this check; engines must enforce the budget while decoding too.
    pub fn new(
        source_length: u64,
        length: u64,
        extents: Vec<FileExtent>,
        max_extents: usize,
    ) -> io::Result<Self> {
        if extents.len() > max_extents {
            return Err(io::Error::other("file extent budget exhausted"));
        }
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid file extent map");
        let mut position = 0u64;
        let mut index: Vec<FileExtent> = Vec::new();
        index
            .try_reserve_exact(extents.len())
            .map_err(io::Error::other)?;
        for extent in extents {
            if extent.offset != position || extent.length == 0 {
                return Err(invalid());
            }
            position = position.checked_add(extent.length).ok_or_else(invalid)?;
            if position > length {
                return Err(invalid());
            }
            if let ExtentKind::Data(offset) = extent.kind
                && offset
                    .checked_add(extent.length)
                    .is_none_or(|end| end > source_length)
            {
                return Err(invalid());
            }
            if let Some(last) = index.last_mut() {
                let adjacent = match (last.kind, extent.kind) {
                    (ExtentKind::Data(a), ExtentKind::Data(b)) => {
                        a.checked_add(last.length) == Some(b)
                    }
                    (ExtentKind::Hole, ExtentKind::Hole)
                    | (ExtentKind::Unwritten, ExtentKind::Unwritten) => true,
                    _ => false,
                };
                if adjacent {
                    last.length += extent.length;
                    continue;
                }
            }
            index.push(extent);
        }
        if position != length {
            return Err(invalid());
        }
        Ok(Self {
            length,
            extents: index.into(),
        })
    }

    /// Fixed logical file size.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether this file has zero size.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Validated, coalesced map; holes and unwritten ranges remain distinct.
    pub fn extents(&self) -> &[FileExtent] {
        &self.extents
    }

    /// Read a range into caller storage, returning a short count only at EOF.
    ///
    /// Offset beyond EOF is rejected, even with an empty buffer. On backend
    /// failure the buffer may have been partly modified and must be discarded.
    /// Reads issue no host calls for holes and no payload-sized allocations.
    pub fn read_at_with(
        &self,
        offset: u64,
        out: &mut [u8],
        mut read: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        if offset > self.length {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let count = (self.length - offset).min(out.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        let mut i = self
            .extents
            .partition_point(|extent| extent.offset <= offset)
            - 1;
        let mut done = 0;
        while done < count {
            let extent = self.extents[i];
            let within = offset + done as u64 - extent.offset;
            let n = (extent.length - within).min((count - done) as u64) as usize;
            let chunk = &mut out[done..done + n];
            match extent.kind {
                ExtentKind::Data(physical) => read(physical + within, chunk)?,
                ExtentKind::Hole | ExtentKind::Unwritten => chunk.fill(0),
            }
            done += n;
            i += 1;
        }
        Ok(done)
    }
}

impl ExtentFile {
    /// Validate complete ordered mapping for an immutable source.
    pub fn new(
        source: Arc<dyn ReadAt>,
        length: u64,
        extents: Vec<FileExtent>,
        max_extents: usize,
    ) -> io::Result<Self> {
        let map = ExtentMap::new(source.len(), length, extents, max_extents)?;
        Ok(Self { source, map })
    }
    /// Logical file size.
    pub fn len(&self) -> u64 {
        self.map.len()
    }
    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Validated ordered extents.
    pub fn extents(&self) -> &[FileExtent] {
        self.map.extents()
    }
    /// Positional read; backend errors may leave partial bytes in the caller buffer.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        self.map
            .read_at_with(offset, out, |at, buf| self.source.read_exact_at(at, buf))
    }
}
