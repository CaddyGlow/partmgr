//! Declared logical NOR flash emulation over exclusively owned regular image storage.
//! This is a storage contract, not JFFS2 decoding, physical-device publication or NAND ECC.
use crate::{
    fs_core::{Error, ErrorKind, Reservation, Resources, Result},
    storage::Storage,
};
use std::{fmt, io};

/// Caller-declared dump interpretation; no layout is inferred from payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashLayout {
    /// Logical NOR bytes with no page spare area, ECC or remapping.
    LogicalNor,
    /// Physical NAND dump; requires a future page/OOB/ECC implementation.
    PhysicalNand {
        /// Main bytes per NAND page.
        page_bytes: u32,
        /// Spare/OOB bytes per page.
        spare_bytes: u32,
    },
}
/// Declared allowed bit transitions; these do not imply an atomic program operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashProgramming {
    /// Only one-to-zero transitions are permitted between erase operations.
    ClearBitsOnly,
    /// Only zero-to-one transitions; unavailable in the logical NOR emulator.
    SetBitsOnly,
}
/// Explicit emulation geometry; erased bits are one and programming only clears bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlashGeometry {
    /// Explicit erased-byte value; logical NOR emulation requires 0xff.
    pub erased_byte: u8,
    /// Allowed program transitions; logical NOR emulation requires ClearBitsOnly.
    pub programming: FlashProgramming,
    /// Complete erase-block length in bytes.
    pub erase_bytes: u32,
    /// Required offset and length alignment for programming.
    pub program_bytes: u32,
    /// Declared image layout.
    pub layout: FlashLayout,
}
/// Shared-budget and operation bounds independent of backing-image allocation.
#[derive(Clone, Copy, Debug)]
pub struct FlashLimits {
    /// Maximum retained caller-declared bad erase-block indices.
    pub bad_blocks: usize,
    /// Maximum bytes in one program or erase call, checked before mutation.
    pub operation_bytes: u64,
    /// Bounded preflight/readback/erase scratch; a multiple of program alignment.
    pub scratch_bytes: usize,
}
/// Accepted and verified bytes; neither establishes durable completion without flush.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlashProgress {
    /// Bytes reported successfully written by the backend.
    pub accepted_bytes: u64,
    /// Accepted bytes subsequently compared against actual storage.
    pub verified_bytes: u64,
}
/// Failure preserves the cause and exact known progress, including uncertain mutation.
#[derive(Debug)]
pub struct FlashFailure {
    /// Native operation.
    pub operation: &'static str,
    /// Known accepted/read-back bytes; an error may hide additional partial writes.
    pub progress: FlashProgress,
    /// A target write was attempted; even zero accepted bytes can mean partial mutation.
    pub mutation_attempted: bool,
    /// Domain error with retained causal I/O error.
    pub source: Error,
}
impl fmt::Display for FlashFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flash {}: {}", self.operation, self.source)
    }
}
impl std::error::Error for FlashFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
/// Mutable flash boundary, deliberately separate from immutable disk ReadAt.
/// Implementations declare layout/geometry and retain exclusive access through deferred work.
/// Success means accepted and read-back bytes; flush is a separate durability boundary.
pub trait FlashStorage {
    /// Declared logical/physical layout and erase/program alignment.
    fn geometry(&self) -> FlashGeometry;
    /// Checked fixed length, failing if the backing geometry changed.
    fn len(&self) -> Result<u64>;
    /// Checked empty-state query; ordinary flash profiles require complete erase blocks.
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Read bounded bytes without a shared seek cursor.
    fn read_exact_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<()>;
    /// Apply declared programming transitions without implicitly erasing storage.
    fn program(
        &mut self,
        at: u64,
        bytes: &[u8],
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure>;
    /// Erase complete aligned blocks according to declared geometry.
    fn erase(
        &mut self,
        at: u64,
        count: u64,
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure>;
    /// Explicit backend persistence boundary, separate from publication-directory durability.
    fn flush(&mut self, r: &Resources) -> std::result::Result<(), FlashFailure>;
    /// Sticky uncertainty cannot be erased by a later successful flush alone.
    fn mutation_uncertain(&self) -> bool;
}
/// Owned fixed-length logical NOR emulator. Backing storage must remain exclusively stable.
/// Bad blocks can be read for inspection but cannot be programmed or erased.
/// There is no immutable ReadAt implementation or mutable backing-handle alias.
pub struct FlashImage<S> {
    storage: S,
    length: u64,
    geometry: FlashGeometry,
    limits: FlashLimits,
    bad: Vec<u64>,
    scratch: Vec<u8>,
    erased: Vec<u8>,
    uncertain: bool,
    _lease: Reservation,
}
fn invalid(context: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, context)
}
fn cap(context: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, context)
}
fn fixed<S: Storage>(storage: &S, length: u64) -> Result<()> {
    if storage
        .len()
        .map_err(|e| Error::io("flash source length", e))?
        != length
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "flash backing length changed",
        ));
    }
    Ok(())
}
impl<S: Storage> FlashImage<S> {
    /// Open a caller-declared logical NOR image without formatting or rewriting it.
    /// Bad indices must be strictly sorted, unique and within complete erase blocks.
    pub fn new(
        storage: S,
        geometry: FlashGeometry,
        bad: &[u64],
        limits: FlashLimits,
        r: &Resources,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if geometry.layout != FlashLayout::LogicalNor {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "physical NAND/OOB/ECC flash layout is not implemented",
            ));
        }
        if geometry.erased_byte != 0xff || geometry.programming != FlashProgramming::ClearBitsOnly {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "logical NOR requires erased ones and clear-bit programming",
            ));
        }
        let erase = u64::from(geometry.erase_bytes);
        let program = u64::from(geometry.program_bytes);
        if erase == 0
            || program == 0
            || !erase.is_multiple_of(program)
            || limits.scratch_bytes == 0
            || !(limits.scratch_bytes as u64).is_multiple_of(program)
        {
            return Err(invalid("flash geometry or scratch alignment"));
        }
        let length = storage
            .len()
            .map_err(|e| Error::io("flash opening length", e))?;
        if length == 0 || !length.is_multiple_of(erase) {
            return Err(invalid("flash image must contain complete erase blocks"));
        }
        if bad.len() > limits.bad_blocks {
            return Err(cap("flash bad-block count"));
        }
        if bad.iter().any(|&block| block >= length / erase)
            || bad.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "flash bad-block indices must be sorted, unique and in range",
            ));
        }
        let charge = (limits.scratch_bytes as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add((bad.len() as u64).checked_mul(8)?))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| cap("flash reservation overflow"))?;
        let lease = r.memory.reserve(charge)?;
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(bad.len())
            .map_err(|_| cap("flash bad-block allocation"))?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.scratch_bytes)
            .map_err(|_| cap("flash scratch allocation"))?;
        let mut erased = Vec::new();
        erased
            .try_reserve_exact(limits.scratch_bytes)
            .map_err(|_| cap("flash erase scratch allocation"))?;
        if indices.capacity() > bad.len()
            || scratch.capacity() > limits.scratch_bytes
            || erased.capacity() > limits.scratch_bytes
        {
            return Err(cap("flash allocation capacity exceeds reservation"));
        }
        indices.extend_from_slice(bad);
        scratch.resize(limits.scratch_bytes, 0);
        erased.resize(limits.scratch_bytes, 0xff);
        r.cancellation.check()?;
        fixed(&storage, length)?;
        Ok(Self {
            storage,
            length,
            geometry,
            limits,
            bad: indices,
            scratch,
            erased,
            uncertain: false,
            _lease: lease,
        })
    }
    /// Fixed logical image length, independent of physical NAND dump interpretation.
    pub fn len(&self) -> u64 {
        self.length
    }
    /// Whether the logical image is empty; opening rejects empty images.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Caller-declared geometry, including alignment and dump interpretation.
    pub fn geometry(&self) -> FlashGeometry {
        self.geometry
    }
    /// Erased-byte value for the supported logical NOR profile.
    pub fn erased_byte(&self) -> u8 {
        0xff
    }
    /// Sorted caller-declared bad erase blocks; no hardware discovery is claimed.
    pub fn bad_blocks(&self) -> &[u64] {
        &self.bad
    }
    /// Sticky write/readback/flush uncertainty, retained after later successful operations.
    pub fn mutation_uncertain(&self) -> bool {
        self.uncertain
    }
    fn bounds(&self, at: u64, count: u64) -> Result<()> {
        fixed(&self.storage, self.length)?;
        if at.checked_add(count).is_none_or(|end| end > self.length) {
            return Err(invalid("flash access outside image"));
        }
        Ok(())
    }
    fn mutation_bounds(&self, at: u64, count: u64, alignment: u64) -> Result<()> {
        self.bounds(at, count)?;
        if !at.is_multiple_of(alignment) || !count.is_multiple_of(alignment) {
            return Err(invalid("flash operation alignment"));
        }
        if count > self.limits.operation_bytes {
            return Err(cap("flash operation byte ceiling"));
        }
        if count != 0 {
            let first = at / u64::from(self.geometry.erase_bytes);
            let last = (at + count - 1) / u64::from(self.geometry.erase_bytes);
            let found = self.bad.partition_point(|&block| block < first);
            if self.bad.get(found).is_some_and(|&block| block <= last) {
                return Err(invalid("flash operation crosses declared bad block"));
            }
        }
        Ok(())
    }
    /// Bounded reads, including bad blocks, with cancellation and fixed-length checks.
    pub fn read_exact_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.bounds(at, out.len() as u64)?;
        self.storage
            .read_exact_at(at, out)
            .map_err(|e| Error::io("flash read", e))?;
        fixed(&self.storage, self.length)?;
        r.cancellation.check()
    }
    /// Program aligned bytes only where every new bit is a subset of existing bits.
    /// The complete range is preflighted before any writes; no implicit erase occurs.
    pub fn program(
        &mut self,
        at: u64,
        bytes: &[u8],
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure> {
        self.mutate("program", at, bytes.len() as u64, Some(bytes), r)
    }
    /// Erase complete aligned blocks to 0xff with bounded writes and readback.
    /// Accepted/readback bytes remain buffered until a successful explicit flush.
    pub fn erase(
        &mut self,
        at: u64,
        count: u64,
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure> {
        self.mutate("erase", at, count, None, r)
    }
    fn mutate(
        &mut self,
        operation: &'static str,
        at: u64,
        count: u64,
        input: Option<&[u8]>,
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure> {
        let mut progress = FlashProgress::default();
        let mut attempted = false;
        let result: Result<()> = (|| {
            r.cancellation.check()?;
            let alignment = if input.is_some() {
                self.geometry.program_bytes
            } else {
                self.geometry.erase_bytes
            };
            self.mutation_bounds(at, count, u64::from(alignment))?;
            if let Some(bytes) = input {
                for (index, chunk) in bytes.chunks(self.scratch.len()).enumerate() {
                    r.cancellation.check()?;
                    let offset = at + (index * self.scratch.len()) as u64;
                    self.storage
                        .read_exact_at(offset, &mut self.scratch[..chunk.len()])
                        .map_err(|e| Error::io("flash program preflight", e))?;
                    if self.scratch[..chunk.len()]
                        .iter()
                        .zip(chunk)
                        .any(|(&old, &new)| old & new != new)
                    {
                        return Err(invalid(
                            "flash programming would set cleared bits; explicit erase required",
                        ));
                    }
                }
                fixed(&self.storage, self.length)?;
            }
            let mut position = 0;
            while position < count {
                r.cancellation.check()?;
                fixed(&self.storage, self.length)?;
                let n = (count - position).min(self.scratch.len() as u64) as usize;
                let data = input.map_or(&self.erased[..n], |bytes| {
                    &bytes[position as usize..position as usize + n]
                });
                let mut done = 0;
                while done < n {
                    r.cancellation.check()?;
                    attempted = true;
                    let wrote = self
                        .storage
                        .write_at(at + position + done as u64, &data[done..])
                        .map_err(|e| Error::io("flash write", e))?;
                    if wrote == 0 || wrote > n - done {
                        return Err(Error::io(
                            "flash short write",
                            io::ErrorKind::WriteZero.into(),
                        ));
                    }
                    done += wrote;
                    progress.accepted_bytes += wrote as u64;
                    fixed(&self.storage, self.length)?;
                }
                r.cancellation.check()?;
                self.storage
                    .read_exact_at(at + position, &mut self.scratch[..n])
                    .map_err(|e| Error::io("flash write readback", e))?;
                if self.scratch[..n] != *data {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "flash write readback differs",
                    ));
                }
                fixed(&self.storage, self.length)?;
                progress.verified_bytes += n as u64;
                position += n as u64;
            }
            r.cancellation.check()?;
            fixed(&self.storage, self.length)
        })();
        match result {
            Ok(()) => Ok(progress),
            Err(mut source) => {
                if attempted {
                    self.uncertain = true;
                    source.kind = ErrorKind::InterruptedWrite;
                }
                Err(FlashFailure {
                    operation,
                    progress,
                    mutation_attempted: attempted,
                    source,
                })
            }
        }
    }
    /// Delegate persistence to the backend; failure retains sticky uncertain durability.
    pub fn flush(&mut self, r: &Resources) -> std::result::Result<(), FlashFailure> {
        let result = r
            .cancellation
            .check()
            .and_then(|()| fixed(&self.storage, self.length));
        if let Err(source) = result {
            return Err(FlashFailure {
                operation: "flush preflight",
                progress: FlashProgress::default(),
                mutation_attempted: false,
                source,
            });
        }
        if let Err(error) = self.storage.flush() {
            self.uncertain = true;
            let mut source = Error::io("flash flush", error);
            source.kind = ErrorKind::UncertainDurability;
            return Err(FlashFailure {
                operation: "flush",
                progress: FlashProgress::default(),
                mutation_attempted: false,
                source,
            });
        }
        if let Err(source) = fixed(&self.storage, self.length) {
            self.uncertain = true;
            return Err(FlashFailure {
                operation: "flush verification",
                progress: FlashProgress::default(),
                mutation_attempted: false,
                source,
            });
        }
        Ok(())
    }
    /// Release the owned backend and sticky uncertainty; no generic recovery is implied.
    pub fn into_storage(self) -> (S, bool) {
        (self.storage, self.uncertain)
    }
}
impl<S: Storage> FlashStorage for FlashImage<S> {
    fn geometry(&self) -> FlashGeometry {
        self.geometry
    }
    fn len(&self) -> Result<u64> {
        fixed(&self.storage, self.length)?;
        Ok(self.length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<()> {
        FlashImage::read_exact_at(self, at, out, r)
    }
    fn program(
        &mut self,
        at: u64,
        bytes: &[u8],
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure> {
        FlashImage::program(self, at, bytes, r)
    }
    fn erase(
        &mut self,
        at: u64,
        count: u64,
        r: &Resources,
    ) -> std::result::Result<FlashProgress, FlashFailure> {
        FlashImage::erase(self, at, count, r)
    }
    fn flush(&mut self, r: &Resources) -> std::result::Result<(), FlashFailure> {
        FlashImage::flush(self, r)
    }
    fn mutation_uncertain(&self) -> bool {
        self.uncertain
    }
}
