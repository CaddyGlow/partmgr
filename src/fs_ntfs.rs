//! Strict NTFS 3.1 positional reads: fixed-up base FILE records and unnamed data.
//! Immutable caller-controlled sources only; no journal replay or ownership audit.
use crate::{
    fs_core::*,
    fs_file::{ExtentFile, ExtentKind as MapKind, FileExtent},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::{DiskView, ReadAt};
#[path = "fs_ntfs_bootstrap.rs"]
mod bootstrap;
#[path = "fs_ntfs_stream.rs"]
mod stream;
pub use stream::{
    NtfsDataStream, NtfsNativeAttribute, NtfsNativeFileName, NtfsNativeStandardInformation,
    NtfsStreamLimits,
};
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
fn bad(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn u64le(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn vector<T>(capacity: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)
        .map_err(|_| budget("NTFS allocation failed"))?;
    Ok(v)
}
/// Caller-selected work limits; all capacities also consume the shared memory pool.
#[derive(Clone, Copy, Debug)]
pub struct NtfsReadLimits {
    /// Maximum attributes parsed in one base record.
    pub attributes: usize,
    /// Maximum encoded allocation runs in one unnamed data attribute.
    pub runs: usize,
    /// Maximum native FILE_NAME attributes retained per record.
    pub names: usize,
}
/// Validated NTFS boot geometry, relative to the supplied volume region.
#[derive(Clone, Debug)]
pub struct NtfsGeometry {
    cluster_bytes: u64,
    record_bytes: usize,
    volume_bytes: u64,
    mft_cluster: u64,
    index_bytes: usize,
    mirror_cluster: u64,
}
impl NtfsGeometry {
    /// Cluster size, independent of container allocation geometry.
    pub fn cluster_bytes(&self) -> u64 {
        self.cluster_bytes
    }
    /// Validated native index block byte size.
    pub fn index_bytes(&self) -> usize {
        self.index_bytes
    }
    /// FILE record byte size.
    pub fn record_bytes(&self) -> usize {
        self.record_bytes
    }
    /// Declared volume bytes; source/container tails are excluded.
    pub fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }
    /// Boot-declared first MFT cluster.
    pub fn mft_cluster(&self) -> u64 {
        self.mft_cluster
    }
}
#[derive(Clone)]
struct Context {
    original: Arc<dyn ReadAt>,
    source: Arc<dyn ReadAt>,
    length: u64,
    scope: u128,
}
impl Context {
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.original.len() != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS source length changed",
            ));
        }
        Ok(())
    }
}
/// Strict clean-marker NTFS 3.1 volume retaining its bounded indexed MFT stream.
pub struct NtfsVolume {
    context: Context,
    geometry: NtfsGeometry,
    limits: NtfsReadLimits,
    mft: ExtentFile,
    _reservation: Reservation,
    volume_flags: u16,
}
/// Exact native name occurrence and parent FILE reference; no directory index claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsName {
    /// Parent record number (low 48 bits of the stored reference).
    pub parent_record: u64,
    /// Parent record sequence (high 16 bits of the stored reference).
    pub parent_sequence: u16,
    /// POSIX(0), Win32(1), DOS(2), or combined(3) namespace selector.
    pub namespace: u8,
    /// Exact little-endian UTF-16 name units; no normalization or display conversion.
    pub name: NativeName,
}
#[derive(Clone, Copy)]
struct Attribute {
    kind: u32,
    start: usize,
    length: usize,
    named: bool,
    nonresident: bool,
    flags: u16,
}
/// Validated allocated base FILE record with exact names and retained fixed-up bytes.
pub struct NtfsRecord {
    identity: ObjectId,
    bytes: Vec<u8>,
    attributes: Vec<Attribute>,
    names: Vec<NtfsName>,
    flags: u16,
    standard: Option<[u64; 4]>,
    file_flags: Option<u32>,
    _reservation: Reservation,
}
impl NtfsRecord {
    /// Sequence-scoped native record identity.
    pub fn identity(&self) -> &ObjectId {
        &self.identity
    }
    /// All native FILE_NAME occurrences; these do not replace directory-index traversal.
    pub fn names(&self) -> &[NtfsName] {
        &self.names
    }
    /// Native directory flag; directory indexes are outside this first reader profile.
    pub fn is_directory(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Inspect verified standard-information ticks/flags, leaving other classes unknown.
    /// The MFT-change FILETIME is retained as a native eight-byte metadata attribute.
    pub fn metadata(&self, r: &Resources) -> Result<Budgeted<Metadata>> {
        r.cancellation.check()?;
        Budgeted::try_new(&r.memory, 4096, || {
            let mut attributes = vector(1)?;
            if let Some(standard) = self.standard {
                let label = b"ntfs.STANDARD_INFORMATION.mft_changed.FILETIME";
                let mut name = vector(label.len())?;
                name.extend_from_slice(label);
                let mut ticks = vector(8)?;
                ticks.extend_from_slice(&standard[2].to_le_bytes());
                attributes.push((NativeName::Bytes(name), MetadataField::Known(ticks)));
            }
            let stamp = |n: usize| {
                self.standard.map_or_else(
                    || MetadataField::Uninspectable {
                        reason: "STANDARD_INFORMATION absent or unsupported encoding".into(),
                    },
                    |v| {
                        MetadataField::Known(NativeTimestamp {
                            ticks: i128::from(v[n]),
                            ticks_per_second: 10_000_000,
                            epoch: "NTFS FILETIME: 1601-01-01 UTC".into(),
                        })
                    },
                )
            };
            Ok(Metadata {
                created: stamp(0),
                modified: stamp(1),
                accessed: stamp(3),
                owner: MetadataField::Uninspectable {
                    reason: "NTFS security ownership mapping not implemented".into(),
                },
                mode: MetadataField::Absent,
                security: MetadataField::Uninspectable {
                    reason: "NTFS security descriptor lookup not implemented".into(),
                },
                attributes,
                native_flags: self.file_flags.map_or(
                    MetadataField::Uninspectable {
                        reason: "NTFS file attributes not inspected".into(),
                    },
                    |f| MetadataField::Known(f.to_le_bytes().to_vec()),
                ),
                symlink_target: MetadataField::Uninspectable {
                    reason: "NTFS reparse interpretation not implemented".into(),
                },
                reparse_data: MetadataField::Uninspectable {
                    reason: "NTFS reparse payload not decoded".into(),
                },
            })
        })
    }
    pub(crate) fn check_tree_profile(&self) -> Result<()> {
        if self
            .file_flags
            .is_some_and(|flags| flags & (0x400 | 0x800 | 0x1000 | 0x4000) != 0)
            || self.attributes.iter().any(|a| {
                matches!(a.kind, 0xc0 | 0xd0 | 0xe0 | 0xf0 | 0x100)
                    || a.kind == 0x80 && (a.named || self.is_directory())
            })
        {
            return Err(unsupported(
                "NTFS special metadata or directory/alternate DATA capture profile unavailable",
            ));
        }
        Ok(())
    }
    fn value(&self, a: Attribute) -> Result<&[u8]> {
        let b = &self.bytes[a.start..a.start + a.length];
        if a.nonresident {
            return Err(unsupported("NTFS nonresident metadata attribute"));
        }
        let at = usize::from(u16le(b, 20));
        let len = u32le(b, 16) as usize;
        Ok(&b[at..at + len])
    }
}
fn identity(context: &Context, number: u64, sequence: u16) -> ObjectId {
    ObjectId {
        source: context.scope,
        generation: u64::from(sequence),
        native: number.to_le_bytes().to_vec(),
    }
}
fn record_size(code: u8, cluster: u64) -> Result<usize> {
    let code = code as i8;
    let bytes = if code < 0 {
        1u64.checked_shl(u32::from(code.unsigned_abs()))
            .ok_or_else(|| bad("NTFS record size exponent"))?
    } else {
        u64::from(code as u8)
            .checked_mul(cluster)
            .ok_or_else(|| bad("NTFS record size overflow"))?
    };
    if !(512..=65536).contains(&bytes) || !bytes.is_power_of_two() {
        return Err(unsupported("NTFS record/index size profile"));
    }
    Ok(bytes as usize)
}
impl NtfsVolume {
    /// Validate boot, bootstrap mapped MFT and resident volume-info version/clean flags.
    /// 512-byte sectors and at most 64-KiB clusters/records are this initial profile.
    /// Attribute-list-dependent MFT layouts fail closed rather than guessed continuation.
    pub fn open(source: Arc<dyn ReadAt>, limits: NtfsReadLimits, r: &Resources) -> Result<Self> {
        Self::open_inner(source, limits, r, false, None)
    }
    /// Explicit readonly stream profile with bounded attribute-list MFT bootstrap.
    /// Does not admit extension ownership audits, complete tree capture or snapshots.
    pub fn open_stream_profile(
        source: Arc<dyn ReadAt>,
        read: NtfsReadLimits,
        streams: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::open_inner(source, read, r, false, Some(streams))
    }
    pub(crate) fn open_for_audit(
        source: Arc<dyn ReadAt>,
        limits: NtfsReadLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::open_inner(source, limits, r, true, None)
    }
    fn open_inner(
        source: Arc<dyn ReadAt>,
        limits: NtfsReadLimits,
        r: &Resources,
        audit: bool,
        expanded: Option<NtfsStreamLimits>,
    ) -> Result<Self> {
        r.cancellation.check()?;
        if source.len() < 512 {
            return Err(bad("NTFS source shorter than boot sector"));
        }
        let mut boot = [0; 512];
        source
            .read_exact_at(0, &mut boot)
            .map_err(|e| Error::io("NTFS boot read", e))?;
        if &boot[3..11] != b"NTFS    " || boot[510..512] != [0x55, 0xaa] {
            return Err(bad("NTFS boot signature"));
        }
        if u16le(&boot, 11) != 512 {
            return Err(unsupported(
                "NTFS sector size (initial profile requires 512)",
            ));
        }
        if boot[13] == 0 || !boot[13].is_power_of_two() || boot[13] > 128 {
            return Err(unsupported("NTFS cluster geometry"));
        }
        if boot[14..21].iter().any(|b| *b != 0) || u16le(&boot, 22) != 0 || u32le(&boot, 32) != 0 {
            return Err(bad("NTFS reserved BPB fields"));
        }
        let volume_bytes = u64le(&boot, 40)
            .checked_mul(512)
            .filter(|n| *n >= 512 && *n <= source.len())
            .ok_or_else(|| bad("NTFS declared volume range"))?;
        let cluster_bytes = u64::from(boot[13]) * 512;
        let record_bytes = record_size(boot[64], cluster_bytes)?;
        let index_bytes = record_size(boot[68], cluster_bytes)?;
        let mft_cluster = u64le(&boot, 48);
        let mft_offset = mft_cluster
            .checked_mul(cluster_bytes)
            .filter(|at| {
                at.checked_add(record_bytes as u64)
                    .is_some_and(|end| end <= volume_bytes)
            })
            .ok_or_else(|| bad("NTFS boot MFT range"))?;
        let mirror = u64le(&boot, 56);
        if mirror == 0 || mirror >= volume_bytes / cluster_bytes || mft_cluster == 0 {
            return Err(bad("NTFS MFT/mirror cluster bounds"));
        }
        let context = Context {
            length: source.len(),
            source: Arc::new(
                DiskView::new(source.clone(), 0, volume_bytes)
                    .map_err(|e| Error::io("NTFS bounded region", e))?,
            ),
            original: source,
            scope: (4u128 << 64)
                | u128::from(
                    NEXT_SOURCE
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                        .map_err(|_| {
                            Error::new(
                                ErrorKind::InvalidOperation,
                                "NTFS source identity space exhausted",
                            )
                        })?,
                ),
        };
        let geometry = NtfsGeometry {
            cluster_bytes,
            record_bytes,
            volume_bytes,
            mft_cluster,
            index_bytes,
            mirror_cluster: mirror,
        };
        let _scratch = r.memory.reserve(record_bytes as u64)?;
        let mut bytes = vector(record_bytes)?;
        bytes.resize(record_bytes, 0);
        context
            .source
            .read_exact_at(mft_offset, &mut bytes)
            .map_err(|e| Error::io("NTFS bootstrap FILE read", e))?;
        let record = if expanded.is_some() {
            parse_record_mode(
                bytes,
                0,
                &context,
                &geometry,
                limits,
                r,
                RecordProfile::CompleteBase,
            )?
        } else {
            parse_record(bytes, 0, &context, &geometry, limits, r)?
        };
        let (mft, reservation) = if let Some(streams) = expanded {
            bootstrap::mapped_mft(&record, &context, &geometry, limits, streams, r)?
        } else {
            let data = unnamed_data(&record)?;
            if !data.nonresident || data.flags != 0 {
                return Err(unsupported(
                    "NTFS MFT must be ordinary nonresident unnamed data",
                ));
            }
            let reservation = r.memory.reserve(map_charge(limits.runs)?)?;
            let (length, extents) = runs(
                &record.bytes[data.start..data.start + data.length],
                &geometry,
                limits,
                r,
            )?;
            if length < 4 * record_bytes as u64
                || !length.is_multiple_of(record_bytes as u64)
                || extents.iter().any(|e| !matches!(e.kind, MapKind::Data(_)))
            {
                return Err(bad("NTFS MFT length or sparse/uninitialized mapping"));
            }
            if extents.first().is_none_or(|e| {
                e.kind != MapKind::Data(mft_offset) || e.length < record_bytes as u64
            }) {
                return Err(bad("NTFS bootstrap and MFT mapping disagree"));
            }
            let mft = ExtentFile::new(
                context.source.clone(),
                length,
                extents,
                limits.runs.saturating_mul(2),
            )
            .map_err(|e| Error::io("NTFS MFT map", e))?;
            (mft, reservation)
        };
        let mut volume = Self {
            context,
            geometry,
            limits,
            mft,
            _reservation: reservation,
            volume_flags: 0,
        };
        let info = volume.record(3, r)?;
        let values = info
            .attributes
            .iter()
            .filter(|a| a.kind == 0x70 && !a.named)
            .copied()
            .collect::<Vec<_>>();
        if values.len() != 1 {
            return Err(bad("NTFS missing/duplicate VOLUME_INFORMATION"));
        }
        let value = info.value(values[0])?;
        if value.len() != 12 {
            return Err(bad("NTFS volume-info size"));
        }
        if value[8..10] != [3, 1] {
            return Err(unsupported("NTFS version is not 3.1"));
        }
        volume.volume_flags = u16le(value, 10);
        if !audit && volume.volume_flags != 0 {
            return Err(unsupported(
                "NTFS volume dirty or unsupported volume flags; replay/repair unavailable",
            ));
        }
        Ok(volume)
    }
    /// Validated bounded boot geometry.
    pub fn geometry(&self) -> &NtfsGeometry {
        &self.geometry
    }
    /// Number of complete base-record slots in the mapped MFT logical data.
    pub fn record_count(&self) -> u64 {
        self.mft.len() / self.geometry.record_bytes as u64
    }
    /// Read one allocated base FILE record through the indexed MFT, applying USA fixups.
    pub fn record(&self, number: u64, r: &Resources) -> Result<NtfsRecord> {
        self.context.check(r)?;
        if number >= self.record_count() {
            return Err(bad("NTFS record outside mapped MFT"));
        }
        let _scratch = r.memory.reserve(self.geometry.record_bytes as u64)?;
        let mut bytes = vector(self.geometry.record_bytes)?;
        bytes.resize(self.geometry.record_bytes, 0);
        self.mft
            .read_at(number * self.geometry.record_bytes as u64, &mut bytes)
            .map_err(|e| Error::io("NTFS mapped FILE read", e))?;
        parse_record(bytes, number, &self.context, &self.geometry, self.limits, r)
    }
    /// Open only regular unnamed, uncompressed, unencrypted data; no hidden ADS loss.
    pub fn open_file(&self, number: u64, r: &Resources) -> Result<NtfsFile> {
        let record = self.record(number, r)?;
        self.open_record(record, r)
    }
    /// Open a previously inspected source/sequence identity, rejecting stale references.
    pub fn open_object(&self, object: &ObjectId, r: &Resources) -> Result<NtfsFile> {
        self.context.check(r)?;
        if object.source != self.context.scope || object.native.len() != 8 {
            return Err(Error::new(ErrorKind::StalePlan, "NTFS foreign identity"));
        }
        let record = self.record(u64le(&object.native, 0), r)?;
        if record.identity != *object {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS FILE sequence changed",
            ));
        }
        self.open_record(record, r)
    }
    fn open_record(&self, record: NtfsRecord, r: &Resources) -> Result<NtfsFile> {
        self.open_record_for(record, r, false)
    }
    fn open_record_for(
        &self,
        record: NtfsRecord,
        r: &Resources,
        allow_named: bool,
    ) -> Result<NtfsFile> {
        if record.is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "NTFS directory has no regular file handle",
            ));
        }
        if record
            .file_flags
            .is_some_and(|f| f & (0x800 | 0x4000 | 0x400 | 0x1000) != 0)
        {
            return Err(unsupported(
                "NTFS compressed/encrypted/reparse/offline object",
            ));
        }
        if record
            .attributes
            .iter()
            .any(|a| a.kind == 0xc0 || a.kind == 0x80 && a.named && !allow_named)
        {
            return Err(unsupported(
                "NTFS reparse or named DATA requires a separate profile",
            ));
        }
        let attribute = unnamed_data(&record)?;
        let reservation = r.memory.reserve(
            map_charge(self.limits.runs)?
                .checked_add(self.geometry.record_bytes as u64)
                .ok_or_else(|| budget("NTFS file charge overflow"))?,
        )?;
        let content = if attribute.nonresident {
            let (length, extents) = runs(
                &record.bytes[attribute.start..attribute.start + attribute.length],
                &self.geometry,
                self.limits,
                r,
            )?;
            Content::Mapped(
                ExtentFile::new(
                    self.context.source.clone(),
                    length,
                    extents,
                    self.limits.runs.saturating_mul(2),
                )
                .map_err(|e| Error::io("NTFS file map", e))?,
            )
        } else {
            if attribute.flags != 0 {
                return Err(unsupported("NTFS resident DATA flags"));
            }
            let value = record.value(attribute)?;
            let mut bytes = vector(value.len())?;
            bytes.extend_from_slice(value);
            Content::Resident(bytes)
        };
        Ok(NtfsFile {
            identity: record.identity,
            context: self.context.clone(),
            content,
            _reservation: reservation,
        })
    }
}
fn map_charge(runs: usize) -> Result<u64> {
    (runs as u64)
        .checked_mul((6 * std::mem::size_of::<FileExtent>() + 32) as u64)
        .ok_or_else(|| budget("NTFS map envelope overflow"))
}
fn unnamed_data(record: &NtfsRecord) -> Result<Attribute> {
    let mut found = None;
    for a in &record.attributes {
        if a.kind == 0x80 && !a.named {
            if found.is_some() {
                return Err(unsupported("NTFS split/multiple unnamed DATA attributes"));
            }
            found = Some(*a);
        }
    }
    found.ok_or_else(|| bad("NTFS missing unnamed DATA"))
}
fn parse_record(
    bytes: Vec<u8>,
    number: u64,
    context: &Context,
    g: &NtfsGeometry,
    limits: NtfsReadLimits,
    r: &Resources,
) -> Result<NtfsRecord> {
    parse_record_mode(bytes, number, context, g, limits, r, RecordProfile::Strict)
}
enum RecordProfile {
    Strict,
    CompleteBase,
    Extension(u64),
}
fn parse_record_mode(
    mut bytes: Vec<u8>,
    number: u64,
    context: &Context,
    g: &NtfsGeometry,
    limits: NtfsReadLimits,
    r: &Resources,
    profile: RecordProfile,
) -> Result<NtfsRecord> {
    context.check(r)?;
    let charge = (g.record_bytes as u64)
        .checked_add(
            (limits.attributes as u64)
                .checked_mul(64)
                .ok_or_else(|| budget("NTFS attribute envelope"))?,
        )
        .and_then(|n| n.checked_add((limits.names as u64).checked_mul(640)?))
        .ok_or_else(|| budget("NTFS record envelope"))?;
    let reservation = r.memory.reserve(charge)?;
    if bytes.len() != g.record_bytes || &bytes[..4] != b"FILE" {
        return Err(bad("NTFS FILE signature/size"));
    }
    let usa = usize::from(u16le(&bytes, 4));
    let usa_count = usize::from(u16le(&bytes, 6));
    let attribute_start = usize::from(u16le(&bytes, 20));
    let used = u32le(&bytes, 24) as usize;
    if usa < 48
        || !usa.is_multiple_of(2)
        || usa_count != bytes.len() / 512 + 1
        || usa
            .checked_add(usa_count * 2)
            .is_none_or(|end| end > attribute_start || end > 510)
        || attribute_start < 48
        || !attribute_start.is_multiple_of(8)
        || used > bytes.len()
        || used < attribute_start + 4
        || u32le(&bytes, 28) as usize != bytes.len()
    {
        return Err(bad("NTFS FILE/USA header bounds"));
    }
    let usn = u16le(&bytes, usa);
    if usn == 0 || usn == 0xffff {
        return Err(bad("NTFS invalid USA sequence"));
    }
    for i in 1..usa_count {
        r.cancellation.check()?;
        let end = i * 512 - 2;
        if u16le(&bytes, end) != usn {
            return Err(bad("NTFS torn FILE USA trailer"));
        }
        let replacement = u16le(&bytes, usa + i * 2).to_le_bytes();
        bytes[end..end + 2].copy_from_slice(&replacement);
    }
    let flags = u16le(&bytes, 22);
    if flags & 1 == 0 {
        return Err(bad("NTFS unused FILE record"));
    }
    if flags & !15 != 0 {
        return Err(unsupported("NTFS FILE flags"));
    }
    let (expected_base, allow_list) = match profile {
        RecordProfile::Strict => (None, false),
        RecordProfile::CompleteBase => (None, true),
        RecordProfile::Extension(reference) => (Some(reference), true),
    };
    match expected_base {
        Some(reference) if u64le(&bytes, 32) != reference => {
            return Err(bad("NTFS extension base-reference mismatch"));
        }
        None if u64le(&bytes, 32) != 0 => {
            return Err(unsupported(
                "NTFS extension FILE record requires attribute-list support",
            ));
        }
        _ => {}
    }
    if u32le(&bytes, 44) as u64 != number {
        return Err(bad("NTFS FILE record-number mismatch"));
    }
    let sequence = u16le(&bytes, 16);
    if sequence == 0 {
        return Err(bad("NTFS zero FILE sequence"));
    }
    let mut attributes = vector(limits.attributes)?;
    let mut names = vector(limits.names)?;
    let mut standard = None;
    let mut file_flags = None;
    let mut at = attribute_start;
    let mut previous = 0;
    let mut ids = vector(limits.attributes)?;
    loop {
        r.cancellation.check()?;
        if at + 4 > used {
            return Err(bad("NTFS missing attribute terminator"));
        }
        let kind = u32le(&bytes, at);
        if kind == u32::MAX {
            break;
        }
        if attributes.len() == limits.attributes {
            return Err(budget("NTFS attribute limit"));
        }
        if at + 24 > used {
            return Err(bad("NTFS attribute header truncated"));
        }
        let length = u32le(&bytes, at + 4) as usize;
        if length < 24
            || !length.is_multiple_of(8)
            || at.checked_add(length).is_none_or(|end| end > used)
        {
            return Err(bad("NTFS attribute range"));
        }
        let b = &bytes[at..at + length];
        let nonresident = match b[8] {
            0 => false,
            1 => true,
            _ => return Err(bad("NTFS attribute residency selector")),
        };
        let flags = u16le(b, 12);
        if flags & !0x8000 != 0 {
            return Err(unsupported(
                "NTFS compressed/encrypted/unknown attribute flags",
            ));
        }
        if kind == 0x20 && !allow_list {
            return Err(unsupported(
                "NTFS ATTRIBUTE_LIST not implemented in strict base profile",
            ));
        }
        if kind == 0 || kind > 0x100 || !kind.is_multiple_of(16) || kind < previous {
            return Err(bad("NTFS attribute type/order"));
        }
        previous = kind;
        let attr_id = u16le(b, 14);
        if ids.contains(&attr_id) {
            return Err(bad("NTFS duplicate attribute id"));
        }
        ids.push(attr_id);
        let name_len = usize::from(b[9]) * 2;
        let name_at = usize::from(u16le(b, 10));
        if !nonresident && flags != 0 {
            return Err(unsupported("NTFS resident attribute flags"));
        }
        let header = if nonresident {
            if flags & 0x8000 != 0 { 72 } else { 64 }
        } else {
            24
        };
        if length < header
            || name_len != 0
                && (name_at < header
                    || !name_at.is_multiple_of(2)
                    || name_at.checked_add(name_len).is_none_or(|end| end > length))
        {
            return Err(bad("NTFS attribute name/header range"));
        }
        let value = if nonresident {
            let run_at = usize::from(u16le(b, 32));
            if run_at < header || run_at >= length || name_len != 0 && run_at < name_at + name_len {
                return Err(bad("NTFS mapping-pairs offset"));
            }
            None
        } else {
            let v = usize::from(u16le(b, 20));
            let n = u32le(b, 16) as usize;
            if v < header
                || v.checked_add(n).is_none_or(|end| end > length)
                || name_len != 0 && v < name_at + name_len
                || b[22] & !1 != 0
                || !allow_list && b[23] != 0
            {
                return Err(bad("NTFS resident value range/flags"));
            }
            Some(&b[v..v + n])
        };
        if kind == 0x10 {
            if standard.is_some() || name_len != 0 {
                return Err(bad("NTFS duplicate/named STANDARD_INFORMATION"));
            }
            let value =
                value.ok_or_else(|| unsupported("NTFS nonresident STANDARD_INFORMATION"))?;
            if !matches!(value.len(), 48 | 72) {
                return Err(unsupported("NTFS STANDARD_INFORMATION size"));
            }
            standard = Some([
                u64le(value, 0),
                u64le(value, 8),
                u64le(value, 16),
                u64le(value, 24),
            ]);
            file_flags = Some(u32le(value, 32));
        }
        if kind == 0x30 {
            if name_len != 0 {
                return Err(bad("NTFS named FILE_NAME attribute"));
            }
            if names.len() == limits.names {
                return Err(budget("NTFS native name limit"));
            }
            let value = value.ok_or_else(|| unsupported("NTFS nonresident FILE_NAME"))?;
            if value.len() < 66
                || value[65] > 3
                || value[64] == 0
                || value.len() != 66 + usize::from(value[64]) * 2
            {
                return Err(bad("NTFS FILE_NAME range/namespace"));
            }
            let mut units = vector(usize::from(value[64]))?;
            for pair in value[66..].as_chunks::<2>().0 {
                let u = u16::from_le_bytes(*pair);
                if u == 0 || u == 47 || u == 92 {
                    return Err(bad("NTFS native leaf contains separator/NUL"));
                }
                units.push(u);
            }
            let parent = u64le(value, 0);
            names.push(NtfsName {
                parent_record: parent & 0xffffffffffff,
                parent_sequence: (parent >> 48) as u16,
                namespace: value[65],
                name: NativeName::Utf16(units),
            });
        }
        attributes.push(Attribute {
            kind,
            start: at,
            length,
            named: name_len != 0,
            nonresident,
            flags,
        });
        at += length;
    }
    Ok(NtfsRecord {
        identity: identity(context, number, sequence),
        bytes,
        attributes,
        names,
        flags,
        standard,
        file_flags,
        _reservation: reservation,
    })
}
pub(crate) struct NtfsRawMap {
    pub(crate) length: u64,
    pub(crate) extents: Vec<FileExtent>,
    pub(crate) physical: Vec<(u64, u64)>,
    pub(crate) runs: usize,
}
fn runs(
    b: &[u8],
    g: &NtfsGeometry,
    limits: NtfsReadLimits,
    r: &Resources,
) -> Result<(u64, Vec<FileExtent>)> {
    let map = decode_runs(b, g, limits, r, false)?;
    Ok((map.length, map.extents))
}
fn decode_runs(
    b: &[u8],
    g: &NtfsGeometry,
    limits: NtfsReadLimits,
    r: &Resources,
    badclus: bool,
) -> Result<NtfsRawMap> {
    if u64le(b, 16) != 0 || b[34] != 0 || b[35..40].iter().any(|v| *v != 0) {
        return Err(unsupported("NTFS continuation/compression-unit profile"));
    }
    let end_vcn = u64le(b, 24);
    let allocated = u64le(b, 40);
    let length = u64le(b, 48);
    let initialized = u64le(b, 56);
    if badclus && (length != g.volume_bytes / g.cluster_bytes * g.cluster_bytes || initialized != 0)
    {
        return Err(bad("NTFS $BadClus virtual geometry/initialized size"));
    }
    if initialized > length || !allocated.is_multiple_of(g.cluster_bytes) {
        return Err(bad("NTFS data/initialized/allocation sizes"));
    }
    let sparse = u16le(b, 12) & 0x8000 != 0;
    let mut extents = vector(
        limits
            .runs
            .checked_mul(2)
            .ok_or_else(|| budget("NTFS run limit overflow"))?,
    )?;
    let mut physical = vector(limits.runs)?;
    let mut at = usize::from(u16le(b, 32));
    let mut vcn = 0u64;
    let mut lcn = 0i128;
    let mut count = 0usize;
    loop {
        r.cancellation.check()?;
        if at >= b.len() {
            return Err(bad("NTFS unterminated mapping pairs"));
        }
        let header = b[at];
        at += 1;
        if header == 0 {
            break;
        }
        count += 1;
        if count > limits.runs {
            return Err(budget("NTFS allocation run limit"));
        }
        let n = usize::from(header & 15);
        let m = usize::from(header >> 4);
        if n == 0 || n > 8 || m > 8 || at.checked_add(n + m).is_none_or(|end| end > b.len()) {
            return Err(bad("NTFS mapping-pair widths/range"));
        }
        let mut raw = [0u8; 8];
        raw[..n].copy_from_slice(&b[at..at + n]);
        let clusters = u64::from_le_bytes(raw);
        at += n;
        if clusters == 0 {
            return Err(bad("NTFS zero run length"));
        }
        let offset = vcn
            .checked_mul(g.cluster_bytes)
            .ok_or_else(|| bad("NTFS VCN overflow"))?;
        vcn = vcn
            .checked_add(clusters)
            .ok_or_else(|| bad("NTFS VCN overflow"))?;
        let bytes = clusters
            .checked_mul(g.cluster_bytes)
            .ok_or_else(|| bad("NTFS run byte overflow"))?;
        let kind = if m == 0 {
            if !sparse && !badclus {
                return Err(bad("NTFS hole without sparse flag"));
            }
            MapKind::Hole
        } else {
            let negative = b[at + m - 1] & 0x80 != 0;
            let mut raw = if negative { [0xff; 8] } else { [0; 8] };
            raw[..m].copy_from_slice(&b[at..at + m]);
            at += m;
            lcn = lcn
                .checked_add(i128::from(i64::from_le_bytes(raw)))
                .ok_or_else(|| bad("NTFS LCN overflow"))?;
            let start = u64::try_from(lcn)
                .map_err(|_| bad("NTFS negative LCN"))?
                .checked_mul(g.cluster_bytes)
                .ok_or_else(|| bad("NTFS LCN byte overflow"))?;
            if start
                .checked_add(bytes)
                .is_none_or(|end| end > g.volume_bytes)
            {
                return Err(bad("NTFS run escapes volume"));
            }
            physical.push((start, bytes));
            MapKind::Data(start)
        };
        let end = offset
            .checked_add(bytes)
            .ok_or_else(|| bad("NTFS run end overflow"))?
            .min(length);
        if end > offset {
            let split = end.min(initialized).max(offset);
            if split > offset {
                extents.push(FileExtent {
                    offset,
                    length: split - offset,
                    kind,
                });
            }
            if end > split {
                extents.push(FileExtent {
                    offset: split,
                    length: end - split,
                    kind: if kind == MapKind::Hole {
                        MapKind::Hole
                    } else {
                        MapKind::Unwritten
                    },
                });
            }
        }
    }
    if vcn == 0 {
        if length != 0 || allocated != 0 || end_vcn != u64::MAX {
            return Err(bad("NTFS empty runlist sizes"));
        }
    } else if vcn - 1 != end_vcn
        || vcn.checked_mul(g.cluster_bytes) != Some(allocated)
        || length > allocated
    {
        return Err(bad("NTFS runlist VCN/allocation coverage"));
    }
    if u16le(b, 12) & 0x8000 != 0 {
        let physical_bytes = physical
            .iter()
            .try_fold(0u64, |sum, (_, length)| sum.checked_add(*length))
            .ok_or_else(|| bad("NTFS sparse allocation sum overflow"))?;
        if u64le(b, 64) != physical_bytes {
            return Err(bad("NTFS sparse physical allocation size"));
        }
    }
    physical.sort_unstable();
    if physical.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
        return Err(bad("NTFS duplicate/overlapping physical allocation"));
    }
    Ok(NtfsRawMap {
        length,
        extents,
        physical,
        runs: count,
    })
}
enum Content {
    Resident(Vec<u8>),
    Mapped(ExtentFile),
}
/// Immutable resident bytes or indexed nonresident unnamed data with retained budget.
pub struct NtfsFile {
    identity: ObjectId,
    context: Context,
    content: Content,
    _reservation: Reservation,
}
impl FileRead for NtfsFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        match &self.content {
            Content::Resident(b) => b.len() as u64,
            Content::Mapped(f) => f.len(),
        }
    }
    fn read_at(&self, offset: u64, buffer: &mut [u8], r: &Resources) -> Result<usize> {
        self.context.check(r)?;
        if offset >= self.len() {
            return Ok(0);
        }
        match &self.content {
            Content::Resident(bytes) => {
                let n = buffer.len().min(bytes.len() - offset as usize);
                buffer[..n].copy_from_slice(&bytes[offset as usize..offset as usize + n]);
                Ok(n)
            }
            Content::Mapped(file) => file
                .read_at(offset, buffer)
                .map_err(|e| Error::io("NTFS payload read", e)),
        }
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.context.check(r)?;
        match &self.content {
            Content::Resident(b) => {
                if !b.is_empty() {
                    visitor(LogicalExtent {
                        offset: 0,
                        length: b.len() as u64,
                        kind: ExtentKind::Data,
                    })?;
                }
            }
            Content::Mapped(file) => {
                for e in file.extents() {
                    r.cancellation.check()?;
                    visitor(LogicalExtent {
                        offset: e.offset,
                        length: e.length,
                        kind: match e.kind {
                            MapKind::Data(_) => ExtentKind::Data,
                            MapKind::Hole => ExtentKind::Hole,
                            MapKind::Unwritten => ExtentKind::Unwritten,
                        },
                    })?;
                }
            }
        }
        Ok(())
    }
}

/// Explicit directory index work envelope.
#[derive(Clone, Copy, Debug)]
pub struct NtfsDirectoryLimits {
    /// Maximum index-allocation blocks, including bitmap-declared unused blocks.
    pub blocks: usize,
    /// Maximum directory entries, including native DOS aliases and system entries.
    pub entries: usize,
    /// Maximum B-tree depth below the resident root.
    pub depth: usize,
}
/// Validated native index occurrence, retaining the target FILE identity.
#[derive(Clone, Debug)]
pub struct NtfsDirectoryEntry {
    /// Target record and sequence scoped to this volume.
    pub identity: ObjectId,
    /// Exact indexed UTF-16 leaf.
    pub name: NativeName,
    /// Native FILE_NAME namespace selector.
    pub namespace: u8,
    /// Target FILE directory flag.
    pub is_directory: bool,
}
/// Complete bounded native index enumeration, with lifetime accounting.
pub struct NtfsDirectory {
    entries: Vec<NtfsDirectoryEntry>,
    audit_blocks: usize,
    _reservation: Reservation,
}
impl NtfsDirectory {
    pub(crate) fn audit_blocks(&self) -> usize {
        self.audit_blocks
    }
    /// All index occurrences in native collation order.
    pub fn entries(&self) -> &[NtfsDirectoryEntry] {
        &self.entries
    }
}
enum IndexTask {
    Block(u64, usize),
    Entry(NtfsDirectoryEntry),
}
impl NtfsVolume {
    /// Native root FILE identity (record 5), with its actual sequence.
    pub fn root_identity(&self, r: &Resources) -> Result<ObjectId> {
        let root = self.record(5, r)?;
        if !root.is_directory() {
            return Err(bad("NTFS root is not a directory"));
        }
        Ok(root.identity.clone())
    }
    fn scoped_record(&self, object: &ObjectId, r: &Resources) -> Result<NtfsRecord> {
        if object.source != self.context.scope || object.native.len() != 8 {
            return Err(Error::new(ErrorKind::StalePlan, "foreign NTFS identity"));
        }
        let record = self.record(u64le(&object.native, 0), r)?;
        if record.identity != *object {
            return Err(Error::new(ErrorKind::StalePlan, "recycled NTFS identity"));
        }
        Ok(record)
    }
    /// Traverse validated $I30 indexes; FILE_NAME metadata alone is never an oracle.
    pub fn directory(
        &self,
        object: &ObjectId,
        limits: NtfsDirectoryLimits,
        r: &Resources,
    ) -> Result<NtfsDirectory> {
        self.context.check(r)?;
        let charge = (limits.entries as u64)
            .checked_mul(4096)
            .and_then(|n| n.checked_add((limits.blocks as u64).checked_mul(128)?))
            .and_then(|n| n.checked_add(131072 + 2 * self.geometry.index_bytes as u64))
            .ok_or_else(|| budget("NTFS directory envelope"))?;
        let reservation = r.memory.reserve(charge)?;
        let record = self.scoped_record(object, r)?;
        if !record.is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "NTFS object is not directory",
            ));
        }
        if record
            .file_flags
            .is_some_and(|f| f & (0x400 | 0x800 | 0x4000 | 0x1000) != 0)
        {
            return Err(unsupported("NTFS special directory"));
        }
        let named = |kind| -> Result<Option<Attribute>> {
            let mut found = None;
            for a in &record.attributes {
                if a.kind != kind {
                    continue;
                }
                let b = &record.bytes[a.start..a.start + a.length];
                let at = usize::from(u16le(b, 10));
                if b[9] != 4 || b[at..at + 8] != [36, 0, 73, 0, 51, 0, 48, 0] {
                    return Err(unsupported("NTFS non-$I30 directory index"));
                }
                if found.replace(*a).is_some() {
                    return Err(unsupported("NTFS split directory index attribute"));
                }
            }
            Ok(found)
        };
        let root_attr = named(0x90)?.ok_or_else(|| bad("NTFS missing INDEX_ROOT"))?;
        let root = record.value(root_attr)?;
        if root.len() < 32
            || u32le(root, 0) != 0x30
            || u32le(root, 4) != 1
            || u32le(root, 8) as usize != self.geometry.index_bytes
            || root[13..16] != [0; 3]
        {
            return Err(unsupported("NTFS index type/collation/geometry"));
        }
        let unit = if (self.geometry.index_bytes as u64) < self.geometry.cluster_bytes {
            512
        } else {
            self.geometry.cluster_bytes
        };
        if u64::from(root[12]) != self.geometry.index_bytes as u64 / unit {
            return Err(bad("NTFS index VCN geometry"));
        }
        let alloc = named(0xa0)?;
        let bitmap = named(0xb0)?;
        let mut blocks = 0usize;
        let mut bitmap_bytes = Vec::new();
        let mut mapped = None;
        let mut map_lease = None;
        if let Some(a) = alloc {
            if !a.nonresident || a.flags != 0 {
                return Err(unsupported("NTFS index allocation residency/flags"));
            }
            map_lease = Some(r.memory.reserve(map_charge(self.limits.runs)?)?);
            let (length, extents) = runs(
                &record.bytes[a.start..a.start + a.length],
                &self.geometry,
                self.limits,
                r,
            )?;
            if !length.is_multiple_of(self.geometry.index_bytes as u64)
                || extents.iter().any(|e| !matches!(e.kind, MapKind::Data(_)))
            {
                return Err(bad("NTFS index allocation initialization"));
            }
            blocks = usize::try_from(length / self.geometry.index_bytes as u64)
                .map_err(|_| budget("NTFS index block address space"))?;
            if blocks > limits.blocks {
                return Err(budget("NTFS directory block limit"));
            }
            mapped = Some(
                ExtentFile::new(
                    self.context.source.clone(),
                    length,
                    extents,
                    self.limits.runs.saturating_mul(2),
                )
                .map_err(|e| Error::io("NTFS index map", e))?,
            );
            let bm = bitmap.ok_or_else(|| bad("NTFS index allocation missing bitmap"))?;
            let max = blocks.div_ceil(8).next_multiple_of(8);
            if bm.nonresident {
                return Err(unsupported(
                    "NTFS nonresident index bitmap (initial profile)",
                ));
            }
            let bytes = record.value(bm)?;
            if bytes.len() < blocks.div_ceil(8) || bytes.len() > max {
                return Err(bad("NTFS index bitmap length"));
            }
            bitmap_bytes = vector(bytes.len())?;
            bitmap_bytes.extend_from_slice(bytes);
            if (blocks..bytes.len() * 8).any(|bit| bytes[bit / 8] & (1 << (bit % 8)) != 0) {
                return Err(bad("NTFS index bitmap tail allocation"));
            }
        } else if bitmap.is_some() {
            return Err(bad("NTFS index bitmap without allocation"));
        }
        let upcase = self.open_record_for(self.record(10, r)?, r, true)?;
        if upcase.len() != 131072 {
            return Err(unsupported("NTFS $UpCase size"));
        }
        let mut upper = vector(131072)?;
        upper.resize(131072, 0);
        if upcase.read_at(0, &mut upper, r)? != upper.len() {
            return Err(bad("NTFS $UpCase truncated"));
        }
        for c in 0..65536usize {
            if c % 256 == 0 {
                r.cancellation.check()?;
            }
            let u = u16le(&upper, c * 2) as usize;
            if u16le(&upper, u * 2) != u as u16 {
                return Err(bad("NTFS $UpCase not idempotent"));
            }
        }
        for c in b'a'..=b'z' {
            if u16le(&upper, usize::from(c) * 2) != u16::from(c - 32) {
                return Err(bad("NTFS $UpCase ASCII mapping"));
            }
        }
        let capacity = limits
            .entries
            .checked_mul(2)
            .and_then(|n| n.checked_add(limits.blocks))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| budget("NTFS task capacity"))?;
        let mut tasks = vector(capacity)?;
        let mut entries = vector(limits.entries)?;
        let mut seen = vector(blocks)?;
        seen.resize(blocks, false);
        let mut counted = 0usize;
        self.index_tasks(root, 16, object, 0, limits, &mut counted, &mut tasks, r)?;
        let mut previous: Option<Vec<u16>> = None;
        while let Some(task) = tasks.pop() {
            self.context.check(r)?;
            match task {
                IndexTask::Entry(entry) => {
                    let NativeName::Utf16(name) = &entry.name else {
                        unreachable!()
                    };
                    let mut folded = vector(name.len())?;
                    for c in name {
                        folded.push(u16le(&upper, usize::from(*c) * 2));
                    }
                    if previous.as_ref().is_some_and(|p| p >= &folded) {
                        return Err(bad("NTFS index collation collision/order"));
                    }
                    previous = Some(folded);
                    entries.push(entry);
                }
                IndexTask::Block(vcn, depth) => {
                    if depth > limits.depth {
                        return Err(budget("NTFS index depth limit"));
                    }
                    let offset = vcn
                        .checked_mul(unit)
                        .ok_or_else(|| bad("NTFS index child VCN overflow"))?;
                    if !offset.is_multiple_of(self.geometry.index_bytes as u64) {
                        return Err(bad("NTFS unaligned index child VCN"));
                    }
                    let block = usize::try_from(offset / self.geometry.index_bytes as u64)
                        .map_err(|_| bad("NTFS child block address space"))?;
                    if block >= blocks
                        || bitmap_bytes[block / 8] & (1 << (block % 8)) == 0
                        || seen[block]
                    {
                        return Err(bad("NTFS index child range/bitmap/cycle"));
                    }
                    seen[block] = true;
                    let mut bytes = vector(self.geometry.index_bytes)?;
                    bytes.resize(self.geometry.index_bytes, 0);
                    mapped
                        .as_ref()
                        .ok_or_else(|| bad("NTFS child without allocation"))?
                        .read_at(offset, &mut bytes)
                        .map_err(|e| Error::io("NTFS index block read", e))?;
                    if &bytes[..4] != b"INDX" || u64le(&bytes, 16) != vcn {
                        return Err(bad("NTFS INDX signature/VCN"));
                    }
                    let usa = usize::from(u16le(&bytes, 4));
                    let count = usize::from(u16le(&bytes, 6));
                    let first = 24usize
                        .checked_add(u32le(&bytes, 24) as usize)
                        .ok_or_else(|| bad("NTFS INDX entry offset"))?;
                    if count != bytes.len() / 512 + 1
                        || usa < 40
                        || !usa.is_multiple_of(2)
                        || usa
                            .checked_add(count * 2)
                            .is_none_or(|end| end > first || end > 510)
                        || first > bytes.len()
                    {
                        return Err(bad("NTFS INDX USA bounds"));
                    }
                    let usn = u16le(&bytes, usa);
                    if usn == 0 || usn == 65535 {
                        return Err(bad("NTFS INDX USA sequence"));
                    }
                    for i in 1..count {
                        if u16le(&bytes, i * 512 - 2) != usn {
                            return Err(bad("NTFS torn INDX sector"));
                        }
                        let value = u16le(&bytes, usa + i * 2);
                        bytes[i * 512 - 2..i * 512].copy_from_slice(&value.to_le_bytes());
                    }
                    self.index_tasks(
                        &bytes,
                        24,
                        object,
                        depth,
                        limits,
                        &mut counted,
                        &mut tasks,
                        r,
                    )?;
                }
            }
        }
        for (bit, visited) in seen.iter().enumerate() {
            if bitmap_bytes[bit / 8] & (1 << (bit % 8)) != 0 && !*visited {
                return Err(bad("NTFS allocated unreachable index block"));
            }
        }
        drop(map_lease);
        Ok(NtfsDirectory {
            entries,
            audit_blocks: blocks,
            _reservation: reservation,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn index_tasks(
        &self,
        b: &[u8],
        h: usize,
        parent: &ObjectId,
        depth: usize,
        limits: NtfsDirectoryLimits,
        counted: &mut usize,
        tasks: &mut Vec<IndexTask>,
        r: &Resources,
    ) -> Result<()> {
        if h + 16 > b.len() {
            return Err(bad("NTFS index header bounds"));
        }
        let start = u32le(b, h) as usize;
        let used = u32le(b, h + 4) as usize;
        let total = u32le(b, h + 8) as usize;
        let flags = u32le(b, h + 12);
        if start < 16
            || !start.is_multiple_of(8)
            || used < start + 16
            || used > total
            || total > b.len() - h
            || flags > 1
        {
            return Err(bad("NTFS index header range/flags"));
        }
        let mut local = vector(
            limits
                .entries
                .checked_add(1)
                .ok_or_else(|| budget("NTFS local index envelope"))?,
        )?;
        let mut at = h + start;
        let end = h + used;
        loop {
            r.cancellation.check()?;
            if at + 16 > end {
                return Err(bad("NTFS index missing terminal entry"));
            }
            let size = usize::from(u16le(b, at + 8));
            let key = usize::from(u16le(b, at + 10));
            let f = u16le(b, at + 12);
            let child = f & 1 != 0;
            let terminal = f & 2 != 0;
            if size < 16 + usize::from(child) * 8
                || !size.is_multiple_of(8)
                || at.checked_add(size).is_none_or(|n| n > end)
                || f & !3 != 0
                || u16le(b, at + 14) != 0
                || child != (flags == 1)
                || key > size - 16 - usize::from(child) * 8
            {
                return Err(bad("NTFS index entry bounds/flags"));
            }
            let mut occurrence = None;
            if terminal {
                if key != 0 || at + size != end {
                    return Err(bad("NTFS index terminal entry"));
                }
            } else {
                if *counted == limits.entries {
                    return Err(budget("NTFS directory entry limit"));
                }
                *counted += 1;
                let value = &b[at + 16..at + 16 + key];
                if value.len() < 66
                    || value[64] == 0
                    || value[65] > 3
                    || value.len() != 66 + usize::from(value[64]) * 2
                {
                    return Err(bad("NTFS index FILE_NAME bounds"));
                }
                let reference = u64le(b, at);
                let number = reference & 0xffffffffffff;
                let sequence = (reference >> 48) as u16;
                if u64le(value, 0) != u64le(&parent.native, 0) | (parent.generation << 48) {
                    return Err(bad("NTFS index FILE_NAME parent reference"));
                }
                let target = self.record(number, r)?;
                if target.identity.generation != u64::from(sequence) {
                    return Err(bad("NTFS index target sequence"));
                }
                let mut name = vector(usize::from(value[64]))?;
                for pair in value[66..].as_chunks::<2>().0 {
                    let c = u16::from_le_bytes(*pair);
                    if c == 0 || c == 47 || c == 92 {
                        return Err(bad("NTFS index invalid native leaf"));
                    }
                    name.push(c);
                }
                let name = NativeName::Utf16(name);
                if (name == NativeName::Utf16(vec![46])
                    && (number != 5 || u64le(&parent.native, 0) != 5))
                    || name == NativeName::Utf16(vec![46, 46])
                {
                    return Err(bad("NTFS unsupported dot namespace entry"));
                }
                if !target.names.iter().any(|n| {
                    n.parent_record == u64le(&parent.native, 0)
                        && u64::from(n.parent_sequence) == parent.generation
                        && n.namespace == value[65]
                        && n.name == name
                }) {
                    return Err(bad("NTFS index and target FILE_NAME disagree"));
                }
                if (u32le(value, 56) & 0x10000000 != 0) != target.is_directory() {
                    return Err(bad("NTFS index target directory flag"));
                }
                occurrence = Some(NtfsDirectoryEntry {
                    identity: target.identity.clone(),
                    name,
                    namespace: value[65],
                    is_directory: target.is_directory(),
                });
            }
            local.push((
                occurrence,
                if child {
                    Some(u64le(b, at + size - 8))
                } else {
                    None
                },
            ));
            if terminal {
                break;
            }
            at += size;
        }
        for (entry, child) in local.into_iter().rev() {
            if let Some(e) = entry {
                tasks.push(IndexTask::Entry(e));
            }
            if let Some(vcn) = child {
                tasks.push(IndexTask::Block(
                    vcn,
                    depth
                        .checked_add(1)
                        .ok_or_else(|| budget("NTFS index depth overflow"))?,
                ));
            }
        }
        Ok(())
    }
}

/// Crate-internal view of an already checked base-record attribute.
#[derive(Clone, Copy)]
pub(crate) struct NtfsAuditAttribute<'a> {
    pub(crate) record: u64,
    pub(crate) kind: u32,
    pub(crate) instance: u16,
    pub(crate) name: &'a [u8],
    pub(crate) nonresident: bool,
    pub(crate) raw: &'a [u8],
    pub(crate) resident: Option<&'a [u8]>,
}
impl NtfsRecord {
    pub(crate) fn audit_attributes(&self) -> impl Iterator<Item = NtfsAuditAttribute<'_>> {
        self.attributes.iter().map(|a| {
            let raw = &self.bytes[a.start..a.start + a.length];
            let at = usize::from(u16le(raw, 10));
            let len = usize::from(raw[9]) * 2;
            NtfsAuditAttribute {
                record: u64le(&self.identity.native, 0),
                kind: a.kind,
                instance: u16le(raw, 14),
                name: if len == 0 { &[] } else { &raw[at..at + len] },
                nonresident: a.nonresident,
                raw,
                resident: if a.nonresident {
                    None
                } else {
                    Some(self.value(*a).expect("checked resident attribute"))
                },
            }
        })
    }
    pub(crate) fn audit_links(&self) -> u16 {
        u16le(&self.bytes, 18)
    }
}
impl NtfsVolume {
    pub(crate) fn audit_check_source(&self, r: &Resources) -> Result<()> {
        self.context.check(r)
    }
    pub(crate) fn audit_flags(&self) -> u16 {
        self.volume_flags
    }
    pub(crate) fn audit_mirror_cluster(&self) -> u64 {
        self.geometry.mirror_cluster
    }
    pub(crate) fn audit_mapping(
        &self,
        a: NtfsAuditAttribute<'_>,
        r: &Resources,
    ) -> Result<Budgeted<NtfsRawMap>> {
        if !a.nonresident {
            return Err(bad("resident attribute has no allocation map"));
        }
        Budgeted::try_new(&r.memory, map_charge(self.limits.runs)?, || {
            decode_runs(
                a.raw,
                &self.geometry,
                self.limits,
                r,
                a.record == 8 && a.kind == 0x80 && a.name == [36, 0, 66, 0, 97, 0, 100, 0],
            )
        })
    }
    pub(crate) fn audit_stream(
        &self,
        record: &NtfsRecord,
        a: NtfsAuditAttribute<'_>,
        r: &Resources,
    ) -> Result<NtfsFile> {
        self.context.check(r)?;
        let reservation = r.memory.reserve(
            map_charge(self.limits.runs)?
                .checked_add(self.geometry.record_bytes as u64)
                .ok_or_else(|| budget("NTFS attribute-stream envelope"))?,
        )?;
        let content = if a.nonresident {
            let map = decode_runs(
                a.raw,
                &self.geometry,
                self.limits,
                r,
                a.record == 8 && a.kind == 0x80 && a.name == [36, 0, 66, 0, 97, 0, 100, 0],
            )?;
            Content::Mapped(
                ExtentFile::new(
                    self.context.source.clone(),
                    map.length,
                    map.extents,
                    self.limits.runs.saturating_mul(2),
                )
                .map_err(|e| Error::io("NTFS audit stream map", e))?,
            )
        } else {
            let value = a.resident.ok_or_else(|| bad("missing resident value"))?;
            let mut bytes = vector(value.len())?;
            bytes.extend_from_slice(value);
            Content::Resident(bytes)
        };
        Ok(NtfsFile {
            identity: record.identity.clone(),
            context: self.context.clone(),
            content,
            _reservation: reservation,
        })
    }
    pub(crate) fn audit_slot_in_use(&self, number: u64, r: &Resources) -> Result<bool> {
        self.context.check(r)?;
        if number >= self.record_count() {
            return Err(bad("NTFS MFT slot outside stream"));
        }
        let mut bytes = [0; 32];
        let n = self
            .mft
            .read_at(number * self.geometry.record_bytes as u64, &mut bytes)
            .map_err(|e| Error::io("NTFS MFT slot header", e))?;
        if n != bytes.len() {
            return Err(bad("NTFS MFT slot truncated"));
        }
        if bytes[..4] == *b"FILE" {
            Ok(u16le(&bytes, 22) & 1 != 0)
        } else if bytes.iter().all(|b| *b == 0) {
            Ok(false)
        } else {
            Err(bad("NTFS MFT slot signature"))
        }
    }
    pub(crate) fn audit_record_bytes(
        &self,
        number: u64,
        r: &Resources,
    ) -> Result<Budgeted<Vec<u8>>> {
        self.context.check(r)?;
        if number >= self.record_count() {
            return Err(bad("NTFS audit record bounds"));
        }
        Budgeted::try_new(&r.memory, self.geometry.record_bytes as u64, || {
            let mut bytes = vector(self.geometry.record_bytes)?;
            bytes.resize(self.geometry.record_bytes, 0);
            if self
                .mft
                .read_at(number * self.geometry.record_bytes as u64, &mut bytes)
                .map_err(|e| Error::io("NTFS primary raw record", e))?
                != bytes.len()
            {
                return Err(bad("NTFS truncated primary raw record"));
            }
            audit_fixup(&mut bytes, r)?;
            Ok(bytes)
        })
    }
    pub(crate) fn audit_mirror_bytes(
        &self,
        stream: &NtfsFile,
        number: u64,
        r: &Resources,
    ) -> Result<Budgeted<Vec<u8>>> {
        self.context.check(r)?;
        Budgeted::try_new(&r.memory, self.geometry.record_bytes as u64, || {
            let mut bytes = vector(self.geometry.record_bytes)?;
            bytes.resize(self.geometry.record_bytes, 0);
            if stream.read_at(number * self.geometry.record_bytes as u64, &mut bytes, r)?
                != bytes.len()
            {
                return Err(bad("NTFS truncated MFT mirror"));
            }
            audit_fixup(&mut bytes, r)?;
            Ok(bytes)
        })
    }
    pub(crate) fn audit_boot_mirror(&self, r: &Resources) -> Result<bool> {
        self.context.check(r)?;
        let offset = self.geometry.volume_bytes;
        if offset
            .checked_add(512)
            .is_none_or(|end| end > self.context.original.len())
        {
            return Ok(false);
        }
        let mut primary = [0; 512];
        let mut backup = [0; 512];
        self.context
            .original
            .read_exact_at(0, &mut primary)
            .map_err(|e| Error::io("NTFS primary boot audit", e))?;
        self.context
            .original
            .read_exact_at(offset, &mut backup)
            .map_err(|e| Error::io("NTFS backup boot audit", e))?;
        self.context.check(r)?;
        Ok(primary == backup)
    }
}

fn audit_fixup(bytes: &mut [u8], r: &Resources) -> Result<()> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(());
    }
    if &bytes[..4] != b"FILE" {
        return Err(bad("NTFS audit mirror FILE signature"));
    }
    let usa = usize::from(u16le(bytes, 4));
    let count = usize::from(u16le(bytes, 6));
    if usa < 48
        || !usa.is_multiple_of(2)
        || count != bytes.len() / 512 + 1
        || usa
            .checked_add(count * 2)
            .is_none_or(|end| end > 510 || end > usize::from(u16le(bytes, 20)))
    {
        return Err(bad("NTFS audit mirror USA bounds"));
    }
    let sequence = u16le(bytes, usa);
    if sequence == 0 || sequence == 65535 {
        return Err(bad("NTFS audit mirror USA sequence"));
    }
    for i in 1..count {
        r.cancellation.check()?;
        if u16le(bytes, i * 512 - 2) != sequence {
            return Err(bad("NTFS audit mirror torn record"));
        }
        let replacement = u16le(bytes, usa + i * 2);
        bytes[i * 512 - 2..i * 512].copy_from_slice(&replacement.to_le_bytes());
    }
    Ok(())
}
