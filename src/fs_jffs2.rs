//! Strict offline JFFS2 logical NOR node inventory and uncompressed reconstruction.
use crate::io::ReadAt;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use crate::{
    fs_core::*,
    fs_file::{ExtentFile, ExtentKind as MapKind, FileExtent},
    fs_flash::{FlashGeometry, FlashLayout, FlashProgramming},
};
#[path = "fs_jffs2_compression.rs"]
pub(crate) mod compression;
pub use compression::Jffs2CompressionLimits;
static NEXT: AtomicU64 = AtomicU64::new(1);
pub(crate) fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
pub(crate) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
pub(crate) fn copy(b: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(b.len())
        .map_err(|_| budget("JFFS2 allocation"))?;
    v.extend_from_slice(b);
    Ok(v)
}
/// Explicit native node byte order; never inferred from magic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Jffs2Endian {
    /// Little-endian native node fields.
    Little,
    /// Big-endian native node fields.
    Big,
}
impl Jffs2Endian {
    pub(crate) fn word(self, b: &[u8], o: usize) -> u16 {
        let a = b[o..o + 2].try_into().unwrap();
        match self {
            Self::Little => u16::from_le_bytes(a),
            Self::Big => u16::from_be_bytes(a),
        }
    }
    pub(crate) fn dword(self, b: &[u8], o: usize) -> u32 {
        let a = b[o..o + 4].try_into().unwrap();
        match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        }
    }
}
/// Explicit scan and reconstruction limits, separate from source size.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2ReadLimits {
    /// Maximum source bytes scanned, including erased space.
    pub scan_bytes: u64,
    /// Maximum retained valid or obsolete nodes.
    pub nodes: usize,
    /// Maximum distinct inode records.
    pub inodes: usize,
    /// Maximum reconstructed fragments across inodes.
    pub fragments: usize,
    /// Maximum retained directory-name bytes.
    pub native_bytes: usize,
    /// Maximum scan/reconstruction work units.
    pub work: u64,
}
pub(crate) fn crc(mut c: u32, b: &[u8]) -> u32 {
    for &v in b {
        c ^= u32::from(v);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    c
}
pub(crate) struct Checked {
    source: Arc<dyn ReadAt>,
    length: u64,
    r: Resources,
}
impl Checked {
    pub(crate) fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.r.cancellation.check()?;
        if self.source.len() != self.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFFS2 source length changed",
            ));
        }
        Ok(())
    }
    fn read(&self, p: u64, b: &mut [u8]) -> Result<()> {
        self.check(&self.r)?;
        self.source
            .read_exact_at(p, b)
            .map_err(|e| Error::io("JFFS2 source read", e))
    }
}
impl ReadAt for Checked {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, p: u64, b: &mut [u8]) -> io::Result<()> {
        self.r.cancellation.check().map_err(io::Error::other)?;
        if self.source.len() != self.length {
            return Err(io::Error::other("JFFS2 stale source"));
        }
        self.source.read_exact_at(p, b)
    }
    fn context(&self) -> crate::io::ReadContext {
        self.source.context()
    }
    fn budget(&self) -> Option<crate::io::ReadBudget> {
        self.source.budget()
    }
    fn sparse_holes(&self) -> io::Result<Vec<(u64, u64)>> {
        self.source.sparse_holes()
    }
}
struct RawInode {
    mapping: u64,
    raw: [u8; 68],
    physical: u64,
}
struct RawDirent {
    physical: u64,
    parent: u32,
    version: u32,
    inode: u32,
    time: u32,
    kind: u8,
    name: Vec<u8>,
}
/// Exact latest native inode metadata and indexed version-resolved payload.
pub struct Jffs2Inode {
    pub(crate) number: u32,
    pub(crate) version: u32,
    pub(crate) raw: [u8; 68],
    pub(crate) map: Vec<FileExtent>,
    pub(crate) children: Vec<Jffs2Entry>,
    pub(crate) deleted: Vec<Jffs2Entry>,
    pub(crate) synthetic: bool,
    pub(crate) dir_time: Option<(u32, u32)>,
    pub(crate) header_offset: Option<u64>,
    pub(crate) namespace_version: u32,
}
impl Jffs2Inode {
    /// Native inode number.
    pub fn number(&self) -> u32 {
        self.number
    }
    /// Latest accepted node version (zero for synthetic root).
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Latest deletion records retained to prevent historical name resurrection.
    pub fn deleted_entries(&self) -> &[Jffs2Entry] {
        &self.deleted
    }
    /// Physical header offset of the latest node; absent for synthetic root.
    pub fn latest_header_offset(&self) -> Option<u64> {
        self.header_offset
    }
    /// Maximum inode or directory-entry version observed for this inode.
    pub fn namespace_version(&self) -> u32 {
        self.namespace_version
    }
    /// Exact native latest raw inode header.
    pub fn raw_metadata(&self) -> &[u8; 68] {
        &self.raw
    }
}
/// Reconstructed live directory name; hardlinks retain native inode numbers.
pub struct Jffs2Entry {
    physical: u64,
    version: u32,
    time: u32,
    /// Exact native bytes, never Unicode-normalized.
    pub name: Vec<u8>,
    /// Referenced native inode.
    pub inode: u32,
    /// Native DT_* type.
    pub file_type: u8,
}
impl Jffs2Entry {
    /// Physical offset of the live version-resolved directory entry node.
    pub fn node_offset(&self) -> u64 {
        self.physical
    }
    /// Native live directory entry version.
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Native directory-entry modification/change timestamp.
    pub fn timestamp(&self) -> u32 {
        self.time
    }
}
/// Immutable scan inventory; backing bytes must remain caller-stable.
pub struct Jffs2Volume {
    codecs: Option<Arc<compression::CodecSource>>,
    pub(crate) source: Arc<Checked>,
    pub(crate) endian: Jffs2Endian,
    pub(crate) inodes: Vec<Jffs2Inode>,
    pub(crate) scope: u128,
    pub(crate) lease: Arc<Reservation>,
    pub(crate) erased: Vec<(u64, u64)>,
    pub(crate) pristine: Vec<(u64, u64)>,
    pub(crate) inode_nodes: Vec<(u32, u64)>,
    pub(crate) obsolete_bytes: u64,
    pub(crate) node_bytes: u64,
    pub(crate) length: u64,
    pub(crate) geometry: FlashGeometry,
}
fn tick(w: &mut u64, l: u64, n: u64) -> Result<()> {
    *w = w
        .checked_add(n)
        .ok_or_else(|| budget("JFFS2 work overflow"))?;
    if *w > l {
        return Err(budget("JFFS2 work cap"));
    }
    Ok(())
}
fn push<T>(v: &mut Vec<T>, value: T, cap: usize) -> Result<()> {
    if v.len() >= cap {
        return Err(budget("JFFS2 retained record cap"));
    }
    v.try_reserve(1)
        .map_err(|_| budget("JFFS2 record allocation"))?;
    v.push(value);
    Ok(())
}
pub(crate) trait DecodeRead {
    fn length(&self) -> u64;
    fn check(&self, r: &Resources) -> Result<()>;
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()>;
}
impl DecodeRead for Checked {
    fn length(&self) -> u64 {
        self.length
    }
    fn check(&self, r: &Resources) -> Result<()> {
        Checked::check(self, r)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        Checked::read(self, offset, out)
    }
}
pub(crate) struct Decoded {
    pub(crate) codecs: Option<compression::Registry>,
    pub(crate) inodes: Vec<Jffs2Inode>,
    pub(crate) lease: Arc<Reservation>,
    pub(crate) erased: Vec<(u64, u64)>,
    pub(crate) pristine: Vec<(u64, u64)>,
    pub(crate) inode_nodes: Vec<(u32, u64)>,
    pub(crate) obsolete_bytes: u64,
    pub(crate) node_bytes: u64,
    pub(crate) length: u64,
    pub(crate) geometry: FlashGeometry,
    pub(crate) endian: Jffs2Endian,
}
pub(crate) fn decode(
    source: &impl DecodeRead,
    geometry: FlashGeometry,
    endian: Jffs2Endian,
    limits: Jffs2ReadLimits,
    r: &Resources,
) -> Result<Decoded> {
    decode_profile(source, geometry, endian, limits, r, None)
}
/// Borrowed codec scan shared by immutable and exclusively owned consumers.
/// No mutable storage is exposed through ReadAt.
pub(crate) fn decode_compressed(
    source: &impl DecodeRead,
    geometry: FlashGeometry,
    endian: Jffs2Endian,
    limits: Jffs2ReadLimits,
    compression: Jffs2CompressionLimits,
    r: &Resources,
) -> Result<Decoded> {
    if source.length() >= 1 << 63 {
        return Err(unsupported("JFFS2 compressed source address limit"));
    }
    let mut registry = compression::Registry::new(compression, limits.nodes, r)?;
    let mut decoded = decode_profile(source, geometry, endian, limits, r, Some(&mut registry))?;
    decoded.codecs = Some(registry);
    Ok(decoded)
}
fn decode_profile(
    source: &impl DecodeRead,
    geometry: FlashGeometry,
    endian: Jffs2Endian,
    limits: Jffs2ReadLimits,
    r: &Resources,
    mut codecs: Option<&mut compression::Registry>,
) -> Result<Decoded> {
    r.cancellation.check()?;
    if geometry.layout != FlashLayout::LogicalNor
        || geometry.erased_byte != 255
        || geometry.programming != FlashProgramming::ClearBitsOnly
    {
        return Err(unsupported(
            "JFFS2 requires explicitly declared logical NOR layout",
        ));
    }
    if geometry.erase_bytes < 4096
        || !geometry.erase_bytes.is_power_of_two()
        || geometry.program_bytes == 0
        || !geometry.program_bytes.is_power_of_two()
        || geometry.program_bytes > 4
    {
        return Err(unsupported("JFFS2 NOR erase/program geometry"));
    }
    let length = source.length();
    let erase = u64::from(geometry.erase_bytes);
    if length == 0 || !length.is_multiple_of(erase) {
        return Err(invalid("JFFS2 source requires complete erase blocks"));
    }
    if length > limits.scan_bytes {
        return Err(budget("JFFS2 scan bytes"));
    }
    let charge = limits.nodes as u128 * 512
        + limits.inodes as u128 * 512
        + limits.fragments as u128 * 192
        + limits.native_bytes as u128 * 3
        + u128::from(length / erase) * 64
        + 65536;
    let lease = Arc::new(
        r.memory
            .reserve(u64::try_from(charge).map_err(|_| budget("JFFS2 accounting overflow"))?)?,
    );
    let mut raw = Vec::new();
    let mut dirs = Vec::new();
    let mut erased = Vec::new();
    let mut pristine = Vec::new();
    let mut inode_nodes = Vec::new();
    let mut scratch = [0u8; 32768];
    let mut work = 0;
    let mut nodes = 0usize;
    let mut names = 0usize;
    let mut obsolete_bytes = 0;
    let mut node_bytes = 0;
    for block in (0..length).step_by(geometry.erase_bytes as usize) {
        let mut p = block;
        let end = block + erase;
        let mut all_erased = true;
        let mut marker_only = true;
        while p < end {
            tick(&mut work, limits.work, 1)?;
            let remaining = end - p;
            if remaining < 12 {
                source.read(p, &mut scratch[..remaining as usize])?;
                if scratch[..remaining as usize].iter().any(|v| *v != 255) {
                    return Err(invalid("JFFS2 non-erased short erase-block tail"));
                }
                break;
            }
            let mut h = [0u8; 12];
            source.read(p, &mut h)?;
            if h[..4] == [255; 4] {
                p += 4;
                continue;
            }
            all_erased = false;
            if endian.word(&h, 0) != 0x1985 {
                return Err(invalid("JFFS2 magic or declared endian mismatch"));
            }
            let kind = endian.word(&h, 2);
            let len = u64::from(endian.dword(&h, 4));
            let padded = len
                .checked_add(3)
                .ok_or_else(|| invalid("JFFS2 node length"))?
                & !3;
            if len < 12 || padded > end - p {
                return Err(invalid("JFFS2 node crosses declared erase boundary"));
            }
            let mut accurate = h;
            let typ = kind | 0x2000;
            let a = match endian {
                Jffs2Endian::Little => typ.to_le_bytes(),
                Jffs2Endian::Big => typ.to_be_bytes(),
            };
            accurate[2..4].copy_from_slice(&a);
            if crc(0, &accurate[..8]) != endian.dword(&h, 8) {
                return Err(invalid("JFFS2 header CRC"));
            }
            nodes += 1;
            if nodes > limits.nodes {
                return Err(budget("JFFS2 node cap"));
            }
            if kind != 0x2003 {
                marker_only = false;
            }
            if kind & 0x2000 == 0 {
                obsolete_bytes += padded;
                p += padded;
                continue;
            }
            node_bytes += padded;
            match kind {
                0xe002 => {
                    if len < 68 {
                        return Err(invalid("JFFS2 short inode"));
                    }
                    let mut b = [0u8; 68];
                    source.read(p, &mut b)?;
                    if crc(0, &b[..60]) != endian.dword(&b, 64) {
                        return Err(invalid("JFFS2 inode CRC"));
                    }
                    let c = endian.dword(&b, 48);
                    let d = endian.dword(&b, 52);
                    if len != 68 + u64::from(c)
                        || endian.dword(&b, 12) == 0
                        || endian.dword(&b, 16) == 0
                    {
                        return Err(invalid("JFFS2 inode length/identity/version"));
                    }
                    match b[56] {
                        0 if c == d => {}
                        1 if c == 0 => {}
                        2 | 6 if codecs.is_some() && c > 0 && d > 0 => {}
                        _ => return Err(unsupported("JFFS2 compression profile unsupported")),
                    }
                    if endian.word(&b, 58) & !3 != 0 {
                        return Err(unsupported("JFFS2 inode flags"));
                    }
                    let mode = endian.dword(&b, 20) & 0xf000;
                    if ![0x4000, 0x8000, 0xa000].contains(&mode) {
                        return Err(unsupported("JFFS2 special inode type"));
                    }
                    if mode == 0x4000
                        && (c != 0
                            || d != 0
                            || endian.dword(&b, 44) != 0
                            || endian.dword(&b, 28) != 0)
                    {
                        return Err(invalid("JFFS2 directory data node"));
                    }
                    if u64::from(endian.dword(&b, 44)) + u64::from(d) > u64::from(u32::MAX) {
                        return Err(invalid("JFFS2 logical extent overflow"));
                    }
                    let mut data_crc = 0;
                    let mut done = 0u64;
                    while done < u64::from(c) {
                        tick(&mut work, limits.work, 1)?;
                        let n = (u64::from(c) - done).min(scratch.len() as u64) as usize;
                        source.read(p + 68 + done, &mut scratch[..n])?;
                        data_crc = crc(data_crc, &scratch[..n]);
                        done += n as u64;
                    }
                    if data_crc != endian.dword(&b, 60) {
                        return Err(invalid("JFFS2 payload CRC"));
                    }
                    let mapping = if matches!(b[56], 2 | 6) {
                        codecs
                            .as_mut()
                            .ok_or_else(|| {
                                unsupported("JFFS2 compression requires explicit profile")
                            })?
                            .add(
                                source,
                                compression::Node {
                                    physical: p + 68,
                                    encoded: c,
                                    decoded: d,
                                    codec: b[56],
                                    checksum: endian.dword(&b, 60),
                                },
                                r,
                            )?
                    } else {
                        p + 68
                    };
                    push(&mut inode_nodes, (endian.dword(&b, 12), p), limits.nodes)?;
                    push(
                        &mut raw,
                        RawInode {
                            mapping,
                            raw: b,
                            physical: p + 68,
                        },
                        limits.nodes,
                    )?;
                }
                0xe001 => {
                    if !(40..=294).contains(&len) {
                        return Err(invalid("JFFS2 dirent length"));
                    }
                    let mut b = [0u8; 294];
                    source.read(p, &mut b[..len as usize])?;
                    let n = usize::from(b[28]);
                    if n == 0
                        || n > 254
                        || len != 40 + n as u64
                        || b[30..32] != [0, 0]
                        || crc(0, &b[..32]) != endian.dword(&b, 32)
                        || crc(0, &b[40..40 + n]) != endian.dword(&b, 36)
                    {
                        return Err(invalid("JFFS2 dirent/name CRC or size"));
                    }
                    let name = &b[40..40 + n];
                    if name == b"."
                        || name == b".."
                        || name.contains(&0)
                        || name.contains(&b'/')
                        || endian.dword(&b, 12) == 0
                    {
                        return Err(invalid("JFFS2 native dirent name/parent/version"));
                    }
                    if ![4, 8, 10].contains(&b[29]) {
                        return Err(unsupported("JFFS2 dirent special file type"));
                    }
                    names = names
                        .checked_add(n)
                        .ok_or_else(|| budget("JFFS2 name accounting"))?;
                    if names > limits.native_bytes {
                        return Err(budget("JFFS2 native name cap"));
                    }
                    push(
                        &mut dirs,
                        RawDirent {
                            physical: p,
                            parent: endian.dword(&b, 12),
                            version: endian.dword(&b, 16),
                            inode: endian.dword(&b, 20),
                            time: endian.dword(&b, 24),
                            kind: b[29],
                            name: copy(name)?,
                        },
                        limits.nodes,
                    )?;
                }
                0x2003 => {
                    if len != 12 || p != block {
                        return Err(unsupported("JFFS2 noncanonical NOR cleanmarker"));
                    }
                }
                0x2004 => {}
                _ => return Err(unsupported("JFFS2 unknown/summary/xattr node profile")),
            }
            p += padded;
        }
        if marker_only {
            push(
                &mut pristine,
                (block, erase),
                usize::try_from(length / erase).map_err(|_| budget("JFFS2 pristine index"))?,
            )?;
        }
        if all_erased {
            push(
                &mut erased,
                (block, erase),
                usize::try_from(length / erase).map_err(|_| budget("JFFS2 erase index"))?,
            )?;
        }
    }
    raw.sort_unstable_by_key(|n| (endian.dword(&n.raw, 12), endian.dword(&n.raw, 16)));
    let mut inodes = Vec::new();
    let mut total_fragments = 0usize;
    let mut start = 0;
    while start < raw.len() {
        let number = endian.dword(&raw[start].raw, 12);
        let mut stop = start + 1;
        while stop < raw.len() && endian.dword(&raw[stop].raw, 12) == number {
            stop += 1;
        }
        let last = &raw[stop - 1].raw;
        let size = u64::from(endian.dword(last, 28));
        if endian.dword(last, 20) & 0xf000 == 0xa000 {
            for node in &raw[start..stop] {
                r.cancellation.check()?;
                source.check(r)?;
                tick(&mut work, limits.work, 1)?;
                let header = &node.raw;
                let n = endian.dword(header, 52) as usize;
                if endian.dword(header, 44) != 0
                    || endian.dword(header, 52) != endian.dword(header, 28)
                    || endian.dword(header, 48) != endian.dword(header, 52)
                    || header[56] != 0
                    || !(1..=254).contains(&n)
                {
                    return Err(unsupported(
                        "JFFS2 symlink history requires complete uncompressed nodes",
                    ));
                }
                let mut target = [0u8; 254];
                source.read(node.physical, &mut target[..n])?;
                if target[..n].contains(&0) {
                    return Err(invalid("JFFS2 symlink embedded NUL"));
                }
            }
        }
        let mut map: Vec<FileExtent> = Vec::new();
        if size > 0 {
            push(
                &mut map,
                FileExtent {
                    offset: 0,
                    length: size,
                    kind: MapKind::Hole,
                },
                limits.fragments,
            )?;
        }
        for (i, node) in raw[start..stop].iter().enumerate() {
            r.cancellation.check()?;
            if i > 0 && endian.dword(&node.raw, 16) == endian.dword(&raw[start + i - 1].raw, 16) {
                return Err(unsupported(
                    "JFFS2 duplicate inode versions require GC-equivalence profile",
                ));
            }
            if endian.dword(&node.raw, 20) & 0xf000 != endian.dword(last, 20) & 0xf000 {
                return Err(invalid("JFFS2 inode type changes across versions"));
            }
            let a = u64::from(endian.dword(&node.raw, 44));
            let z = (a + u64::from(endian.dword(&node.raw, 52))).min(size);
            if a >= z {
                continue;
            }
            let kind = if node.raw[56] == 1 {
                MapKind::Hole
            } else {
                MapKind::Data(node.mapping)
            };
            let mut next = Vec::new();
            for e in &map {
                tick(&mut work, limits.work, 1)?;
                let end = e.offset + e.length;
                if end <= a || e.offset >= z {
                    push(&mut next, *e, limits.fragments)?;
                    continue;
                }
                if e.offset < a {
                    push(
                        &mut next,
                        FileExtent {
                            offset: e.offset,
                            length: a - e.offset,
                            kind: e.kind,
                        },
                        limits.fragments,
                    )?;
                }
                let left = e.offset.max(a);
                let right = end.min(z);
                push(
                    &mut next,
                    FileExtent {
                        offset: left,
                        length: right - left,
                        kind: match kind {
                            MapKind::Data(p) => MapKind::Data(p + left - a),
                            k => k,
                        },
                    },
                    limits.fragments,
                )?;
                if end > z {
                    push(
                        &mut next,
                        FileExtent {
                            offset: z,
                            length: end - z,
                            kind: match e.kind {
                                MapKind::Data(p) => MapKind::Data(p + z - e.offset),
                                k => k,
                            },
                        },
                        limits.fragments,
                    )?;
                }
            }
            map = next;
        }
        total_fragments = total_fragments
            .checked_add(map.len())
            .ok_or_else(|| budget("JFFS2 fragment count"))?;
        if total_fragments > limits.fragments {
            return Err(budget("JFFS2 total fragments"));
        }
        if endian.dword(last, 20) & 0xf000 == 0x4000 && size != 0 {
            return Err(invalid("JFFS2 directory payload"));
        }
        if endian.dword(last, 20) & 0xf000 == 0xa000 && (size == 0 || size > 254) {
            return Err(unsupported("JFFS2 symlink length profile"));
        }
        push(
            &mut inodes,
            Jffs2Inode {
                number,
                version: endian.dword(last, 16),
                raw: *last,
                map,
                children: Vec::new(),
                deleted: Vec::new(),
                header_offset: Some(raw[stop - 1].physical - 68),
                namespace_version: endian.dword(last, 16),
                synthetic: false,
                dir_time: None,
            },
            limits.inodes,
        )?;
        start = stop;
    }
    if inodes.binary_search_by_key(&1, |n| n.number).is_err() {
        let mut b = [0u8; 68];
        let m = match endian {
            Jffs2Endian::Little => 0x41edu32.to_le_bytes(),
            Jffs2Endian::Big => 0x41edu32.to_be_bytes(),
        };
        b[20..24].copy_from_slice(&m);
        push(
            &mut inodes,
            Jffs2Inode {
                number: 1,
                version: 0,
                raw: b,
                map: Vec::new(),
                children: Vec::new(),
                deleted: Vec::new(),
                header_offset: None,
                namespace_version: 0,
                synthetic: true,
                dir_time: None,
            },
            limits.inodes,
        )?;
        inodes.sort_unstable_by_key(|n| n.number);
    }
    dirs.sort_unstable_by(|a, b| {
        (a.parent, &a.name, a.version).cmp(&(b.parent, &b.name, b.version))
    });
    let mut index = 0;
    while index < dirs.len() {
        tick(&mut work, limits.work, 1)?;
        source.check(r)?;
        let mut stop = index + 1;
        while stop < dirs.len()
            && dirs[stop].parent == dirs[index].parent
            && dirs[stop].name == dirs[index].name
        {
            if dirs[stop].version == dirs[stop - 1].version {
                return Err(unsupported("JFFS2 duplicate dirent versions"));
            }
            stop += 1;
        }
        let d = &dirs[stop - 1];
        let parent = inodes
            .binary_search_by_key(&d.parent, |n| n.number)
            .map_err(|_| invalid("JFFS2 absent dirent parent inode"))?;
        if endian.dword(&inodes[parent].raw, 20) & 0xf000 != 0x4000 {
            return Err(invalid("JFFS2 dirent parent not directory"));
        }
        inodes[parent].namespace_version = inodes[parent].namespace_version.max(d.version);
        if d.version > inodes[parent].version
            && inodes[parent]
                .dir_time
                .is_none_or(|(version, _)| d.version > version)
        {
            inodes[parent].dir_time = Some((d.version, d.time));
        }
        {
            let entries = if d.inode == 0 {
                &mut inodes[parent].deleted
            } else {
                &mut inodes[parent].children
            };
            push(
                entries,
                Jffs2Entry {
                    physical: d.physical,
                    version: d.version,
                    time: d.time,
                    name: copy(&d.name)?,
                    inode: d.inode,
                    file_type: d.kind,
                },
                limits.nodes,
            )?;
        }
        index = stop;
    }
    source.check(r)?;
    Ok(Decoded {
        codecs: None,
        inodes,
        lease,
        erased,
        pristine,
        inode_nodes,
        obsolete_bytes,
        node_bytes,
        length,
        geometry,
        endian,
    })
}

impl Jffs2Volume {
    /// Scan complete declared logical NOR image, validate CRCs and reconstruct versions.
    pub fn open(
        source: Arc<dyn ReadAt>,
        geometry: FlashGeometry,
        endian: Jffs2Endian,
        limits: Jffs2ReadLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::open_profile(source, geometry, endian, limits, None, r)
    }
    /// Validate every accurate NONE/ZERO/RTIME/ZLIB node under explicit codec budgets.
    /// Deferred reads inflate only the referenced bounded node; no payload cache is retained.
    /// Strict owned editing rejects compressed histories; opt-in editing binds its codec profile.
    pub fn open_compressed(
        source: Arc<dyn ReadAt>,
        geometry: FlashGeometry,
        endian: Jffs2Endian,
        limits: Jffs2ReadLimits,
        compression: Jffs2CompressionLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::open_profile(source, geometry, endian, limits, Some(compression), r)
    }
    fn open_profile(
        source: Arc<dyn ReadAt>,
        geometry: FlashGeometry,
        endian: Jffs2Endian,
        limits: Jffs2ReadLimits,
        compression: Option<Jffs2CompressionLimits>,
        r: &Resources,
    ) -> Result<Self> {
        if compression.is_some() && source.len() >= 1 << 63 {
            return Err(unsupported("JFFS2 compressed source address limit"));
        }
        let source = Arc::new(Checked {
            length: source.len(),
            source,
            r: r.clone(),
        });
        let mut d = match compression {
            Some(profile) => {
                decode_compressed(source.as_ref(), geometry, endian, limits, profile, r)?
            }
            None => decode(source.as_ref(), geometry, endian, limits, r)?,
        };
        let codecs = d.codecs.take().map(|registry| {
            Arc::new(compression::CodecSource {
                source: source.clone(),
                registry,
                r: r.clone(),
            })
        });
        let scope = (10u128 << 64)
            | u128::from(
                NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                    .map_err(|_| budget("JFFS2 source scope"))?,
            );
        Ok(Self {
            codecs,
            source,
            scope,
            endian: d.endian,
            inodes: d.inodes,
            lease: d.lease,
            erased: d.erased,
            pristine: d.pristine,
            inode_nodes: d.inode_nodes,
            obsolete_bytes: d.obsolete_bytes,
            node_bytes: d.node_bytes,
            length: d.length,
            geometry: d.geometry,
        })
    }
    /// Exact declared logical NOR source length.
    pub fn len(&self) -> u64 {
        self.length
    }
    /// Whether the declared source is empty (accepted images are nonempty).
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// All accurate native inode-header locations, including superseded versions.
    pub fn inode_node_offsets(&self) -> &[(u32, u64)] {
        &self.inode_nodes
    }
    /// Entirely erased or canonical-cleanmarker-only blocks, with no other node bytes.
    /// This is a physical inventory fact, not erase or mutation authorization.
    pub fn pristine_blocks(&self) -> &[(u64, u64)] {
        &self.pristine
    }
    /// Caller-declared flash interpretation.
    pub fn geometry(&self) -> FlashGeometry {
        self.geometry
    }
    /// Check caller-stable backing length and both cancellation contexts.
    pub fn check_stability(&self, r: &Resources) -> Result<()> {
        self.source.check(r)
    }
    /// Find native reconstructed inode, including unreachable historical objects.
    pub fn inode(&self, number: u32) -> Result<&Jffs2Inode> {
        self.inodes
            .binary_search_by_key(&number, |n| n.number)
            .map(|i| &self.inodes[i])
            .map_err(|_| invalid("JFFS2 absent inode"))
    }
    /// Scoped native identity, with latest node version as generation.
    pub fn identity(&self, number: u32) -> Result<ObjectId> {
        let i = self.inode(number)?;
        Ok(ObjectId {
            source: self.scope,
            generation: u64::from(i.version),
            native: copy(&number.to_le_bytes())?,
        })
    }
    /// Deferred regular-file or unfollowed symlink bytes, with retained inventory lease.
    pub fn open_file(&self, number: u32, r: &Resources) -> Result<Jffs2File> {
        self.check_stability(r)?;
        let i = self.inode(number)?;
        if self.endian.dword(&i.raw, 20) & 0xf000 == 0x4000 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "JFFS2 directory stream",
            ));
        }
        let lease = Arc::new(r.memory.reserve(i.map.len() as u64 * 128 + 256)?);
        let mut map = Vec::new();
        map.try_reserve_exact(i.map.len())
            .map_err(|_| budget("JFFS2 deferred map"))?;
        map.extend_from_slice(&i.map);
        let payload_source: Arc<dyn ReadAt> = self.codecs.as_ref().map_or_else(
            || self.source.clone() as Arc<dyn ReadAt>,
            |c| c.clone() as Arc<dyn ReadAt>,
        );
        let file = ExtentFile::new(
            payload_source,
            u64::from(self.endian.dword(&i.raw, 28)),
            map,
            i.map.len(),
        )
        .map_err(|e| Error::io("JFFS2 extent map", e))?;
        Ok(Jffs2File {
            file,
            codecs: self.codecs.clone(),
            source: self.source.clone(),
            id: self.identity(number)?,
            _inventory: self.lease.clone(),
            _map: lease,
        })
    }
}
/// Cloneable immutable indexed payload retaining source, inventory and mapping budgets.
#[derive(Clone)]
pub struct Jffs2File {
    codecs: Option<Arc<compression::CodecSource>>,
    file: ExtentFile,
    source: Arc<Checked>,
    id: ObjectId,
    _inventory: Arc<Reservation>,
    _map: Arc<Reservation>,
}
impl FileRead for Jffs2File {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(&self, p: u64, b: &mut [u8], r: &Resources) -> Result<usize> {
        self.source.check(r)?;
        if p >= self.len() {
            return Ok(0);
        }
        if let Some(codecs) = &self.codecs {
            return codecs.read_file(&self.file, p, b, r);
        }
        self.file
            .read_at(p, b)
            .map_err(|e| Error::io("JFFS2 deferred payload", e))
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.source.check(r)?;
        for e in self.file.extents() {
            r.cancellation.check()?;
            v(LogicalExtent {
                offset: e.offset,
                length: e.length,
                kind: match e.kind {
                    MapKind::Data(_) => ExtentKind::Data,
                    MapKind::Hole => ExtentKind::Hole,
                    MapKind::Unwritten => ExtentKind::Unwritten,
                },
            })?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
#[path = "../tests/fixtures/jffs2_clean.rs"]
pub(crate) mod borrowed_fixture;
#[cfg(all(test, feature = "std"))]
mod borrowed_tests {
    use super::*;
    use crate::{
        fs_flash::{FlashImage, FlashLimits, FlashStorage},
        fs_jffs2_audit::{AuditParts, Jffs2AuditLimits, audit_parts},
        storage::Storage,
    };
    struct Bytes(Vec<u8>);
    impl Storage for Bytes {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, p: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.0
                    .get(p as usize..p as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, p: u64, bytes: &[u8]) -> io::Result<usize> {
            self.0[p as usize..p as usize + bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    // This borrowed capability intentionally has no ReadAt implementation.
    struct Borrowed<'a> {
        flash: &'a dyn FlashStorage,
        length: u64,
        r: &'a Resources,
    }
    impl DecodeRead for Borrowed<'_> {
        fn length(&self) -> u64 {
            self.length
        }
        fn check(&self, r: &Resources) -> Result<()> {
            r.cancellation.check()?;
            self.r.cancellation.check()?;
            if self.flash.len()? != self.length {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "borrowed flash length changed",
                ));
            }
            Ok(())
        }
        fn read(&self, p: u64, out: &mut [u8]) -> Result<()> {
            self.check(self.r)?;
            self.flash.read_exact_at(p, out, self.r)
        }
    }
    #[cfg(feature = "std")]
    #[test]
    fn borrowed_owned_flash_reuses_checked_decode_and_audit_without_read_at() {
        let geometry = FlashGeometry {
            erased_byte: 255,
            programming: FlashProgramming::ClearBitsOnly,
            erase_bytes: 4096,
            program_bytes: 4,
            layout: FlashLayout::LogicalNor,
        };
        for (big, endian) in [(false, Jffs2Endian::Little), (true, Jffs2Endian::Big)] {
            let r = Resources {
                memory: Budget::new(4 << 20),
                cancellation: Cancellation::default(),
            };
            let flash = FlashImage::new(
                Bytes(super::borrowed_fixture::jffs2_seed(big)),
                geometry,
                &[],
                FlashLimits {
                    bad_blocks: 0,
                    operation_bytes: 8192,
                    scratch_bytes: 128,
                },
                &r,
            )
            .unwrap();
            let source = Borrowed {
                flash: &flash,
                length: 8192,
                r: &r,
            };
            let limits = Jffs2ReadLimits {
                scan_bytes: 8192,
                nodes: 128,
                inodes: 32,
                fragments: 128,
                native_bytes: 4096,
                work: 100_000,
            };
            let d = decode(&source, geometry, endian, limits, &r).unwrap();
            let a = audit_parts(
                AuditParts {
                    inodes: &d.inodes,
                    endian,
                    erased: &d.erased,
                    node_bytes: d.node_bytes,
                    obsolete_bytes: d.obsolete_bytes,
                },
                Jffs2AuditLimits {
                    entries: 128,
                    work: 128,
                    findings: 16,
                },
                &r,
                |r| source.check(r),
            )
            .unwrap();
            assert!(a.is_complete() && a.is_clean());
            assert_eq!(d.pristine, vec![(4096, 4096)]);
            let root = d.inodes.iter().find(|i| i.number == 1).unwrap();
            assert!(root.latest_header_offset().is_some());
            assert!(root.namespace_version() >= root.version());
            for entry in &root.children {
                assert!(entry.node_offset() < 4096);
                assert!(entry.version() <= root.namespace_version());
            }
            assert_eq!(a.reachable_inodes(), 4);
            assert_eq!(a.historical_inodes(), 1);
            assert_eq!(a.free_ranges()[0].offset, 4096);
            r.cancellation.cancel();
            assert_eq!(
                decode(&source, geometry, endian, limits, &r)
                    .err()
                    .unwrap()
                    .kind,
                ErrorKind::Cancelled
            );
            drop(a);
            drop(d);
            drop(flash);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
