//! Strict immutable XFS v5 baseline: leaf AG trees, inline extents and shortform directories.
use crate::{
    fs_core::*,
    fs_file::{ExtentFile, ExtentKind as MapKind, FileExtent},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::{DiskView, ReadAt};
static NEXT_SOURCE: AtomicU64 = AtomicU64::new(1);
pub(crate) fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidData, s)
}
pub(crate) fn unsupported(s: &str) -> Error {
    Error::new(ErrorKind::Unsupported, s)
}
pub(crate) fn budget(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
pub(crate) fn bytes(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(input.len())
        .map_err(|_| budget("XFS allocation"))?;
    out.extend_from_slice(input);
    Ok(out)
}
pub(crate) fn u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes(b[o..o + 2].try_into().unwrap())
}
pub(crate) fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
pub(crate) fn u64be(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}
const fn table() -> [u32; 256] {
    let mut out = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut n = 0;
        while n < 8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0x82f63b78 } else { 0 };
            n += 1;
        }
        out[i] = c;
        i += 1;
    }
    out
}
const CRC: [u32; 256] = table();
fn checksum(b: &[u8], offset: usize) -> Result<()> {
    let mut c = u32::MAX;
    for (i, v) in b.iter().enumerate() {
        let v = if (offset..offset + 4).contains(&i) {
            0
        } else {
            *v
        };
        c = (c >> 8) ^ CRC[((c ^ u32::from(v)) & 255) as usize];
    }
    if !c != u32::from_le_bytes(b[offset..offset + 4].try_into().unwrap()) {
        return Err(invalid("XFS CRC32C mismatch"));
    }
    Ok(())
}
/// Explicit independent inventory, metadata, log scan and traversal caps.
#[derive(Clone, Copy, Debug)]
pub struct XfsReadLimits {
    /// Maximum allocation groups.
    pub allocation_groups: u32,
    /// Maximum allocated inode slots, including free slots within allocated chunks.
    pub inodes: usize,
    /// Maximum total AG metadata records and freelist entries.
    pub metadata_records: usize,
    /// Maximum decoded extent records across allocated live inodes.
    pub extent_records: usize,
    /// Maximum metadata/log work units (512-byte log sectors plus bounded records).
    pub work: u64,
    /// Maximum internal log bytes validated.
    pub log_bytes: u64,
}
/// Verified baseline geometry. No editing or generalized XFS support is implied.
#[derive(Clone, Debug)]
pub struct XfsGeometry {
    pub(crate) blocks: u64,
    pub(crate) agblocks: u32,
    pub(crate) groups: u32,
    pub(crate) aglog: u8,
    pub(crate) root: u64,
    pub(crate) system: [u64; 2],
    pub(crate) log_start: u64,
    pub(crate) log_blocks: u32,
    pub(crate) inode_count: u64,
    pub(crate) inode_free: u64,
    pub(crate) free_blocks: u64,
}
impl XfsGeometry {
    /// Supported block size is exactly 4096 bytes.
    pub fn block_size(&self) -> u32 {
        4096
    }
    /// Declared data-device blocks, excluding any source framing.
    pub fn blocks(&self) -> u64 {
        self.blocks
    }
    /// Declared allocation groups.
    pub fn allocation_groups(&self) -> u32 {
        self.groups
    }
    /// Native root inode.
    pub fn root_inode(&self) -> u64 {
        self.root
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Extent {
    pub logical: u64,
    pub physical: u64,
    pub count: u32,
    pub unwritten: bool,
}
/// Checksummed native v3 inode, with exact metadata and decoded baseline forks.
pub struct XfsInode {
    pub(crate) raw: [u8; 512],
    pub(crate) extents: Vec<Extent>,
    pub(crate) children: Vec<XfsEntry>,
    pub(crate) parent: Option<u64>,
}
impl XfsInode {
    /// Native inode number, verified against its physical location.
    pub fn number(&self) -> u64 {
        u64be(&self.raw, 152)
    }
    /// Native generation, retained in common identities.
    pub fn generation(&self) -> u32 {
        u32be(&self.raw, 92)
    }
    /// Logical stream length.
    pub fn len(&self) -> u64 {
        u64be(&self.raw, 56)
    }
    /// Whether logical stream is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Native type and POSIX permission bits.
    pub fn mode(&self) -> u16 {
        u16be(&self.raw, 2)
    }
    /// Full Linux owner.
    pub fn uid(&self) -> u32 {
        u32be(&self.raw, 8)
    }
    /// Full Linux group.
    pub fn gid(&self) -> u32 {
        u32be(&self.raw, 12)
    }
    /// Native hardlink count.
    pub fn links(&self) -> u32 {
        u32be(&self.raw, 16)
    }
    /// Exact checksummed 512-byte inode, including native times and flags.
    pub fn raw_metadata(&self) -> &[u8; 512] {
        &self.raw
    }
    /// Whether the supported object is a directory.
    pub fn is_directory(&self) -> bool {
        self.mode() & 0xf000 == 0x4000
    }
    /// Exact shortform directory entries, without synthetic dot entries.
    pub fn directory_entries(&self) -> &[XfsEntry] {
        &self.children
    }
    /// Stored shortform parent; dot refers implicitly to self.
    pub fn parent_inode(&self) -> Option<u64> {
        self.parent
    }
}
/// Native directory reference; repeated regular inode numbers are hardlinks.
#[derive(Debug)]
pub struct XfsEntry {
    /// Exact native bytes, without conversion or case folding.
    pub name: Vec<u8>,
    /// Referenced native inode number.
    pub inode: u64,
    /// Native v5 filetype (1 regular, 2 directory in this profile).
    pub file_type: u8,
}
pub(crate) struct Group {
    pub start: u64,
    pub protected: Vec<(u32, u32)>,
    pub free: Vec<(u32, u32)>,
    pub free_blocks: u32,
    pub freelist: u32,
}
struct CheckedSource {
    inner: Arc<dyn ReadAt>,
    length: u64,
    resources: Resources,
}
impl ReadAt for CheckedSource {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        if self.inner.len() != self.length {
            return Err(io::Error::other(Error::new(
                ErrorKind::StalePlan,
                "XFS source length changed",
            )));
        }
        self.inner.read_exact_at(at, out)
    }
    fn context(&self) -> virtdisk::ReadContext {
        self.inner.context()
    }
    fn budget(&self) -> Option<virtdisk::ReadBudget> {
        self.inner.budget()
    }
    fn sparse_holes(&self) -> io::Result<Vec<(u64, u64)>> {
        self.inner.sparse_holes()
    }
}
/// Caller-stabilized indexed volume. Unsupported structures fail explicitly at open.
pub struct XfsVolume {
    pub(crate) source: Arc<dyn ReadAt>,
    pub(crate) geometry: XfsGeometry,
    pub(crate) groups: Vec<Group>,
    pub(crate) inodes: Vec<XfsInode>,
    scope: u128,
    original: Arc<dyn ReadAt>,
    original_len: u64,
    lease: Arc<Reservation>,
    resources: Resources,
}
struct Scan<'a> {
    source: &'a dyn ReadAt,
    r: &'a Resources,
    work: u64,
    records: usize,
    limits: XfsReadLimits,
}
impl Scan<'_> {
    fn step(&mut self, n: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| budget("XFS work overflow"))?;
        if self.work > self.limits.work {
            return Err(budget("XFS work cap"));
        }
        Ok(())
    }
    fn read(&mut self, at: u64, out: &mut [u8]) -> Result<()> {
        self.step(1)?;
        self.source
            .read_exact_at(at, out)
            .map_err(|e| Error::io("XFS metadata", e))
    }
    fn record(&mut self, n: usize) -> Result<()> {
        self.step(n as u64)?;
        self.records = self
            .records
            .checked_add(n)
            .ok_or_else(|| budget("XFS record overflow"))?;
        if self.records > self.limits.metadata_records {
            return Err(budget("XFS metadata record cap"));
        }
        Ok(())
    }
}
fn vec<T>(n: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| budget("XFS inventory allocation"))?;
    Ok(v)
}
fn leaf(
    s: &mut Scan<'_>,
    g: &XfsGeometry,
    uuid: &[u8],
    agno: u32,
    block: u32,
    magic: u32,
    record_size: usize,
) -> Result<Vec<u8>> {
    let length = (g.blocks - u64::from(agno) * u64::from(g.agblocks)).min(u64::from(g.agblocks));
    if block == 0 || u64::from(block) >= length {
        return Err(invalid("XFS AG btree address"));
    }
    let physical = u64::from(agno) * u64::from(g.agblocks) + u64::from(block);
    let mut b = [0; 4096];
    s.read(physical * 4096, &mut b)?;
    checksum(&b, 52)?;
    if u64be(&b, 24) != 0 {
        return Err(unsupported(
            "XFS historical btree LSN outside fresh-log baseline",
        ));
    }
    if u32be(&b, 0) != magic
        || u16be(&b, 4) != 0
        || u32be(&b, 8) != u32::MAX
        || u32be(&b, 12) != u32::MAX
        || u64be(&b, 16) != physical * 8
        || &b[32..48] != uuid
        || u32be(&b, 48) != agno
    {
        return Err(invalid("XFS leaf btree identity/shape"));
    }
    let count = usize::from(u16be(&b, 6));
    if count > (4096 - 56) / record_size {
        return Err(invalid("XFS leaf record count"));
    }
    s.record(count)?;
    bytes(&b[56..56 + count * record_size])
}
fn decode_fsblock(g: &XfsGeometry, block: u64, count: u32) -> Result<u64> {
    let ag = block >> g.aglog;
    let b = block & ((1u64 << g.aglog) - 1);
    if count == 0
        || ag >= u64::from(g.groups)
        || b + u64::from(count) > u64::from(g.agblocks)
        || ag * u64::from(g.agblocks) + b + u64::from(count) > g.blocks
    {
        return Err(invalid("XFS extent crosses AG/data boundary"));
    }
    Ok(ag * u64::from(g.agblocks) + b)
}
fn log(s: &mut Scan<'_>, g: &XfsGeometry, uuid: &[u8]) -> Result<()> {
    let length = u64::from(g.log_blocks) * 4096;
    if length > s.limits.log_bytes {
        return Err(budget("XFS internal log scan cap"));
    }
    let mut expected = [0; 512];
    for (o, v) in [
        (0, 0xfeedbabeu32),
        (4, 1),
        (8, 2),
        (12, 512),
        (16, 1),
        (24, 1),
        (36, u32::MAX),
        (40, 1),
        (44, 0xb0c0d0d0),
        (300, 1),
        (320, 32768),
    ] {
        expected[o..o + 4].copy_from_slice(&v.to_be_bytes());
    }
    expected[304..320].copy_from_slice(uuid);
    let mut b = [0; 512];
    s.read(g.log_start * 4096, &mut b)?;
    if b != expected {
        return Err(unsupported(
            "XFS log profile requires exact fresh-format clean-unmount header; replay/history unsupported",
        ));
    }
    expected.fill(0);
    expected[0..4].copy_from_slice(&1u32.to_be_bytes());
    expected[4..8].copy_from_slice(&8u32.to_be_bytes());
    expected[8] = 0xaa;
    expected[9] = 0x20;
    expected[12..14].copy_from_slice(&0x556eu16.to_le_bytes());
    s.read(g.log_start * 4096 + 512, &mut b)?;
    if b != expected {
        return Err(unsupported(
            "XFS log lacks baseline clean unmount operation",
        ));
    }
    let mut scratch = [0; 65536];
    let mut done = 1024;
    while done < length {
        let n = (length - done).min(scratch.len() as u64) as usize;
        s.step((n as u64).div_ceil(512))?;
        s.source
            .read_exact_at(g.log_start * 4096 + done, &mut scratch[..n])
            .map_err(|e| Error::io("XFS log scan", e))?;
        if scratch[..n].iter().any(|v| *v != 0) {
            return Err(unsupported(
                "XFS historical/nonempty log unsupported; no replay",
            ));
        }
        done += n as u64;
    }
    Ok(())
}
impl XfsVolume {
    /// Check all baseline metadata identities/CRC32C and index allocated live inodes.
    /// A complete ownership/reference audit remains a separate operation.
    pub fn open(original: Arc<dyn ReadAt>, limits: XfsReadLimits, r: &Resources) -> Result<Self> {
        r.cancellation.check()?;
        let original_len = original.len();
        let checked: Arc<dyn ReadAt> = Arc::new(CheckedSource {
            inner: original.clone(),
            length: original_len,
            resources: r.clone(),
        });
        let mut sb = [0; 512];
        checked
            .read_exact_at(0, &mut sb)
            .map_err(|e| Error::io("XFS superblock", e))?;
        if &sb[..4] != b"XFSB" {
            return Err(invalid("XFS magic"));
        }
        checksum(&sb, 224)?;
        if u64be(&sb, 240) != 0 {
            return Err(unsupported(
                "XFS nonzero metadata log sequence outside fresh-log baseline",
            ));
        }
        if u16be(&sb, 100) != 0xb4a5
            || u32be(&sb, 200) != 0x18a
            || u32be(&sb, 204) != 0x18a
            || u32be(&sb, 208) != 0
            || u32be(&sb, 212) != 0
            || u32be(&sb, 216) != 1
            || u32be(&sb, 220) != 0
        {
            return Err(unsupported(
                "XFS v5 feature profile: quota/reflink/rmap/finobt/sparse/bigtime/parent/exchange/unknown feature",
            ));
        }
        if u32be(&sb, 4) != 4096
            || u16be(&sb, 102) != 512
            || u16be(&sb, 104) != 512
            || u16be(&sb, 106) != 8
            || sb[120..124] != [12, 9, 9, 3]
            || sb[126] != 0
            || sb[192] != 0
            || sb[193] != 0
            || u16be(&sb, 194) != 0
            || u32be(&sb, 196) != 1
            || sb[160..180].iter().any(|b| *b != 0)
            || u32be(&sb, 180) != 4
            || sb[184..192].iter().any(|b| *b != 0)
            || sb[264..].iter().any(|b| *b != 0)
            || u64be(&sb, 16) != 0
            || u64be(&sb, 24) != 0
            || u32be(&sb, 92) != 0
            || u64be(&sb, 152) != 0
        {
            return Err(unsupported(
                "XFS device/geometry/realtime/quota/in-progress profile",
            ));
        }
        let blocks = u64be(&sb, 8);
        let agblocks = u32be(&sb, 84);
        let groups = u32be(&sb, 88);
        let aglog = sb[124];
        if blocks == 0
            || !(16..=(1u32 << 31)).contains(&agblocks)
            || groups == 0
            || groups > limits.allocation_groups
            || blocks.div_ceil(u64::from(agblocks)) != u64::from(groups)
            || aglog != agblocks.next_power_of_two().trailing_zeros() as u8
            || aglog > 31
            || blocks.checked_mul(4096).is_none_or(|n| n > original_len)
        {
            return Err(invalid("XFS allocation group geometry/source bounds"));
        }
        let mut g = XfsGeometry {
            blocks,
            agblocks,
            groups,
            aglog,
            root: u64be(&sb, 56),
            system: [u64be(&sb, 64), u64be(&sb, 72)],
            log_start: 0,
            log_blocks: u32be(&sb, 96),
            inode_count: u64be(&sb, 128),
            inode_free: u64be(&sb, 136),
            free_blocks: u64be(&sb, 144),
        };
        g.log_start = decode_fsblock(&g, u64be(&sb, 48), g.log_blocks)?;
        let slots = usize::try_from(g.inode_count).map_err(|_| budget("XFS inode count"))?;
        if slots > limits.inodes || g.inode_free > g.inode_count || slots == 0 {
            return Err(budget("XFS allocated inode slots cap"));
        }
        let charge = (slots as u128) * 4096
            + (limits.metadata_records as u128) * 128
            + u128::from(groups) * 4096
            + 131072;
        let lease = Arc::new(
            r.memory
                .reserve(u64::try_from(charge).map_err(|_| budget("XFS inventory accounting"))?)?,
        );
        let source: Arc<dyn ReadAt> = Arc::new(
            DiskView::new(checked, 0, blocks * 4096)
                .map_err(|e| Error::io("XFS bounded source", e))?,
        );
        let mut scan = Scan {
            source: source.as_ref(),
            r,
            work: 0,
            records: 0,
            limits,
        };
        log(&mut scan, &g, &sb[32..48])?;
        let mut ags = vec(groups as usize)?;
        let mut allocated = vec(slots)?;
        let mut total_slots = 0u64;
        let mut total_free = 0u64;
        for ag in 0..groups {
            let start = u64::from(ag) * u64::from(agblocks);
            let length = (blocks - start).min(u64::from(agblocks)) as u32;
            let mut header = [0; 2048];
            scan.read(start * 4096, &mut header)?;
            checksum(&header[..512], 224)?;
            // Secondary copies intentionally retain stale root/system inode,
            // mkfs-in-progress and lazy counters; only static facts are compared.
            for (a, b) in [
                (0, 56),
                (80, 126),
                (127, 128),
                (160, 224),
                (228, 240),
                (248, 264),
            ] {
                if header[a..b] != sb[a..b] {
                    return Err(invalid("XFS secondary superblock static facts disagree"));
                }
            }
            let agf = &header[512..1024];
            let agi = &header[1024..1536];
            let agfl = &header[1536..2048];
            checksum(agf, 216)?;
            checksum(agi, 312)?;
            checksum(agfl, 32)?;
            if u64be(agf, 208) != 0 || u64be(agi, 320) != 0 || u64be(agfl, 24) != 0 {
                return Err(unsupported(
                    "XFS historical AG log sequence outside fresh-log baseline",
                ));
            }
            if &agf[..4] != b"XAGF"
                || u32be(agf, 4) != 1
                || u32be(agf, 8) != ag
                || u32be(agf, 12) != length
                || agf[64..80] != sb[32..48]
                || &agi[..4] != b"XAGI"
                || u32be(agi, 4) != 1
                || u32be(agi, 8) != ag
                || u32be(agi, 12) != length
                || agi[296..312] != sb[32..48]
                || &agfl[..4] != b"XAFL"
                || u32be(agfl, 4) != ag
                || agfl[8..24] != sb[32..48]
            {
                return Err(invalid("XFS AG header identity"));
            }
            if u32be(agf, 28) != 1 || u32be(agf, 32) != 1 || u32be(agi, 24) != 1 {
                return Err(unsupported(
                    "XFS multi-level AG btrees outside leaf baseline",
                ));
            }
            if u32be(agf, 24) != 0
                || u32be(agf, 36) != 0
                || agf[80..96].iter().any(|b| *b != 0)
                || agf[96..208].iter().any(|b| *b != 0)
                || u32be(agf, 60) != 0
                || agi[328..344].iter().any(|b| *b != 0)
                || agi[40..296]
                    .chunks_exact(4)
                    .any(|b| u32be(b, 0) != u32::MAX)
            {
                return Err(unsupported(
                    "XFS advanced AG state or unlinked inode recovery required",
                ));
            }
            let bno = u32be(agf, 16);
            let cnt = u32be(agf, 20);
            let ino = u32be(agi, 20);
            let bnorecs = leaf(&mut scan, &g, &sb[32..48], ag, bno, 0x41423342, 8)?;
            let cntrecs = leaf(&mut scan, &g, &sb[32..48], ag, cnt, 0x41423343, 8)?;
            let inorecs = leaf(&mut scan, &g, &sb[32..48], ag, ino, 0x49414233, 16)?;
            let mut free = vec(bnorecs.len() / 8)?;
            let mut free_count = 0u64;
            let mut longest = 0;
            let mut previous = 0u64;
            for record in bnorecs.chunks_exact(8) {
                let b = u32be(record, 0);
                let count = u32be(record, 4);
                if count == 0
                    || u64::from(b) < previous
                    || u64::from(b) + u64::from(count) > u64::from(length)
                {
                    return Err(invalid("XFS free extent order/range"));
                }
                previous = u64::from(b) + u64::from(count);
                free_count += u64::from(count);
                longest = longest.max(count);
                free.push((b, count));
            }
            let mut bycount = vec(cntrecs.len() / 8)?;
            for record in cntrecs.chunks_exact(8) {
                bycount.push((u32be(record, 0), u32be(record, 4)));
            }
            if bycount
                .windows(2)
                .any(|w| (w[0].1, w[0].0) >= (w[1].1, w[1].0))
            {
                return Err(invalid("XFS cntbt order"));
            }
            bycount.sort_unstable();
            if bycount != free
                || free_count != u64::from(u32be(agf, 52))
                || longest != u32be(agf, 56)
            {
                return Err(invalid("XFS free trees/counters disagree"));
            }
            let mut protected = vec(inorecs.len() / 16 + 124)?;
            protected.extend([(0, 1), (bno, 1), (cnt, 1), (ino, 1)]);
            let first = u32be(agf, 40);
            let last = u32be(agf, 44);
            let flcount = u32be(agf, 48);
            if first >= 119
                || last >= 119
                || flcount > 119
                || (flcount != 0 && (first + flcount - 1) % 119 != last)
            {
                return Err(invalid("XFS AGFL ring bounds"));
            }
            scan.record(flcount as usize)?;
            for n in 0..flcount {
                let b = u32be(agfl, 36 + ((first + n) % 119) as usize * 4);
                if b == 0 || b >= length {
                    return Err(invalid("XFS AGFL block"));
                }
                protected.push((b, 1));
            }
            let mut prev_end = 0u64;
            let mut ag_slots = 0u32;
            let mut ag_free = 0u32;
            for record in inorecs.chunks_exact(16) {
                let firstino = u32be(record, 0);
                let free_slots = u32be(record, 4);
                let mask = u64be(record, 8);
                if !firstino.is_multiple_of(64)
                    || u64::from(firstino) < prev_end
                    || u64::from(firstino) + 64 > u64::from(length) * 8
                    || free_slots != mask.count_ones()
                {
                    return Err(invalid("XFS dense inode chunk record"));
                }
                prev_end = u64::from(firstino) + 64;
                ag_slots = ag_slots
                    .checked_add(64)
                    .ok_or_else(|| invalid("XFS AG inode count overflow"))?;
                ag_free += free_slots;
                total_slots += 64;
                if total_slots > g.inode_count {
                    return Err(invalid("XFS inode records exceed superblock slots"));
                }
                protected.push((firstino / 8, 8));
                for bit in 0..64 {
                    if mask & (1u64 << bit) == 0 {
                        allocated.push((u64::from(ag) << (aglog + 3)) | u64::from(firstino + bit));
                    }
                }
            }
            if ag_slots != u32be(agi, 16) || ag_free != u32be(agi, 28) {
                return Err(invalid("XFS AG inode counters"));
            }
            total_free += u64::from(ag_free);
            ags.push(Group {
                start,
                protected,
                free,
                free_blocks: u32be(agf, 52),
                freelist: flcount,
            });
        }
        if total_slots != g.inode_count || total_free != g.inode_free {
            return Err(invalid("XFS superblock inode counters"));
        }
        allocated.sort_unstable();
        if allocated.windows(2).any(|w| w[0] == w[1]) {
            return Err(invalid("XFS duplicate allocated inode"));
        }
        let mut inodes = vec(allocated.len())?;
        let mut extent_count = 0usize;
        for number in allocated {
            scan.step(1)?;
            let ag = number >> (aglog + 3);
            let agino = number & ((1u64 << (aglog + 3)) - 1);
            let address = (ag * u64::from(agblocks) + agino / 8) * 4096 + (agino % 8) * 512;
            let mut raw = [0; 512];
            scan.read(address, &mut raw)?;
            checksum(&raw, 100)?;
            if u16be(&raw, 0) != 0x494e
                || raw[4] != 3
                || u64be(&raw, 152) != number
                || raw[160..176] != sb[32..48]
                || u32be(&raw, 96) != u32::MAX
                || u32be(&raw, 16) == 0
                || u32be(&raw, 16) > i32::MAX as u32
            {
                return Err(invalid("XFS allocated inode identity/live state"));
            }
            if raw[6..8] != [0, 0]
                || raw[24..32].iter().any(|b| *b != 0)
                || raw[80..82] != [0, 0]
                || raw[82] != 0
                || raw[83] != 2
                || raw[84..90].iter().any(|b| *b != 0)
                || u64be(&raw, 120) != 0
                || raw[132..144].iter().any(|b| *b != 0)
            {
                return Err(unsupported(
                    "XFS attribute fork/advanced inode encoding unsupported",
                ));
            }
            if u64be(&raw, 112) != 0 {
                return Err(unsupported(
                    "XFS historical inode LSN outside fresh-log baseline",
                ));
            }
            let flags = u16be(&raw, 90);
            if flags & 1 != 0 || flags & !0x7ffe != 0 || (flags & 4 != 0 && number != g.system[0]) {
                return Err(unsupported("XFS realtime or unsupported inode flags"));
            }
            for at in [32, 40, 48, 144] {
                if u32be(&raw, at + 4) >= 1_000_000_000 {
                    return Err(invalid("XFS native timestamp nanoseconds"));
                }
            }
            let mode = u16be(&raw, 2) & 0xf000;
            let length = u64be(&raw, 56);
            if length > i64::MAX as u64 {
                return Err(invalid("XFS negative/overflowing native file length"));
            }
            if ![0x4000, 0x8000].contains(&mode) {
                return Err(unsupported("XFS special/symlink inode outside baseline"));
            }
            let mut extents = vec((u32be(&raw, 76) as usize).min(21))?;
            let mut children = Vec::new();
            let mut parent = None;
            if mode == 0x8000 {
                if raw[5] != 2 {
                    return Err(unsupported(
                        "XFS regular fork requires inline extent records",
                    ));
                }
                let count = u32be(&raw, 76) as usize;
                if count > 21 {
                    return Err(invalid("XFS inline extent record capacity"));
                }
                extent_count = extent_count
                    .checked_add(count)
                    .ok_or_else(|| budget("XFS extent count overflow"))?;
                if extent_count > limits.extent_records {
                    return Err(budget("XFS extent record cap"));
                }
                let mut previous = 0u64;
                let mut data_blocks = 0u64;
                for n in 0..count {
                    let at = 176 + n * 16;
                    let hi = u64be(&raw, at);
                    let lo = u64be(&raw, at + 8);
                    let logical = (hi & 0x7fff_ffff_ffff_ffff) >> 9;
                    let fsblock = ((hi & 511) << 43) | (lo >> 21);
                    let count = (lo & 0x1f_ffff) as u32;
                    let physical = decode_fsblock(&g, fsblock, count)?;
                    if logical < previous
                        || logical
                            .checked_add(u64::from(count))
                            .is_none_or(|end| end > (i64::MAX as u64).div_ceil(4096))
                    {
                        return Err(invalid("XFS extent logical overlap/overflow"));
                    }
                    previous = logical + u64::from(count);
                    data_blocks += u64::from(count);
                    extents.push(Extent {
                        logical,
                        physical,
                        count,
                        unwritten: hi >> 63 != 0,
                    });
                }
                if data_blocks != u64be(&raw, 64) {
                    return Err(invalid("XFS inode allocation counter"));
                }
            } else {
                if raw[5] != 1
                    || u32be(&raw, 76) != 0
                    || u64be(&raw, 64) != 0
                    || !(6..=336).contains(&length)
                {
                    return Err(unsupported("XFS directory requires shortform baseline"));
                }
                let dir = &raw[176..176 + length as usize];
                let wide = dir[1] != 0;
                let width = if wide { 8 } else { 4 };
                if dir.len() < 2 + width {
                    return Err(invalid("XFS shortform header"));
                }
                parent = Some(if wide {
                    u64be(dir, 2)
                } else {
                    u64::from(u32be(dir, 2))
                });
                let count = usize::from(dir[0]);
                children = vec(count)?;
                let mut pos = 2 + width;
                let mut i8 = usize::from(parent.unwrap() > u32::MAX as u64);
                let mut offset = 0x60usize;
                for _ in 0..count {
                    if pos + 3 > dir.len() {
                        return Err(invalid("XFS shortform entry header"));
                    }
                    let n = usize::from(dir[pos]);
                    let stored = usize::from(u16be(dir, pos + 1));
                    if n == 0 || pos + 4 + n + width > dir.len() || stored < offset {
                        return Err(invalid("XFS shortform entry geometry"));
                    }
                    if stored + (12 + n).next_multiple_of(8) > 4096 {
                        return Err(invalid(
                            "XFS shortform expanded directory offset exceeds block",
                        ));
                    }
                    let name = &dir[pos + 3..pos + 3 + n];
                    if name == b"." || name == b".." || name.contains(&0) || name.contains(&b'/') {
                        return Err(invalid("XFS native directory name"));
                    }
                    let file_type = dir[pos + 3 + n];
                    if ![1, 2].contains(&file_type) {
                        return Err(unsupported("XFS shortform special directory reference"));
                    }
                    let number = if wide {
                        u64be(dir, pos + 4 + n)
                    } else {
                        u64::from(u32be(dir, pos + 4 + n))
                    };
                    i8 += usize::from(number > u32::MAX as u64);
                    children.push(XfsEntry {
                        name: bytes(name)?,
                        inode: number,
                        file_type,
                    });
                    offset = stored + (8 + 1 + n + 1 + 2).next_multiple_of(8);
                    pos += 4 + n + width;
                }
                if pos != dir.len() || i8 != usize::from(dir[1]) {
                    return Err(invalid("XFS shortform trailing bytes/i8count"));
                }
                children.sort_unstable_by(|a, b| a.name.cmp(&b.name));
                if children.windows(2).any(|w| w[0].name == w[1].name) {
                    return Err(invalid("XFS duplicate native directory name"));
                }
            }
            inodes.push(XfsInode {
                raw,
                extents,
                children,
                parent,
            });
        }
        for system in g.system {
            let inode = inodes
                .binary_search_by_key(&system, XfsInode::number)
                .ok()
                .map(|n| &inodes[n])
                .ok_or_else(|| invalid("XFS absent baseline realtime system inode"))?;
            if inode.mode() & 0xf000 != 0x8000
                || !inode.is_empty()
                || !inode.extents.is_empty()
                || inode.links() != 1
            {
                return Err(unsupported("XFS nonempty realtime system inode"));
            }
        }
        let scope = (9u128 << 64)
            | u128::from(
                NEXT_SOURCE
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                    .map_err(|_| budget("XFS source scope exhausted"))?,
            );
        Ok(Self {
            source,
            geometry: g,
            groups: ags,
            inodes,
            scope,
            original,
            original_len,
            lease,
            resources: r.clone(),
        })
    }
    /// Checked native geometry.
    pub fn geometry(&self) -> &XfsGeometry {
        &self.geometry
    }
    /// Caller guarantee revalidation checks source length and both cancellation contexts.
    pub fn check_stability(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.resources.cancellation.check()?;
        if self.original.len() != self.original_len {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "XFS source length changed",
            ));
        }
        Ok(())
    }
    /// Lookup an allocated, checksummed indexed inode.
    pub fn inode(&self, number: u64) -> Result<&XfsInode> {
        self.inodes
            .binary_search_by_key(&number, XfsInode::number)
            .map(|n| &self.inodes[n])
            .map_err(|_| invalid("XFS reference to unallocated inode"))
    }
    /// Native generation and open-scoped identity; different opens are distinct sources.
    pub fn identity(&self, number: u64) -> Result<ObjectId> {
        let i = self.inode(number)?;
        Ok(ObjectId {
            source: self.scope,
            generation: u64::from(i.generation()),
            native: bytes(&number.to_le_bytes())?,
        })
    }
    /// Deferred sparse-aware stream. Unwritten allocation reads as zero without source reads.
    pub fn open_file(&self, number: u64, r: &Resources) -> Result<XfsFile> {
        self.check_stability(r)?;
        let i = self.inode(number)?;
        if i.is_directory() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "XFS directory has no regular stream",
            ));
        }
        let lease = Arc::new(r.memory.reserve((i.extents.len() as u64 + 1) * 128 + 512)?);
        let mut map = vec(i.extents.len() * 2 + 1)?;
        let mut position = 0u64;
        for e in &i.extents {
            let group = &self.groups[(e.physical / u64::from(self.geometry.agblocks)) as usize];
            let first = e.physical - group.start;
            let end = first + u64::from(e.count);
            if group
                .protected
                .iter()
                .chain(group.free.iter())
                .any(|&(b, count)| first < u64::from(b) + u64::from(count) && u64::from(b) < end)
                || (e.physical < self.geometry.log_start + u64::from(self.geometry.log_blocks)
                    && self.geometry.log_start < e.physical + u64::from(e.count))
            {
                return Err(invalid(
                    "XFS payload references metadata, log or free allocation",
                ));
            }
            let start = e
                .logical
                .checked_mul(4096)
                .ok_or_else(|| invalid("XFS logical extent byte overflow"))?;
            if start >= i.len() {
                break;
            }
            if start > position {
                map.push(FileExtent {
                    offset: position,
                    length: start - position,
                    kind: MapKind::Hole,
                });
            }
            let length = (u64::from(e.count) * 4096).min(i.len() - start);
            map.push(FileExtent {
                offset: start,
                length,
                kind: if e.unwritten {
                    MapKind::Unwritten
                } else {
                    MapKind::Data(e.physical * 4096)
                },
            });
            position = start + length;
        }
        if position < i.len() {
            map.push(FileExtent {
                offset: position,
                length: i.len() - position,
                kind: MapKind::Hole,
            });
        }
        let max = map.len();
        let file = ExtentFile::new(self.source.clone(), i.len(), map, max)
            .map_err(|e| Error::io("XFS file extent index", e))?;
        Ok(XfsFile {
            identity: self.identity(number)?,
            file,
            _lease: lease,
            _inventory: self.lease.clone(),
            original: self.original.clone(),
            original_len: self.original_len,
            resources: self.resources.clone(),
        })
    }
}
/// Deferred indexed XFS regular stream retaining volume and index budget leases.
#[derive(Clone)]
pub struct XfsFile {
    identity: ObjectId,
    file: ExtentFile,
    _lease: Arc<Reservation>,
    _inventory: Arc<Reservation>,
    original: Arc<dyn ReadAt>,
    original_len: u64,
    resources: Resources,
}
impl XfsFile {
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.resources.cancellation.check()?;
        if self.original.len() != self.original_len {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "XFS deferred source length changed",
            ));
        }
        Ok(())
    }
}
impl FileRead for XfsFile {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.file.len()
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        self.check(r)?;
        if at >= self.file.len() || out.is_empty() {
            return Ok(0);
        }
        self.file
            .read_at(at, out)
            .map_err(|e| Error::io("XFS payload", e))
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.check(r)?;
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
