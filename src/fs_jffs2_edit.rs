//! Owned bounded logical NOR append, exact external-intent recovery and single-block GC.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
};
use crate::{
    fs_core::*,
    fs_file::ExtentKind,
    fs_flash::{FlashGeometry, FlashStorage},
    fs_jffs2::{DecodeRead, Decoded, Jffs2Endian, Jffs2Inode, Jffs2ReadLimits, copy, crc, decode},
    fs_jffs2_audit::{AuditParts, Jffs2AuditLimits, Jffs2AuditReport, audit_parts},
    storage::Storage,
};
use sha2::{Digest, Sha256};
#[path = "fs_jffs2_edit_journal.rs"]
mod journal;
use journal::{Intent, Slot, State};
#[path = "fs_jffs2_edit_namespace.rs"]
mod namespace;
pub use namespace::Jffs2CreateMetadata;
#[path = "fs_jffs2_edit_compression.rs"]
mod compression_edit;
#[path = "fs_jffs2_edit_file.rs"]
mod file_edit;
#[path = "fs_jffs2_edit_gc.rs"]
mod gc_edit;
static NEXT: AtomicU64 = AtomicU64::new(1);
fn invalid(s: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, s)
}
fn cap(s: &str) -> Error {
    Error::new(ErrorKind::BudgetExhausted, s)
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn vec_bytes(n: usize, v: u8) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    b.try_reserve_exact(n)
        .map_err(|_| cap("JFFS2 edit byte allocation"))?;
    b.resize(n, v);
    Ok(b)
}
/// Operation encoded in the exact external intent, validated before any recovery writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Jffs2EditOperation {
    /// Replace one single-named regular file with a fresh inode.
    Replace = 1,
    /// Relocate sole live references and erase one victim after durable COPIED.
    GarbageCollect = 2,
    /// Create one complete inode and its new native name.
    Create = 3,
    /// Publish destination and a final source-name tombstone, retaining native inode.
    Rename = 4,
    /// Publish one higher-version deletion tombstone.
    Unlink = 5,
    /// Publish a new hardlink to a reachable regular file or symlink.
    Link = 6,
    /// Replace a bounded regular-file range and publish final length without changing inode.
    FileRange = 7,
}
/// Independent parser, intent and working-buffer bounds.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2EditLimits {
    /// Complete underlying node scan bounds.
    pub read: Jffs2ReadLimits,
    /// Complete namespace audit bounds.
    pub audit: Jffs2AuditLimits,
    /// Maximum external intent bytes, including two 512-byte headers.
    pub journal_bytes: u64,
    /// Maximum appended records in one transaction.
    pub slots: usize,
    /// Maximum data payload per appended NONE inode, at most 32768.
    pub file_bytes: usize,
    /// Bounded full-image hashing/readback scratch, 128..32768 bytes.
    pub scratch_bytes: usize,
}
impl Jffs2EditLimits {
    fn validate(self) -> Result<()> {
        if self.file_bytes > 32768
            || !(128..=32768).contains(&self.scratch_bytes)
            || self.slots == 0
            || self.slots > u32::MAX as usize
            || self.journal_bytes < 1024
            || self.journal_bytes > usize::MAX as u64
        {
            return Err(invalid("JFFS2 edit limits"));
        }
        Ok(())
    }
    fn reserve(self, r: &Resources) -> Result<Reservation> {
        self.validate()?;
        r.memory.reserve(
            self.journal_bytes
                .checked_mul(3)
                .and_then(|n| n.checked_add(self.slots as u64 * 256 + 65536))
                .ok_or_else(|| cap("JFFS2 edit accounting overflow"))?,
        )
    }
}
#[derive(Clone, Copy)]
enum View {
    Actual,
    Baseline(bool),
    Copied,
    After,
}
struct Borrowed<'a> {
    flash: &'a dyn FlashStorage,
    length: u64,
    r: &'a Resources,
    intent: Option<&'a Intent>,
    view: View,
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
                "JFFS2 mutable backing length changed",
            ));
        }
        Ok(())
    }
    fn read(&self, p: u64, out: &mut [u8]) -> Result<()> {
        self.check(self.r)?;
        if p.checked_add(out.len() as u64)
            .is_none_or(|e| e > self.length)
        {
            return Err(invalid("JFFS2 borrowed read bounds"));
        }
        self.flash.read_exact_at(p, out, self.r)?;
        if let Some(i) = self.intent {
            for s in &i.slots {
                overlay(
                    out,
                    p,
                    s.offset,
                    &s.bytes,
                    matches!(self.view, View::Baseline(_)),
                );
            }
            if let Some((at, before)) = &i.victim {
                match self.view {
                    View::Baseline(true) | View::Copied => overlay(out, p, *at, before, false),
                    View::After => overlay(out, p, *at, before, true),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
fn overlay(out: &mut [u8], p: u64, at: u64, bytes: &[u8], erased: bool) {
    let a = p.max(at);
    let b = (p + out.len() as u64).min(at + bytes.len() as u64);
    if a < b {
        let dst = &mut out[(a - p) as usize..(b - p) as usize];
        if erased {
            dst.fill(255)
        } else {
            dst.copy_from_slice(&bytes[(a - at) as usize..(b - at) as usize])
        }
    }
}
fn view<'a>(flash: &'a dyn FlashStorage, i: &'a Intent, r: &'a Resources, v: View) -> Borrowed<'a> {
    Borrowed {
        flash,
        length: i.length,
        r,
        intent: Some(i),
        view: v,
    }
}
fn digest(source: &impl DecodeRead, l: Jffs2EditLimits, r: &Resources) -> Result<[u8; 32]> {
    let mut b = vec_bytes(l.scratch_bytes, 0)?;
    let mut h = Sha256::new();
    let mut p = 0;
    while p < source.length() {
        source.check(r)?;
        let n = (source.length() - p).min(b.len() as u64) as usize;
        source.read(p, &mut b[..n])?;
        h.update(&b[..n]);
        p += n as u64;
    }
    source.check(r)?;
    Ok(h.finalize().into())
}
fn inspect(
    source: &impl DecodeRead,
    g: FlashGeometry,
    e: Jffs2Endian,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<(Decoded, Jffs2AuditReport)> {
    inspect_profile(source, g, e, l, None, r)
}
fn inspect_profile(
    source: &impl DecodeRead,
    g: FlashGeometry,
    e: Jffs2Endian,
    l: Jffs2EditLimits,
    compression: Option<journal::CompressionProfile>,
    r: &Resources,
) -> Result<(Decoded, Jffs2AuditReport)> {
    let d = match compression {
        Some(profile) => {
            crate::fs_jffs2::decode_compressed(source, g, e, l.read, profile.limits, r)?
        }
        None => decode(source, g, e, l.read, r)?,
    };
    let a = audit_parts(
        AuditParts {
            inodes: &d.inodes,
            endian: e,
            erased: &d.erased,
            node_bytes: d.node_bytes,
            obsolete_bytes: d.obsolete_bytes,
        },
        l.audit,
        r,
        |r| source.check(r),
    )?;
    if !a.is_clean() {
        return Err(invalid(
            "JFFS2 edit requires complete clean namespace audit",
        ));
    }
    Ok((d, a))
}
fn inode(d: &Decoded, n: u32) -> Result<&Jffs2Inode> {
    d.inodes
        .binary_search_by_key(&n, |i| i.number)
        .map(|at| &d.inodes[at])
        .map_err(|_| invalid("JFFS2 edit absent inode"))
}
fn put(e: Jffs2Endian, b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&match e {
        Jffs2Endian::Little => v.to_le_bytes(),
        Jffs2Endian::Big => v.to_be_bytes(),
    });
}
fn word(e: Jffs2Endian, b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&match e {
        Jffs2Endian::Little => v.to_le_bytes(),
        Jffs2Endian::Big => v.to_be_bytes(),
    });
}
fn finish(e: Jffs2Endian, b: &mut [u8], kind: u16, len: usize) {
    word(e, b, 0, 0x1985);
    word(e, b, 2, kind);
    put(e, b, 4, len as u32);
    let c = crc(0, &b[..8]);
    put(e, b, 8, c);
    let c = crc(0, &b[..if kind == 0xe002 { 60 } else { 32 }]);
    put(e, b, if kind == 0xe002 { 64 } else { 32 }, c);
}
fn file_node(
    e: Jffs2Endian,
    old: &Jffs2Inode,
    n: u32,
    v: u32,
    payload: &[u8],
    timestamp: Option<u32>,
) -> Result<Vec<u8>> {
    let len = 68 + payload.len();
    let mut b = vec_bytes((len + 3) & !3, 255)?;
    b[..68].copy_from_slice(&old.raw);
    put(e, &mut b, 12, n);
    put(e, &mut b, 16, v);
    put(e, &mut b, 28, payload.len() as u32);
    put(e, &mut b, 44, 0);
    put(e, &mut b, 48, payload.len() as u32);
    put(e, &mut b, 52, payload.len() as u32);
    b[56] = 0;
    b[57] = 0;
    if let Some(t) = timestamp {
        put(e, &mut b, 36, t);
        put(e, &mut b, 40, t);
    }
    b[68..len].copy_from_slice(payload);
    put(e, &mut b, 60, crc(0, payload));
    finish(e, &mut b, 0xe002, len);
    Ok(b)
}
fn dirent(
    e: Jffs2Endian,
    parent: u32,
    n: u32,
    v: u32,
    time: u32,
    kind: u8,
    name: &[u8],
) -> Result<Vec<u8>> {
    if name.is_empty()
        || name.len() > 254
        || name.contains(&0)
        || name.contains(&b'/')
        || [b".".as_slice(), b".."].contains(&name)
    {
        return Err(invalid("JFFS2 edit native name"));
    }
    let len = 40 + name.len();
    let mut b = vec_bytes((len + 3) & !3, 255)?;
    b[..len].fill(0);
    put(e, &mut b, 12, parent);
    put(e, &mut b, 16, v);
    put(e, &mut b, 20, n);
    put(e, &mut b, 24, time);
    b[28] = name.len() as u8;
    b[29] = kind;
    b[40..len].copy_from_slice(name);
    put(e, &mut b, 36, crc(0, name));
    finish(e, &mut b, 0xe001, len);
    Ok(b)
}
fn allocate(
    d: &Decoded,
    records: Vec<Vec<u8>>,
    victim: Option<u64>,
    l: Jffs2EditLimits,
) -> Result<Vec<Slot>> {
    if (records.is_empty() && victim.is_none()) || records.len() > l.slots {
        return Err(cap("JFFS2 edit record cap"));
    }
    // Preflight every aligned record and the retained external intent before choosing
    // locations. The actual next-fit pass below accounts for unusable block tails.
    let erase = u64::from(d.geometry.erase_bytes);
    let capacity = erase
        .checked_sub(12)
        .ok_or_else(|| cap("JFFS2 edit erase capacity"))?;
    let mut retained = 1024u64;
    if victim.is_some() {
        retained = retained
            .checked_add(erase)
            .ok_or_else(|| cap("JFFS2 edit intent overflow"))?;
    }
    for bytes in &records {
        let length = bytes.len() as u64;
        if length < 12 || !length.is_multiple_of(4) || length > capacity {
            return Err(cap("JFFS2 edit aligned node exceeds erase block"));
        }
        retained = retained
            .checked_add(16)
            .and_then(|n| n.checked_add(length))
            .ok_or_else(|| cap("JFFS2 edit packed intent overflow"))?;
    }
    if retained > l.journal_bytes {
        return Err(cap("JFFS2 edit packed intent cap"));
    }
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(records.len())
        .map_err(|_| cap("JFFS2 edit slots"))?;
    let mut index = 0;
    let mut p = 0;
    for bytes in records {
        loop {
            let &(block, erase) = d
                .pristine
                .get(index)
                .ok_or_else(|| cap("JFFS2 edit pristine erase-block space"))?;
            if victim == Some(block) {
                index += 1;
                p = 0;
                continue;
            }
            let end = block
                .checked_add(erase)
                .ok_or_else(|| cap("JFFS2 edit block end overflow"))?;
            let start = block
                .checked_add(12)
                .ok_or_else(|| cap("JFFS2 edit block start overflow"))?;
            p = p.max(start);
            if bytes.len() as u64 > erase.saturating_sub(12) {
                return Err(cap("JFFS2 edit node exceeds erase block"));
            }
            let next = p
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| cap("JFFS2 edit packed end overflow"))?;
            if next <= end {
                slots.push(Slot { offset: p, bytes });
                p = next;
                break;
            }
            index += 1;
            p = 0;
        }
    }
    Ok(slots)
}
/// Exact bounded append/GC intent bound to one owned editor session.
pub struct Jffs2EditPlan {
    intent: Intent,
    scope: u128,
    resources: Resources,
}
impl Jffs2EditPlan {
    /// Minimum externally pre-sized journal length for this exact transaction.
    pub fn journal_length(&self) -> u64 {
        1024 + self
            .intent
            .slots
            .iter()
            .map(|s| 16 + s.bytes.len() as u64)
            .sum::<u64>()
            + self.intent.victim.as_ref().map_or(0, |v| v.1.len() as u64)
    }
    /// Exact namespace, replacement or GC operation encoded in the bound intent.
    pub fn operation(&self) -> Jffs2EditOperation {
        self.intent.operation
    }
    /// Whole-image hash expected after durable completion.
    pub fn expected_sha256(&self) -> [u8; 32] {
        self.intent.after
    }
}
/// Explicit supported metadata treatment; raw headers and allocation are not preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Jffs2EditMetadataOutcome {
    /// Mode, UID/GID, flags and access time survive; modification/change seconds replace.
    Replacement {
        /// Caller-selected unsigned Unix modification/change seconds.
        modification_change_seconds: u32,
    },
    /// Fresh native metadata is explicitly authored without source transplantation.
    Creation {
        /// Complete native type and permission mode.
        native_mode: u32,
        /// Native user ID.
        uid: u16,
        /// Native group ID.
        gid: u16,
        /// Access seconds.
        accessed: u32,
        /// Modification seconds.
        modified: u32,
        /// Change seconds.
        changed: u32,
    },
    /// Existing object metadata/payload remain intact; parent dirent timestamps update.
    Namespace {
        /// Explicit parent directory-entry modification/change seconds.
        parent_timestamp: u32,
    },
    /// Supported interpreted metadata survives GC; raw versions/headers change.
    Relocation,
}
/// Successful logical completion; physical power-loss behavior is not established.
#[derive(Debug)]
pub struct Jffs2EditReport {
    /// Exact complete target digest after readback and strict namespace audit.
    pub sha256: [u8; 32],
    /// Backend-reported accepted program/erase bytes.
    pub accepted_bytes: u64,
    /// Bytes compared by the flash backend after program/erase.
    pub verified_bytes: u64,
    /// Sticky uncertainty remains true even if logical recovery subsequently succeeds.
    pub mutation_uncertain: bool,
    /// Whether this transaction erased one victim after durable COPIED.
    pub garbage_collection: bool,
    /// Exact validated transaction operation.
    pub operation: Jffs2EditOperation,
    /// Explicit supported metadata transformation.
    pub metadata: Jffs2EditMetadataOutcome,
    /// Allocation shape is intentionally not preserved by these canonical complete nodes.
    pub allocation_shape_preserved: bool,
}
/// Causal failure retains known target progress; external intent enables roll-forward.
#[derive(Debug)]
pub struct Jffs2EditFailure {
    /// Framework error retaining underlying I/O diagnostics.
    pub source: Error,
    /// Target program/erase was attempted; hidden partial mutation is possible.
    pub mutation_attempted: bool,
    /// Backend-reported accepted target bytes.
    pub accepted_bytes: u64,
    /// Backend-verified target bytes.
    pub verified_bytes: u64,
    /// Sticky uncertainty requires reopening storage before a subsequent edit.
    pub mutation_uncertain: bool,
}
impl fmt::Display for Jffs2EditFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JFFS2 edit: {}", self.source)
    }
}
impl crate::platform::error::Error for Jffs2EditFailure {
    fn source(&self) -> Option<&(dyn crate::platform::error::Error + 'static)> {
        Some(&self.source)
    }
}
#[derive(Default)]
struct Progress {
    attempted: bool,
    accepted: u64,
    verified: u64,
}
impl Progress {
    fn failure(&self, source: Error, flash: &dyn FlashStorage) -> Jffs2EditFailure {
        Jffs2EditFailure {
            source,
            mutation_attempted: self.attempted,
            accepted_bytes: self.accepted,
            verified_bytes: self.verified,
            mutation_uncertain: flash.mutation_uncertain() || self.attempted,
        }
    }
    fn program(&mut self, f: &mut dyn FlashStorage, p: u64, b: &[u8], r: &Resources) -> Result<()> {
        self.attempted = true;
        match f.program(p, b, r) {
            Ok(v) => {
                self.accepted += v.accepted_bytes;
                self.verified += v.verified_bytes;
                Ok(())
            }
            Err(e) => {
                self.accepted += e.progress.accepted_bytes;
                self.verified += e.progress.verified_bytes;
                Err(e.source)
            }
        }
    }
    fn erase(&mut self, f: &mut dyn FlashStorage, p: u64, n: u64, r: &Resources) -> Result<()> {
        self.attempted = true;
        match f.erase(p, n, r) {
            Ok(v) => {
                self.accepted += v.accepted_bytes;
                self.verified += v.verified_bytes;
                Ok(())
            }
            Err(e) => {
                self.accepted += e.progress.accepted_bytes;
                self.verified += e.progress.verified_bytes;
                Err(e.source)
            }
        }
    }
}
/// Explicit supported compressed-history and deterministic regular-file authoring profile.
/// Metadata and symlinks remain NONE. Data falls back to NONE unless the selected
/// codec is smaller and fits the declared per-node caps; ZERO gaps remain compact.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2EditCompression {
    /// Selected deterministic RTIME or RFC1950 ZLIB authoring codec.
    pub codec: crate::fs_jffs2_builder::Jffs2BuildCompression,
    /// Per-node and aggregate complete-scan/deferred decoder bounds bound into recovery.
    pub read: crate::fs_jffs2::Jffs2CompressionLimits,
}
impl Jffs2EditCompression {
    fn native(self) -> journal::CompressionProfile {
        journal::CompressionProfile {
            codec: self.codec.native(),
            limits: self.read,
        }
    }
}
/// Exclusively owned mutable flash session; never implements immutable ReadAt.
pub struct Jffs2Editor<F: FlashStorage> {
    flash: F,
    compression: Option<journal::CompressionProfile>,
    decoded: Decoded,
    audit: Jffs2AuditReport,
    binding: [u8; 32],
    digest: [u8; 32],
    scope: u128,
    limits: Jffs2EditLimits,
    resources: Resources,
    stopped: bool,
    inode_floor: u32,
}
impl<F: FlashStorage> Jffs2Editor<F> {
    /// Inspect and audit exclusively owned clean logical NOR bytes before planning.
    pub fn open(
        flash: F,
        binding: [u8; 32],
        endian: Jffs2Endian,
        limits: Jffs2EditLimits,
        r: &Resources,
    ) -> Result<Self> {
        Self::open_profile(flash, binding, endian, limits, None, r)
    }
    /// Open clean supported compressed histories under explicit codec and decoder bounds.
    /// Existing strict open remains NONE/ZERO only. Recovery must use the identical profile.
    pub fn open_compressed(
        flash: F,
        binding: [u8; 32],
        endian: Jffs2Endian,
        limits: Jffs2EditLimits,
        compression: Jffs2EditCompression,
        r: &Resources,
    ) -> Result<Self> {
        Self::open_profile(
            flash,
            binding,
            endian,
            limits,
            Some(compression.native()),
            r,
        )
    }
    fn open_profile(
        flash: F,
        binding: [u8; 32],
        endian: Jffs2Endian,
        limits: Jffs2EditLimits,
        compression: Option<journal::CompressionProfile>,
        r: &Resources,
    ) -> Result<Self> {
        limits.validate()?;
        if let Some(profile) = compression {
            profile.validate()?;
        }
        if flash.mutation_uncertain() {
            return Err(invalid("JFFS2 reopen storage required after uncertainty"));
        }
        let source = Borrowed {
            flash: &flash,
            length: flash.len()?,
            r,
            intent: None,
            view: View::Actual,
        };
        let (decoded, audit) = match compression {
            Some(profile) => {
                inspect_profile(&source, flash.geometry(), endian, limits, Some(profile), r)?
            }
            None => inspect(&source, flash.geometry(), endian, limits, r)?,
        };
        let digest = digest(&source, limits, r)?;
        let scope = (13u128 << 64)
            | u128::from(
                NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                    .map_err(|_| cap("JFFS2 editor scope"))?,
            );
        let inode_floor = decoded.inodes.last().unwrap().number;
        Ok(Self {
            inode_floor,
            audit,
            flash,
            compression,
            decoded,
            binding,
            digest,
            scope,
            limits,
            resources: r.clone(),
            stopped: false,
        })
    }
    /// Release exclusively owned flash; no mutable aliases or deferred readers escape.
    pub fn into_flash(self) -> F {
        self.flash
    }
    /// Mutable-session identity; native generation includes namespace changes.
    pub fn identity(&self, number: u32) -> Result<ObjectId> {
        let at = self
            .decoded
            .inodes
            .binary_search_by_key(&number, |i| i.number)
            .map_err(|_| invalid("JFFS2 editor absent inode"))?;
        if !self.audit.reachable[at] {
            return Err(invalid("JFFS2 editor identity requires reachable object"));
        }
        let i = &self.decoded.inodes[at];
        Ok(ObjectId {
            source: self.scope,
            generation: u64::from(i.namespace_version()),
            native: copy(&number.to_le_bytes())?,
        })
    }
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.resources.cancellation.check()?;
        if self.stopped || self.flash.mutation_uncertain() {
            return Err(invalid(
                "JFFS2 stopped editor requires exact recovery and storage reopen",
            ));
        }
        if self.flash.len()? != self.decoded.length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFFS2 editor length changed",
            ));
        }
        Ok(())
    }
    fn number(&self, id: &ObjectId) -> Result<u32> {
        if id.native.len() != 4 {
            return Err(invalid("JFFS2 editor identity encoding"));
        }
        let n = u32::from_le_bytes(id.native.as_slice().try_into().unwrap());
        if self.identity(n)? != *id {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFFS2 editor identity changed",
            ));
        }
        Ok(n)
    }
    /// Plan replacement of one existing single-named regular file with one complete NONE node.
    /// Supported ownership/mode/flags/access time are preserved; modification/change time is explicit.
    pub fn replace(
        &self,
        parent: &ObjectId,
        name: &[u8],
        payload: &[u8],
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        if payload.len() > self.limits.file_bytes {
            return Err(cap("JFFS2 replacement payload cap"));
        }
        let lease = self.limits.reserve(r)?;
        let p = self.number(parent)?;
        let dir = inode(&self.decoded, p)?;
        let entry = dir
            .children
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| invalid("JFFS2 replacement requires existing name"))?;
        let old = inode(&self.decoded, entry.inode)?;
        if self.decoded.endian.dword(&old.raw, 20) & 0xf000 != 0x8000 {
            return Err(invalid("JFFS2 replacement requires regular file"));
        }
        let refs = self
            .decoded
            .inodes
            .iter()
            .flat_map(|i| &i.children)
            .filter(|e| e.inode == old.number)
            .count();
        if refs != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFFS2 replacement hardlink policy unsupported",
            ));
        }
        let n = self
            .inode_floor
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 new inode number overflow"))?;
        let v = dir
            .namespace_version()
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 directory version overflow"))?;
        let records = vec![
            file_node(self.decoded.endian, old, n, 1, payload, Some(timestamp))?,
            dirent(self.decoded.endian, p, n, v, timestamp, 8, name)?,
        ];
        let slots = allocate(&self.decoded, records, None, self.limits)?;
        self.plan(slots, None, Jffs2EditOperation::Replace, lease, r)
    }
    fn plan(
        &self,
        slots: Vec<Slot>,
        victim: Option<(u64, Vec<u8>)>,
        operation: Jffs2EditOperation,
        lease: Reservation,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        let mut i = Intent {
            compression: self.compression,
            length: self.decoded.length,
            geometry: self.decoded.geometry,
            endian: self.decoded.endian,
            binding: self.binding,
            inode_floor: self.inode_floor,
            operation,
            before: self.digest,
            copied: [0; 32],
            after: [0; 32],
            slots,
            victim,
            state: State::Prepared,
            sequence: 0,
            _lease: lease,
        };
        if let Some(profile) = i.compression {
            compression_edit::encode_slots(&mut i.slots, i.endian, profile, &self.resources, r)?;
        }
        let base = view(&self.flash, &i, r, View::Baseline(false));
        if digest(&base, self.limits, r)? != i.before {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFFS2 editor baseline changed",
            ));
        }
        i.copied = digest(&view(&self.flash, &i, r, View::Copied), self.limits, r)?;
        i.after = digest(&view(&self.flash, &i, r, View::After), self.limits, r)?;
        validate(&self.flash, &i, self.limits, r, false)?;
        self.check(r)?;
        let plan = Jffs2EditPlan {
            intent: i,
            scope: self.scope,
            resources: r.clone(),
        };
        if plan.journal_length() > self.limits.journal_bytes {
            return Err(cap("JFFS2 planned journal cap"));
        }
        Ok(plan)
    }
    /// Durably journal, append, verify and publish one preflighted exact transaction.
    pub fn commit(
        &mut self,
        mut plan: Jffs2EditPlan,
        journal: &mut dyn Storage,
        r: &Resources,
    ) -> crate::platform::result::Result<Jffs2EditReport, Jffs2EditFailure> {
        let mut progress = Progress::default();
        let result = (|| {
            self.check(r)?;
            plan.resources.cancellation.check()?;
            if plan.scope != self.scope || plan.intent.before != self.digest {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 plan belongs to another state/session",
                ));
            }
            validate(&self.flash, &plan.intent, self.limits, r, false)?;
            self.check(r)?;
            journal::prepare(journal, &mut plan.intent, self.limits, r)?;
            execute(
                &mut self.flash,
                journal,
                &mut plan.intent,
                self.limits,
                r,
                &mut progress,
                || {
                    self.resources.cancellation.check()?;
                    plan.resources.cancellation.check()
                },
            )?;
            let source = Borrowed {
                flash: &self.flash,
                length: self.decoded.length,
                r,
                intent: None,
                view: View::Actual,
            };
            let (d, audit) = inspect_profile(
                &source,
                self.decoded.geometry,
                self.decoded.endian,
                self.limits,
                self.compression,
                r,
            )?;
            self.inode_floor = self.inode_floor.max(d.inodes.last().unwrap().number);
            self.decoded = d;
            self.audit = audit;
            self.digest = plan.intent.after;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(report(&self.flash, &plan.intent, &progress)),
            Err(e) => {
                self.stopped = true;
                Err(progress.failure(e, &self.flash))
            }
        }
    }
}
fn report(f: &dyn FlashStorage, i: &Intent, p: &Progress) -> Jffs2EditReport {
    Jffs2EditReport {
        sha256: i.after,
        accepted_bytes: p.accepted,
        verified_bytes: p.verified,
        mutation_uncertain: f.mutation_uncertain(),
        garbage_collection: i.victim.is_some(),
        operation: i.operation,
        metadata: match i.operation {
            Jffs2EditOperation::GarbageCollect => Jffs2EditMetadataOutcome::Relocation,
            Jffs2EditOperation::Replace | Jffs2EditOperation::FileRange => {
                Jffs2EditMetadataOutcome::Replacement {
                    modification_change_seconds: i.endian.dword(&i.slots[0].bytes, 36),
                }
            }
            Jffs2EditOperation::Create => {
                let b = &i.slots[0].bytes;
                Jffs2EditMetadataOutcome::Creation {
                    native_mode: i.endian.dword(b, 20),
                    uid: i.endian.word(b, 24),
                    gid: i.endian.word(b, 26),
                    accessed: i.endian.dword(b, 32),
                    modified: i.endian.dword(b, 36),
                    changed: i.endian.dword(b, 40),
                }
            }
            Jffs2EditOperation::Rename | Jffs2EditOperation::Unlink | Jffs2EditOperation::Link => {
                Jffs2EditMetadataOutcome::Namespace {
                    parent_timestamp: i.endian.dword(&i.slots.last().unwrap().bytes, 24),
                }
            }
        },
        allocation_shape_preserved: false,
    }
}
/// Recover only the exact caller-bound external intent; legal NOR replay never restores cleared bits.
/// Ordinary strict open may reject torn appends until this roll-forward completes.
/// Sticky uncertainty remains reported and requires storage reopen before subsequent editing.
pub fn recover(
    flash: &mut dyn FlashStorage,
    journal: &mut dyn Storage,
    binding: [u8; 32],
    endian: Jffs2Endian,
    limits: Jffs2EditLimits,
    r: &Resources,
) -> crate::platform::result::Result<Jffs2EditReport, Jffs2EditFailure> {
    recover_profile(flash, journal, binding, endian, limits, None, r)
}
/// Recover an exact version-2 compressed intent with the identical caller codec and caps.
/// Profile mismatch or strict recovery rejection leaves target and journal untouched.
pub fn recover_compressed(
    flash: &mut dyn FlashStorage,
    journal: &mut dyn Storage,
    binding: [u8; 32],
    endian: Jffs2Endian,
    limits: Jffs2EditLimits,
    compression: Jffs2EditCompression,
    r: &Resources,
) -> crate::platform::result::Result<Jffs2EditReport, Jffs2EditFailure> {
    recover_profile(
        flash,
        journal,
        binding,
        endian,
        limits,
        Some(compression.native()),
        r,
    )
}
fn recover_profile(
    flash: &mut dyn FlashStorage,
    journal: &mut dyn Storage,
    binding: [u8; 32],
    endian: Jffs2Endian,
    limits: Jffs2EditLimits,
    compression: Option<journal::CompressionProfile>,
    r: &Resources,
) -> crate::platform::result::Result<Jffs2EditReport, Jffs2EditFailure> {
    let mut p = Progress::default();
    let result = (|| {
        limits.validate()?;
        let mut i = match compression {
            Some(profile) => journal::load_profile(
                journal,
                binding,
                flash.geometry(),
                endian,
                flash.len()?,
                limits,
                Some(profile),
                r,
            )?,
            None => journal::load(
                journal,
                binding,
                flash.geometry(),
                endian,
                flash.len()?,
                limits,
                r,
            )?,
        };
        if i.state == State::Complete {
            validate(flash, &i, limits, r, i.victim.is_some())?;
            if digest(
                &Borrowed {
                    flash,
                    length: i.length,
                    r,
                    intent: None,
                    view: View::Actual,
                },
                limits,
                r,
            )? != i.after
            {
                return Err(invalid("JFFS2 complete intent actual digest mismatch"));
            }
            inspect_profile(
                &Borrowed {
                    flash,
                    length: i.length,
                    r,
                    intent: None,
                    view: View::Actual,
                },
                i.geometry,
                endian,
                limits,
                i.compression,
                r,
            )?;
            return Ok(i);
        }
        validate(flash, &i, limits, r, i.state == State::Copied)?;
        execute(flash, journal, &mut i, limits, r, &mut p, || {
            r.cancellation.check()
        })?;
        Ok(i)
    })();
    match result {
        Ok(i) => Ok(report(flash, &i, &p)),
        Err(e) => Err(p.failure(e, flash)),
    }
}
fn replay_compatible(
    f: &dyn FlashStorage,
    i: &Intent,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    let mut b = vec_bytes(l.scratch_bytes, 0)?;
    for s in &i.slots {
        let mut done = 0;
        while done < s.bytes.len() {
            r.cancellation.check()?;
            let n = (s.bytes.len() - done).min(b.len());
            f.read_exact_at(s.offset + done as u64, &mut b[..n], r)?;
            if b[..n]
                .iter()
                .zip(&s.bytes[done..done + n])
                .any(|(a, e)| a & e != *e)
            {
                return Err(invalid(
                    "JFFS2 observed bits incompatible with exact NOR replay",
                ));
            }
            done += n;
        }
    }
    Ok(())
}
fn erase_compatible(
    f: &dyn FlashStorage,
    i: &Intent,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    let Some((at, before)) = &i.victim else {
        return Err(invalid("JFFS2 copied intent without victim"));
    };
    let mut scratch = vec_bytes(l.scratch_bytes, 0)?;
    let mut done = 0;
    while done < before.len() {
        r.cancellation.check()?;
        let n = (before.len() - done).min(scratch.len());
        f.read_exact_at(*at + done as u64, &mut scratch[..n], r)?;
        if scratch[..n]
            .iter()
            .zip(&before[done..done + n])
            .any(|(observed, old)| observed & old != *old)
        {
            return Err(invalid("JFFS2 GC victim incompatible with partial erase"));
        }
        done += n;
    }
    Ok(())
}
fn validate(
    f: &dyn FlashStorage,
    i: &Intent,
    l: Jffs2EditLimits,
    r: &Resources,
    mask_victim: bool,
) -> Result<()> {
    if (i.operation == Jffs2EditOperation::GarbageCollect) != i.victim.is_some() {
        return Err(invalid("JFFS2 GC operation/victim mismatch"));
    }
    let baseline = view(f, i, r, View::Baseline(mask_victim));
    if digest(&baseline, l, r)? != i.before {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFFS2 intent baseline/outside ranges changed",
        ));
    }
    let (b, a) = inspect_profile(&baseline, i.geometry, i.endian, l, i.compression, r)?;
    if i.inode_floor < b.inodes.last().unwrap().number {
        return Err(invalid("JFFS2 intent inode floor regressed"));
    }
    for s in &i.slots {
        let at = b.pristine.partition_point(|(p, _)| *p <= s.offset);
        if at == 0 || {
            let (p, n) = b.pristine[at - 1];
            s.offset < p + 12 || s.offset + s.bytes.len() as u64 > p + n
        } {
            return Err(invalid("JFFS2 intent does not occupy pristine space"));
        }
    }
    if mask_victim {
        erase_compatible(f, i, l, r)?;
    }
    replay_compatible(f, i, l, r)?;
    let copied = view(f, i, r, View::Copied);
    let after = view(f, i, r, View::After);
    if digest(&copied, l, r)? != i.copied || digest(&after, l, r)? != i.after {
        return Err(invalid("JFFS2 expected intent image digest"));
    }
    let (c, ca) = inspect_profile(&copied, i.geometry, i.endian, l, i.compression, r)?;
    let (end, ea) = inspect_profile(&after, i.geometry, i.endian, l, i.compression, r)?;
    if let Some(victim) = i.victim.as_ref().map(|v| v.0) {
        same_namespace(&b, &a, &baseline, &c, &ca, &copied, l, r)?;
        same_namespace(&b, &a, &baseline, &end, &ea, &after, l, r)?;
        no_victim_references(&c, &ca, victim, u64::from(i.geometry.erase_bytes))?;
        validate_gc_nodes(i, &b, &a, l, r)?;
    } else {
        if i.operation == Jffs2EditOperation::Replace {
            validate_replace(i, &b, &c, l)?;
        } else if i.operation == Jffs2EditOperation::FileRange {
            file_edit::validate(i, &b, &a, &c, &ca, &baseline, &after, l, r)?;
        } else {
            namespace::validate(i, &b, &a, &c, &ca, l)?;
        }
    }
    Ok(())
}
fn validate_replace(i: &Intent, b: &Decoded, c: &Decoded, l: Jffs2EditLimits) -> Result<()> {
    if i.slots.len() != 2 {
        return Err(invalid("JFFS2 replacement intent record count"));
    }
    let f = &i.slots[0].bytes;
    let d = &i.slots[1].bytes;
    let e = i.endian;
    if f.len() < 68 || d.len() < 40 || e.word(f, 2) != 0xe002 || e.word(d, 2) != 0xe001 {
        return Err(invalid("JFFS2 replacement intent node types"));
    }
    let size = e.dword(f, 28) as usize;
    let encoded = e.dword(f, 48) as usize;
    let name_len = d[28] as usize;
    if size > l.file_bytes
        || f.len() != ((68 + encoded + 3) & !3)
        || e.dword(f, 4) as usize != 68 + encoded
        || d.len() != ((40 + name_len + 3) & !3)
        || e.dword(d, 4) as usize != 40 + name_len
        || name_len == 0
        || e.dword(f, 44) != 0
        || e.dword(f, 52) as usize != size
        || !compression_edit::data_shape(i.compression, f[56], encoded, size, l.file_bytes)
        || f[57] != 0
        || e.dword(f, 16) != 1
    {
        return Err(invalid("JFFS2 replacement intent complete node profile"));
    }
    let parent = inode(b, e.dword(d, 12))?;
    let name = &d[40..40 + name_len];
    let entry = parent
        .children
        .iter()
        .find(|ent| ent.name == name)
        .ok_or_else(|| invalid("JFFS2 recovery publication name absent"))?;
    let old = inode(b, entry.inode)?;
    if b.endian.dword(&old.raw, 20) & 0xf000 != 0x8000
        || b.inodes
            .iter()
            .flat_map(|n| &n.children)
            .filter(|ent| ent.inode == old.number)
            .count()
            != 1
    {
        return Err(invalid("JFFS2 recovery regular single-name policy"));
    }
    if i.inode_floor < b.inodes.last().unwrap().number {
        return Err(invalid("JFFS2 intent inode floor regressed"));
    }
    let fresh = i
        .inode_floor
        .checked_add(1)
        .ok_or_else(|| cap("JFFS2 recovery inode overflow"))?;
    if e.dword(f, 12) != fresh
        || e.dword(d, 20) != fresh
        || e.dword(d, 16)
            != parent
                .namespace_version()
                .checked_add(1)
                .ok_or_else(|| cap("JFFS2 recovery namespace version"))?
        || d[29] != 8
        || f[20..28] != old.raw[20..28]
        || f[32..36] != old.raw[32..36]
        || f[58..60] != old.raw[58..60]
        || e.dword(f, 36) != e.dword(f, 40)
        || e.dword(d, 24) != e.dword(f, 36)
    {
        return Err(invalid("JFFS2 recovery replacement semantic intent"));
    }
    // No baseline inode metadata or unselected name may be changed by this intent.
    for old in &b.inodes {
        let new = inode(c, old.number)?;
        if old.raw != new.raw || old.children.len() != new.children.len() {
            return Err(invalid("JFFS2 replacement changed unrelated metadata"));
        }
        for (x, y) in old.children.iter().zip(&new.children) {
            let expected = if old.number == parent.number && x.name == name {
                fresh
            } else {
                x.inode
            };
            if x.name != y.name || expected != y.inode || x.file_type != y.file_type {
                return Err(invalid("JFFS2 replacement changed unrelated namespace"));
            }
        }
    }
    Ok(())
}
fn effective(i: &Jffs2Inode, e: Jffs2Endian, p: usize) -> u32 {
    if p == 36 || p == 40 {
        i.dir_time.map(|(_, t)| t).unwrap_or(e.dword(&i.raw, p))
    } else {
        e.dword(&i.raw, p)
    }
}
#[allow(clippy::too_many_arguments)]
fn same_content(
    bd: &Decoded,
    cd: &Decoded,
    old: &Jffs2Inode,
    new: &Jffs2Inode,
    bs: &impl DecodeRead,
    cs: &impl DecodeRead,
    l: Jffs2EditLimits,
    r: &Resources,
    work: &mut u64,
    codec_work: &mut u64,
) -> Result<()> {
    let mut left = vec_bytes(l.scratch_bytes, 0)?;
    let mut right = vec_bytes(l.scratch_bytes, 0)?;
    let mut a = 0;
    let mut b = 0;
    let mut at = 0u64;
    while a < old.map.len() && b < new.map.len() {
        bs.check(r)?;
        cs.check(r)?;
        let x = old.map[a];
        let y = new.map[b];
        let end = (x.offset + x.length).min(y.offset + y.length);
        if x.offset > at || y.offset > at || end <= at {
            return Err(invalid("JFFS2 GC logical map gap"));
        }
        *work = work
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 GC comparison work overflow"))?;
        if *work > l.read.work {
            return Err(cap("JFFS2 GC comparison work cap"));
        }
        let xkind = match x.kind {
            ExtentKind::Data(p) => ExtentKind::Data(p + at - x.offset),
            k => k,
        };
        let ykind = match y.kind {
            ExtentKind::Data(p) => ExtentKind::Data(p + at - y.offset),
            k => k,
        };
        let virtual_mapping =
            |kind: ExtentKind| matches!(kind, ExtentKind::Data(p) if p & (1 << 63) != 0);
        // Scan-order registry indexes cannot establish equality across views.
        if xkind != ykind || virtual_mapping(xkind) || virtual_mapping(ykind) {
            let mut done = 0;
            while done < end - at {
                bs.check(r)?;
                cs.check(r)?;
                *work = work
                    .checked_add(1)
                    .ok_or_else(|| cap("JFFS2 GC comparison work overflow"))?;
                if *work > l.read.work {
                    return Err(cap("JFFS2 GC comparison work cap"));
                }
                let n = (end - at - done).min(left.len() as u64) as usize;
                match xkind {
                    ExtentKind::Data(p) => match &bd.codecs {
                        Some(registry) => {
                            registry.read_mapping(bs, p + done, &mut left[..n], r, codec_work)?
                        }
                        None => bs.read(p + done, &mut left[..n])?,
                    },
                    _ => left[..n].fill(0),
                }
                match ykind {
                    ExtentKind::Data(p) => match &cd.codecs {
                        Some(registry) => {
                            registry.read_mapping(cs, p + done, &mut right[..n], r, codec_work)?
                        }
                        None => cs.read(p + done, &mut right[..n])?,
                    },
                    _ => right[..n].fill(0),
                }
                if left[..n] != right[..n] {
                    return Err(invalid("JFFS2 GC changed logical bytes"));
                }
                done += n as u64;
            }
        }
        at = end;
        if at == x.offset + x.length {
            a += 1;
        }
        if at == y.offset + y.length {
            b += 1;
        }
    }
    if a != old.map.len() || b != new.map.len() {
        return Err(invalid("JFFS2 GC unequal logical coverage"));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn same_namespace(
    b: &Decoded,
    ba: &Jffs2AuditReport,
    bs: &impl DecodeRead,
    c: &Decoded,
    ca: &Jffs2AuditReport,
    cs: &impl DecodeRead,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    if ba.reachable_inodes() != ca.reachable_inodes() {
        return Err(invalid("JFFS2 GC changed reachable inode count"));
    }
    let mut work = 0;
    let mut codec_work = 0;
    for (at, old) in b.inodes.iter().enumerate() {
        if !ba.reachable[at] {
            continue;
        }
        let pos = c
            .inodes
            .binary_search_by_key(&old.number, |i| i.number)
            .map_err(|_| invalid("JFFS2 GC lost native inode"))?;
        if !ca.reachable[pos] {
            return Err(invalid("JFFS2 GC lost inode reachability"));
        }
        let new = &c.inodes[pos];
        if old.raw[20..36] != new.raw[20..36]
            || old.raw[58..60] != new.raw[58..60]
            || effective(old, b.endian, 36) != effective(new, c.endian, 36)
            || effective(old, b.endian, 40) != effective(new, c.endian, 40)
            || old.children.len() != new.children.len()
        {
            return Err(invalid("JFFS2 GC changed supported metadata"));
        }
        for (x, y) in old.children.iter().zip(&new.children) {
            if x.name != y.name || x.inode != y.inode || x.file_type != y.file_type {
                return Err(invalid("JFFS2 GC changed native namespace"));
            }
        }
        same_content(b, c, old, new, bs, cs, l, r, &mut work, &mut codec_work)?;
    }
    Ok(())
}
fn no_victim_references(d: &Decoded, a: &Jffs2AuditReport, p: u64, n: u64) -> Result<()> {
    let inside = |at: u64| at >= p && at < p + n;
    for (at, i) in d.inodes.iter().enumerate() {
        if !a.reachable[at] {
            continue;
        }
        if i.header_offset.is_some_and(inside)
            || i.children
                .iter()
                .chain(&i.deleted)
                .any(|e| inside(e.node_offset()))
        {
            return Err(invalid("JFFS2 GC victim retains sole live references"));
        }
        for extent in &i.map {
            if let ExtentKind::Data(at) = extent.kind {
                let certificate = d
                    .codecs
                    .as_ref()
                    .map(|registry| registry.resolve(at))
                    .transpose()?
                    .flatten();
                let (start, end) = match certificate {
                    Some((node, _)) => (
                        node.physical
                            .checked_sub(68)
                            .ok_or_else(|| invalid("JFFS2 codec node header dependency"))?,
                        node.physical
                            .checked_add(u64::from(node.encoded))
                            .ok_or_else(|| invalid("JFFS2 codec node dependency overflow"))?,
                    ),
                    None => (
                        at,
                        at.checked_add(extent.length)
                            .ok_or_else(|| invalid("JFFS2 data dependency overflow"))?,
                    ),
                };
                if start < p + n && end > p {
                    return Err(invalid("JFFS2 GC victim retains sole live references"));
                }
            }
        }
    }
    Ok(())
}
fn validate_gc_nodes(
    i: &Intent,
    b: &Decoded,
    a: &Jffs2AuditReport,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    let e = i.endian;
    let mut seen_nodes = Vec::new();
    let mut seen_names = Vec::new();
    seen_nodes
        .try_reserve_exact(i.slots.len())
        .map_err(|_| cap("JFFS2 GC node validation"))?;
    seen_names
        .try_reserve_exact(i.slots.len())
        .map_err(|_| cap("JFFS2 GC name validation"))?;
    for (slot_index, slot) in i.slots.iter().enumerate() {
        let bytes = &slot.bytes;
        match e.word(bytes, 2) {
            0xe002 => {
                if bytes.len() < 68 {
                    return Err(invalid("JFFS2 short GC inode"));
                }
                let n = e.dword(bytes, 12);
                let old = inode(b, n)?;
                let index = b.inodes.binary_search_by_key(&n, |i| i.number).unwrap();
                let size = e.dword(bytes, 28) as usize;
                let kind = e.dword(&old.raw, 20) & 0xf000;
                if kind == 0x8000 {
                    if !a.reachable[index] {
                        return Err(invalid("JFFS2 GC unreachable regular inode"));
                    }
                    seen_nodes.push((n, slot_index));
                    continue;
                }
                if !a.reachable[index]
                    || ![0x4000, 0x8000, 0xa000].contains(&kind)
                    || (kind == 0x8000 && size > l.file_bytes)
                    || (kind == 0xa000 && !(1..=254).contains(&size))
                    || bytes.len() != ((68 + size + 3) & !3)
                    || e.dword(bytes, 4) as usize != 68 + size
                    || e.dword(bytes, 44) != 0
                    || e.dword(bytes, 48) as usize != size
                    || e.dword(bytes, 52) as usize != size
                    || bytes[56] != 0
                    || bytes[57] != 0
                    || e.dword(bytes, 16)
                        != old
                            .namespace_version()
                            .checked_add(1)
                            .ok_or_else(|| cap("JFFS2 GC inode version"))?
                {
                    return Err(invalid("JFFS2 GC inode semantic profile"));
                }
                seen_nodes.push((n, slot_index));
            }
            0xe001 => {
                if bytes.len() < 40 {
                    return Err(invalid("JFFS2 short GC dirent"));
                }
                let parent = inode(b, e.dword(bytes, 12))?;
                let index = b
                    .inodes
                    .binary_search_by_key(&parent.number, |i| i.number)
                    .unwrap();
                let len = bytes[28] as usize;
                if !a.reachable[index]
                    || len == 0
                    || bytes.len() != ((40 + len + 3) & !3)
                    || e.dword(bytes, 4) as usize != 40 + len
                {
                    return Err(invalid("JFFS2 GC dirent bounds"));
                }
                let name = &bytes[40..40 + len];
                let old = parent
                    .children
                    .binary_search_by(|ent| ent.name.as_slice().cmp(name))
                    .ok()
                    .map(|at| &parent.children[at])
                    .or_else(|| {
                        parent
                            .deleted
                            .binary_search_by(|ent| ent.name.as_slice().cmp(name))
                            .ok()
                            .map(|at| &parent.deleted[at])
                    })
                    .ok_or_else(|| invalid("JFFS2 GC new name forbidden"))?;
                if e.dword(bytes, 20) != old.inode
                    || bytes[29] != old.file_type
                    || e.dword(bytes, 24) != effective(parent, e, 36)
                    || e.dword(bytes, 16) <= parent.namespace_version()
                {
                    return Err(invalid("JFFS2 GC dirent semantics"));
                }
                seen_names.push((parent.number, copy(name)?));
            }
            _ => return Err(invalid("JFFS2 GC unsupported record")),
        }
    }
    // Sorting charges bounded inventory, avoiding quadratic duplicate native-name checks.
    let victim = i
        .victim
        .as_ref()
        .ok_or_else(|| invalid("JFFS2 GC absent victim"))?
        .0;
    let _dependency_lease = r.memory.reserve(b.inode_nodes.len() as u64 * 4)?;
    let mut required = Vec::new();
    required
        .try_reserve_exact(b.inode_nodes.len())
        .map_err(|_| cap("JFFS2 GC dependency validation"))?;
    for &(number, physical) in &b.inode_nodes {
        r.cancellation.check()?;
        if physical >= victim && physical < victim + u64::from(i.geometry.erase_bytes) {
            required.push(number);
        }
    }
    required.sort_unstable();
    required.dedup();
    seen_nodes.sort_unstable();
    for number in &required {
        let index = b
            .inodes
            .binary_search_by_key(number, |n| n.number)
            .map_err(|_| invalid("JFFS2 GC absent required inode"))?;
        if a.reachable[index]
            && seen_nodes
                .binary_search_by_key(number, |(n, _)| *n)
                .is_err()
        {
            return Err(invalid("JFFS2 GC missing required live inode group"));
        }
    }
    let mut start = 0;
    while start < seen_nodes.len() {
        let number = seen_nodes[start].0;
        let mut stop = start + 1;
        while stop < seen_nodes.len() && seen_nodes[stop].0 == number {
            stop += 1;
        }
        let old = inode(b, number)?;
        if e.dword(&old.raw, 20) & 0xf000 == 0x8000 {
            gc_edit::validate_regular(i, old, &seen_nodes[start..stop], l)?;
        } else if stop - start != 1 {
            return Err(invalid("JFFS2 duplicate GC special inodes"));
        }
        start = stop;
    }
    seen_names.sort_unstable();
    if seen_names.windows(2).any(|w| w[0] == w[1]) {
        return Err(invalid("JFFS2 duplicate GC names"));
    }
    Ok(())
}
fn actual_slot(f: &dyn FlashStorage, s: &Slot, l: Jffs2EditLimits, r: &Resources) -> Result<()> {
    let mut b = vec_bytes(l.scratch_bytes, 0)?;
    let mut done = 0;
    while done < s.bytes.len() {
        let n = (s.bytes.len() - done).min(b.len());
        f.read_exact_at(s.offset + done as u64, &mut b[..n], r)?;
        if b[..n] != s.bytes[done..done + n] {
            return Err(invalid("JFFS2 append exact readback mismatch"));
        }
        done += n;
    }
    Ok(())
}
fn flash_flush(f: &mut dyn FlashStorage, r: &Resources) -> Result<()> {
    f.flush(r).map_err(|e| e.source)
}
#[allow(clippy::too_many_arguments)]
fn execute(
    f: &mut dyn FlashStorage,
    j: &mut dyn Storage,
    i: &mut Intent,
    l: Jffs2EditLimits,
    r: &Resources,
    p: &mut Progress,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    check()?;
    replay_compatible(f, i, l, r)?;
    for (index, s) in i.slots.iter().enumerate() {
        if i.victim.is_none() && index == i.slots.len() - 1 {
            check()?;
            flash_flush(f, r)?;
            for prior in &i.slots[..index] {
                actual_slot(f, prior, l, r)?;
            }
        }
        check()?;
        p.program(f, s.offset + 12, &s.bytes[12..], r)?;
        check()?;
        p.program(f, s.offset, &s.bytes[..12], r)?;
        actual_slot(f, s, l, r)?;
    }
    check()?;
    flash_flush(f, r)?;
    if let Some(victim) = i.victim.as_ref().map(|v| v.0) {
        if i.state == State::Prepared {
            let source = Borrowed {
                flash: f,
                length: i.length,
                r,
                intent: None,
                view: View::Actual,
            };
            if digest(&source, l, r)? != i.copied {
                return Err(invalid("JFFS2 GC actual copied digest"));
            }
            let (d, a) = inspect_profile(&source, i.geometry, i.endian, l, i.compression, r)?;
            no_victim_references(&d, &a, victim, u64::from(i.geometry.erase_bytes))?;
            check()?;
            journal::mark(j, i, State::Copied, l, r)?;
        }
        // Durable COPIED alone permits a partially erased victim to be masked and finished.
        validate(f, i, l, r, true)?;
        check()?;
        p.erase(f, victim, u64::from(i.geometry.erase_bytes), r)?;
        check()?;
        flash_flush(f, r)?;
    }
    let actual = Borrowed {
        flash: f,
        length: i.length,
        r,
        intent: None,
        view: View::Actual,
    };
    if digest(&actual, l, r)? != i.after {
        return Err(invalid("JFFS2 actual completed digest"));
    }
    inspect_profile(&actual, i.geometry, i.endian, l, i.compression, r)?;
    check()?;
    journal::mark(j, i, State::Complete, l, r)?;
    Ok(())
}
impl<F: FlashStorage> Jffs2Editor<F> {
    /// Relocate all sole live dependencies of one victim, then durably authorize its erase.
    /// Regular files use bounded NONE/ZERO groups; supported complete symlink nodes relocate.
    /// Native inode numbers, names, hardlinks and interpreted metadata survive; raw versions
    /// and physical allocation change. Physical NAND/hardware GC is unsupported.
    pub fn collect(&self, victim: u64, r: &Resources) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        let lease = self.limits.reserve(r)?;
        let erase = u64::from(self.decoded.geometry.erase_bytes);
        if !victim.is_multiple_of(erase)
            || victim
                .checked_add(erase)
                .is_none_or(|e| e > self.decoded.length)
        {
            return Err(invalid("JFFS2 GC victim bounds"));
        }
        if self.decoded.pristine.iter().any(|(p, _)| *p == victim) {
            return Err(invalid("JFFS2 GC victim is already pristine"));
        }
        let source = Borrowed {
            flash: &self.flash,
            length: self.decoded.length,
            r: &self.resources,
            intent: None,
            view: View::Actual,
        };
        let (_, audit) = inspect_profile(
            &source,
            self.decoded.geometry,
            self.decoded.endian,
            self.limits,
            self.compression,
            r,
        )?;
        let mut dependency = Vec::new();
        dependency
            .try_reserve_exact(self.decoded.inode_nodes.len())
            .map_err(|_| cap("JFFS2 GC inode dependency allocation"))?;
        for &(number, p) in &self.decoded.inode_nodes {
            if p >= victim && p < victim + erase {
                dependency.push(number);
            }
        }
        dependency.sort_unstable();
        dependency.dedup();
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.limits.slots)
            .map_err(|_| cap("JFFS2 GC record allocation"))?;
        let mut retained = 1024 + erase;
        let mut add = |bytes: Vec<u8>| -> Result<()> {
            if records.len() >= self.limits.slots {
                return Err(cap("JFFS2 GC record cap"));
            }
            retained = retained
                .checked_add(16 + bytes.len() as u64)
                .ok_or_else(|| cap("JFFS2 GC intent overflow"))?;
            if retained > self.limits.journal_bytes {
                return Err(cap("JFFS2 GC journal cap"));
            }
            records.push(bytes);
            Ok(())
        };
        let mut codec_work = 0u64;
        for (at, old) in self.decoded.inodes.iter().enumerate() {
            if !audit.reachable[at] || dependency.binary_search(&old.number).is_err() {
                continue;
            }
            let kind = self.decoded.endian.dword(&old.raw, 20) & 0xf000;
            let size = self.decoded.endian.dword(&old.raw, 28) as usize;
            if kind == 0x8000 {
                gc_edit::emit_regular(
                    &self.decoded,
                    old,
                    self.decoded.endian,
                    &source,
                    &mut codec_work,
                    self.limits,
                    r,
                    self.decoded.geometry.erase_bytes,
                    &mut add,
                )?;
                continue;
            }
            let mut payload = vec_bytes(size, 0)?;
            for m in &old.map {
                if let ExtentKind::Data(p) = m.kind {
                    source.read(
                        p,
                        &mut payload[m.offset as usize..(m.offset + m.length) as usize],
                    )?;
                }
            }
            let v = old
                .namespace_version()
                .checked_add(1)
                .ok_or_else(|| cap("JFFS2 GC node version overflow"))?;
            let mut node = file_node(self.decoded.endian, old, old.number, v, &payload, None)?;
            if kind == 0x4000 {
                put(
                    self.decoded.endian,
                    &mut node,
                    36,
                    effective(old, self.decoded.endian, 36),
                );
                put(
                    self.decoded.endian,
                    &mut node,
                    40,
                    effective(old, self.decoded.endian, 40),
                );
                finish(self.decoded.endian, &mut node, 0xe002, 68);
            }
            add(node)?;
        }
        for (at, parent) in self.decoded.inodes.iter().enumerate() {
            if !audit.reachable[at] {
                continue;
            }
            let mut version = parent
                .namespace_version()
                .checked_add(1)
                .ok_or_else(|| cap("JFFS2 GC directory version overflow"))?;
            for ent in parent.children.iter().chain(&parent.deleted) {
                if ent.node_offset() < victim || ent.node_offset() >= victim + erase {
                    continue;
                }
                version = version
                    .checked_add(1)
                    .ok_or_else(|| cap("JFFS2 GC dirent version overflow"))?;
                add(dirent(
                    self.decoded.endian,
                    parent.number,
                    ent.inode,
                    version,
                    effective(parent, self.decoded.endian, 36),
                    ent.file_type,
                    &ent.name,
                )?)?;
            }
        }

        let slots = allocate(&self.decoded, records, Some(victim), self.limits)?;
        let mut before = vec_bytes(erase as usize, 0)?;
        source.read(victim, &mut before)?;
        self.plan(
            slots,
            Some((victim, before)),
            Jffs2EditOperation::GarbageCollect,
            lease,
            r,
        )
    }
}

#[cfg(all(test, feature = "std"))]
#[path = "fs_jffs2_edit_compression_tests.rs"]
mod compression_tests;
