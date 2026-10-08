//! Native little-endian JFS log-page and after-image codec, staged privately.
use super::super::{DecodeRead, bad, budget, le16, le32, pxd, vector};
use crate::fs_core::*;
const PAGE: usize = 4096;
const HEADER: usize = 8;
const TRAILER: usize = 4088;
const DESCRIPTOR: usize = 36;
const SYNC: u16 = 0x4000;
const COMMIT: u16 = 0x8000;
const REDO: u16 = 0x0800;
struct Record<'a> {
    end: u32,
    tid: u32,
    backchain: u32,
    aggregate: u32,
    kind: u16,
    detail: &'a [u8],
    body: &'a [u8],
}
struct Parsed<'a> {
    records: Vec<Record<'a>>,
    _lease: Reservation,
}
fn records<'a>(page: &'a [u8; PAGE], number: u32, cap: usize, r: &Resources) -> Result<Parsed<'a>> {
    r.cancellation.check()?;
    if page[..8] != page[TRAILER..] || le16(page, 4) != 0 {
        return Err(bad("JFS torn/unsupported native log page"));
    }
    let mut end = usize::from(le16(page, 6));
    if !(HEADER..=TRAILER).contains(&end) || !end.is_multiple_of(4) {
        return Err(bad("JFS native log end alignment"));
    }
    let lease = r.memory.reserve(
        (cap as u64)
            .checked_mul(128)
            .ok_or_else(|| budget("JFS log record charge"))?,
    )?;
    let mut out = vector(cap)?;
    while end > HEADER {
        r.cancellation.check()?;
        if out.len() == cap {
            return Err(budget("JFS native log record ceiling"));
        }
        let at = end
            .checked_sub(DESCRIPTOR)
            .filter(|at| *at >= HEADER)
            .ok_or_else(|| bad("JFS split native descriptor requires multi-page decoder"))?;
        let d = &page[at..end];
        let length = usize::from(le16(d, 10));
        if !length.is_multiple_of(4) {
            return Err(bad("JFS log record data alignment"));
        }
        let start = at
            .checked_sub(length)
            .filter(|at| *at >= HEADER)
            .ok_or_else(|| bad("JFS split native data requires multi-page decoder"))?;
        let kind = le16(d, 8);
        match kind {
            SYNC if length == 0 && le32(d, 0) == 0 && le32(d, 4) == 0 => {}
            COMMIT if length == 0 && le32(d, 0) != 0 => {}
            REDO if length >= 4 && le32(d, 0) != 0 => {}
            SYNC | COMMIT | REDO => return Err(bad("JFS native descriptor semantics")),
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "JFS native record type not yet reconstructed",
                ));
            }
        }
        out.push(Record {
            end: number
                .checked_mul(PAGE as u32)
                .and_then(|v| v.checked_add(end as u32))
                .ok_or_else(|| bad("JFS native log address overflow"))?,
            tid: le32(d, 0),
            backchain: le32(d, 4),
            aggregate: le32(d, 12),
            kind,
            detail: &d[16..],
            body: &page[start..at],
        });
        end = start;
    }
    Ok(Parsed {
        records: out,
        _lease: lease,
    })
}
fn redo_lines(
    record: &Record<'_>,
    blocks: u64,
    r: &Resources,
    apply: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    r.cancellation.check()?;
    if record.kind != REDO {
        return Err(bad("JFS expected native after-image"));
    }
    let ty = le16(record.detail, 8);
    let scale = le16(record.detail, 10);
    // Metadata line sizes are native powers of two; DATA is intentionally not accepted.
    if ![(1u16, 7u16), (2, 4), (4, 5), (0x12, 4), (0x14, 5)].contains(&(ty, scale)) {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS redo metadata type/line scale",
        ));
    }
    let page = pxd(record.detail, 12, blocks)?;
    if page.count != 1 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS redo multi-page home extent",
        ));
    }
    // Native BTROOT vectors are relative to di_btroot, not to the page.
    // A page has eight 512-byte dinodes, each with a 288-byte root at 224.
    let root = ty & 0x10 != 0;
    let base = if root {
        (le32(record.detail, 4) as usize & 7) * 512 + 224
    } else {
        0
    };
    let span = if root { 288 } else { PAGE };
    let mut end = record.body.len();
    // Validate every descriptor before any callback can mutate its home page.
    let mut ranges = vector(end / 4)?;
    let _lease = r.memory.reserve(
        (end as u64)
            .checked_mul(8)
            .ok_or_else(|| budget("JFS redo vector charge"))?,
    )?;
    while end > 0 {
        r.cancellation.check()?;
        if end < 4 {
            return Err(bad("JFS incomplete native line descriptor"));
        }
        let lv = &record.body[end - 4..end];
        let offset = usize::from(le16(lv, 0)) << scale;
        let length = usize::from(le16(lv, 2)) << scale;
        if length == 0 || offset.checked_add(length).is_none_or(|v| v > span) || end < length + 4 {
            return Err(bad("JFS native line range"));
        }
        if ty == 1 && (!offset.is_multiple_of(512) || length != 128) {
            return Err(bad("JFS native base-inode section line"));
        }
        let start = end - length - 4;
        ranges.push((base + offset, start, length));
        end = start;
    }
    for (offset, start, length) in ranges {
        r.cancellation.check()?;
        apply(
            page.start * PAGE as u64 + offset as u64,
            &record.body[start..start + length],
        )?;
    }
    Ok(())
}
fn append(
    page: &mut [u8; PAGE],
    number: u32,
    descriptor: &[u8; DESCRIPTOR],
    body: &[u8],
) -> Result<u32> {
    let end = usize::from(le16(page, 6));
    if page[..8] != page[TRAILER..]
        || !(HEADER..=TRAILER).contains(&end)
        || !end.is_multiple_of(4)
        || !body.len().is_multiple_of(4)
        || usize::from(le16(descriptor, 10)) != body.len()
    {
        return Err(bad("JFS native append framing"));
    }
    let next = end
        .checked_add(body.len())
        .and_then(|v| v.checked_add(DESCRIPTOR))
        .filter(|v| *v <= TRAILER)
        .ok_or_else(|| budget("JFS native page capacity"))?;
    let address = number
        .checked_mul(PAGE as u32)
        .and_then(|v| v.checked_add(next as u32))
        .ok_or_else(|| bad("JFS log address overflow"))?;
    page[end..end + body.len()].copy_from_slice(body);
    page[end + body.len()..next].copy_from_slice(descriptor);
    page[6..8].copy_from_slice(&(next as u16).to_le_bytes());
    page[TRAILER + 6..].copy_from_slice(&(next as u16).to_le_bytes());
    Ok(address)
}
#[derive(Clone, Copy)]
struct HistoryLimits {
    pages: usize,
    records: usize,
    data: usize,
    work: u64,
}
struct OwnedRecord {
    end: u32,
    descriptor: [u8; DESCRIPTOR],
    body: Vec<u8>,
}
struct History {
    records: Vec<OwnedRecord>,
    reconciled: Vec<u32>,
    _lease: Reservation,
}
struct Cursor<'a> {
    source: &'a dyn DecodeRead,
    log: super::super::Physical,
    metadata: Vec<(u32, u16)>,
    page: [u8; PAGE],
    number: u32,
    offset: usize,
    work: u64,
    limits: HistoryLimits,
    r: &'a Resources,
    loaded: bool,
    crossings: usize,
    reconcile: bool,
}
impl Cursor<'_> {
    fn tick(&mut self, bytes: u64) -> Result<()> {
        self.r.cancellation.check()?;
        self.work = self
            .work
            .checked_add(bytes)
            .filter(|n| *n <= self.limits.work)
            .ok_or_else(|| budget("JFS native history work"))?;
        Ok(())
    }
    fn load(&mut self) -> Result<()> {
        if self.loaded {
            return Ok(());
        }
        self.tick(PAGE as u64)?;
        self.source.exact(
            (self.log.start + u64::from(self.number)) * PAGE as u64,
            &mut self.page,
        )?;
        let mut head = [0; 8];
        let mut tail = [0; 8];
        head.copy_from_slice(&self.page[..8]);
        tail.copy_from_slice(&self.page[TRAILER..]);
        if framing(&head, &tail, self.reconcile)? != self.metadata[self.number as usize - 2] {
            return Err(bad("JFS native history page changed/torn"));
        }
        self.loaded = true;
        Ok(())
    }
    fn previous(&mut self) -> Result<()> {
        self.crossings += 1;
        if self.crossings >= self.metadata.len() {
            return Err(bad("JFS native log crossed full circular history"));
        }
        let old = self.number;
        self.number = if old == 2 {
            self.log.count as u32 - 1
        } else {
            old - 1
        };
        if self.metadata[self.number as usize - 2].0.wrapping_add(1)
            != self.metadata[old as usize - 2].0
        {
            return Err(bad("JFS native circular sequence discontinuity"));
        }
        self.offset = TRAILER;
        self.loaded = false;
        Ok(())
    }
    fn backwards(&mut self, out: &mut [u8]) -> Result<()> {
        if !out.len().is_multiple_of(4) {
            return Err(bad("JFS native history word alignment"));
        }
        let mut remaining = out.len();
        while remaining > 0 {
            if self.offset == HEADER {
                self.previous()?;
            }
            self.load()?;
            let take = remaining.min(self.offset - HEADER);
            self.tick(take as u64)?;
            out[remaining - take..remaining]
                .copy_from_slice(&self.page[self.offset - take..self.offset]);
            remaining -= take;
            self.offset -= take;
        }
        Ok(())
    }
}
// jfsutils 1.1.15 log_read.c:setLogpage takes the smaller EOR when
// equal-sequence frames differ. This profile never overwrites a log sequence;
// it rejects sequence changes and retains strict parsing outside recovery.
fn framing(head: &[u8; 8], tail: &[u8; 8], reconcile: bool) -> Result<(u32, u16)> {
    for frame in [head, tail] {
        let end = le16(frame, 6);
        if le16(frame, 4) != 0
            || !(HEADER as u16..=TRAILER as u16).contains(&end)
            || !end.is_multiple_of(4)
        {
            return Err(bad("JFS native discovery torn/alignment"));
        }
    }
    if le32(head, 0) != le32(tail, 0) || (!reconcile && head != tail) {
        return Err(bad("JFS native discovery sequence/torn"));
    }
    Ok((le32(head, 0), le16(head, 6).min(le16(tail, 6))))
}
fn history(
    source: &dyn DecodeRead,
    log: super::super::Physical,
    limits: HistoryLimits,
    r: &Resources,
) -> Result<History> {
    history_framing(source, log, limits, r, false)
}
fn history_framing(
    source: &dyn DecodeRead,
    log: super::super::Physical,
    limits: HistoryLimits,
    r: &Resources,
    reconcile: bool,
) -> Result<History> {
    r.cancellation.check()?;
    let length = source.length()?;
    if !length.is_multiple_of(PAGE as u64)
        || log
            .start
            .checked_add(log.count)
            .is_none_or(|end| end > length / PAGE as u64)
    {
        return Err(bad("JFS native history source bounds"));
    }
    if log.count < 3
        || log.count > u64::from(u32::MAX) / PAGE as u64
        || usize::try_from(log.count - 2).is_err()
    {
        return Err(bad("JFS native history geometry"));
    }
    let pages = (log.count - 2) as usize;
    if pages > limits.pages {
        return Err(budget("JFS native history page ceiling"));
    }
    let charge = (pages as u64)
        .checked_mul(32)
        .and_then(|n| n.checked_add((limits.records as u64).checked_mul(128)?))
        .and_then(|n| n.checked_add(limits.data as u64))
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(|| budget("JFS native history memory"))?;
    let lease = r.memory.reserve(charge)?;
    let mut metadata = vector(pages)?;
    let mut reconciled = vector(pages)?;
    let mut header = [0u8; 8];
    let mut trailer = [0u8; 8];
    let mut work = 0u64;
    let mut maximum = None;
    for number in 2..log.count as u32 {
        r.cancellation.check()?;
        work = work
            .checked_add(16)
            .filter(|n| *n <= limits.work)
            .ok_or_else(|| budget("JFS native discovery work"))?;
        let at = (log.start + u64::from(number)) * PAGE as u64;
        source.exact(at, &mut header)?;
        source.exact(at + TRAILER as u64, &mut trailer)?;
        let (sequence, eor) = framing(&header, &trailer, reconcile)?;
        if header != trailer {
            reconciled.push(number);
        }
        if let Some((seq, _)) = maximum {
            let difference = sequence.wrapping_sub(seq) as i32;
            if difference == 0 || difference == i32::MIN {
                return Err(bad("JFS duplicate/ambiguous log sequence"));
            }
            if difference > 0 {
                maximum = Some((sequence, number));
            }
        } else {
            maximum = Some((sequence, number));
        }
        metadata.push((sequence, eor));
    }
    let (_, number) = maximum.unwrap();
    let offset = usize::from(metadata[number as usize - 2].1);
    let mut cursor = Cursor {
        source,
        log,
        metadata,
        page: [0; PAGE],
        number,
        offset,
        work,
        limits,
        r,
        loaded: false,
        crossings: 0,
        reconcile,
    };
    while cursor.offset == HEADER {
        cursor.previous()?;
        cursor.offset = usize::from(cursor.metadata[cursor.number as usize - 2].1);
    }
    let mut records = vector(limits.records)?;
    let mut bytes = 0usize;
    loop {
        r.cancellation.check()?;
        if records.len() == limits.records {
            return Err(budget("JFS native history record ceiling"));
        }
        let end = cursor
            .number
            .checked_mul(PAGE as u32)
            .and_then(|at| at.checked_add(cursor.offset as u32))
            .ok_or_else(|| bad("JFS native history address"))?;
        let mut descriptor = [0u8; DESCRIPTOR];
        cursor.backwards(&mut descriptor)?;
        let length = usize::from(le16(&descriptor, 10));
        if !length.is_multiple_of(4) || length > 2 * PAGE {
            return Err(bad("JFS native history record data bounds"));
        }
        bytes = bytes
            .checked_add(length)
            .filter(|n| *n <= limits.data)
            .ok_or_else(|| budget("JFS native aggregate record bytes"))?;
        let mut body = vector(length)?;
        body.resize(length, 0);
        cursor.backwards(&mut body)?;
        let kind = le16(&descriptor, 8);
        if ![SYNC, COMMIT, REDO].contains(&kind) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS native history record family not yet implemented",
            ));
        }
        if kind == SYNC && (length != 0 || le32(&descriptor, 0) != 0 || le32(&descriptor, 4) != 0)
            || kind == COMMIT && (length != 0 || le32(&descriptor, 0) == 0)
            || kind == REDO && (length < 4 || le32(&descriptor, 0) == 0)
        {
            return Err(bad("JFS native history descriptor semantics"));
        }
        records.push(OwnedRecord {
            end,
            descriptor,
            body,
        });
        if kind == SYNC {
            if le32(&descriptor, 16) != 0 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "JFS earlier nonzero native syncpoint traversal pending",
                ));
            }
            break;
        }
    }
    source.length()?;
    Ok(History {
        records,
        reconciled,
        _lease: lease,
    })
}

pub(super) struct Prepared {
    header: [[u8; PAGE]; 2],
    logs: [u8; PAGE],
    before_page: [u8; PAGE],
    prepared: [u8; PAGE],
    committed: [u8; PAGE],
    checkpoint: [u8; PAGE],
    page_at: u64,
    log_at: u64,
    home: u64,
    before: [u8; 128],
    after: [u8; 128],
    serial: u32,
    end: u32,
    uuid: [u8; 16],
    length: u64,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    _lease: Reservation,
}
pub(super) fn prepare_uid(
    storage: &dyn crate::storage::Storage,
    inode: u32,
    uid: u32,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<Prepared> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let lease = r.memory.reserve(65536)?;
    let baseline = super::inspect_with(storage, read, audit, original, r)?;
    let length = storage
        .len()
        .map_err(|e| Error::io("JFS native prepare length", e))?;
    let source = super::Borrowed {
        storage,
        length,
        resources: original,
    };
    let mut header = [[0u8; PAGE]; 2];
    for (at, bytes) in [32768u64, 61440].into_iter().zip(&mut header) {
        source.exact(at, bytes)?;
    }
    let log = pxd(&header[0], 72, length / PAGE as u64)?;
    let log_at = (log.start + 1) * PAGE as u64;
    let mut logs = [0u8; PAGE];
    source.exact(log_at, &mut logs)?;
    let scanned = history(
        &source,
        log,
        HistoryLimits {
            pages: read.pages,
            records: 64,
            data: 8192,
            work: read.work,
        },
        r,
    )?;
    if scanned.records.len() != 1
        || le16(&scanned.records[0].descriptor, 8) != SYNC
        || scanned.records[0].end != le32(&logs, 32)
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native clean checkpoint bootstrap",
        ));
    }
    let end = scanned.records[0].end;
    drop(scanned);
    let serial = le32(&logs, 8)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::Unsupported, "JFS native mount serial wrap"))?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&header[0][136..152]);
    if uuid.iter().all(|v| *v == 0) {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native aggregate UUID required",
        ));
    }
    let node = baseline
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS UID native inode absent"))?;
    let extent = pxd(&node.raw, 16, length / PAGE as u64)?;
    if extent.count != 4 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS UID inode extent profile",
        ));
    }
    let page = extent.start + u64::from((inode & 31) / 8);
    let home = page * PAGE as u64 + u64::from(inode & 7) * 512;
    let mut before = [0u8; 128];
    source.exact(home, &mut before)?;
    if before != node.raw[..128] {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS native inode changed during preparation",
        ));
    }
    let mut after = before;
    after[44..48].copy_from_slice(&uid.to_le_bytes());
    let mut patches = vector(1)?;
    patches.push((home, super::super::copied(&after)?));
    let overlay = super::Overlay {
        source: super::Borrowed {
            storage,
            length,
            resources: original,
        },
        patches: &patches,
    };
    let resulting = super::super::decode(&overlay, read, r)?;
    let proof = crate::fs_jfs_audit::audit_decoded(&resulting, audit, r)?;
    if !proof.is_clean()
        || le32(
            &resulting
                .nodes
                .get(&inode)
                .ok_or_else(|| bad("JFS resulting inode absent"))?
                .raw,
            44,
        ) != uid
    {
        return Err(bad("JFS resulting UID proof"));
    }
    drop((proof, resulting, patches, baseline));
    let page_at = (log.start + u64::from(end / PAGE as u32)) * PAGE as u64;
    let mut before_page = [0u8; PAGE];
    source.exact(page_at, &mut before_page)?;
    let mut prepared = before_page;
    let number = end / PAGE as u32;
    let mut d = [0u8; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    append(&mut prepared, number, &d, &[])?;
    d.fill(0);
    d[..4].copy_from_slice(&1u32.to_le_bytes());
    d[8..10].copy_from_slice(&REDO.to_le_bytes());
    d[10..12].copy_from_slice(&132u16.to_le_bytes());
    d[16..20].copy_from_slice(&le32(&before, 4).to_le_bytes());
    d[20..24].copy_from_slice(&inode.to_le_bytes());
    d[24..26].copy_from_slice(&1u16.to_le_bytes());
    d[26..28].copy_from_slice(&7u16.to_le_bytes());
    d[28..32].copy_from_slice(&(1u32 | ((page >> 32) as u32) << 24).to_le_bytes());
    d[32..].copy_from_slice(&(page as u32).to_le_bytes());
    let mut body = [0u8; 132];
    body[..128].copy_from_slice(&after);
    body[128..130].copy_from_slice(&((inode & 7) as u16 * 4).to_le_bytes());
    body[130..].copy_from_slice(&1u16.to_le_bytes());
    let redo = append(&mut prepared, number, &d, &body)?;
    let mut committed = prepared;
    d.fill(0);
    d[..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..8].copy_from_slice(&redo.to_le_bytes());
    d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    append(&mut committed, number, &d, &[])?;
    let mut checkpoint = committed;
    d.fill(0);
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    let end = append(&mut checkpoint, number, &d, &[])?;
    original.cancellation.check()?;
    r.cancellation.check()?;
    source.length()?;
    Ok(Prepared {
        header,
        logs,
        before_page,
        prepared,
        committed,
        checkpoint,
        page_at,
        log_at,
        home,
        before,
        after,
        serial,
        end,
        uuid,
        length,
        read,
        audit,
        _lease: lease,
    })
}
pub(super) fn write_checked(
    storage: &mut dyn crate::storage::Storage,
    at: u64,
    bytes: &[u8],
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    let mut done = 0;
    while done < bytes.len() {
        original.cancellation.check()?;
        r.cancellation.check()?;
        let n = storage
            .write_at(at + done as u64, &bytes[done..])
            .map_err(|e| Error::io("JFS native write", e))?;
        if n == 0 || n > bytes.len() - done {
            return Err(bad("JFS native write progress"));
        }
        done += n;
    }
    Ok(())
}
fn flush_readback(
    storage: &mut dyn crate::storage::Storage,
    at: u64,
    bytes: &[u8],
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    storage
        .flush()
        .map_err(|e| Error::io("JFS native durability barrier", e))?;
    let mut buffer = [0u8; PAGE];
    let mut done = 0;
    while done < bytes.len() {
        original.cancellation.check()?;
        r.cancellation.check()?;
        let n = (bytes.len() - done).min(PAGE);
        storage
            .read_exact_at(at + done as u64, &mut buffer[..n])
            .map_err(|e| Error::io("JFS native readback", e))?;
        if buffer[..n] != bytes[done..done + n] {
            return Err(bad("JFS native readback mismatch"));
        }
        done += n;
    }
    Ok(())
}
pub(super) fn publish_uid(
    storage: &mut dyn crate::storage::Storage,
    mut plan: Prepared,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    if storage
        .len()
        .map_err(|e| Error::io("JFS native commit length", e))?
        != plan.length
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS native commit geometry",
        ));
    }
    for (at, expected) in [
        (plan.home, plan.before.as_slice()),
        (plan.page_at, plan.before_page.as_slice()),
        (plan.log_at, plan.logs.as_slice()),
        (32768, plan.header[0].as_slice()),
        (61440, plan.header[1].as_slice()),
    ] {
        let mut buffer = [0u8; PAGE];
        storage
            .read_exact_at(at, &mut buffer[..expected.len()])
            .map_err(|e| Error::io("JFS native stale preflight", e))?;
        if buffer[..expected.len()] != *expected {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS native stale preflight",
            ));
        }
    }
    let result = (|| {
        write_checked(storage, plan.page_at, &plan.prepared, original, r)?;
        flush_readback(storage, plan.page_at, &plan.prepared, original, r)?;
        for (at, header) in [32768u64, 61440].into_iter().zip(&mut plan.header) {
            header[40..44].copy_from_slice(&1u32.to_le_bytes());
            header[68..72].copy_from_slice(&plan.serial.to_le_bytes());
            write_checked(storage, at, header, original, r)?;
        }
        plan.logs[8..12].copy_from_slice(&plan.serial.to_le_bytes());
        plan.logs[28..32].copy_from_slice(&0u32.to_le_bytes());
        plan.logs[68..84].copy_from_slice(&plan.uuid);
        write_checked(storage, plan.log_at, &plan.logs, original, r)?;
        flush_readback(storage, plan.log_at, &plan.logs, original, r)?;
        write_checked(storage, plan.page_at, &plan.committed, original, r)?;
        flush_readback(storage, plan.page_at, &plan.committed, original, r)?;
        write_checked(storage, plan.home, &plan.after, original, r)?;
        flush_readback(storage, plan.home, &plan.after, original, r)?;
        write_checked(storage, plan.page_at, &plan.checkpoint, original, r)?;
        flush_readback(storage, plan.page_at, &plan.checkpoint, original, r)?;
        plan.logs[28..32].copy_from_slice(&1u32.to_le_bytes());
        plan.logs[32..36].copy_from_slice(&plan.end.to_le_bytes());
        plan.logs[68..84].fill(0);
        write_checked(storage, plan.log_at, &plan.logs, original, r)?;
        flush_readback(storage, plan.log_at, &plan.logs, original, r)?;
        for (at, header) in [32768u64, 61440].into_iter().zip(&mut plan.header) {
            header[40..44].fill(0);
            write_checked(storage, at, header, original, r)?;
            flush_readback(storage, at, header, original, r)?;
        }
        let resulting = super::inspect_with(storage, plan.read, plan.audit, original, r)?;
        let id = le32(&plan.after, 8);
        if resulting
            .nodes
            .get(&id)
            .is_none_or(|node| node.raw[..128] != plan.after)
        {
            return Err(bad("JFS final native inode verification"));
        }
        original.cancellation.check()?;
        r.cancellation.check()?;
        Ok(())
    })();
    result.map_err(|mut error: Error| {
        error.kind = ErrorKind::UncertainDurability;
        error.context = format!(
            "JFS native publication requires explicit recovery: {}",
            error.context
        );
        error
    })
}

// The staged publisher changes the two native superblock serial words and
// then the inline-log word in order. A short positional write may leave a
// little-endian prefix of old+1 followed by the old suffix. At least one of
// the three copies is complete at every cut of that sequential protocol.
fn activation_serial(words: [u32; 3]) -> Result<(u32, bool)> {
    if words.iter().all(|word| *word == words[0]) {
        return Ok((words[0], false));
    }
    let mut selected = None;
    for word in words {
        for old in [Some(word), word.checked_sub(1)].into_iter().flatten() {
            let Some(new) = old.checked_add(1) else {
                continue;
            };
            let before = old.to_le_bytes();
            let after = new.to_le_bytes();
            if !words.iter().any(|word| *word == old || *word == new) {
                continue;
            }
            if words.iter().all(|word| {
                let observed = word.to_le_bytes();
                (0..=4)
                    .any(|cut| observed[..cut] == after[..cut] && observed[cut..] == before[cut..])
            }) {
                if selected.is_some_and(|value| value != new) {
                    return Err(bad("JFS ambiguous partial activation serial"));
                }
                selected = Some(new);
            }
        }
    }
    selected
        .map(|serial| (serial, true))
        .ok_or_else(|| bad("JFS incompatible partial activation serial"))
}
pub(super) fn recover_uid(
    storage: &mut dyn crate::storage::Storage,
    binding: [u8; 16],
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let _lease = r.memory.reserve(65536)?;
    let length = storage
        .len()
        .map_err(|e| Error::io("JFS native recovery length", e))?;
    let source = super::Borrowed {
        storage,
        length,
        resources: original,
    };
    let mut headers = [[0u8; PAGE]; 2];
    for (at, header) in [32768u64, 61440].into_iter().zip(&mut headers) {
        source.exact(at, header)?;
    }
    if headers[0][136..152] != binding || binding.iter().all(|v| *v == 0) {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS native recovery aggregate binding",
        ));
    }
    let log = pxd(&headers[0], 72, length / PAGE as u64)?;
    let log_at = (log.start + 1) * PAGE as u64;
    let mut logs = [0u8; PAGE];
    source.exact(log_at, &mut logs)?;
    let (serial, partial_serial) =
        activation_serial([le32(&headers[0], 68), le32(&headers[1], 68), le32(&logs, 8)])?;
    let inactive = logs[68..84].iter().all(|v| *v == 0);
    let active = logs[68..84] == binding;
    let partial_active = !inactive && !active;
    let legal_active = (0..=16).any(|cut| {
        logs[68..68 + cut] == binding[..cut] && logs[68 + cut..84].iter().all(|v| *v == 0)
    });
    if ![0, 1].contains(&le32(&logs, 28))
        || !headers.iter().all(|h| [0, 1].contains(&le32(h, 40)))
        || logs[84..68 + 128 * 16].iter().any(|v| *v != 0)
        || !legal_active
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native recovery bootstrap/activation reconciliation pending",
        ));
    }
    let mut projected = headers;
    for header in &mut projected {
        header[40..44].fill(0);
        header[68..72].copy_from_slice(&serial.to_le_bytes());
    }
    let mut cleanlogs = logs;
    cleanlogs[8..12].copy_from_slice(&serial.to_le_bytes());
    cleanlogs[28..32].copy_from_slice(&1u32.to_le_bytes());
    cleanlogs[68..68 + 128 * 16].fill(0);
    let mut patches = vector(67)?;
    for (at, header) in [32768u64, 61440].into_iter().zip(&projected) {
        patches.push((at, super::super::copied(header)?));
    }
    patches.push((log_at, super::super::copied(&cleanlogs)?));
    let overlay = super::Overlay {
        source: super::Borrowed {
            storage,
            length,
            resources: original,
        },
        patches: &patches,
    };
    let baseline = super::super::decode(&overlay, read, r)?;
    let proof = crate::fs_jfs_audit::audit_decoded(&baseline, audit, r)?;
    if !proof.is_clean() {
        return Err(bad("JFS native recovery baseline ownership"));
    }
    drop(proof);
    let scanned = history_framing(
        &source,
        log,
        HistoryLimits {
            pages: read.pages,
            records: 64,
            data: 8192,
            work: read.work,
        },
        r,
        true,
    )?;
    let newest = scanned
        .records
        .first()
        .ok_or_else(|| bad("JFS native recovery empty history"))?;
    let newest_end = newest.end;
    let number = newest_end / PAGE as u32;
    if scanned.reconciled.iter().any(|page| *page != number) {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS torn older-page reconciliation pending",
        ));
    }
    let repaired = !scanned.reconciled.is_empty();
    let kind = le16(&newest.descriptor, 8);
    let committed = kind == COMMIT;
    let checkpointed = kind == SYNC;
    if (partial_serial || partial_active) && kind != REDO {
        return Err(bad(
            "JFS native partial activation with published transaction",
        ));
    }
    if le32(&logs, 28) == 1 && (committed || checkpointed && le32(&logs, 32) != newest_end) {
        return Err(bad("JFS native recovery completed checkpoint mismatch"));
    }
    if ![COMMIT, REDO, SYNC].contains(&kind) {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native recovery publication state",
        ));
    }
    let mut chain = if committed {
        le32(&newest.descriptor, 4)
    } else {
        0
    };
    let tid = le32(&newest.descriptor, 0);
    let mut home = vector(64)?;
    for record in scanned.records.iter().skip(usize::from(committed)) {
        let d = &record.descriptor;
        if le16(d, 8) == SYNC {
            if chain != 0 {
                return Err(bad("JFS native recovery incomplete transaction backchain"));
            }
            break;
        }
        if le16(d, 8) != REDO
            || le32(d, 0) != tid
            || le32(d, 12) != 0
            || committed && record.end != chain
        {
            return Err(bad("JFS native recovery transaction membership"));
        }
        chain = le32(d, 4);
        let inode = le32(d, 20);
        let node = baseline
            .nodes
            .get(&inode)
            .ok_or_else(|| bad("JFS native recovery inode absent"))?;
        let extent = pxd(&node.raw, 16, length / PAGE as u64)?;
        let physical = pxd(d, 28, length / PAGE as u64)?;
        let expected = extent.start + u64::from((inode & 31) / 8);
        if extent.count != 4
            || physical.start != expected
            || physical.count != 1
            || le32(d, 16) != le32(&node.raw, 4)
            || le16(d, 24) != 1
            || le16(d, 26) != 7
            || record.body.len() != 132
            || le16(&record.body, 128) != (inode & 7) as u16 * 4
            || le16(&record.body, 130) != 1
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS native recovery bounded UID after-image profile",
            ));
        }
        let at = expected * PAGE as u64 + u64::from(inode & 7) * 512;
        let mut actual = [0u8; 128];
        source.exact(at, &mut actual)?;
        if actual[..44] != record.body[..44] || actual[48..] != record.body[48..128] {
            return Err(bad("JFS native recovery changes beyond UID operation"));
        }
        if home.iter().any(|(old, _)| *old == at) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS native recovery repeated inode precedence pending",
            ));
        }
        if committed {
            home.push((at, super::super::copied(&record.body[..128])?));
        }
    }
    drop((scanned, baseline));
    for (at, bytes) in &home {
        patches.push((*at, super::super::copied(bytes)?));
    }
    let overlay = super::Overlay {
        source: super::Borrowed {
            storage,
            length,
            resources: original,
        },
        patches: &patches,
    };
    let resulting = super::super::decode(&overlay, read, r)?;
    let proof = crate::fs_jfs_audit::audit_decoded(&resulting, audit, r)?;
    if !proof.is_clean() {
        return Err(bad("JFS native recovery resulting ownership"));
    }
    drop((resulting, proof, patches));
    if checkpointed
        && !repaired
        && le32(&logs, 28) == 1
        && headers.iter().all(|h| le32(h, 40) == 0)
        && logs[68..68 + 128 * 16].iter().all(|v| *v == 0)
    {
        original.cancellation.check()?;
        r.cancellation.check()?;
        return Ok(());
    }
    let page_at = (log.start + u64::from(number)) * PAGE as u64;
    let mut page = [0u8; PAGE];
    source.exact(page_at, &mut page)?;
    if repaired {
        let end = (newest_end % PAGE as u32) as u16;
        page[6..8].copy_from_slice(&end.to_le_bytes());
        page[TRAILER + 6..].copy_from_slice(&end.to_le_bytes());
    }
    let mut d = [0u8; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    let end = if checkpointed {
        newest_end
    } else {
        append(&mut page, number, &d, &[])?
    };
    cleanlogs[32..36].copy_from_slice(&end.to_le_bytes());
    original.cancellation.check()?;
    r.cancellation.check()?;
    source.length()?;
    let result = (|| {
        for (at, bytes) in &home {
            write_checked(storage, *at, bytes, original, r)?;
        }
        if !home.is_empty() {
            for (at, bytes) in &home {
                flush_readback(storage, *at, bytes, original, r)?;
            }
        }
        if !checkpointed || repaired {
            write_checked(storage, page_at, &page, original, r)?;
            flush_readback(storage, page_at, &page, original, r)?;
        }
        write_checked(storage, log_at, &cleanlogs, original, r)?;
        flush_readback(storage, log_at, &cleanlogs, original, r)?;
        for (at, header) in [32768u64, 61440].into_iter().zip(&projected) {
            write_checked(storage, at, header, original, r)?;
            flush_readback(storage, at, header, original, r)?;
        }
        drop(super::inspect_with(storage, read, audit, original, r)?);
        original.cancellation.check()?;
        r.cancellation.check()?;
        Ok(())
    })();
    result.map_err(|mut error: Error| {
        error.kind = ErrorKind::UncertainDurability;
        error.context = format!("JFS native recovery interrupted: {}", error.context);
        error
    })
}

#[test]
fn independent_split_native_history_caps_sequence_torn_and_source_failures_refund() {
    use super::fixture::{p16, p32};
    struct Source {
        bytes: Vec<u8>,
        fail: bool,
    }
    impl DecodeRead for Source {
        fn length(&self) -> Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
            if self.fail {
                return Err(Error::io(
                    "independent split source",
                    std::io::Error::other("causal"),
                ));
            }
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or_else(|| bad("fixture bounds"))?,
            );
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let log = super::super::Physical { start: 1, count: 6 };
    let mut bytes = vec![0; 7 * PAGE];
    for (number, sequence, eor) in [(2usize, 4u32, 44u16), (3, 5, 80), (4, 2, 8), (5, 3, 8)] {
        let at = (1 + number) * PAGE;
        p32(&mut bytes, at, sequence);
        p16(&mut bytes, at + 6, eor);
        p32(&mut bytes, at + TRAILER, sequence);
        p16(&mut bytes, at + TRAILER + 6, eor);
    }
    let base = 3 * PAGE;
    let next = 4 * PAGE;
    p16(&mut bytes, base + 8 + 8, SYNC);
    let body = vec![0x5a; 4044];
    bytes[base + 44..base + TRAILER].copy_from_slice(&body);
    p32(&mut bytes, next + 8, 7);
    p16(&mut bytes, next + 16, REDO);
    p16(&mut bytes, next + 18, 4044);
    p32(&mut bytes, next + 44, 7);
    p32(&mut bytes, next + 48, 3 * PAGE as u32 + 44);
    p16(&mut bytes, next + 52, COMMIT);
    let source = Source {
        bytes: bytes.clone(),
        fail: false,
    };
    let caps = HistoryLimits {
        pages: 4,
        records: 3,
        data: 4044,
        work: 100000,
    };
    let scanned = history(&source, log, caps, &r).unwrap();
    assert_eq!(scanned.records.len(), 3);
    assert_eq!(scanned.records[0].end, 3 * PAGE as u32 + 80);
    assert_eq!(scanned.records[1].body, body);
    assert_eq!(scanned.records[2].end, 2 * PAGE as u32 + 44);
    drop(scanned);
    assert_eq!(r.memory.used(), 0);
    for caps in [
        HistoryLimits { pages: 3, ..caps },
        HistoryLimits { records: 2, ..caps },
        HistoryLimits { data: 4043, ..caps },
        HistoryLimits { work: 63, ..caps },
        HistoryLimits { work: 1000, ..caps },
    ] {
        assert!(history(&source, log, caps, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    for (at, value) in [
        (base, 3u8),
        (base + TRAILER, 3),
        (next + 6, 81),
        (next + TRAILER + 6, 81),
    ] {
        let mut badbytes = bytes.clone();
        badbytes[at] = value;
        assert!(
            history(
                &Source {
                    bytes: badbytes,
                    fail: false
                },
                log,
                caps,
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
    let mut changed = bytes;
    for at in [base, base + TRAILER] {
        p32(&mut changed, at, 1);
    }
    assert!(
        history(
            &Source {
                bytes: changed,
                fail: false
            },
            log,
            caps,
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
    assert!(
        history(
            &Source {
                bytes: source.bytes.clone(),
                fail: true
            },
            log,
            caps,
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
    r.cancellation.cancel();
    assert!(history(&source, log, caps, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_after_image_lines_backchains_and_torn_bounds_are_checked_before_callbacks() {
    use super::fixture::{p16, p32, pxd};
    let r = Resources {
        memory: Budget::new(1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let mut page = [0u8; PAGE];
    p32(&mut page, 0, 7);
    p32(&mut page, TRAILER, 7);
    p16(&mut page, 6, 8);
    p16(&mut page, TRAILER + 6, 8);
    let mut d = [0u8; DESCRIPTOR];
    p16(&mut d, 8, SYNC);
    let sync = append(&mut page, 2, &d, &[]).unwrap();
    d.fill(0);
    p32(&mut d, 0, 42);
    p16(&mut d, 8, REDO);
    p16(&mut d, 10, 132);
    p32(&mut d, 12, 3);
    p32(&mut d, 16, 16);
    p32(&mut d, 20, 4);
    p16(&mut d, 24, 1);
    p16(&mut d, 26, 7);
    pxd(&mut d, 28, 29, 1);
    let mut body = [0x5a; 132];
    body[128..].copy_from_slice(&[16, 0, 1, 0]);
    let redo = append(&mut page, 2, &d, &body).unwrap();
    d.fill(0);
    p32(&mut d, 0, 42);
    p32(&mut d, 4, redo);
    p16(&mut d, 8, COMMIT);
    let commit = append(&mut page, 2, &d, &[]).unwrap();
    let parsed = records(&page, 2, 3, &r).unwrap();
    assert_eq!(parsed.records[0].end, commit);
    assert_eq!(parsed.records[0].backchain, redo);
    assert_eq!(parsed.records[1].tid, 42);
    assert_eq!(parsed.records[1].aggregate, 3);
    assert_eq!(parsed.records[2].end, sync);
    let mut applied = Vec::new();
    redo_lines(&parsed.records[1], 512, &r, &mut |at, bytes| {
        applied.push((at, bytes.to_vec()));
        Ok(())
    })
    .unwrap();
    assert_eq!(applied, [(29 * 4096 + 2048, vec![0x5a; 128])]);
    drop(parsed);
    assert_eq!(r.memory.used(), 0);
    let mut malformed = page;
    let payload = 8 + 36;
    malformed[payload + 130..payload + 132].copy_from_slice(&u16::MAX.to_le_bytes());
    let parsed = records(&malformed, 2, 3, &r).unwrap();
    let mut calls = 0;
    assert!(
        redo_lines(&parsed.records[1], 512, &r, &mut |_, _| {
            calls += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls, 0);
    drop(parsed);
    for byte in [0usize, 6, TRAILER, TRAILER + 6] {
        let mut torn = page;
        torn[byte] ^= 1;
        assert!(records(&torn, 2, 3, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    assert!(records(&page, 2, 2, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_inline_root_vectors_use_inode_relative_bounds_before_callbacks() {
    use super::fixture::{p16, p32, pxd};
    let r = Resources {
        memory: Budget::new(1024 * 1024),
        cancellation: Cancellation::default(),
    };
    for (ty, scale, line) in [(0x12u16, 4u16, 16usize), (0x14, 5, 32)] {
        let mut detail = [0u8; 20];
        p32(&mut detail, 4, 4);
        p16(&mut detail, 8, ty);
        p16(&mut detail, 10, scale);
        pxd(&mut detail, 12, 29, 1);
        let mut body = vec![0x6b; line + 4];
        p16(&mut body, line, 1);
        p16(&mut body, line + 2, 1);
        let mut record = Record {
            end: 0,
            tid: 7,
            backchain: 0,
            aggregate: 0,
            kind: REDO,
            detail: &detail,
            body: &body,
        };
        let mut applied = Vec::new();
        redo_lines(&record, 512, &r, &mut |at, bytes| {
            applied.push((at, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            applied,
            [(29 * 4096 + 4 * 512 + 224 + line as u64, vec![0x6b; line])]
        );
        let mut bad_body = body.clone();
        p16(&mut bad_body, line, (288 / line) as u16);
        record.body = &bad_body;
        let mut calls = 0;
        assert!(
            redo_lines(&record, 512, &r, &mut |_, _| {
                calls += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls, 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
#[ignore = "requires fresh PARTMGR_JFS_REDO_EVIDENCE and JFS_TOOLS with native formatter/replay/dump"]
fn native_formatter_and_redo_replay_inode_line_layout() {
    use super::{
        Borrowed,
        fixture::{p16, p32, pxd},
    };
    use crate::storage::{FileStorage, Storage};
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    let evidence = PathBuf::from(
        std::env::var_os("PARTMGR_JFS_REDO_EVIDENCE").expect("fresh evidence directory required"),
    );
    assert!(evidence.is_dir());
    let receipt_path = evidence.join("receipt.txt");
    assert!(!receipt_path.exists());
    let tools =
        PathBuf::from(std::env::var_os("JFS_TOOLS").expect("jfsutils tool directory required"));
    let sources = [
        ("src/fs_jfs.rs", include_bytes!("fs_jfs.rs").as_slice()),
        (
            "src/fs_jfs_audit.rs",
            include_bytes!("fs_jfs_audit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit.rs",
            include_bytes!("fs_jfs_edit.rs").as_slice(),
        ),
        (
            "src/fs_jfs_edit_journal.rs",
            include_bytes!("fs_jfs_edit_journal.rs").as_slice(),
        ),
        (
            "tests/fixtures/jfs_clean.rs",
            include_bytes!("../tests/fixtures/jfs_clean.rs").as_slice(),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ];
    let mut receipt = String::from(
        "status=running\nprofile=private-native-single-page-inode-line-codec; no public editor/recovery claim\n",
    );
    for (name, bytes) in sources {
        assert_eq!(fs::read(name).unwrap(), bytes);
        let dst = evidence.join("source").join(name);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::write(dst, bytes).unwrap();
        receipt.push_str(&format!("source={name} sha256={}\n", hash(bytes)));
    }
    let binary = std::env::current_exe().unwrap();
    let binary_hash = hash(&fs::read(&binary).unwrap());
    receipt.push_str(&format!(
        "binary={} sha256={binary_hash}\n",
        binary.display()
    ));
    let bindings = ["mkfs.jfs", "fsck.jfs", "jfs_logdump"].map(|name| {
        let path = tools.join(name);
        let digest = hash(&fs::read(&path).unwrap());
        receipt.push_str(&format!("tool={} sha256={digest}\n", path.display()));
        (path, digest)
    });
    let mut run = |label: &str, program: &str, args: &[&str]| {
        let output = Command::new(tools.join(program))
            .args(args)
            .current_dir(&evidence)
            .output()
            .unwrap();
        fs::write(evidence.join(format!("{label}.stdout")), &output.stdout).unwrap();
        fs::write(evidence.join(format!("{label}.stderr")), &output.stderr).unwrap();
        receipt.push_str(&format!(
            "command={program} argv={args:?} exit={}\n",
            output.status
        ));
        assert!(output.status.success(), "{label}: {:?}", output.stderr);
        output
    };
    let image = evidence.join("native.img");
    fs::File::create(&image)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    run("format", "mkfs.jfs", &["-q", image.to_str().unwrap()]);
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let mut storage = FileStorage::open(&image).unwrap();
    let len = storage.len().unwrap();
    let borrowed = Borrowed {
        storage: &storage,
        length: len,
        resources: &r,
    };
    let mut header = [0u8; PAGE];
    borrowed.exact(32768, &mut header).unwrap();
    let log = super::super::pxd(&header, 72, len / 4096).unwrap();
    let mut logs = [0u8; PAGE];
    borrowed.exact((log.start + 1) * 4096, &mut logs).unwrap();
    let mut page = [0u8; PAGE];
    borrowed.exact((log.start + 2) * 4096, &mut page).unwrap();
    let baseline = records(&page, 2, 8, &r).unwrap();
    assert_eq!(baseline.records.len(), 1);
    assert_eq!(baseline.records[0].kind, SYNC);
    drop(baseline);
    let mut fileset = [0u8; 512];
    borrowed.exact(45056 + 16 * 512, &mut fileset).unwrap();
    let imap = super::super::pxd(&fileset, 264, len / 4096).unwrap();
    let mut iag = [0u8; PAGE];
    borrowed.exact((imap.start + 1) * 4096, &mut iag).unwrap();
    let inodes = super::super::pxd(&iag, 3072, len / 4096).unwrap();
    let mut home = [0u8; PAGE];
    borrowed.exact(inodes.start * 4096, &mut home).unwrap();
    assert_eq!(le32(&home, 2 * 512 + 8), 2);
    let fileset_id = le32(&home, 2 * 512 + 4);
    let mut line = [0u8; 128];
    line.copy_from_slice(&home[1024..1152]);
    p32(&mut line, 44, 777);
    let mut body = [0u8; 132];
    body[..128].copy_from_slice(&line);
    p16(&mut body, 128, 8);
    p16(&mut body, 130, 1);
    let sequence = le32(&page, 0).checked_add(1).unwrap();
    p32(&mut page, 0, sequence);
    p32(&mut page, TRAILER, sequence);
    // Native mount bootstrap adds a fresh zero-sync marker after the formatter marker.
    // jfsutils validates the predecessor address before interpreting SYNCPT;
    // starting at byte8 would wrap to a trailer beyond its accepted record bound.
    let mut checkpoint = [0u8; DESCRIPTOR];
    p16(&mut checkpoint, 8, SYNC);
    append(&mut page, 2, &checkpoint, &[]).unwrap();
    let mut d = [0u8; DESCRIPTOR];
    p32(&mut d, 0, 1);
    p16(&mut d, 8, REDO);
    p16(&mut d, 10, 132);
    p32(&mut d, 16, fileset_id);
    p32(&mut d, 20, 2);
    p16(&mut d, 24, 1);
    p16(&mut d, 26, 7);
    pxd(&mut d, 28, inodes.start, 1);
    let redo = append(&mut page, 2, &d, &body).unwrap();
    d.fill(0);
    p32(&mut d, 0, 1);
    p32(&mut d, 4, redo);
    p16(&mut d, 8, COMMIT);
    let committed = append(&mut page, 2, &d, &[]).unwrap();
    let serial = le32(&logs, 8).checked_add(1).unwrap();
    p32(&mut logs, 8, serial);
    p32(&mut logs, 28, 0);
    p32(&mut logs, 32, committed);
    logs[68..84].copy_from_slice(&header[136..152]);
    p32(&mut header, 40, 1);
    p32(&mut header, 68, serial);
    // This independently inspected fixture authors native dirty metadata directly;
    // production transaction ordering/restart recovery is not yet claimed.
    fn write(storage: &mut dyn Storage, at: u64, bytes: &[u8]) {
        let mut n = 0;
        while n < bytes.len() {
            let done = storage.write_at(at + n as u64, &bytes[n..]).unwrap();
            assert!(done > 0);
            n += done;
        }
    }
    write(&mut storage, 32768, &header);
    write(&mut storage, 61440, &header);
    write(&mut storage, (log.start + 1) * 4096, &logs);
    write(&mut storage, (log.start + 2) * 4096, &page);
    storage.flush().unwrap();
    let borrowed = Borrowed {
        storage: &storage,
        length: len,
        resources: &r,
    };
    let scanned = history(
        &borrowed,
        log,
        HistoryLimits {
            pages: 1024,
            records: 16,
            data: 8192,
            work: 1024 * 1024,
        },
        &r,
    )
    .unwrap();
    assert_eq!(scanned.records.len(), 3);
    assert_eq!(scanned.records[0].end, committed);
    assert_eq!(le16(&scanned.records[0].descriptor, 8), COMMIT);
    assert_eq!(scanned.records[1].body, body);
    drop(scanned);
    drop(storage);
    run("dump", "jfs_logdump", &["-a", image.to_str().unwrap()]);
    let dump = fs::read_to_string(evidence.join("jfslog.dmp")).unwrap();
    assert!(dump.contains("REDOPAGE") && dump.contains("COMMIT"));
    let replay = run(
        "replay",
        "fsck.jfs",
        &["--replay_journal_only", image.to_str().unwrap()],
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    )
    .to_lowercase();
    assert!(
        !diagnostic.contains("logredo failed") && !diagnostic.contains("rc=-"),
        "native replay diagnostic: {diagnostic}"
    );
    let storage = FileStorage::open(&image).unwrap();
    let mut actual = [0u8; 128];
    storage
        .read_exact_at(inodes.start * 4096 + 1024, &mut actual)
        .unwrap();
    assert_eq!(actual, line);
    drop(storage);
    assert_eq!(r.memory.used(), 0);
    receipt.push_str(&format!(
        "native_replayed_inode_uid=777 inode=2 home={} image_sha256={}\n",
        inodes.start,
        hash(&fs::read(&image).unwrap())
    ));
    for (name, bytes) in sources {
        assert_eq!(fs::read(name).unwrap(), bytes);
    }
    for (path, digest) in bindings {
        assert_eq!(hash(&fs::read(path).unwrap()), digest);
    }
    assert_eq!(hash(&fs::read(binary).unwrap()), binary_hash);
    receipt.push_str("end_source_tool_binary_revalidation=passed\nstatus=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}
