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
const UPDATE_MAP: u16 = 0x0008;
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
            UPDATE_MAP if le32(d, 0) != 0 => {}
            SYNC | COMMIT | REDO | UPDATE_MAP => {
                return Err(bad("JFS native descriptor semantics"));
            }
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
    redo_lines_profile(record, blocks, r, false, apply)
}
fn redo_namespace_lines(
    record: &Record<'_>,
    blocks: u64,
    r: &Resources,
    apply: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    redo_lines_profile(record, blocks, r, true, apply)
}
fn redo_lines_profile(
    record: &Record<'_>,
    blocks: u64,
    r: &Resources,
    inline_data: bool,
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
        if (ty == 2 || ty == 0x12) && (offset == 0 && length != 32 || offset > 0 && offset < 32) {
            return Err(bad("JFS native xtree header/XAD line separation"));
        }
        if ty == 1
            && (!offset.is_multiple_of(512) || !(length == 128 || inline_data && length == 256))
        {
            return Err(bad("JFS native base-inode section line"));
        }
        let start = end - length - 4;
        // Native base+idata count-two strips the final32-byte BTROOT overlap.
        let applied = if ty == 1 && length == 256 {
            224
        } else {
            length
        };
        ranges.push((base + offset, start, applied));
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
// Native map records authorize physical allocation flips. List variants
// not replayed by jfsutils1.1.15 remain unsupported, even if their constants
// appear in headers. Every extent is checked before exposing any update.
fn map_extents(
    record: &Record<'_>,
    blocks: u64,
    cap: usize,
    work: u64,
    r: &Resources,
    apply: &mut dyn FnMut(super::super::Physical, bool) -> Result<()>,
) -> Result<()> {
    r.cancellation.check()?;
    if record.kind != UPDATE_MAP || record.tid == 0 {
        return Err(bad("JFS expected native allocation record"));
    }
    let ty = le16(record.detail, 8);
    let count = usize::from(le16(record.detail, 10));
    if count > i16::MAX as usize {
        return Err(bad("JFS negative native map extent count"));
    }
    if count == 0 || count > cap {
        return Err(budget("JFS native map extent ceiling"));
    }
    let effort = (count as u64)
        .checked_mul(u64::from(count.next_power_of_two().ilog2()) + 8)
        .filter(|n| *n <= work)
        .ok_or_else(|| budget("JFS native map extent work"))?;
    let _ = effort;
    let _lease = r.memory.reserve(
        (count as u64)
            .checked_mul(32)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| budget("JFS native map extent memory"))?,
    )?;
    let (allocated, width) = match ty {
        1 => (false, 0usize),
        16 => (true, 0),
        4 => (false, 8),
        8 => (false, 16),
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS native map subtype not replayed in this profile",
            ));
        }
    };
    if width == 0 && (count != 1 || !record.body.is_empty())
        || width != 0
            && record.body.len()
                != count
                    .checked_mul(width)
                    .ok_or_else(|| bad("JFS map list size overflow"))?
    {
        return Err(bad("JFS native map extent/body agreement"));
    }
    let mut extents = vector(count)?;
    for index in 0..count {
        r.cancellation.check()?;
        let physical = if width == 0 {
            pxd(record.detail, 12, blocks)?
        } else {
            let at = index * width;
            if width == 16 && record.body[at] & !8 != 0 {
                return Err(Error::new(ErrorKind::Unsupported, "JFS map XAD flags"));
            }
            pxd(record.body, at + width - 8, blocks)?
        };
        if physical.count == 0 {
            return Err(bad("JFS native empty map extent"));
        }
        extents.push(physical);
    }
    extents.sort_unstable_by_key(|extent| extent.start);
    if extents
        .windows(2)
        .any(|pair| pair[0].start + pair[0].count > pair[1].start)
    {
        return Err(bad("JFS native map list overlaps"));
    }
    for extent in extents {
        r.cancellation.check()?;
        apply(extent, allocated)?;
    }
    Ok(())
}
struct TransactionFields {
    tid: u32,
    backchain: u32,
    fileset: u32,
    inode: u32,
}

#[test]
fn authored_native_free_list_validates_every_extent_before_publication() {
    use super::super::Physical;
    let r = Resources {
        memory: Budget::new(65536),
        cancellation: Cancellation::default(),
    };
    let transaction = || TransactionFields {
        tid: 7,
        backchain: 0,
        fileset: 16,
        inode: 4,
    };
    let expected = [
        Physical {
            start: 90,
            count: 1,
        },
        Physical {
            start: 100,
            count: 1,
        },
        Physical {
            start: 102,
            count: 1,
        },
        Physical {
            start: 110,
            count: 1,
        },
    ];
    let unordered = [expected[3], expected[0], expected[2], expected[1]];
    let record = author_free_record(transaction(), &unordered, 480, 4096, &r).unwrap();
    assert_eq!(le16(&record.descriptor, 24), 4);
    assert_eq!(le16(&record.descriptor, 26), 4);
    assert_eq!(record.body.len(), 32);
    let mut page = [0; PAGE];
    page[..4].copy_from_slice(&1u32.to_le_bytes());
    page[6..8].copy_from_slice(&8u16.to_le_bytes());
    let header: [u8; 8] = page[..8].try_into().unwrap();
    page[TRAILER..].copy_from_slice(&header);
    append(&mut page, 3, &record.descriptor, &record.body).unwrap();
    let parsed = records(&page, 3, 8, &r).unwrap();
    let mut actual = Vec::new();
    map_extents(
        &parsed.records[0],
        480,
        4,
        4096,
        &r,
        &mut |extent, allocated| {
            assert!(!allocated);
            actual.push(extent);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(actual, expected);
    drop((parsed, record));
    assert_eq!(r.memory.used(), 0);
    for invalid in [
        vec![
            Physical {
                start: 90,
                count: 2,
            },
            Physical {
                start: 91,
                count: 1,
            },
        ],
        vec![Physical {
            start: 479,
            count: 2,
        }],
        vec![Physical {
            start: 90,
            count: 0,
        }],
        vec![Physical {
            start: 0,
            count: 1 << 24,
        }],
    ] {
        let blocks = if invalid[0].count == 1 << 24 {
            1 << 25
        } else {
            480
        };
        assert!(author_free_record(transaction(), &invalid, blocks, 4096, &r).is_err());
        assert_eq!(r.memory.used(), 0);
    }
    assert_eq!(
        author_free_record(transaction(), &expected, 480, 0, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    let low = Resources {
        memory: Budget::new(256),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        author_free_record(transaction(), &expected, 480, 4096, &low)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), 0);
    r.cancellation.cancel();
    assert_eq!(
        author_free_record(transaction(), &expected, 480, 4096, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
}
struct FreeRecord {
    descriptor: [u8; DESCRIPTOR],
    body: Vec<u8>,
    _lease: Reservation,
}
struct InodeRecord {
    descriptor: [u8; DESCRIPTOR],
    body: [u8; 132],
}
fn author_inode_record(
    transaction: TransactionFields,
    page: u64,
    after: &[u8; 128],
    blocks: u64,
    r: &Resources,
) -> Result<InodeRecord> {
    r.cancellation.check()?;
    if transaction.tid == 0
        || page >= blocks
        || page >= 1 << 40
        || le32(after, 4) != transaction.fileset
        || le32(after, 8) != transaction.inode
    {
        return Err(bad("JFS authored native inode identity/page"));
    }
    let mut descriptor = [0; DESCRIPTOR];
    descriptor[..4].copy_from_slice(&transaction.tid.to_le_bytes());
    descriptor[4..8].copy_from_slice(&transaction.backchain.to_le_bytes());
    descriptor[8..10].copy_from_slice(&REDO.to_le_bytes());
    descriptor[10..12].copy_from_slice(&132u16.to_le_bytes());
    descriptor[16..20].copy_from_slice(&transaction.fileset.to_le_bytes());
    descriptor[20..24].copy_from_slice(&transaction.inode.to_le_bytes());
    descriptor[24..26].copy_from_slice(&1u16.to_le_bytes());
    descriptor[26..28].copy_from_slice(&7u16.to_le_bytes());
    descriptor[28..32].copy_from_slice(&(1u32 | ((page >> 32) as u32) << 24).to_le_bytes());
    descriptor[32..].copy_from_slice(&(page as u32).to_le_bytes());
    let mut body = [0; 132];
    body[..128].copy_from_slice(after);
    body[128..130].copy_from_slice(&((transaction.inode & 7) as u16 * 4).to_le_bytes());
    body[130..].copy_from_slice(&1u16.to_le_bytes());
    Ok(InodeRecord { descriptor, body })
}
struct RootRecord {
    descriptor: [u8; DESCRIPTOR],
    body: Vec<u8>,
    _lease: Reservation,
}
fn author_root_record(
    tx: TransactionFields,
    home_page: u64,
    root: &[u8; 288],
    blocks: u64,
    r: &Resources,
) -> Result<RootRecord> {
    let next = usize::from(le16(root, 18));
    if tx.tid == 0 || !(2..=18).contains(&next) || home_page >= blocks {
        return Err(bad("JFS authored ROOT bounds"));
    }
    // Empty publication must overwrite the removed first XAD as a zero slot.
    let slots = (next - 2).max(1);
    let body_length = 40 + slots * 16;
    let lease = r.memory.reserve(4096)?;
    let mut descriptor = [0; DESCRIPTOR];
    descriptor[..4].copy_from_slice(&tx.tid.to_le_bytes());
    descriptor[4..8].copy_from_slice(&tx.backchain.to_le_bytes());
    descriptor[8..10].copy_from_slice(&REDO.to_le_bytes());
    descriptor[10..12].copy_from_slice(&(body_length as u16).to_le_bytes());
    descriptor[16..20].copy_from_slice(&tx.fileset.to_le_bytes());
    descriptor[20..24].copy_from_slice(&tx.inode.to_le_bytes());
    descriptor[24..26].copy_from_slice(&0x12u16.to_le_bytes());
    descriptor[26..28].copy_from_slice(&4u16.to_le_bytes());
    descriptor[28..32].copy_from_slice(&(1u32 | ((home_page >> 32) as u32) << 24).to_le_bytes());
    descriptor[32..36].copy_from_slice(&(home_page as u32).to_le_bytes());
    let mut body = vector(body_length)?;
    body.extend_from_slice(&root[..32]);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&root[32..32 + slots * 16]);
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&(slots as u16).to_le_bytes());
    let record = Record {
        end: 0,
        tid: tx.tid,
        backchain: tx.backchain,
        aggregate: 0,
        kind: REDO,
        detail: &descriptor[16..],
        body: &body,
    };
    redo_lines(&record, blocks, r, &mut |at, bytes| {
        let base = home_page * PAGE as u64 + u64::from(tx.inode & 7) * 512 + 224;
        let offset = at
            .checked_sub(base)
            .ok_or_else(|| bad("JFS ROOT author address"))? as usize;
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > 32 + slots * 16)
            || bytes != &root[offset..offset + bytes.len()]
        {
            return Err(bad("JFS ROOT author native vector mismatch"));
        }
        Ok(())
    })?;
    Ok(RootRecord {
        descriptor,
        body,
        _lease: lease,
    })
}

fn author_free_record(
    transaction: TransactionFields,
    extents: &[super::super::Physical],
    blocks: u64,
    work: u64,
    r: &Resources,
) -> Result<FreeRecord> {
    r.cancellation.check()?;
    if transaction.tid == 0 || extents.is_empty() || extents.len() > 256 {
        return Err(budget("JFS authored native free-list ceiling"));
    }
    if (extents.len() as u64) * (u64::from(extents.len().next_power_of_two().ilog2()) + 8) > work {
        return Err(budget("JFS authored native free-list work"));
    }
    let body_length = if extents.len() == 1 {
        0
    } else {
        extents.len() * 8
    };
    let lease = r
        .memory
        .reserve((extents.len() * 32 + body_length + 256) as u64)?;
    let mut ordered = vector(extents.len())?;
    for extent in extents {
        r.cancellation.check()?;
        if extent.count == 0
            || extent.count >= 1 << 24
            || extent.start >= 1 << 40
            || extent
                .start
                .checked_add(extent.count)
                .is_none_or(|end| end > blocks)
        {
            return Err(bad("JFS authored native free extent"));
        }
        ordered.push(*extent);
    }
    ordered.sort_unstable_by_key(|extent| extent.start);
    if ordered
        .windows(2)
        .any(|pair| pair[0].start + pair[0].count > pair[1].start)
    {
        return Err(bad("JFS authored native free-list overlap"));
    }
    let mut descriptor = [0; DESCRIPTOR];
    descriptor[..4].copy_from_slice(&transaction.tid.to_le_bytes());
    descriptor[4..8].copy_from_slice(&transaction.backchain.to_le_bytes());
    descriptor[8..10].copy_from_slice(&UPDATE_MAP.to_le_bytes());
    descriptor[10..12].copy_from_slice(&(body_length as u16).to_le_bytes());
    descriptor[16..20].copy_from_slice(&transaction.fileset.to_le_bytes());
    descriptor[20..24].copy_from_slice(&transaction.inode.to_le_bytes());
    descriptor[24..26]
        .copy_from_slice(&(if ordered.len() == 1 { 1u16 } else { 4u16 }).to_le_bytes());
    descriptor[26..28].copy_from_slice(&(ordered.len() as u16).to_le_bytes());
    let mut body = vector(body_length)?;
    for extent in ordered {
        r.cancellation.check()?;
        let mut encoded = [0; 8];
        encoded[..4].copy_from_slice(
            &((extent.count as u32) | ((extent.start >> 32) as u32) << 24).to_le_bytes(),
        );
        encoded[4..].copy_from_slice(&(extent.start as u32).to_le_bytes());
        if body_length == 0 {
            descriptor[28..].copy_from_slice(&encoded);
        } else {
            body.extend_from_slice(&encoded);
        }
    }
    Ok(FreeRecord {
        descriptor,
        body,
        _lease: lease,
    })
}
// Native FREEXADLIST retains logical offsets and recorded/unwritten flags.
fn old_data_runs(
    d: &[u8; DESCRIPTOR],
    body: &[u8],
    blocks: u64,
    work: u64,
    r: &Resources,
) -> Result<Vec<super::super::Run>> {
    let record = Record {
        end: 0,
        tid: le32(d, 0),
        backchain: le32(d, 4),
        aggregate: le32(d, 12),
        kind: le16(d, 8),
        detail: &d[16..],
        body,
    };
    if ![1, 8].contains(&le16(d, 24)) {
        return Err(bad("JFS inline old map subtype"));
    }
    map_extents(&record, blocks, 32, work, r, &mut |_, allocated| {
        if allocated {
            Err(bad("JFS old inline map allocates"))
        } else {
            Ok(())
        }
    })?;
    let count = usize::from(le16(d, 26));
    let mut runs = vector(count)?;
    for index in 0..count {
        r.cancellation.check()?;
        let (logical, physical, unwritten) = if le16(d, 24) == 1 {
            (0, pxd(d, 28, blocks)?, false)
        } else {
            let xad = &body[index * 16..(index + 1) * 16];
            if xad[1..3].iter().any(|byte| *byte != 0) {
                return Err(bad("JFS old XAD reserved bytes"));
            }
            (
                u64::from(xad[3]) << 32 | u64::from(le32(xad, 4)),
                pxd(xad, 8, blocks)?,
                xad[0] == 8,
            )
        };
        if logical
            .checked_add(physical.count)
            .is_none_or(|end| end > 32)
            || runs.last().is_some_and(|prior: &super::super::Run| {
                prior.logical + prior.physical.count > logical
            })
        {
            return Err(bad("JFS bounded old XAD logical ordering"));
        }
        runs.push(super::super::Run {
            logical,
            physical,
            unwritten,
        });
    }
    Ok(runs)
}
fn author_free_xads(
    tx: TransactionFields,
    xads: &[u8],
    blocks: u64,
    work: u64,
    r: &Resources,
) -> Result<FreeRecord> {
    if xads.is_empty() || xads.len() > 512 || !xads.len().is_multiple_of(16) {
        return Err(budget("JFS authored inline XAD ceiling"));
    }
    let lease = r.memory.reserve(4096)?;
    let mut descriptor = [0; DESCRIPTOR];
    descriptor[..4].copy_from_slice(&tx.tid.to_le_bytes());
    descriptor[4..8].copy_from_slice(&tx.backchain.to_le_bytes());
    descriptor[8..10].copy_from_slice(&UPDATE_MAP.to_le_bytes());
    descriptor[10..12].copy_from_slice(&(xads.len() as u16).to_le_bytes());
    descriptor[16..20].copy_from_slice(&tx.fileset.to_le_bytes());
    descriptor[20..24].copy_from_slice(&tx.inode.to_le_bytes());
    descriptor[24..26].copy_from_slice(&8u16.to_le_bytes());
    descriptor[26..28].copy_from_slice(&((xads.len() / 16) as u16).to_le_bytes());
    drop(old_data_runs(&descriptor, xads, blocks, work, r)?);
    let mut body = vector(xads.len())?;
    body.extend_from_slice(xads);
    Ok(FreeRecord {
        descriptor,
        body,
        _lease: lease,
    })
}
fn author_free_runs(
    tx: TransactionFields,
    runs: &[super::super::Run],
    blocks: u64,
    work: u64,
    r: &Resources,
) -> Result<FreeRecord> {
    if runs.is_empty() || runs.len() > 32 {
        return Err(budget("JFS authored old data run ceiling"));
    }
    let mut xads = [0u8; 512];
    for (index, run) in runs.iter().enumerate() {
        r.cancellation.check()?;
        if run.logical >= 1 << 40
            || run.physical.start >= 1 << 40
            || run.physical.count == 0
            || run.physical.count >= 1 << 24
        {
            return Err(bad("JFS authored old XAD field bounds"));
        }
        let at = index * 16;
        xads[at] = if run.unwritten { 8 } else { 0 };
        xads[at + 3] = (run.logical >> 32) as u8;
        xads[at + 4..at + 8].copy_from_slice(&(run.logical as u32).to_le_bytes());
        xads[at + 8..at + 12].copy_from_slice(
            &((run.physical.count as u32) | ((run.physical.start >> 32) as u32) << 24)
                .to_le_bytes(),
        );
        xads[at + 12..at + 16].copy_from_slice(&(run.physical.start as u32).to_le_bytes());
    }
    author_free_xads(tx, &xads[..runs.len() * 16], blocks, work, r)
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
    history_framing_profile(source, log, limits, r, reconcile, false)
}
fn history_framing_profile(
    source: &dyn DecodeRead,
    log: super::super::Physical,
    limits: HistoryLimits,
    r: &Resources,
    reconcile: bool,
    skip_initial_sync: bool,
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
        if ![SYNC, COMMIT, REDO, UPDATE_MAP].contains(&kind) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS native history record family not yet implemented",
            ));
        }
        if kind == SYNC && (length != 0 || le32(&descriptor, 0) != 0 || le32(&descriptor, 4) != 0)
            || kind == COMMIT && (length != 0 || le32(&descriptor, 0) == 0)
            || kind == REDO && (length < 4 || le32(&descriptor, 0) == 0)
            || kind == UPDATE_MAP && le32(&descriptor, 0) == 0
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
            if skip_initial_sync && records.len() == 1 {
                continue;
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
    let inode_record = author_inode_record(
        TransactionFields {
            tid: 1,
            backchain: 0,
            fileset: le32(&before, 4),
            inode,
        },
        page,
        &after,
        length / PAGE as u64,
        r,
    )?;
    let redo = append(
        &mut prepared,
        number,
        &inode_record.descriptor,
        &inode_record.body,
    )?;
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
    plan: Prepared,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    let before = plan.before;
    let after = plan.after;
    publish_inode_plan(storage, plan, &before, &after, original, r)
}
fn publish_inode_plan(
    storage: &mut dyn crate::storage::Storage,
    mut plan: Prepared,
    before: &[u8],
    after: &[u8],
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
        (plan.home, before),
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
        write_checked(storage, plan.home, after, original, r)?;
        flush_readback(storage, plan.home, after, original, r)?;
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
        let id = le32(after, 8);
        if resulting
            .nodes
            .get(&id)
            .is_none_or(|node| node.raw.get(..after.len()) != Some(after))
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
    let activating_active = (0..=16).any(|cut| {
        logs[68..68 + cut] == binding[..cut] && logs[68 + cut..84].iter().all(|v| *v == 0)
    });
    let clearing_active = (0..=16).any(|cut| {
        logs[68..68 + cut].iter().all(|byte| *byte == 0) && logs[68 + cut..84] == binding[cut..]
    });
    let legal_active = activating_active || clearing_active;
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
    if partial_serial && kind != REDO
        || partial_active
            && !(kind == REDO && activating_active
                || checkpointed
                    && clearing_active
                    && le32(&logs, 28) == 1
                    && le32(&logs, 32) == newest_end)
    {
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
    finish_metadata_recovery(
        storage,
        &home,
        RecoveryCleanup {
            page: (!checkpointed || repaired).then_some((page_at, page)),
            log_at,
            logs: cleanlogs,
            headers: projected,
            read,
            audit,
        },
        original,
        r,
    )
}
struct RecoveryCleanup {
    page: Option<(u64, [u8; PAGE])>,
    log_at: u64,
    logs: [u8; PAGE],
    headers: [[u8; PAGE]; 2],
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
}
fn finish_metadata_recovery(
    storage: &mut dyn crate::storage::Storage,
    home: &[(u64, Vec<u8>)],
    cleanup: RecoveryCleanup,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    let result = (|| {
        for (at, bytes) in home {
            write_checked(storage, *at, bytes, original, r)?;
        }
        if !home.is_empty() {
            for (at, bytes) in home {
                flush_readback(storage, *at, bytes, original, r)?;
            }
        }
        if let Some((at, page)) = &cleanup.page {
            write_checked(storage, *at, page, original, r)?;
            flush_readback(storage, *at, page, original, r)?;
        }
        write_checked(storage, cleanup.log_at, &cleanup.logs, original, r)?;
        flush_readback(storage, cleanup.log_at, &cleanup.logs, original, r)?;
        for (at, header) in [32768u64, 61440].into_iter().zip(&cleanup.headers) {
            write_checked(storage, at, header, original, r)?;
            flush_readback(storage, at, header, original, r)?;
        }
        drop(super::inspect_with(
            storage,
            cleanup.read,
            cleanup.audit,
            original,
            r,
        )?);
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

// Test-only native COW journal fixture authoring. This constructs actual
// BTROOT/XAD_NEW + UPDATEMAP FREE + COMMIT for an independent native replay
// oracle; it is not the owned COW transaction/public recovery API.

pub(super) struct PreparedCow {
    original_header: [[u8; PAGE]; 2],
    original_logs: [u8; PAGE],
    before_page: [u8; PAGE],
    prepared: [u8; PAGE],
    committed: [u8; PAGE],
    header: [[u8; PAGE]; 2],
    logs: [u8; PAGE],
    page_at: u64,
    log_at: u64,
    home: u64,
    before: [u8; 512],
    old_runs: Vec<super::super::Run>,
    old_pages: Vec<super::super::Physical>,
    new: u64,
    blocks: u32,
    inode: u32,
    length: u64,
    file: std::sync::Arc<dyn FileRead>,
    identity: ObjectId,
    payload_length: u64,
    source_length: u64,
    range: Option<RangeRecipe>,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    _maps: super::allocation::MapPlan,
    _lease: Reservation,
}
struct RangeRecipe {
    old_length: u64,
    offset: u64,
    runs: Vec<super::super::Run>,
}
pub(super) struct CowRequest {
    pub(super) inode: u32,
    pub(super) new: u64,
    pub(super) file: std::sync::Arc<dyn FileRead>,
}
pub(super) fn prepare_cow(
    storage: &dyn crate::storage::Storage,
    request: CowRequest,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<PreparedCow> {
    prepare_cow_inner(
        storage,
        request,
        read,
        audit,
        original,
        r,
        CowMode::Replace(false),
    )
}
pub(super) fn prepare_cow_resized(
    storage: &dyn crate::storage::Storage,
    request: CowRequest,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<PreparedCow> {
    prepare_cow_inner(
        storage,
        request,
        read,
        audit,
        original,
        r,
        CowMode::Replace(true),
    )
}
pub(super) enum CowMode {
    Replace(bool),
    Range(u64),
}
pub(super) fn prepare_cow_range(
    storage: &dyn crate::storage::Storage,
    request: CowRequest,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
    offset: u64,
) -> Result<PreparedCow> {
    prepare_cow_inner(
        storage,
        request,
        read,
        audit,
        original,
        r,
        CowMode::Range(offset),
    )
}
fn prepare_cow_inner(
    storage: &dyn crate::storage::Storage,
    request: CowRequest,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
    mode: CowMode,
) -> Result<PreparedCow> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let source = super::Borrowed {
        storage,
        length: storage
            .len()
            .map_err(|e| Error::io("JFS COW preparation length", e))?,
        resources: original,
    };
    prepare_cow_source(&source, request, read, audit, original, r, mode)
}
fn prepare_cow_source(
    source: &dyn DecodeRead,
    request: CowRequest,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
    mode: CowMode,
) -> Result<PreparedCow> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let CowRequest { inode, new, file } = request;
    if file.identity().native.len() > 4096 {
        return Err(budget("JFS COW source identity ceiling"));
    }
    let lease = r
        .memory
        .reserve(65536 + file.identity().native.len() as u64)?;
    let declared = file.identity();
    let mut native = vector(declared.native.len())?;
    native.extend_from_slice(&declared.native);
    let identity = ObjectId {
        source: declared.source,
        generation: declared.generation,
        native,
    };
    let baseline = super::super::decode(source, read, r)?;
    if !crate::fs_jfs_audit::audit_decoded(&baseline, audit, r)?.is_clean() {
        return Err(bad("JFS COW projected source ownership"));
    }
    let node = baseline
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS native COW fixture inode"))?;
    let old_data_blocks: u64 = node.runs.iter().map(|run| run.physical.count).sum();
    let old_blocks = old_data_blocks + node.pages.iter().map(|page| page.count).sum::<u64>();
    let old_logical_end = node
        .runs
        .last()
        .map_or(0, |run| run.logical + run.physical.count);
    let source_length = file.len();
    let (payload_length, range_offset) = match mode {
        CowMode::Replace(_) => (source_length, None),
        CowMode::Range(offset) => {
            if source_length == 0 {
                return Err(bad("JFS empty range replacement"));
            }
            let end = offset
                .checked_add(source_length)
                .ok_or_else(|| bad("JFS range EOF overflow"))?;
            (node.length.max(end), Some(offset))
        }
    };
    let blocks = payload_length.div_ceil(PAGE as u64);
    if node.directory
        || node.runs.is_empty()
        || node.runs.len() > 32
        || blocks == 0 && !(matches!(mode, CowMode::Replace(true)) && new == 0)
        || blocks > 32
        || old_blocks == 0
        || old_blocks > 32
        || node.length == 0
        || node.length.div_ceil(4096) != old_logical_end
        || old_logical_end > 32
        || node.pages.len() > 8
        || new
            .checked_add(blocks)
            .is_none_or(|end| end > baseline.geometry.mapped)
        || (new..new.saturating_add(blocks)).any(|block| baseline.bitmap[block as usize])
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native COW bounded regular extent tree",
        ));
    }
    if matches!(mode, CowMode::Replace(false)) && payload_length != node.length {
        return Err(bad("JFS COW replacement source length"));
    }
    let mut old_runs = vector(node.runs.len())?;
    old_runs.extend(node.runs.iter().cloned());
    let mut old_pages = vector(node.pages.len())?;
    old_pages.extend_from_slice(&node.pages);
    let range = if let Some(offset) = range_offset {
        let mut runs = vector(node.runs.len())?;
        runs.extend(node.runs.iter().cloned());
        Some(RangeRecipe {
            old_length: node.length,
            offset,
            runs,
        })
    } else {
        None
    };
    let length = source.length()?;
    let before: [u8; 512] = node
        .raw
        .as_slice()
        .try_into()
        .map_err(|_| bad("JFS COW inode size"))?;
    let old = node.runs[0].physical.start;
    let mut root = [0u8; 288];
    root.copy_from_slice(&node.raw[224..]);
    root[16] = (root[16] & !6) | 2;
    root[18..20].copy_from_slice(&(if blocks == 0 { 2u16 } else { 3 }).to_le_bytes());
    root[32..48].fill(0);
    root[32] = 1; // native transient XAD_NEW: replay allocates and clears it.
    root[40..44].copy_from_slice(&((blocks as u32) | ((new >> 32) as u32) << 24).to_le_bytes());
    root[44..48].copy_from_slice(&(new as u32).to_le_bytes());
    if blocks == 0 {
        root[18..20].copy_from_slice(&2u16.to_le_bytes());
        root[32..48].fill(0);
    }
    let extent = pxd(&node.raw, 16, baseline.geometry.blocks)?;
    let home_page = extent.start + u64::from((inode & 31) / 8);
    let mut header = [baseline.header, baseline.header];
    source.exact(61440, &mut header[1])?;
    let log = pxd(&header[0], 72, baseline.geometry.blocks)?;
    let mut logs = [0; PAGE];
    source.exact((log.start + 1) * PAGE as u64, &mut logs)?;
    let end = le32(&logs, 32);
    let number = end / PAGE as u32;
    let mut page = [0; PAGE];
    source.exact((log.start + u64::from(number)) * PAGE as u64, &mut page)?;
    if usize::from(le16(&page, 6)) != (end % PAGE as u32) as usize {
        return Err(bad("JFS fixture established log end"));
    }
    let before_page = page;
    let original_header = header;
    let original_logs = logs;
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let old_root_record = if node.pages.is_empty() {
        0
    } else {
        let old_root: [u8; 288] = before[224..512].try_into().unwrap();
        let record = author_root_record(
            TransactionFields {
                tid: 7,
                backchain: 0,
                fileset: le32(&node.raw, 4),
                inode,
            },
            home_page,
            &old_root,
            baseline.geometry.blocks,
            r,
        )?;
        append(&mut page, number, &record.descriptor, &record.body)?
    };
    let mut inode_after: [u8; 128] = before[..128].try_into().unwrap();
    inode_after[24..32].copy_from_slice(&payload_length.to_le_bytes());
    inode_after[32..40].copy_from_slice(&blocks.to_le_bytes());
    let inode_redo = if payload_length != node.length || blocks != old_blocks {
        let inode_record = author_inode_record(
            TransactionFields {
                tid: 7,
                backchain: old_root_record,
                fileset: le32(&node.raw, 4),
                inode,
            },
            home_page,
            &inode_after,
            baseline.geometry.blocks,
            r,
        )?;
        append(
            &mut page,
            number,
            &inode_record.descriptor,
            &inode_record.body,
        )?
    } else {
        old_root_record
    };
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&inode_redo.to_le_bytes());
    d[8..10].copy_from_slice(&REDO.to_le_bytes());
    d[10..12].copy_from_slice(&56u16.to_le_bytes());
    d[16..20].copy_from_slice(&le32(&node.raw, 4).to_le_bytes());
    d[20..24].copy_from_slice(&inode.to_le_bytes());
    d[24..26].copy_from_slice(&0x12u16.to_le_bytes());
    d[26..28].copy_from_slice(&4u16.to_le_bytes());
    d[28..32].copy_from_slice(&(1u32 | ((home_page >> 32) as u32) << 24).to_le_bytes());
    d[32..].copy_from_slice(&(home_page as u32).to_le_bytes());
    let mut body = [0; 56];
    body[..32].copy_from_slice(&root[..32]);
    body[34..36].copy_from_slice(&2u16.to_le_bytes());
    body[36..52].copy_from_slice(&root[32..48]);
    body[52..54].copy_from_slice(&2u16.to_le_bytes());
    body[54..56].copy_from_slice(&1u16.to_le_bytes());
    let redo = append(&mut page, number, &d, &body)?;
    let tx = TransactionFields {
        tid: 7,
        backchain: redo,
        fileset: le32(&node.raw, 4),
        inode,
    };
    let free = if node.pages.is_empty()
        && node.runs.len() == 1
        && node.runs[0].logical == 0
        && !node.runs[0].unwritten
    {
        author_free_record(
            tx,
            &[super::super::Physical {
                start: old,
                count: old_blocks,
            }],
            baseline.geometry.mapped,
            read.work,
            r,
        )?
    } else if !node.pages.is_empty() {
        author_free_runs(tx, &node.runs, baseline.geometry.mapped, read.work, r)?
    } else {
        author_free_xads(
            tx,
            &node.raw[256..256 + node.runs.len() * 16],
            baseline.geometry.mapped,
            read.work,
            r,
        )?
    };
    let mapping = append(&mut page, number, &free.descriptor, &free.body)?;
    drop(free);
    let mapping = if node.pages.is_empty() {
        mapping
    } else {
        let metadata = author_free_record(
            TransactionFields {
                tid: 7,
                backchain: mapping,
                fileset: le32(&node.raw, 4),
                inode,
            },
            &node.pages,
            baseline.geometry.mapped,
            read.work,
            r,
        )?;
        append(&mut page, number, &metadata.descriptor, &metadata.body)?
    };
    let prepared = page;
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&mapping.to_le_bytes());
    d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let committed = page;
    let parsed = records(&page, number, 64, r)?;
    assert_eq!(parsed.records[0].kind, COMMIT);
    let data_at = if node.pages.is_empty() { 1 } else { 2 };
    map_extents(
        &parsed.records[data_at],
        baseline.geometry.mapped,
        32,
        read.work,
        r,
        &mut |range, allocated| {
            if allocated || !node.runs.iter().any(|run| run.physical == range) {
                return Err(bad("JFS COW fixture free record"));
            }
            Ok(())
        },
    )?;
    redo_lines(
        &parsed.records[data_at + 1],
        baseline.geometry.blocks,
        r,
        &mut |at, bytes| {
            let base = home_page * 4096 + u64::from(inode & 7) * 512 + 224;
            let offset =
                at.checked_sub(base)
                    .ok_or_else(|| bad("JFS COW fixture root address"))? as usize;
            if offset.checked_add(bytes.len()).is_none_or(|end| end > 48)
                || bytes != &root[offset..offset + bytes.len()]
            {
                return Err(bad("JFS COW fixture root line"));
            }
            Ok(())
        },
    )?;
    drop(parsed);
    let serial = le32(&logs, 8)
        .checked_add(1)
        .ok_or_else(|| bad("JFS fixture serial wrap"))?;
    logs[8..12].copy_from_slice(&serial.to_le_bytes());
    logs[28..32].fill(0);
    logs[68..84].copy_from_slice(&header[0][136..152]);
    for block in &mut header {
        block[40..44].copy_from_slice(&1u32.to_le_bytes());
        block[68..72].copy_from_slice(&serial.to_le_bytes());
    }
    let mut after = before;
    after[..128].copy_from_slice(&inode_after);
    after[224..].copy_from_slice(&root);
    after[256] = 0;
    let home_at = home_page * PAGE as u64 + u64::from(inode & 7) * 512;

    let mut changes = vector((blocks + old_blocks) as usize)?;
    for run in &node.runs {
        for offset in 0..run.physical.count {
            changes.push((run.physical.start + offset, false));
        }
    }
    for page in &node.pages {
        for offset in 0..page.count {
            changes.push((page.start + offset, false));
        }
    }
    for offset in 0..blocks {
        changes.push((new + offset, true));
    }
    let maps = super::allocation::prepare_map(source, &baseline, &changes, r)?;
    let mut patches = vector(maps.pages.len() + 1)?;
    patches.push((home_at, super::super::copied(&after)?));
    for map in &maps.pages {
        patches.push((map.at, super::super::copied(&map.after)?));
    }
    let projected = super::super::decode(
        &super::SourceOverlay {
            source,
            patches: &patches,
        },
        read,
        r,
    )?;
    if !crate::fs_jfs_audit::audit_decoded(&projected, audit, r)?.is_clean() {
        return Err(bad("JFS COW preparation complete ownership"));
    }
    drop(projected);
    drop((patches, baseline));
    if file.identity() != &identity || file.len() != source_length {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS COW deferred source changed",
        ));
    }
    original.cancellation.check()?;
    r.cancellation.check()?;
    if source.length()? != length {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS COW projected geometry changed",
        ));
    }
    Ok(PreparedCow {
        original_header,
        original_logs,
        before_page,
        prepared,
        committed,
        header,
        logs,
        page_at: (log.start + u64::from(number)) * PAGE as u64,
        log_at: (log.start + 1) * PAGE as u64,
        home: home_at,
        before,
        old_runs,
        old_pages,
        new,
        blocks: blocks as u32,
        inode,
        length,
        file,
        identity,
        payload_length,
        source_length,
        range,
        read,
        audit,
        _maps: maps,
        _lease: lease,
    })
}

pub(super) struct RotatingCow {
    rotation: rollover::Plan,
    cow: PreparedCow,
}
pub(super) fn prepare_rotating_cow(
    storage: &dyn crate::storage::Storage,
    binding: [u8; 16],
    request: CowRequest,
    limits: (
        super::super::JfsReadLimits,
        crate::fs_jfs_audit::JfsAuditLimits,
    ),
    original: &Resources,
    r: &Resources,
    mode: CowMode,
) -> Result<RotatingCow> {
    prepare_rotating_profile(
        storage,
        binding,
        request,
        limits,
        original,
        r,
        (mode, false),
    )
}

pub(super) fn prepare_recycling_cow(
    storage: &dyn crate::storage::Storage,
    binding: [u8; 16],
    request: CowRequest,
    limits: (
        super::super::JfsReadLimits,
        crate::fs_jfs_audit::JfsAuditLimits,
    ),
    original: &Resources,
    r: &Resources,
    mode: CowMode,
) -> Result<RotatingCow> {
    prepare_rotating_profile(storage, binding, request, limits, original, r, (mode, true))
}

fn prepare_rotating_profile(
    storage: &dyn crate::storage::Storage,
    binding: [u8; 16],
    request: CowRequest,
    limits: (
        super::super::JfsReadLimits,
        crate::fs_jfs_audit::JfsAuditLimits,
    ),
    original: &Resources,
    r: &Resources,
    profile: (CowMode, bool),
) -> Result<RotatingCow> {
    let (mode, recycling) = profile;
    let (read, audit) = limits;
    let prepare = if recycling {
        rollover::prepare_recycling
    } else {
        rollover::prepare
    };
    let rotation = prepare(storage, binding, read, audit, original, r, false)?;
    let patches = rotation.projection()?;
    let source = super::Borrowed {
        storage,
        length: storage
            .len()
            .map_err(|e| Error::io("JFS rotating COW length", e))?,
        resources: original,
    };
    let overlay = super::SourceOverlay {
        source: &source,
        patches: &patches,
    };
    let cow = prepare_cow_source(&overlay, request, read, audit, original, r, mode)?;
    Ok(RotatingCow { rotation, cow })
}
pub(super) fn publish_rotating_cow(
    storage: &mut dyn crate::storage::Storage,
    plan: RotatingCow,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    source_length_check(storage, plan.cow.length)?;
    if plan.cow.file.identity() != &plan.cow.identity
        || plan.cow.file.len() != plan.cow.source_length
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS rotating COW deferred source changed",
        ));
    }
    let current = super::inspect_with(storage, plan.cow.read, plan.cow.audit, original, r)?;
    let node = current
        .nodes
        .get(&plan.cow.inode)
        .ok_or_else(|| bad("JFS rotating COW source inode absent"))?;
    if node.raw != plan.cow.before
        || node.runs.len() != plan.cow.old_runs.len()
        || node.runs.iter().zip(&plan.cow.old_runs).any(|(a, b)| {
            a.logical != b.logical || a.physical != b.physical || a.unwritten != b.unwritten
        })
        || node.pages != plan.cow.old_pages
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS rotating COW native extent graph changed",
        ));
    }
    drop(current);
    for page in &plan.cow._maps.pages {
        let mut actual = [0; PAGE];
        storage
            .read_exact_at(page.at, &mut actual)
            .map_err(|e| Error::io("JFS rotating COW map preflight", e))?;
        if actual != page.before {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS rotating COW native map changed",
            ));
        }
    }
    rollover::publish(storage, plan.rotation, original, r)?;
    publish_cow(storage, plan.cow, original, r).map_err(|mut error| {
        error.kind = ErrorKind::UncertainDurability;
        error.context = format!(
            "JFS rotating COW checkpoint published; explicit recovery required: {}",
            error.context
        );
        error
    })
}
pub(super) fn recover_rotating_cow(
    storage: &mut dyn crate::storage::Storage,
    binding: [u8; 16],
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    match recover_cow(storage, binding, read, audit, original, r) {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported) => {
            let plan = rollover::prepare(storage, binding, read, audit, original, r, true)?;
            rollover::publish(storage, plan, original, r)
        }
        Err(error) => Err(error),
    }
}
pub(super) fn recover_recycling_cow(
    storage: &mut dyn crate::storage::Storage,
    binding: [u8; 16],
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    match recover_cow(storage, binding, read, audit, original, r) {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.kind, ErrorKind::InvalidData | ErrorKind::Unsupported) => {
            let plan =
                rollover::prepare_recycling(storage, binding, read, audit, original, r, true)?;
            rollover::publish(storage, plan, original, r)
        }
        Err(error) => Err(error),
    }
}

fn fill_cow_payload(
    storage: &dyn crate::storage::Storage,
    plan: &PreparedCow,
    base: u64,
    out: &mut [u8; PAGE],
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    out.fill(0);
    let end = plan.payload_length.min(base + PAGE as u64);
    let (replacement_start, replacement_end) = if let Some(recipe) = &plan.range {
        let source = super::Borrowed {
            storage,
            length: plan.length,
            resources: original,
        };
        for run in &recipe.runs {
            r.cancellation.check()?;
            if run.unwritten {
                continue;
            }
            let left = base.max(run.logical * PAGE as u64);
            let right = end
                .min(recipe.old_length)
                .min((run.logical + run.physical.count) * PAGE as u64);
            if left < right {
                source.exact(
                    run.physical.start * PAGE as u64 + left - run.logical * PAGE as u64,
                    &mut out[(left - base) as usize..(right - base) as usize],
                )?;
            }
        }
        (recipe.offset, recipe.offset + plan.source_length)
    } else {
        (0, plan.source_length)
    };
    let left = base.max(replacement_start);
    let right = end.min(replacement_end);
    let mut position = left;
    while position < right {
        original.cancellation.check()?;
        r.cancellation.check()?;
        let n = plan.file.read_at(
            position - replacement_start,
            &mut out[(position - base) as usize..(right - base) as usize],
            r,
        )?;
        if n == 0 || n as u64 > right - position {
            return Err(bad("JFS COW deferred source progress"));
        }
        position += n as u64;
        if plan.file.identity() != &plan.identity || plan.file.len() != plan.source_length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS COW deferred source changed during read",
            ));
        }
    }
    source_length_check(storage, plan.length)?;
    original.cancellation.check()?;
    r.cancellation.check()?;
    Ok(())
}
pub(super) fn publish_cow(
    storage: &mut dyn crate::storage::Storage,
    plan: PreparedCow,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    source_length_check(storage, plan.length)?;
    if plan.file.identity() != &plan.identity || plan.file.len() != plan.source_length {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS COW publication source changed",
        ));
    }
    let _scratch = r.memory.reserve(16384)?;
    let current = super::inspect_with(storage, plan.read, plan.audit, original, r)?;
    if current.nodes.get(&plan.inode).is_none_or(|node| {
        node.raw != plan.before
            || node.pages != plan.old_pages
            || node.runs.len() != plan.old_runs.len()
            || node.runs.iter().zip(&plan.old_runs).any(|(a, b)| {
                a.logical != b.logical || a.physical != b.physical || a.unwritten != b.unwritten
            })
    }) {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS COW native inode or extent graph changed",
        ));
    }
    drop(current);
    let source = super::Borrowed {
        storage,
        length: plan.length,
        resources: original,
    };
    let mut observed = [0; PAGE];
    for (at, expected) in [32768u64, 61440]
        .into_iter()
        .zip(&plan.original_header)
        .chain([
            (plan.log_at, &plan.original_logs),
            (plan.page_at, &plan.before_page),
        ])
    {
        source.exact(at, &mut observed)?;
        if observed != *expected {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS COW native publication metadata changed",
            ));
        }
    }
    for map in &plan._maps.pages {
        source.exact(map.at, &mut observed)?;
        if observed != map.before {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS COW allocation preimage changed",
            ));
        }
    }
    let mut payload = [0; PAGE];
    fill_cow_payload(storage, &plan, 0, &mut payload, original, r)?;
    source_length_check(storage, plan.length)?;
    original.cancellation.check()?;
    r.cancellation.check()?;
    let result = (|| {
        // The initialized new block is flushed/read back before the native
        // transaction becomes committed. The old inode stays authoritative.
        if plan.blocks != 0 {
            write_checked(storage, plan.new * PAGE as u64, &payload, original, r)?;
            flush_readback(storage, plan.new * PAGE as u64, &payload, original, r)?;
        }
        for block in 1..u64::from(plan.blocks) {
            fill_cow_payload(
                storage,
                &plan,
                block * PAGE as u64,
                &mut payload,
                original,
                r,
            )?;
            write_checked(
                storage,
                (plan.new + block) * PAGE as u64,
                &payload,
                original,
                r,
            )?;
            flush_readback(
                storage,
                (plan.new + block) * PAGE as u64,
                &payload,
                original,
                r,
            )?;
        }
        if plan.file.identity() != &plan.identity || plan.file.len() != plan.source_length {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFS COW source changed after payload publication",
            ));
        }
        write_checked(storage, plan.page_at, &plan.prepared, original, r)?;
        flush_readback(storage, plan.page_at, &plan.prepared, original, r)?;
        for (at, header) in [32768u64, 61440].into_iter().zip(&plan.header) {
            write_checked(storage, at, header, original, r)?;
            flush_readback(storage, at, header, original, r)?;
        }
        write_checked(storage, plan.log_at, &plan.logs, original, r)?;
        flush_readback(storage, plan.log_at, &plan.logs, original, r)?;
        write_checked(storage, plan.page_at, &plan.committed, original, r)?;
        flush_readback(storage, plan.page_at, &plan.committed, original, r)?;
        let mut binding = [0; 16];
        binding.copy_from_slice(&plan.header[0][136..152]);
        recover_cow(storage, binding, plan.read, plan.audit, original, r)?;
        let mut home = [0; 512];
        storage
            .read_exact_at(plan.home, &mut home)
            .map_err(|e| Error::io("JFS COW final inode", e))?;
        if home[256] != 0 {
            return Err(bad("JFS COW transient flag remained"));
        }
        Ok(())
    })();
    result.map_err(|mut error: Error| {
        error.kind = ErrorKind::UncertainDurability;
        error.context = format!(
            "JFS native COW publication requires recovery: {}",
            error.context
        );
        error
    })
}
pub(super) fn author_cow_log_fixture(
    storage: &mut dyn crate::storage::Storage,
    inode: u32,
    new: u64,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    r: &Resources,
) -> Result<()> {
    let _lease = r.memory.reserve(65536)?;
    let baseline = super::inspect(storage, read, audit, r)?;
    let node = baseline
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS native COW fixture inode"))?;
    if node.directory
        || node.runs.len() != 1
        || node.runs[0].logical != 0
        || node.runs[0].physical.count != 1
        || node.runs[0].unwritten
        || node.length == 0
        || node.length > 4096
        || !node.pages.is_empty()
        || new >= baseline.geometry.mapped
        || baseline.bitmap[new as usize]
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native COW fixture one inline recorded block",
        ));
    }
    let old = node.runs[0].physical.start;
    let mut root = [0u8; 288];
    root.copy_from_slice(&node.raw[224..]);
    root[32] = 1; // native transient XAD_NEW: replay allocates and clears it.
    root[40..44].copy_from_slice(&(1u32 | ((new >> 32) as u32) << 24).to_le_bytes());
    root[44..48].copy_from_slice(&(new as u32).to_le_bytes());
    let extent = pxd(&node.raw, 16, baseline.geometry.blocks)?;
    let home_page = extent.start + u64::from((inode & 31) / 8);
    let mut header = [baseline.header, baseline.header];
    storage
        .read_exact_at(61440, &mut header[1])
        .map_err(|e| Error::io("JFS fixture secondary superblock", e))?;
    let log = pxd(&header[0], 72, baseline.geometry.blocks)?;
    let mut logs = [0; PAGE];
    storage
        .read_exact_at((log.start + 1) * PAGE as u64, &mut logs)
        .map_err(|e| Error::io("JFS fixture log super", e))?;
    let end = le32(&logs, 32);
    let number = end / PAGE as u32;
    let mut page = [0; PAGE];
    storage
        .read_exact_at((log.start + u64::from(number)) * PAGE as u64, &mut page)
        .map_err(|e| Error::io("JFS fixture log page", e))?;
    if usize::from(le16(&page, 6)) != (end % PAGE as u32) as usize {
        return Err(bad("JFS fixture established log end"));
    }
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[8..10].copy_from_slice(&REDO.to_le_bytes());
    d[10..12].copy_from_slice(&56u16.to_le_bytes());
    d[16..20].copy_from_slice(&le32(&node.raw, 4).to_le_bytes());
    d[20..24].copy_from_slice(&inode.to_le_bytes());
    d[24..26].copy_from_slice(&0x12u16.to_le_bytes());
    d[26..28].copy_from_slice(&4u16.to_le_bytes());
    d[28..32].copy_from_slice(&(1u32 | ((home_page >> 32) as u32) << 24).to_le_bytes());
    d[32..].copy_from_slice(&(home_page as u32).to_le_bytes());
    let mut body = [0; 56];
    body[..32].copy_from_slice(&root[..32]);
    body[34..36].copy_from_slice(&2u16.to_le_bytes());
    body[36..52].copy_from_slice(&root[32..48]);
    body[52..54].copy_from_slice(&2u16.to_le_bytes());
    body[54..56].copy_from_slice(&1u16.to_le_bytes());
    let redo = append(&mut page, number, &d, &body)?;
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&redo.to_le_bytes());
    d[8..10].copy_from_slice(&UPDATE_MAP.to_le_bytes());
    d[16..20].copy_from_slice(&le32(&node.raw, 4).to_le_bytes());
    d[20..24].copy_from_slice(&inode.to_le_bytes());
    d[24..26].copy_from_slice(&1u16.to_le_bytes());
    d[26..28].copy_from_slice(&1u16.to_le_bytes());
    d[28..32].copy_from_slice(&(1u32 | ((old >> 32) as u32) << 24).to_le_bytes());
    d[32..].copy_from_slice(&(old as u32).to_le_bytes());
    let mapping = append(&mut page, number, &d, &[])?;
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&mapping.to_le_bytes());
    d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let parsed = records(&page, number, 64, r)?;
    assert_eq!(parsed.records[0].kind, COMMIT);
    map_extents(
        &parsed.records[1],
        baseline.geometry.mapped,
        1,
        100,
        r,
        &mut |range, allocated| {
            if allocated || range.start != old || range.count != 1 {
                return Err(bad("JFS COW fixture free record"));
            }
            Ok(())
        },
    )?;
    redo_lines(
        &parsed.records[2],
        baseline.geometry.blocks,
        r,
        &mut |at, bytes| {
            let base = home_page * 4096 + u64::from(inode & 7) * 512 + 224;
            let offset =
                at.checked_sub(base)
                    .ok_or_else(|| bad("JFS COW fixture root address"))? as usize;
            if offset.checked_add(bytes.len()).is_none_or(|end| end > 48)
                || bytes != &root[offset..offset + bytes.len()]
            {
                return Err(bad("JFS COW fixture root line"));
            }
            Ok(())
        },
    )?;
    drop(parsed);
    let serial = le32(&logs, 8)
        .checked_add(1)
        .ok_or_else(|| bad("JFS fixture serial wrap"))?;
    logs[8..12].copy_from_slice(&serial.to_le_bytes());
    logs[28..32].fill(0);
    logs[68..84].copy_from_slice(&header[0][136..152]);
    for block in &mut header {
        block[40..44].copy_from_slice(&1u32.to_le_bytes());
        block[68..72].copy_from_slice(&serial.to_le_bytes());
    }
    drop(baseline);
    write_checked(storage, (log.start + u64::from(number)) * 4096, &page, r, r)?;
    write_checked(storage, (log.start + 1) * 4096, &logs, r, r)?;
    for (at, block) in [32768u64, 61440].into_iter().zip(&header) {
        write_checked(storage, at, block, r, r)?;
    }
    storage
        .flush()
        .map_err(|e| Error::io("JFS native fixture flush", e))?;
    Ok(())
}

pub(super) fn author_cow_overlap_fixture(
    storage: &mut dyn crate::storage::Storage,
    inode: u32,
    new: u64,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    r: &Resources,
) -> Result<()> {
    let _lease = r.memory.reserve(65536)?;
    let baseline = super::inspect(storage, read, audit, r)?;
    let node = baseline
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS native COW fixture inode"))?;
    if node.directory
        || node.runs.len() != 1
        || node.runs[0].logical != 0
        || node.runs[0].physical.count != 1
        || node.runs[0].unwritten
        || node.length == 0
        || node.length > 4096
        || !node.pages.is_empty()
        || new >= baseline.geometry.mapped
        || baseline.bitmap[new as usize]
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS native COW fixture one inline recorded block",
        ));
    }
    let old = node.runs[0].physical.start;
    let mut root = [0u8; 288];
    root.copy_from_slice(&node.raw[224..]);
    root[32] = 1; // native transient XAD_NEW: replay allocates and clears it.
    root[40..44].copy_from_slice(&(1u32 | ((new >> 32) as u32) << 24).to_le_bytes());
    root[44..48].copy_from_slice(&(new as u32).to_le_bytes());
    let extent = pxd(&node.raw, 16, baseline.geometry.blocks)?;
    let home_page = extent.start + u64::from((inode & 31) / 8);
    let mut header = [baseline.header, baseline.header];
    storage
        .read_exact_at(61440, &mut header[1])
        .map_err(|e| Error::io("JFS fixture secondary superblock", e))?;
    let log = pxd(&header[0], 72, baseline.geometry.blocks)?;
    let mut logs = [0; PAGE];
    storage
        .read_exact_at((log.start + 1) * PAGE as u64, &mut logs)
        .map_err(|e| Error::io("JFS fixture log super", e))?;
    let end = le32(&logs, 32);
    let number = end / PAGE as u32;
    let mut page = [0; PAGE];
    storage
        .read_exact_at((log.start + u64::from(number)) * PAGE as u64, &mut page)
        .map_err(|e| Error::io("JFS fixture log page", e))?;
    if usize::from(le16(&page, 6)) != (end % PAGE as u32) as usize {
        return Err(bad("JFS fixture established log end"));
    }
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let old_root: [u8; 288] = node.raw[224..512].try_into().unwrap();
    let old_record = author_root_record(
        TransactionFields {
            tid: 7,
            backchain: 0,
            fileset: le32(&node.raw, 4),
            inode,
        },
        home_page,
        &old_root,
        baseline.geometry.blocks,
        r,
    )?;
    let old_redo = append(&mut page, number, &old_record.descriptor, &old_record.body)?;
    let new_record = author_root_record(
        TransactionFields {
            tid: 7,
            backchain: old_redo,
            fileset: le32(&node.raw, 4),
            inode,
        },
        home_page,
        &root,
        baseline.geometry.blocks,
        r,
    )?;
    let redo = append(&mut page, number, &new_record.descriptor, &new_record.body)?;
    drop((old_record, new_record));
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&redo.to_le_bytes());
    d[8..10].copy_from_slice(&UPDATE_MAP.to_le_bytes());
    d[16..20].copy_from_slice(&le32(&node.raw, 4).to_le_bytes());
    d[20..24].copy_from_slice(&inode.to_le_bytes());
    d[24..26].copy_from_slice(&1u16.to_le_bytes());
    d[26..28].copy_from_slice(&1u16.to_le_bytes());
    d[28..32].copy_from_slice(&(1u32 | ((old >> 32) as u32) << 24).to_le_bytes());
    d[32..].copy_from_slice(&(old as u32).to_le_bytes());
    let mapping = append(&mut page, number, &d, &[])?;
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&mapping.to_le_bytes());
    d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let parsed = records(&page, number, 64, r)?;
    assert_eq!(parsed.records[0].kind, COMMIT);
    map_extents(
        &parsed.records[1],
        baseline.geometry.mapped,
        1,
        100,
        r,
        &mut |range, allocated| {
            if allocated || range.start != old || range.count != 1 {
                return Err(bad("JFS COW fixture free record"));
            }
            Ok(())
        },
    )?;
    redo_lines(
        &parsed.records[2],
        baseline.geometry.blocks,
        r,
        &mut |at, bytes| {
            let base = home_page * 4096 + u64::from(inode & 7) * 512 + 224;
            let offset =
                at.checked_sub(base)
                    .ok_or_else(|| bad("JFS COW fixture root address"))? as usize;
            if offset.checked_add(bytes.len()).is_none_or(|end| end > 48)
                || bytes != &root[offset..offset + bytes.len()]
            {
                return Err(bad("JFS COW fixture root line"));
            }
            Ok(())
        },
    )?;
    drop(parsed);
    let serial = le32(&logs, 8)
        .checked_add(1)
        .ok_or_else(|| bad("JFS fixture serial wrap"))?;
    logs[8..12].copy_from_slice(&serial.to_le_bytes());
    logs[28..32].fill(0);
    logs[68..84].copy_from_slice(&header[0][136..152]);
    for block in &mut header {
        block[40..44].copy_from_slice(&1u32.to_le_bytes());
        block[68..72].copy_from_slice(&serial.to_le_bytes());
    }
    drop(baseline);
    write_checked(storage, (log.start + u64::from(number)) * 4096, &page, r, r)?;
    write_checked(storage, (log.start + 1) * 4096, &logs, r, r)?;
    for (at, block) in [32768u64, 61440].into_iter().zip(&header) {
        write_checked(storage, at, block, r, r)?;
    }
    storage
        .flush()
        .map_err(|e| Error::io("JFS native fixture flush", e))?;
    Ok(())
}

// No write capability is returned. This validates the complete committed COW
// fixture grammar, overlays every tree change, reconstructs authorized native
// maps, and requires strict whole-volume ownership before future replay code
// may consume the projected images.
struct CowProjection {
    patches: Vec<(u64, Vec<u8>)>,
    headers: [[u8; PAGE]; 2],
    logs: [u8; PAGE],
    log: super::super::Physical,
    committed_end: u32,
    committed: bool,
    length: u64,
    _lease: Reservation,
    _map_overlay_lease: Reservation,
}
pub(super) fn prove_cow_fixture(
    storage: &dyn crate::storage::Storage,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    r: &Resources,
) -> Result<()> {
    drop(cow_projection(storage, read, audit, r, r)?);
    Ok(())
}
fn cow_projection(
    storage: &dyn crate::storage::Storage,
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<CowProjection> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let lease = r.memory.reserve(65536)?;
    let length = storage
        .len()
        .map_err(|e| Error::io("JFS COW preflight length", e))?;
    let source = super::Borrowed {
        storage,
        length,
        resources: original,
    };
    let mut headers = [[0; PAGE]; 2];
    for (at, header) in [32768u64, 61440].into_iter().zip(&mut headers) {
        source.exact(at, header)?;
    }
    let log = pxd(&headers[0], 72, length / PAGE as u64)?;
    let mut logs = [0; PAGE];
    source.exact((log.start + 1) * PAGE as u64, &mut logs)?;
    let (serial, partial_serial) =
        activation_serial([le32(&headers[0], 68), le32(&headers[1], 68), le32(&logs, 8)])?;
    let active = logs[68..84] == headers[0][136..152];
    let legal_active = (0..=16).any(|cut| {
        logs[68..68 + cut] == headers[0][136..136 + cut]
            && logs[68 + cut..84].iter().all(|byte| *byte == 0)
    });
    if headers[0][136..152].iter().all(|v| *v == 0)
        || !legal_active
        || logs[84..68 + 128 * 16].iter().any(|v| *v != 0)
        || ![0, 1].contains(&le32(&logs, 28))
        || headers.iter().any(|h| ![0, 1].contains(&le32(h, 40)))
    {
        return Err(bad("JFS COW preflight activation"));
    }
    let scanned = history_framing(
        &source,
        log,
        HistoryLimits {
            pages: read.pages,
            records: 8,
            data: 1536,
            work: read.work,
        },
        r,
        true,
    )?;
    let committed = scanned
        .records
        .first()
        .is_some_and(|record| le16(&record.descriptor, 8) == COMMIT);
    if scanned.records.len() < 3 + usize::from(committed) {
        return Err(bad("JFS COW preflight bounded history"));
    }
    let newest_end = scanned.records[0].end;
    if scanned
        .reconciled
        .iter()
        .any(|number| *number != newest_end / PAGE as u32)
    {
        return Err(bad("JFS COW preflight older torn frame"));
    }
    if committed
        && (partial_serial
            || !active
            || le32(&logs, 28) != 0
            || headers.iter().any(|h| le32(h, 40) != 1))
    {
        return Err(bad("JFS COW committed activation incomplete"));
    }
    let mut cursor = usize::from(committed);
    let metadata = (scanned
        .records
        .get(cursor + 1)
        .is_some_and(|record| le16(&record.descriptor, 8) == UPDATE_MAP))
    .then(|| {
        let record = &scanned.records[cursor];
        cursor += 1;
        record
    });
    let mapping = &scanned.records[cursor];
    let root = scanned
        .records
        .get(cursor + 1)
        .ok_or_else(|| bad("JFS COW missing new ROOT"))?;
    cursor += 2;
    let inode_record = scanned
        .records
        .get(cursor)
        .filter(|record| le16(&record.descriptor, 8) == REDO && le16(&record.descriptor, 24) == 1);
    cursor += usize::from(inode_record.is_some());
    let old_root = scanned.records.get(cursor).filter(|record| {
        le16(&record.descriptor, 8) == REDO && le16(&record.descriptor, 24) == 0x12
    });
    cursor += usize::from(old_root.is_some());
    if cursor + 1 != scanned.records.len() || metadata.is_some() != old_root.is_some() {
        return Err(bad("JFS COW unexpected native history roles"));
    }
    let sync = scanned.records.last().unwrap();
    let mut abort_descriptor = [0; DESCRIPTOR];
    abort_descriptor[..4].copy_from_slice(&mapping.descriptor[..4]);
    abort_descriptor[4..8].copy_from_slice(&metadata.unwrap_or(mapping).end.to_le_bytes());
    abort_descriptor[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    let commit = if committed {
        &scanned.records[0]
    } else {
        &OwnedRecord {
            end: newest_end,
            descriptor: abort_descriptor,
            body: Vec::new(),
        }
    };
    let cd = &commit.descriptor;
    let md = &mapping.descriptor;
    let rd = &root.descriptor;
    if le16(cd, 8) != COMMIT
        || le16(md, 8) != UPDATE_MAP
        || le16(rd, 8) != REDO
        || le16(&sync.descriptor, 8) != SYNC
        || le32(cd, 0) == 0
        || le32(cd, 4) != metadata.unwrap_or(mapping).end
        || le32(md, 4) != root.end
        || le32(rd, 4) != inode_record.or(old_root).map_or(0, |record| record.end)
        || le32(md, 0) != le32(cd, 0)
        || le32(rd, 0) != le32(cd, 0)
        || [cd, md, rd].iter().any(|d| le32(*d, 12) != 0)
        || le32(md, 16) != le32(rd, 16)
        || le32(md, 20) != le32(rd, 20)
        || ![1, 8].contains(&le16(md, 24))
        || le16(rd, 24) != 0x12
        || le16(rd, 26) != 4
        || root.body.len() != 56
        || le16(&root.body, 32) != 0
        || le16(&root.body, 34) != 2
        || le16(&root.body, 52) != 2
        || le16(&root.body, 54) != 1
    {
        return Err(bad("JFS COW preflight transaction grammar"));
    }
    let mut old_metadata = vector(8)?;
    if let Some(record) = metadata {
        let d = &record.descriptor;
        if le16(d, 8) != UPDATE_MAP
            || ![1, 4].contains(&le16(d, 24))
            || le32(d, 0) != le32(cd, 0)
            || le32(d, 4) != mapping.end
            || le32(d, 12) != 0
            || d[16..24] != rd[16..24]
        {
            return Err(bad("JFS COW metadata FREE grammar"));
        }
        let parsed = Record {
            end: record.end,
            tid: le32(d, 0),
            backchain: le32(d, 4),
            aggregate: 0,
            kind: UPDATE_MAP,
            detail: &d[16..],
            body: &record.body,
        };
        map_extents(
            &parsed,
            length / PAGE as u64,
            8,
            read.work,
            r,
            &mut |physical, allocated| {
                if allocated || physical.count != 1 {
                    return Err(bad("JFS COW metadata FREE role"));
                }
                old_metadata.push(physical);
                Ok(())
            },
        )?;
    }
    if let Some(record) = old_root {
        let d = &record.descriptor;
        let body = &record.body;
        let slots = body
            .len()
            .checked_sub(40)
            .filter(|length| length.is_multiple_of(16))
            .map(|length| length / 16)
            .ok_or_else(|| bad("JFS COW old ROOT vector size"))?;
        if le32(d, 0) != le32(cd, 0)
            || le32(d, 4) != 0
            || le32(d, 12) != 0
            || d[16..36] != rd[16..36]
            || !(1..=16).contains(&slots)
            || le16(body, 18) as usize != slots + 2
            || body[16] & 7 != 5
            || body[..16] != root.body[..16]
            || body[16] & !6 != root.body[16] & !6
            || body[17] != root.body[17]
            || body[20..32] != root.body[20..32]
            || le16(body, 32) != 0
            || le16(body, 34) != 2
            || le16(body, body.len() - 4) != 2
            || le16(body, body.len() - 2) as usize != slots
        {
            return Err(bad("JFS COW exact old ROOT grammar"));
        }
    }
    let inode = le32(rd, 20);
    let physical = pxd(rd, 28, length / PAGE as u64)?;
    if physical.count != 1 {
        return Err(bad("JFS COW preflight inode page"));
    }
    let inode_at = physical.start * PAGE as u64 + u64::from(inode & 7) * 512;
    let mut raw = [0; 512];
    source.exact(inode_at, &mut raw)?;
    let extent = pxd(&raw, 16, length / PAGE as u64)?;
    if le32(&raw, 8) != inode
        || le32(&raw, 4) != le32(rd, 16)
        || extent.count != 4
        || physical.start != extent.start + u64::from((inode & 31) / 8)
        || old_root.is_none()
            && (raw[224..242] != root.body[..18] || raw[244..256] != root.body[20..32])
    {
        return Err(bad("JFS COW preflight native identity/root header"));
    }
    let xad = &root.body[36..52];
    // Bounded recorded logical run, NEW allocation only.
    if xad[0] != 1 && xad.iter().any(|v| *v != 0) || xad[1..8].iter().any(|v| *v != 0) {
        return Err(bad("JFS COW preflight XAD logical/flag profile"));
    }
    let new = pxd(xad, 8, length / PAGE as u64)?;
    let old_runs = old_data_runs(md, &mapping.body, length / PAGE as u64, read.work, r)?;
    if old_root.is_none() && old_runs.len() > 16 || old_root.is_some() && le16(md, 24) != 8 {
        return Err(bad("JFS COW old data/root profile mismatch"));
    }
    let old_blocks: u64 = old_runs.iter().map(|run| run.physical.count).sum::<u64>()
        + old_metadata.iter().map(|page| page.count).sum::<u64>();
    let old_end = old_runs
        .last()
        .map_or(0, |run| run.logical + run.physical.count);
    if new.count == 0
        && (inode_record.is_none()
            || le16(&root.body, 18) != 2
            || xad.iter().any(|byte| *byte != 0))
        || new.count != 0 && le16(&root.body, 18) != 3
        || new.count > 32
        || old_blocks == 0
        || old_blocks > 32
        || old_runs.iter().any(|run| {
            new.start < run.physical.start + run.physical.count
                && run.physical.start < new.start + new.count
        })
        || inode_record.is_none()
            && (old_blocks != new.count
                || super::super::le64(&raw, 24).div_ceil(PAGE as u64) != old_end)
    {
        return Err(bad("JFS COW preflight allocation range"));
    }
    let mut after = raw;
    if let Some(record) = inode_record {
        let d = &record.descriptor;
        if le16(d, 8) != REDO
            || le32(d, 0) != le32(cd, 0)
            || le32(d, 4) != old_root.map_or(0, |record| record.end)
            || le32(d, 12) != 0
            || le32(d, 16) != le32(rd, 16)
            || le32(d, 20) != inode
            || d[24..36]
                != author_inode_record(
                    TransactionFields {
                        tid: le32(cd, 0),
                        backchain: 0,
                        fileset: le32(rd, 16),
                        inode,
                    },
                    physical.start,
                    &raw[..128].try_into().unwrap(),
                    length / PAGE as u64,
                    r,
                )?
                .descriptor[24..36]
            || record.body.len() != 132
            || le16(&record.body, 128) != (inode & 7) as u16 * 4
            || le16(&record.body, 130) != 1
            || raw[..24] != record.body[..24]
            || raw[40..128] != record.body[40..128]
            || super::super::le64(&record.body, 24).div_ceil(PAGE as u64) != new.count
            || super::super::le64(&record.body, 32) != new.count
        {
            return Err(bad("JFS COW native inode resize grammar"));
        }
        after[..128].copy_from_slice(&record.body[..128]);
    }
    after[224..256].copy_from_slice(&root.body[..32]);
    after[256..272].copy_from_slice(xad);
    after[256] = 0;
    let mut before = after;
    if let Some(record) = old_root {
        let slots = (record.body.len() - 40) / 16;
        before[224..256].copy_from_slice(&record.body[..32]);
        before[256..256 + slots * 16].copy_from_slice(&record.body[36..36 + slots * 16]);
        if slots > 1 {
            after[272..256 + slots * 16].copy_from_slice(&record.body[52..36 + slots * 16]);
        }
    } else {
        before[242..244].copy_from_slice(&((old_runs.len() + 2) as u16).to_le_bytes());
        if le16(md, 24) == 8 {
            before[256..256 + mapping.body.len()].copy_from_slice(&mapping.body);
            if mapping.body.len() > 16 {
                after[272..256 + mapping.body.len()].copy_from_slice(&mapping.body[16..]);
            }
        } else {
            before[264..272].copy_from_slice(&md[28..36]);
        }
    }
    if inode_record.is_some() {
        before[32..40].copy_from_slice(&old_blocks.to_le_bytes());
    }
    // Ordered positional home publication cannot change any other inode byte.
    let minimum_old = (old_end - 1) * PAGE as u64 + 1;
    let maximum_old = old_end * PAGE as u64;
    let mut valid_prefix = false;
    for cut in 0..=8 {
        original.cancellation.check()?;
        r.cancellation.check()?;
        if inode_record.is_some() {
            if raw[24..24 + cut] != after[24..24 + cut] {
                continue;
            }
            let mask = if cut == 8 {
                u64::MAX
            } else {
                (1u64 << (cut * 8)) - 1
            };
            let base = super::super::le64(&raw, 24) & !mask;
            let lower = base.max(minimum_old);
            if lower > base.saturating_add(mask).min(maximum_old) {
                continue;
            }
            before[24..32].copy_from_slice(&lower.to_le_bytes());
        }
        let mut old_suffix = false;
        if raw
            .iter()
            .zip(&before)
            .zip(&after)
            .all(|((actual, old), new)| {
                if actual == new && (actual == old || !old_suffix) {
                    true
                } else if actual == old {
                    old_suffix = true;
                    true
                } else {
                    false
                }
            })
        {
            valid_prefix = true;
            break;
        }
        if inode_record.is_none() {
            break;
        }
    }
    if !valid_prefix {
        return Err(bad("JFS COW preflight unauthorized inode prefix"));
    }
    if !committed && raw != before {
        return Err(bad("JFS COW uncommitted home changed"));
    }
    let mut patches = vector(7)?;
    for (at, header) in [32768u64, 61440].into_iter().zip(&mut headers) {
        header[40..44].fill(0);
        header[68..72].copy_from_slice(&serial.to_le_bytes());
        patches.push((at, super::super::copied(header)?));
    }
    logs[8..12].copy_from_slice(&serial.to_le_bytes());
    logs[28..32].copy_from_slice(&1u32.to_le_bytes());
    logs[68..68 + 128 * 16].fill(0);
    patches.push(((log.start + 1) * PAGE as u64, super::super::copied(&logs)?));
    if !committed {
        let unchanged = super::super::decode(
            &super::Overlay {
                source: super::Borrowed {
                    storage,
                    length,
                    resources: original,
                },
                patches: &patches,
            },
            read,
            r,
        )?;
        if old_runs.iter().any(|run| {
            (run.physical.start..run.physical.start + run.physical.count)
                .any(|block| !unchanged.bitmap[block as usize])
        }) || (new.start..new.start + new.count).any(|block| unchanged.bitmap[block as usize])
            || !crate::fs_jfs_audit::audit_decoded(&unchanged, audit, r)?.is_clean()
        {
            return Err(bad("JFS COW abort baseline ownership"));
        }
    }
    patches.push((inode_at, super::super::copied(&after)?));
    let mut changes = vector((new.count + old_blocks) as usize)?;
    for run in &old_runs {
        for offset in 0..run.physical.count {
            changes.push((run.physical.start + offset, false));
        }
    }
    for page in &old_metadata {
        changes.push((page.start, false));
    }
    for offset in 0..new.count {
        changes.push((new.start + offset, true));
    }
    changes.sort_unstable_by_key(|change| change.0);
    let overlay = super::Overlay {
        source,
        patches: &patches,
    };
    let tentative = super::super::decode_recovery(&overlay, read, r, &changes)?;
    let maps = super::allocation::recovery_map(&overlay, &tentative, &changes, r)?;
    drop(tentative);
    let map_overlay_lease = r.memory.reserve(
        (maps.pages.len() as u64)
            .checked_mul(8192)
            .and_then(|bytes| bytes.checked_add(4096 + 512))
            .ok_or_else(|| budget("JFS canonical ownership overlay charge"))?,
    )?;
    let mut before_patches = vector(maps.pages.len() + 4)?;
    for (at, bytes) in patches.iter().take(3) {
        before_patches.push((*at, super::super::copied(bytes)?));
    }
    before_patches.push((inode_at, super::super::copied(&before)?));
    for page in &maps.pages {
        before_patches.push((page.at, super::super::copied(&page.canonical_before)?));
    }
    let old_verified = super::super::decode(
        &super::Overlay {
            source: super::Borrowed {
                storage,
                length,
                resources: original,
            },
            patches: &before_patches,
        },
        read,
        r,
    )?;
    let old_node = old_verified
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS COW old inode missing"))?;
    if old_node.runs.len() != old_runs.len()
        || old_node.runs.iter().zip(&old_runs).any(|(a, b)| {
            a.logical != b.logical || a.physical != b.physical || a.unwritten != b.unwritten
        })
        || old_node.pages.len() != old_metadata.len()
        || old_node
            .pages
            .iter()
            .any(|page| !old_metadata.contains(page))
        || !crate::fs_jfs_audit::audit_decoded(&old_verified, audit, r)?.is_clean()
    {
        return Err(bad("JFS COW preflight canonical old ownership"));
    }
    drop((old_verified, before_patches));
    for page in maps.pages {
        patches.push((page.at, super::super::copied(&page.after)?));
    }
    let verified = super::super::decode(
        &super::Overlay {
            source: super::Borrowed {
                storage,
                length,
                resources: original,
            },
            patches: &patches,
        },
        read,
        r,
    )?;
    if !crate::fs_jfs_audit::audit_decoded(&verified, audit, r)?.is_clean() {
        return Err(bad("JFS COW preflight complete ownership"));
    }
    original.cancellation.check()?;
    r.cancellation.check()?;
    source_length_check(storage, length)?;
    Ok(CowProjection {
        patches,
        headers,
        logs,
        log,
        committed_end: newest_end,
        committed,
        length,
        _lease: lease,
        _map_overlay_lease: map_overlay_lease,
    })
}

fn source_length_check(storage: &dyn crate::storage::Storage, expected: u64) -> Result<()> {
    if storage
        .len()
        .map_err(|e| Error::io("JFS COW recovery length", e))?
        != expected
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS COW recovery length changed",
        ));
    }
    Ok(())
}
pub(super) fn recover_cow(
    storage: &mut dyn crate::storage::Storage,
    binding: [u8; 16],
    read: super::super::JfsReadLimits,
    audit: crate::fs_jfs_audit::JfsAuditLimits,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    original.cancellation.check()?;
    r.cancellation.check()?;
    let mut observed_binding = [0; 16];
    storage
        .read_exact_at(32768 + 136, &mut observed_binding)
        .map_err(|e| Error::io("JFS COW recovery binding", e))?;
    if binding != observed_binding || binding.iter().all(|v| *v == 0) {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "JFS COW recovery aggregate binding",
        ));
    }
    // A durable checkpoint means all COW home/map pages have already been
    // verified. The existing native shutdown reconciliation validates that
    // complete tree and handles idempotent cleanup without replaying data.
    let length = storage
        .len()
        .map_err(|e| Error::io("JFS COW recovery size", e))?;
    let source = super::Borrowed {
        storage,
        length,
        resources: original,
    };
    let mut header = [0; PAGE];
    source.exact(32768, &mut header)?;
    let log = pxd(&header, 72, length / PAGE as u64)?;
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
    let checkpointed = scanned
        .records
        .first()
        .is_some_and(|record| le16(&record.descriptor, 8) == SYNC);
    drop(scanned);
    if checkpointed {
        return recover_uid(storage, binding, read, audit, original, r);
    }
    let mut projected = cow_projection(storage, read, audit, original, r)?;
    let number = projected.committed_end / PAGE as u32;
    let page_at = (projected.log.start + u64::from(number)) * PAGE as u64;
    let log_at = (projected.log.start + 1) * PAGE as u64;
    let mut page = [0; PAGE];
    storage
        .read_exact_at(page_at, &mut page)
        .map_err(|e| Error::io("JFS COW recovery checkpoint page", e))?;
    let eor = (projected.committed_end % PAGE as u32) as u16;
    page[6..8].copy_from_slice(&eor.to_le_bytes());
    page[TRAILER + 6..].copy_from_slice(&eor.to_le_bytes());
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    let end = append(&mut page, number, &d, &[])?;
    projected.logs[32..36].copy_from_slice(&end.to_le_bytes());
    source_length_check(storage, projected.length)?;
    original.cancellation.check()?;
    r.cancellation.check()?;
    // Complete grammar, ordered-prefix validation and strict ownership proof
    // precede the first replay write, including checkpoint capacity preflight.
    let result = (|| {
        if !projected.committed {
            // Establish dirty/active shutdown authority before publishing the
            // abort checkpoint. Otherwise a cut could leave LOGREDONE paired
            // with the predecessor end pointer after a new SYNC is durable.
            for (at, clean) in [32768u64, 61440].into_iter().zip(&projected.headers) {
                let mut dirty = *clean;
                dirty[40..44].copy_from_slice(&1u32.to_le_bytes());
                write_checked(storage, at, &dirty, original, r)?;
                flush_readback(storage, at, &dirty, original, r)?;
            }
            let mut active = projected.logs;
            active[28..32].fill(0);
            active[68..84].copy_from_slice(&binding);
            write_checked(storage, log_at, &active, original, r)?;
            flush_readback(storage, log_at, &active, original, r)?;
        }

        for (at, bytes) in &projected.patches {
            if !projected.committed || [32768, 61440, log_at].contains(at) {
                continue;
            }
            write_checked(storage, *at, bytes, original, r)?;
            flush_readback(storage, *at, bytes, original, r)?;
        }
        write_checked(storage, page_at, &page, original, r)?;
        flush_readback(storage, page_at, &page, original, r)?;
        write_checked(storage, log_at, &projected.logs, original, r)?;
        flush_readback(storage, log_at, &projected.logs, original, r)?;
        for (at, header) in [32768u64, 61440].into_iter().zip(&projected.headers) {
            write_checked(storage, at, header, original, r)?;
            flush_readback(storage, at, header, original, r)?;
        }
        drop(super::inspect_with(storage, read, audit, original, r)?);
        Ok(())
    })();
    result.map_err(|mut error: Error| {
        error.kind = ErrorKind::UncertainDurability;
        error.context = format!("JFS native COW recovery interrupted: {}", error.context);
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
        let offset = if ty == 0x12 { 2 } else { 1 };
        p16(&mut body, line, offset);
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
            [(
                29 * 4096 + 4 * 512 + 224 + u64::from(offset) * line as u64,
                vec![0x6b; line]
            )]
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
fn independent_native_map_records_check_whole_lists_limits_and_unsupported_types_before_callbacks()
{
    use super::fixture::{p16, p32, pxd};
    let r = Resources {
        memory: Budget::new(1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let mut page = [0; PAGE];
    p32(&mut page, 0, 7);
    p32(&mut page, TRAILER, 7);
    p16(&mut page, 6, 8);
    p16(&mut page, TRAILER + 6, 8);
    let mut d = [0; DESCRIPTOR];
    p16(&mut d, 8, SYNC);
    append(&mut page, 2, &d, &[]).unwrap();
    d.fill(0);
    p32(&mut d, 0, 9);
    p16(&mut d, 8, UPDATE_MAP);
    p16(&mut d, 24, 1);
    p16(&mut d, 26, 1);
    pxd(&mut d, 28, 112, 1);
    append(&mut page, 2, &d, &[]).unwrap();
    let parsed = records(&page, 2, 2, &r).unwrap();
    let mut updates = Vec::new();
    map_extents(
        &parsed.records[0],
        480,
        4,
        1000,
        &r,
        &mut |extent, allocated| {
            updates.push((extent.start, extent.count, allocated));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(updates, [(112, 1, false)]);
    drop(parsed);
    assert_eq!(r.memory.used(), 0);
    for (ty, width) in [(4u16, 8usize), (8, 16)] {
        let mut detail = [0; 20];
        p16(&mut detail, 8, ty);
        p16(&mut detail, 10, 2);
        let mut body = vec![0; 2 * width];
        pxd(&mut body, width - 8, 113, 1);
        pxd(&mut body, 2 * width - 8, 112, 1);
        let mut record = Record {
            end: 0,
            tid: 9,
            backchain: 0,
            aggregate: 0,
            kind: UPDATE_MAP,
            detail: &detail,
            body: &body,
        };
        let mut calls = 0;
        map_extents(&record, 480, 2, 1000, &r, &mut |_, allocated| {
            assert!(!allocated);
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        let mut overlapping = body.clone();
        pxd(&mut overlapping, 2 * width - 8, 113, 1);
        record.body = &overlapping;
        calls = 0;
        assert!(
            map_extents(&record, 480, 2, 1000, &r, &mut |_, _| {
                calls += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls, 0);
        assert!(
            map_extents(&record, 480, 1, 1000, &r, &mut |_, _| panic!(
                "cap callback"
            ))
            .is_err()
        );
        assert!(map_extents(&record, 480, 2, 1, &r, &mut |_, _| panic!("work callback")).is_err());
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
        assert!(
            fs::read(name).unwrap() == bytes,
            "compiled source mismatch: {name}"
        );
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
        assert!(
            fs::read(name).unwrap() == bytes,
            "compiled source mismatch: {name}"
        );
    }
    for (path, digest) in bindings {
        assert_eq!(hash(&fs::read(path).unwrap()), digest);
    }
    assert_eq!(hash(&fs::read(binary).unwrap()), binary_hash);
    receipt.push_str("end_source_tool_binary_revalidation=passed\nstatus=passed\n");
    fs::write(receipt_path, receipt).unwrap();
}

#[path = "fs_jfs_edit_rollover.rs"]
pub(super) mod rollover;

#[test]
fn namespace_inode_vector_uses_native_224_byte_overlap_rule_and_strict_default_rejects() {
    use super::fixture::{p16, p32, pxd};
    let r = Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    };
    let mut detail = [0; 20];
    p32(&mut detail, 4, 2);
    p16(&mut detail, 8, 1);
    p16(&mut detail, 10, 7);
    pxd(&mut detail, 12, 29, 1);
    let mut body = vec![0x69; 260];
    p16(&mut body, 256, 8);
    p16(&mut body, 258, 2);
    let mut record = Record {
        end: 0,
        tid: 7,
        backchain: 0,
        aggregate: 0,
        kind: REDO,
        detail: &detail,
        body: &body,
    };
    let mut calls = Vec::new();
    assert!(
        redo_lines(&record, 512, &r, &mut |at, data| {
            calls.push((at, data.len()));
            Ok(())
        })
        .is_err()
    );
    assert!(calls.is_empty());
    redo_namespace_lines(&record, 512, &r, &mut |at, data| {
        calls.push((at, data.len()));
        assert_eq!(data, &[0x69; 224]);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, [(29 * 4096 + 2 * 512, 224)]);
    let mut bad_body = body.clone();
    p16(&mut bad_body, 256, 9);
    record.body = &bad_body;
    calls.clear();
    assert!(
        redo_namespace_lines(&record, 512, &r, &mut |at, data| {
            calls.push((at, data.len()));
            Ok(())
        })
        .is_err()
    );
    assert!(calls.is_empty());
    assert_eq!(r.memory.used(), 0);
}

#[path = "fs_jfs_edit_namespace.rs"]
mod namespace;
#[path = "fs_jfs_edit_rename.rs"]
pub(super) mod rename;
#[test]
fn native_namespace_encoder_reopens_long_names_and_reordered_cookies_with_complete_audit() {
    use crate::fs_jfs::JfsReadLimits;
    use crate::fs_jfs_audit::JfsAuditLimits;
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 << 20,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut b = super::journal_seed();
    super::fixture::small_hardlink(&mut b);
    let source = super::CowTestBackend {
        durable: b.clone(),
        bytes: b,
        writes: 0,
        flushes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let tree = super::inspect(&source, read, audit, &r).unwrap();
    let node = &tree.nodes[&5];
    let new: Vec<_> = "z-long-native-α-name".encode_utf16().collect();
    let after = namespace::rename_inline(
        node.raw.as_slice().try_into().unwrap(),
        &node.entries,
        &"Child".encode_utf16().collect::<Vec<_>>(),
        &new,
        &r,
    )
    .unwrap();
    assert_eq!(&after[..128], &node.raw[..128]);
    let patches = [(29 * 4096 + 5 * 512, super::super::copied(&after).unwrap())];
    let overlay = super::Overlay {
        source: super::Borrowed {
            storage: &source,
            length: source.bytes.len() as u64,
            resources: &r,
        },
        patches: &patches,
    };
    let result = super::super::decode(&overlay, read, &r).unwrap();
    assert!(
        crate::fs_jfs_audit::audit_decoded(&result, audit, &r)
            .unwrap()
            .is_clean()
    );
    assert_eq!(
        result.nodes[&5].entries[0].name,
        "Peer".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(result.nodes[&5].entries[1].name, new);
    assert_eq!(result.nodes[&6].raw, tree.nodes[&6].raw);
    drop((tree, result));
    assert_eq!(r.memory.used(), 0);
}

pub(super) fn author_namespace_overlap_fixture(
    storage: &mut dyn crate::storage::Storage,
    request: (u32, &[u16], &[u16]),
    limits: (
        super::super::JfsReadLimits,
        crate::fs_jfs_audit::JfsAuditLimits,
    ),
    r: &Resources,
) -> Result<[u8; 512]> {
    let _lease = r.memory.reserve(65536)?;
    let (inode, old, new) = request;
    let (read, audit) = limits;
    let baseline = super::inspect(storage, read, audit, r)?;
    let node = baseline
        .nodes
        .get(&inode)
        .ok_or_else(|| bad("JFS namespace fixture directory absent"))?;
    if !node.directory || !node.pages.is_empty() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS namespace fixture inline directory",
        ));
    }
    let before: [u8; 512] = node
        .raw
        .as_slice()
        .try_into()
        .map_err(|_| bad("JFS namespace inode size"))?;
    let after = namespace::rename_inline(&before, &node.entries, old, new, r)?;
    let home_page = pxd(&before, 16, baseline.geometry.blocks)?.start + u64::from((inode & 31) / 8);
    let home = home_page * 4096 + u64::from(inode & 7) * 512;
    let patches = [(home, super::super::copied(&after)?)];
    let projected = super::Overlay {
        source: super::Borrowed {
            storage,
            length: storage
                .len()
                .map_err(|e| Error::io("JFS namespace fixture length", e))?,
            resources: r,
        },
        patches: &patches,
    };
    let checked = super::super::decode(&projected, read, r)?;
    if !crate::fs_jfs_audit::audit_decoded(&checked, audit, r)?.is_clean() {
        return Err(bad("JFS namespace fixture projection audit"));
    }
    drop((checked, patches));
    let mut header = [baseline.header, baseline.header];
    storage
        .read_exact_at(61440, &mut header[1])
        .map_err(|e| Error::io("JFS namespace secondary header", e))?;
    let log = pxd(&header[0], 72, baseline.geometry.blocks)?;
    let mut logs = [0; PAGE];
    storage
        .read_exact_at((log.start + 1) * 4096, &mut logs)
        .map_err(|e| Error::io("JFS namespace log super", e))?;
    let number = le32(&logs, 32) / PAGE as u32;
    let mut page = [0; PAGE];
    storage
        .read_exact_at((log.start + u64::from(number)) * 4096, &mut page)
        .map_err(|e| Error::io("JFS namespace log page", e))?;
    if number < 2
        || u64::from(number) >= log.count
        || usize::from(le16(&page, 6)) != (le32(&logs, 32) % PAGE as u32) as usize
    {
        return Err(bad("JFS namespace established log end"));
    }
    let mut d = [0; DESCRIPTOR];
    d[8..10].copy_from_slice(&SYNC.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let mut chain = 0u32;
    for image in [&before, &after] {
        for root in [false, true] {
            let mut descriptor = [0; DESCRIPTOR];
            descriptor[..4].copy_from_slice(&7u32.to_le_bytes());
            descriptor[4..8].copy_from_slice(&chain.to_le_bytes());
            descriptor[8..10].copy_from_slice(&REDO.to_le_bytes());
            descriptor[16..20].copy_from_slice(&le32(image, 4).to_le_bytes());
            descriptor[20..24].copy_from_slice(&inode.to_le_bytes());
            descriptor[24..26].copy_from_slice(&(if root { 0x14u16 } else { 1 }).to_le_bytes());
            descriptor[26..28].copy_from_slice(&(if root { 5u16 } else { 7 }).to_le_bytes());
            descriptor[28..32]
                .copy_from_slice(&(1u32 | ((home_page >> 32) as u32) << 24).to_le_bytes());
            descriptor[32..].copy_from_slice(&(home_page as u32).to_le_bytes());
            let mut body = [0u8; 292];
            let length = if root { 292 } else { 260 };
            if root {
                body[..288].copy_from_slice(&image[224..]);
                body[290..292].copy_from_slice(&9u16.to_le_bytes());
            } else {
                body[..256].copy_from_slice(&image[..256]);
                body[256..258].copy_from_slice(&((inode & 7) as u16 * 4).to_le_bytes());
                body[258..260].copy_from_slice(&2u16.to_le_bytes());
            }
            descriptor[10..12].copy_from_slice(&(length as u16).to_le_bytes());
            let record = Record {
                end: 0,
                tid: 7,
                backchain: chain,
                aggregate: 0,
                kind: REDO,
                detail: &descriptor[16..],
                body: &body[..length],
            };
            redo_namespace_lines(&record, baseline.geometry.blocks, r, &mut |at, data| {
                let offset = at
                    .checked_sub(home)
                    .ok_or_else(|| bad("JFS namespace home vector"))?
                    as usize;
                if offset.checked_add(data.len()).is_none_or(|n| n > 512)
                    || data != &image[offset..offset + data.len()]
                {
                    return Err(bad("JFS namespace vector afterimage"));
                }
                Ok(())
            })?;
            chain = append(&mut page, number, &descriptor, &body[..length])?;
        }
    }
    d.fill(0);
    d[..4].copy_from_slice(&7u32.to_le_bytes());
    d[4..8].copy_from_slice(&chain.to_le_bytes());
    d[8..10].copy_from_slice(&COMMIT.to_le_bytes());
    append(&mut page, number, &d, &[])?;
    let serial = le32(&logs, 8)
        .checked_add(1)
        .ok_or_else(|| bad("JFS namespace fixture serial wrap"))?;
    logs[8..12].copy_from_slice(&serial.to_le_bytes());
    logs[28..32].fill(0);
    logs[68..84].copy_from_slice(&header[0][136..152]);
    for block in &mut header {
        block[40..44].copy_from_slice(&1u32.to_le_bytes());
        block[68..72].copy_from_slice(&serial.to_le_bytes());
    }
    drop(baseline);
    write_checked(storage, (log.start + u64::from(number)) * 4096, &page, r, r)?;
    write_checked(storage, (log.start + 1) * 4096, &logs, r, r)?;
    for (at, block) in [32768u64, 61440].into_iter().zip(&header) {
        write_checked(storage, at, block, r, r)?;
    }
    storage
        .flush()
        .map_err(|e| Error::io("JFS namespace fixture flush", e))?;
    Ok(after)
}
