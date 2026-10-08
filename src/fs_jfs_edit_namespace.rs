//! Private bounded native namespace codec; publication remains separately checked.
use crate::fs_core::*;
use crate::fs_jfs::{Entry, bad, budget};
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(super) fn rename_inline(
    original: &[u8; 512],
    entries: &[Entry],
    old: &[u16],
    new: &[u16],
    r: &Resources,
) -> Result<[u8; 512]> {
    r.cancellation.check()?;
    let _lease = r.memory.reserve(2048)?;
    if entries.len() > 8 || original[240] != 0x83 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS inline namespace root profile",
        ));
    }
    if new == old {
        return Err(bad("JFS rename requires a name change"));
    }
    if new.is_empty()
        || new.len() > 255
        || new.iter().any(|u| matches!(*u, 0 | 47))
        || new == [46]
        || new == [46, 46]
    {
        return Err(bad("JFS native namespace name"));
    }
    let selected = entries
        .iter()
        .position(|e| e.name == old)
        .ok_or_else(|| bad("JFS rename source absent"))?;
    if entries
        .iter()
        .enumerate()
        .any(|(i, e)| i != selected && e.name == new)
    {
        return Err(bad("JFS rename destination exists"));
    }
    let name = |i: usize| {
        if i == selected {
            new
        } else {
            entries[i].name.as_slice()
        }
    };
    let mut order = [0usize; 8];
    let mut needed = 0usize;
    for (i, e) in entries.iter().enumerate() {
        r.cancellation.check()?;
        if e.name.is_empty() || e.name.len() > 255 || e.page != 0 || !(2..14).contains(&e.index) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "JFS inline namespace index profile",
            ));
        }
        needed = needed
            .checked_add(1 + name(i).len().saturating_sub(11).div_ceil(15))
            .ok_or_else(|| budget("JFS namespace slot arithmetic"))?;
        order[i] = i;
    }
    if needed > 8 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "JFS namespace requires external root promotion",
        ));
    }
    // Eight entries at most: fixed bounded scratch and no allocated name copies.
    for i in 1..entries.len() {
        let v = order[i];
        let mut j = i;
        while j > 0 && name(order[j - 1]) > name(v) {
            order[j] = order[j - 1];
            j -= 1;
        }
        order[j] = v;
    }
    let mut after = *original;
    after[256..512].fill(0);
    after[241] = entries.len() as u8;
    after[242] = (8 - needed) as u8;
    after[243] = if needed == 8 { 255 } else { (needed + 1) as u8 };
    after[248..256].fill(0);
    let mut slot = 1usize;
    let mut cookies = [false; 12];
    for (rank, i) in order[..entries.len()].iter().copied().enumerate() {
        r.cancellation.check()?;
        let e = &entries[i];
        let n = name(i);
        let ci = (e.index - 2) as usize;
        if cookies[ci] {
            return Err(bad("JFS duplicate namespace cookie"));
        }
        cookies[ci] = true;
        let c = 128 + ci * 8;
        if original[c] != 0
            || original[c + 1] != 1
            || original[c + 2] != e.slot
            || original[c + 3..c + 8].iter().any(|v| *v != 0)
        {
            return Err(bad("JFS namespace cookie/source disagreement"));
        }
        after[c + 2] = rank as u8;
        after[248 + rank] = slot as u8;
        let head = 224 + slot * 32;
        after[head..head + 4].copy_from_slice(&e.ino.to_le_bytes());
        after[head + 5] = n.len() as u8;
        after[head + 28..head + 32].copy_from_slice(&e.index.to_le_bytes());
        let first = n.len().min(11);
        for (i, u) in n[..first].iter().enumerate() {
            after[head + 6 + 2 * i..head + 8 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        let mut written = first;
        after[head + 4] = if written == n.len() {
            255
        } else {
            (slot + 1) as u8
        };
        slot += 1;
        while written < n.len() {
            let at = 224 + slot * 32;
            let count = (n.len() - written).min(15);
            after[at] = if written + count == n.len() {
                255
            } else {
                (slot + 1) as u8
            };
            after[at + 1] = 1;
            for (i, u) in n[written..written + count].iter().enumerate() {
                after[at + 2 + 2 * i..at + 4 + 2 * i].copy_from_slice(&u.to_le_bytes());
            }
            written += count;
            slot += 1;
        }
    }
    for free in slot..9 {
        let at = 224 + free * 32;
        after[at] = if free == 8 { 255 } else { (free + 1) as u8 };
        after[at + 1] = 1;
    }
    r.cancellation.check()?;
    Ok(after)
}
