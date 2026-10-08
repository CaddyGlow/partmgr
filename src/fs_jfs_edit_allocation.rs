//! Staged bounded native block-map after-image construction; no publication API.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(super) struct PagePatch {
    pub(super) at: u64,
    logical: u64,
    pub(super) before: [u8; 4096],
    pub(super) canonical_before: [u8; 4096],
    pub(super) after: [u8; 4096],
}
pub(super) struct MapPlan {
    pub(super) pages: Vec<PagePatch>,
    _lease: Reservation,
}
fn native_page(
    map: &MetadataMap<'_>,
    number: u64,
    w: &mut Work,
    r: &Resources,
) -> Result<PagePatch> {
    let mut before = [0; 4096];
    let logical = number
        .checked_mul(4096)
        .ok_or_else(|| bad("JFS map page overflow"))?;
    mapread(map, logical, &mut before, w, r)?;
    let mut physical = None;
    for run in map.runs {
        w.tick(1, r)?;
        if run.logical <= number && number < run.logical + run.physical.count {
            physical = Some((run.physical.start + number - run.logical) * 4096);
            break;
        }
    }
    Ok(PagePatch {
        at: physical.ok_or_else(|| bad("JFS map home page absent"))?,
        logical: number,
        after: before,
        before,
        canonical_before: before,
    })
}
fn rebuild_summary(page: &mut [u8; 4096], at: usize, leaves: Vec<i8>, minimum: i8) -> Result<i8> {
    let tree = summaries(leaves, minimum)?;
    for (out, value) in page[at + 17..].iter_mut().zip(&tree) {
        *out = *value as u8;
    }
    Ok(tree[0])
}
pub(super) fn prepare_map(
    source: &dyn DecodeRead,
    baseline: &Decoded,
    changes: &[(u64, bool)],
    r: &Resources,
) -> Result<MapPlan> {
    r.cancellation.check()?;
    if changes.is_empty() || changes.len() as u64 > baseline.geometry.mapped {
        return Err(bad("JFS map change ceiling/empty operation"));
    }
    let _working = r.memory.reserve(
        (changes.len() as u64)
            .checked_mul(32)
            .and_then(|n| n.checked_add(16384))
            .ok_or_else(|| budget("JFS map working charge"))?,
    )?;
    let mut w = Work {
        limits: baseline.limits,
        work: 0,
        pages: 0,
        extents: 0,
        entries: 0,
    };
    let sorting = (changes.len() as u64)
        .checked_mul(u64::from(changes.len().next_power_of_two().ilog2()) + 4)
        .ok_or_else(|| budget("JFS map sorting work"))?;
    w.tick(sorting, r)?;
    let mut ordered = vector(changes.len())?;
    for &(block, allocated) in changes {
        r.cancellation.check()?;
        if block >= baseline.geometry.mapped || baseline.bitmap[block as usize] == allocated {
            return Err(bad("JFS allocation change does not match baseline"));
        }
        ordered.push((block, allocated));
    }
    ordered.sort_unstable_by_key(|entry| entry.0);
    if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(bad("JFS repeated allocation change"));
    }
    let mut affected = 0usize;
    let mut last = None;
    for &(block, _) in &ordered {
        if last != Some(block / 8192) {
            affected += 1;
            last = Some(block / 8192);
        }
    }
    let lease = r.memory.reserve(
        ((affected + 2) as u64)
            .checked_mul(crate::platform::mem::size_of::<PagePatch>() as u64)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| budget("JFS retained map after-image charge"))?,
    )?;
    let map = MetadataMap {
        source,
        length: baseline.map_length,
        runs: &baseline.map_runs,
    };
    let mut control = native_page(&map, 0, &mut w, r)?;
    let mut summary = native_page(&map, 3, &mut w, r)?;
    let mut pages = vector(affected + 2)?;
    let mut cursor = 0;
    while cursor < ordered.len() {
        let number = ordered[cursor].0 / 8192;
        let mut page = native_page(&map, 4 + number, &mut w, r)?;
        let mut free = le32(&page.after, 4);
        let mut total = le64(&control.after, 8);
        let mut group = le64(&control.after, 56 + number as usize * 8);
        while cursor < ordered.len() && ordered[cursor].0 / 8192 == number {
            w.tick(1, r)?;
            let (block, allocated) = ordered[cursor];
            let relative = (block % 8192) as usize;
            let word_at = 3072 + relative / 32 * 4;
            let mask = 0x80000000u32 >> (relative % 32);
            let word = le32(&page.after, word_at);
            if (word & mask != 0) == allocated {
                return Err(bad("JFS map baseline changed"));
            }
            let after = if allocated { word | mask } else { word & !mask };
            for at in [word_at - 1024, word_at] {
                page.after[at..at + 4].copy_from_slice(&after.to_le_bytes());
            }
            if allocated {
                free = free
                    .checked_sub(1)
                    .ok_or_else(|| bad("JFS dmap count underflow"))?;
                total = total
                    .checked_sub(1)
                    .ok_or_else(|| bad("JFS total free underflow"))?;
                group = group
                    .checked_sub(1)
                    .ok_or_else(|| bad("JFS group free underflow"))?;
            } else {
                free = free
                    .checked_add(1)
                    .ok_or_else(|| bad("JFS dmap count overflow"))?;
                total = total
                    .checked_add(1)
                    .filter(|n| *n <= baseline.geometry.mapped)
                    .ok_or_else(|| bad("JFS total free overflow"))?;
                group = group
                    .checked_add(1)
                    .filter(|n| *n <= 8192)
                    .ok_or_else(|| bad("JFS group free overflow"))?;
            }
            cursor += 1;
        }
        page.after[4..8].copy_from_slice(&free.to_le_bytes());
        control.after[8..16].copy_from_slice(&total.to_le_bytes());
        control.after[56 + number as usize * 8..64 + number as usize * 8]
            .copy_from_slice(&group.to_le_bytes());
        let mut leaves = vector(256)?;
        for word in 0..256 {
            w.tick(64, r)?;
            leaves.push(word_buddy(le32(&page.after, 3072 + word * 4)));
        }
        w.tick(256 * 10, r)?;
        let root = rebuild_summary(&mut page.after, 16, leaves, 5)?;
        // L0 has 1024 leaves after the 341 internal quaternary nodes.
        summary.after[17 + 341 + number as usize] = root as u8;
        pages.push(page);
    }
    // Reconstruct raw per-dmap roots rather than treating already coalesced
    // L0 leaf values as independent free-buddy roots.
    let mut roots = vector(1024)?;
    roots.resize(1024, -1);
    for number in 0..baseline.geometry.mapped.div_ceil(8192) {
        w.tick(1, r)?;
        w.tick(u64::from(pages.len().next_power_of_two().ilog2()) + 1, r)?;
        roots[number as usize] =
            match pages.binary_search_by_key(&(4 + number), |page| page.logical) {
                Ok(index) => pages[index].after[33] as i8,
                Err(_) => native_page(&map, 4 + number, &mut w, r)?.after[33] as i8,
            };
    }
    w.tick(1024 * 12, r)?;
    control.after[1088] = rebuild_summary(&mut summary.after, 0, roots, 13)? as u8;
    pages.push(control);
    pages.push(summary);
    r.cancellation.check()?;
    source.length()?;
    Ok(MapPlan {
        pages,
        _lease: lease,
    })
}

// This is a metadata preflight, never a replay capability. The tentative index
// supplies geometry and a journal-authorized desired bitmap only. Every native
// page is checked against canonical old/new images before a caller can overlay
// the resulting pages and obtain a fresh strict ownership proof.
pub(super) fn recovery_map(
    source: &dyn DecodeRead,
    tentative: &Decoded,
    changes: &[(u64, bool)],
    r: &Resources,
) -> Result<MapPlan> {
    r.cancellation.check()?;
    if changes.len() as u64 > tentative.geometry.mapped {
        return Err(budget("JFS recovery allocation change ceiling"));
    }
    let mut w = Work {
        limits: tentative.limits,
        work: 0,
        pages: 0,
        extents: 0,
        entries: 0,
    };
    w.tick(changes.len() as u64 * 3, r)?;
    if tentative.allocation_agreement
        || changes.is_empty()
        || changes.len() as u64 > tentative.geometry.mapped
        || changes.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || changes.iter().any(|&(block, allocated)| {
            block >= tentative.geometry.mapped || tentative.bitmap[block as usize] != allocated
        })
    {
        return Err(bad("JFS recovery map authorization/index mismatch"));
    }
    let _scratch = r.memory.reserve(65536)?;
    let affected = changes
        .iter()
        .map(|(block, _)| block / 8192)
        .fold((0usize, None), |(count, previous), number| {
            (count + usize::from(previous != Some(number)), Some(number))
        })
        .0;
    let lease = r.memory.reserve(
        ((affected + 2) as u64)
            .checked_mul(crate::platform::mem::size_of::<PagePatch>() as u64)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| budget("JFS recovery map retained charge"))?,
    )?;
    let map = MetadataMap {
        source,
        length: tentative.map_length,
        runs: &tentative.map_runs,
    };
    let mut control = native_page(&map, 0, &mut w, r)?;
    let mut summary = native_page(&map, 3, &mut w, r)?;
    let mut old_control = control.before;
    let mut old_summary = summary.before;
    let mut old_roots = vector(1024)?;
    let mut new_roots = vector(1024)?;
    old_roots.resize(1024, -1);
    new_roots.resize(1024, -1);
    let mut old_total = 0u64;
    let mut new_total = 0u64;
    let mut pages = vector(affected + 2)?;
    let mut cursor = 0usize;
    for number in 0..tentative.geometry.mapped.div_ceil(8192) {
        let mut page = native_page(&map, 4 + number, &mut w, r)?;
        let mut old = page.before;
        let first = number * 8192;
        let covered = (tentative.geometry.mapped - first).min(8192);
        let begin = cursor;
        while changes
            .get(cursor)
            .is_some_and(|entry| entry.0 < first + covered)
        {
            cursor += 1;
        }
        let page_changes = &changes[begin..cursor];
        let mut change_at = 0usize;
        let mut old_free = 0u32;
        let mut new_free = 0u32;
        let mut old_leaves = vector(256)?;
        let mut new_leaves = vector(256)?;
        for word in 0..256 {
            let mut old_word = 0u32;
            let mut new_word = 0u32;
            for bit in 0..32 {
                w.tick(1, r)?;
                let relative = word * 32 + bit;
                let block = first + relative as u64;
                let new_bit = relative as u64 >= covered || tentative.bitmap[block as usize];
                let changed = page_changes
                    .get(change_at)
                    .is_some_and(|entry| entry.0 == block);
                let old_bit = if changed {
                    change_at += 1;
                    !new_bit
                } else {
                    new_bit
                };
                let mask = 0x80000000 >> bit;
                if new_bit {
                    new_word |= mask;
                } else {
                    new_free += 1;
                }
                if old_bit {
                    old_word |= mask;
                } else {
                    old_free += 1;
                }
            }
            w.tick(128, r)?;
            old_leaves.push(word_buddy(old_word));
            new_leaves.push(word_buddy(new_word));
            for at in [2048 + word * 4, 3072 + word * 4] {
                old[at..at + 4].copy_from_slice(&old_word.to_le_bytes());
                page.after[at..at + 4].copy_from_slice(&new_word.to_le_bytes());
            }
        }
        old[4..8].copy_from_slice(&old_free.to_le_bytes());
        page.after[4..8].copy_from_slice(&new_free.to_le_bytes());
        w.tick(256 * 20, r)?;
        old_roots[number as usize] = rebuild_summary(&mut old, 16, old_leaves, 5)?;
        new_roots[number as usize] = rebuild_summary(&mut page.after, 16, new_leaves, 5)?;
        old_total += u64::from(old_free);
        new_total += u64::from(new_free);
        old_control[56 + number as usize * 8..64 + number as usize * 8]
            .copy_from_slice(&u64::from(old_free).to_le_bytes());
        control.after[56 + number as usize * 8..64 + number as usize * 8]
            .copy_from_slice(&u64::from(new_free).to_le_bytes());
        validate_prefix(&page.before, &old, &page.after, &mut w, r)?;
        if !page_changes.is_empty() {
            page.canonical_before = old;
            pages.push(page);
        }
    }
    // Unused group counters are also part of the exact native map proof.
    for number in tentative.geometry.mapped.div_ceil(8192) as usize..128 {
        old_control[56 + number * 8..64 + number * 8].fill(0);
        control.after[56 + number * 8..64 + number * 8].fill(0);
    }
    old_control[8..16].copy_from_slice(&old_total.to_le_bytes());
    control.after[8..16].copy_from_slice(&new_total.to_le_bytes());
    w.tick(1024 * 24, r)?;
    old_control[1088] = rebuild_summary(&mut old_summary, 0, old_roots, 13)? as u8;
    control.after[1088] = rebuild_summary(&mut summary.after, 0, new_roots, 13)? as u8;
    validate_prefix(&control.before, &old_control, &control.after, &mut w, r)?;
    validate_prefix(&summary.before, &old_summary, &summary.after, &mut w, r)?;
    control.canonical_before = old_control;
    summary.canonical_before = old_summary;
    pages.push(control);
    pages.push(summary);
    source.length()?;
    Ok(MapPlan {
        pages,
        _lease: lease,
    })
}
fn validate_prefix(
    observed: &[u8; 4096],
    old: &[u8; 4096],
    new: &[u8; 4096],
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let mut old_suffix = false;
    for ((actual, before), after) in observed.iter().zip(old).zip(new) {
        w.tick(1, r)?;
        if actual == before && actual == after {
            continue;
        }
        if !old_suffix && actual == after {
            continue;
        }
        if actual == before {
            old_suffix = true;
            continue;
        }
        return Err(bad(
            "JFS recovery map is not an authorized ordered native page prefix",
        ));
    }
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn independently_reconstructed_cow_allocation_map_matches_codec_and_complete_ownership() {
    struct Bytes(Vec<u8>);
    impl Storage for Bytes {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.0
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("preflight must not mutate")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("preflight must not flush")
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let storage = Bytes(journal_seed());
    let baseline = inspect(&storage, read, audit, &r).unwrap();
    let source = Borrowed {
        storage: &storage,
        length: storage.0.len() as u64,
        resources: &r,
    };
    let plan = prepare_map(&source, &baseline, &[(112, false), (113, true)], &r).unwrap();
    assert_eq!(plan.pages.len(), 3);
    let mut patches: Vec<_> = plan
        .pages
        .iter()
        .map(|page| {
            assert_eq!(
                &storage.0[page.at as usize..page.at as usize + 4096],
                &page.before
            );
            (page.at, page.after.to_vec())
        })
        .collect();
    let mut inode = baseline.nodes[&6].raw.clone();
    fixture::pxd(&mut inode, 224 + 40, 113, 1);
    patches.push((29 * 4096 + 6 * 512, inode));
    let overlay = Overlay {
        source,
        patches: &patches,
    };
    let resulting = decode(&overlay, read, &r).unwrap();
    assert!(!resulting.bitmap[112] && resulting.bitmap[113]);
    assert_eq!(resulting.geometry.free, baseline.geometry.free);
    assert_eq!(resulting.nodes[&6].runs[0].physical.start, 113);
    assert!(audit_decoded(&resulting, audit, &r).unwrap().is_clean());
    drop(resulting);
    for changes in [
        vec![(112, true)],
        vec![(113, true), (113, true)],
        vec![(480, true)],
    ] {
        assert!(prepare_map(&overlay.source, &baseline, &changes, &r).is_err());
    }
    drop((patches, plan, baseline));
    assert_eq!(r.memory.used(), 0);
}

#[cfg(feature = "std")]
#[test]
fn journal_authorized_partial_bitmap_index_cannot_supply_allocation_authority() {
    struct Bytes(Vec<u8>);
    impl DecodeRead for Bytes {
        fn length(&self) -> Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
            out.copy_from_slice(&self.0[at as usize..at as usize + out.len()]);
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let read = JfsReadLimits {
        blocks: 65536,
        inodes: 64,
        entries: 256,
        pages: 256,
        extents: 256,
        work: 64 * 1024 * 1024,
    };
    let audit = JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    };
    let mut source = Bytes(journal_seed());
    let clean = decode(&source, read, &r).unwrap();
    let plan = prepare_map(&source, &clean, &[(112, false), (113, true)], &r).unwrap();
    let page = plan.pages.iter().find(|page| page.logical == 4).unwrap();
    // Only the working bitmap has reached its post-image; persistent bitmap,
    // native counters and buddy trees are still the independent pre-image.
    let working = page.at as usize + 2048;
    source.0[working..working + 1024].copy_from_slice(&page.after[2048..3072]);
    assert!(decode(&source, read, &r).is_err());
    let changes = [(112, false), (113, true)];
    let tentative = decode_recovery(&source, read, &r, &changes).unwrap();
    assert!(!tentative.allocation_agreement);
    assert!(!tentative.bitmap[112] && tentative.bitmap[113]);
    assert!(audit_decoded(&tentative, audit, &r).is_err());
    // This equal-count COW pair also leaves the buddy summary unchanged,
    // so working-new/persistent-old is a legal ordered page prefix.
    assert!(recovery_map(&source, &tentative, &changes, &r).is_ok());
    let original = journal_seed();
    for cut in [0, 5, 9, 34, 1025, 2063, 3079, 4096] {
        let mut restarted = Bytes(original.clone());
        for patch in &plan.pages {
            let at = patch.at as usize;
            restarted.0[at..at + cut].copy_from_slice(&patch.after[..cut]);
        }
        let desired = decode_recovery(&restarted, read, &r, &changes).unwrap();
        let replay = recovery_map(&restarted, &desired, &changes, &r).unwrap();
        let mut patches: Vec<_> = replay
            .pages
            .iter()
            .map(|page| (page.at, page.after.to_vec()))
            .collect();
        let mut inode = clean.nodes[&6].raw.clone();
        fixture::pxd(&mut inode, 224 + 40, 113, 1);
        patches.push((29 * 4096 + 6 * 512, inode));
        struct Patched<'a> {
            source: &'a Bytes,
            patches: &'a [(u64, Vec<u8>)],
        }
        impl DecodeRead for Patched<'_> {
            fn length(&self) -> Result<u64> {
                self.source.length()
            }
            fn exact(&self, at: u64, out: &mut [u8]) -> Result<()> {
                self.source.exact(at, out)?;
                for (start, bytes) in self.patches {
                    let lo = at.max(*start);
                    let hi = (at + out.len() as u64).min(*start + bytes.len() as u64);
                    if lo < hi {
                        out[(lo - at) as usize..(hi - at) as usize]
                            .copy_from_slice(&bytes[(lo - start) as usize..(hi - start) as usize]);
                    }
                }
                Ok(())
            }
        }
        let verified = decode(
            &Patched {
                source: &restarted,
                patches: &patches,
            },
            read,
            &r,
        )
        .unwrap();
        assert!(audit_decoded(&verified, audit, &r).unwrap().is_clean());
        // Native buddy corruption outside old/new authorized images cannot
        // be laundered by regeneration, even when bitmap masks agree.
        restarted.0[page.at as usize + 33] ^= 0x80;
        let damaged = decode_recovery(&restarted, read, &r, &changes).unwrap();
        assert!(recovery_map(&restarted, &damaged, &changes, &r).is_err());
    }
    // A different bit, even within the same native word, is not authorized.
    source.0[working + 113 / 32 * 4] ^= 1;
    assert!(decode_recovery(&source, read, &r, &changes).is_err());
    for invalid in [
        vec![],
        vec![(113, true), (112, false)],
        vec![(112, false), (112, true)],
        vec![(480, true)],
    ] {
        assert!(decode_recovery(&source, read, &r, &invalid).is_err());
    }
    drop((tentative, plan, clean));
    assert_eq!(r.memory.used(), 0);
}
