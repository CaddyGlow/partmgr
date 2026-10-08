//! Staged bounded native block-map after-image construction; no publication API.
use super::*;

pub(super) struct PagePatch {
    pub(super) at: u64,
    logical: u64,
    pub(super) before: [u8; 4096],
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
            .checked_mul(std::mem::size_of::<PagePatch>() as u64)
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
