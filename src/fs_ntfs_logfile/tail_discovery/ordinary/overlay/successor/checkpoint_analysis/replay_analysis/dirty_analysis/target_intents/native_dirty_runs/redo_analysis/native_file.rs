//! Private native FILE buffer/cache transformations and source-owned MFT effects.
use super::*;

// mi_read uses simple USA framing and admits a restored mismatch as dirty.
pub(super) fn restore(raw: &mut [u8], w: &mut Work, r: &Resources) -> Result<bool> {
    if raw.len() < 512 || !raw.len().is_multiple_of(512) {
        return Err(unsupported("NTFS native FILE sector geometry"));
    }
    charge(w, 12, r)?;
    let offset = usize::from(le16(raw, 4));
    let sectors = raw.len() / 512;
    let bytes = (sectors + 1)
        .checked_mul(2)
        .ok_or_else(|| unsupported("NTFS native FILE USA width"))?;
    if !offset.is_multiple_of(2) || offset.checked_add(bytes).is_none_or(|n| n > 512) {
        return Err(unsupported("NTFS native FILE USA framing"));
    }
    let sample = le16(raw, offset);
    let mut mismatch = false;
    for i in 1..=sectors {
        charge(w, 6, r)?;
        let tail = i * 512 - 2;
        mismatch |= le16(raw, tail) != sample;
        let saved = [raw[offset + 2 * i], raw[offset + 2 * i + 1]];
        raw[tail..tail + 2].copy_from_slice(&saved);
    }
    if le32(raw, 28) as usize != raw.len() {
        return Err(unsupported(
            "NTFS native FILE total differs from source geometry",
        ));
    }
    Ok(mismatch)
}

// ntfs_write_bh updates only cached marker, saving tails into disk/BH copies.
pub(super) fn protect(
    cache: &mut [u8],
    disk: &mut [u8],
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    if cache.len() < 512 || !cache.len().is_multiple_of(512) || disk.len() != cache.len() {
        return Err(unsupported("NTFS native FILE output geometry"));
    }
    charge(w, 12, r)?;
    let offset = usize::from(le16(cache, 4));
    let count = usize::from(le16(cache, 6));
    if !offset.is_multiple_of(2)
        || count == 0
        || offset.checked_add(count * 2).is_none_or(|n| n > 512)
        || (count - 1).checked_mul(512).is_none_or(|n| n > cache.len())
    {
        return Err(unsupported("NTFS native FILE write USA framing"));
    }
    // Native writes every actual sector even when raw fix_num is smaller.
    let actual = cache.len() / 512;
    if offset.checked_add((actual + 1) * 2).is_none_or(|n| n > 512) {
        return Err(unsupported(
            "NTFS native FILE buffer-head USA crossing unresolved",
        ));
    }
    charge(w, cache.len(), r)?;
    disk.copy_from_slice(cache);
    let prior = le16(cache, offset);
    let marker = if prior >= 0x7fff { 1 } else { prior + 1 };
    charge(w, 4, r)?;
    cache[offset..offset + 2].copy_from_slice(&marker.to_le_bytes());
    disk[offset..offset + 2].copy_from_slice(&marker.to_le_bytes());
    for i in 1..=actual {
        charge(w, 6, r)?;
        let tail = i * 512 - 2;
        let saved = [cache[tail], cache[tail + 1]];
        disk[offset + 2 * i..offset + 2 * i + 2].copy_from_slice(&saved);
        disk[tail..tail + 2].copy_from_slice(&marker.to_le_bytes());
    }
    Ok(())
}

// Deallocate preparation skips native FILE/attribute validation and LSN gate.
pub(super) fn deallocate(
    cache: &mut [u8],
    redo_lsn: Option<u64>,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    if cache.len() < 48 {
        return Err(unsupported("NTFS native FILE fixed header"));
    }
    charge(w, 8, r)?;
    let flags = le16(cache, 22) & !1;
    let sequence = le16(cache, 16).wrapping_add(1);
    cache[22..24].copy_from_slice(&flags.to_le_bytes());
    cache[16..18].copy_from_slice(&sequence.to_le_bytes());
    if let Some(lsn) = redo_lsn {
        charge(w, 8, r)?;
        cache[8..16].copy_from_slice(&lsn.to_le_bytes());
    }
    Ok(())
}

fn admit_fragment_bytes(
    fragments: &[NtfsLogRedoFragment],
    bytes: usize,
    maximum: usize,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let mut total = bytes;
    for fragment in fragments {
        charge(w, 1, r)?;
        total = total
            .checked_add(fragment.original.len())
            .ok_or_else(|| exhausted("NTFS FILE retained source bytes"))?;
    }
    if total > maximum {
        return Err(exhausted("NTFS FILE retained source byte ceiling"));
    }
    Ok(())
}

// Cached FILE writes must check the whole consumed query graph too: a
// cache hit skips physical preparation, but does not prove MFT/log disjointness.
pub(super) fn reject_log_overlap(
    physical: u64,
    length: usize,
    ranges: impl Iterator<Item = (u64, usize)>,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    let end = physical
        .checked_add(length as u64)
        .ok_or_else(|| unsupported("NTFS FILE physical effect range overflow"))?;
    for (offset, bytes) in ranges {
        charge(w, 1, r)?;
        let query_end = offset
            .checked_add(bytes as u64)
            .ok_or_else(|| unsupported("NTFS FILE consumed query range overflow"))?;
        if physical < query_end && offset < end {
            return Err(unsupported(
                "NTFS FILE effect overlaps ordered log query source",
            ));
        }
    }
    Ok(())
}
// Initialize bypasses check_file_record/check_lsn just like native op2. The
// uncached mi_format_new branch remains explicit unsupported until modeled.
pub(super) enum Mutation<'a> {
    Deallocate,
    Initialize { offset: usize, data: &'a [u8] },
}

fn mutate(
    cache: &mut [u8],
    mutation: Mutation<'_>,
    redo_lsn: Option<u64>,
    dirty_volume: &mut bool,
    w: &mut Work,
    r: &Resources,
) -> Result<bool> {
    match mutation {
        Mutation::Deallocate => deallocate(cache, redo_lsn, w, r)?,
        Mutation::Initialize { offset, data } => {
            charge(w, 1, r)?;
            if offset
                .checked_add(data.len())
                .is_none_or(|end| end > cache.len())
            {
                // Native dirty_vol sets log->set_dirty and returns current err=0;
                // it does not reach the LSN update or mi_write.
                *dirty_volume = true;
                return Ok(false);
            }
            charge(w, data.len(), r)?;
            cache[offset..offset + data.len()].copy_from_slice(data);
            if let Some(lsn) = redo_lsn {
                charge(w, 8, r)?;
                cache[8..16].copy_from_slice(&lsn.to_le_bytes());
            }
        }
    }
    Ok(true)
}

// Interpreter wiring: source-owned MFT scatter plus native cached/cold distinction.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply<'a>(
    context: &NtfsLogNativeAnalysisContext,
    captures: impl Iterator<Item = &'a NativeReadCapture> + Clone,
    files: &mut Vec<NtfsLogRuntimeFile>,
    fragments: &mut Vec<NtfsLogRedoFragment>,
    vbo: u64,
    cached: bool,
    mutation: Mutation<'_>,
    dirty_volume: &mut bool,
    lsn: u64,
    redo_lsn: Option<u64>,
    limits: NtfsLogRedoLimits,
    w: &mut Work,
    r: &Resources,
) -> Result<bool> {
    let size = context.geometry().record_bytes();
    let number = vbo / size as u64;
    let mut selected = None;
    for (index, file) in files.iter().enumerate() {
        charge(w, 1, r)?;
        if file.number == number && file.cached && file.loaded {
            selected = Some(index);
            break;
        }
    }
    if selected.is_none() && matches!(mutation, Mutation::Initialize { .. }) {
        return Err(unsupported(
            "NTFS initialize FILE requires actual loaded inode cache; mi_format_new unresolved",
        ));
    }
    let index = if let Some(index) = selected {
        index
    } else {
        if files.len() >= limits.files {
            return Err(exhausted("NTFS FILE runtime inventory"));
        }
        let mut retained = size;
        for file in files.iter() {
            charge(w, 1, r)?;
            retained = retained
                .checked_add(file.raw.len())
                .ok_or_else(|| exhausted("NTFS FILE cache bytes"))?;
        }
        if retained > limits.file_bytes {
            return Err(exhausted("NTFS FILE cache byte ceiling"));
        }
        let start = number
            .checked_mul(size as u64)
            .ok_or_else(|| unsupported("NTFS FILE virtual range"))?;
        let (map, bound) = context.native_mft_map();
        if start.checked_add(size as u64).is_none_or(|n| n > bound) {
            return Err(unsupported(
                "NTFS native FILE beyond logical MFT requires whole native runs",
            ));
        }
        charge(w, size, r)?;
        let lease = r.memory.reserve(size as u64)?;
        let raw = bytes(size)?;
        let (segments, segment_lease) = vector(limits.fragments, r)?;
        let index = files.len();
        files.push(NtfsLogRuntimeFile {
            number,
            cached,
            loaded: false,
            fixup_mismatch: false,
            raw,
            segments,
            _lease: lease,
            _segments_lease: segment_lease,
        });
        let mut cursor = start;
        let mut done = 0;
        while done < size {
            let mut selected = None;
            for extent in map {
                charge(w, 1, r)?;
                if cursor >= extent.offset && cursor - extent.offset < extent.length {
                    selected = Some(*extent);
                    break;
                }
            }
            let extent =
                selected.ok_or_else(|| unsupported("NTFS native FILE missing MFT range"))?;
            let physical = match extent.kind {
                crate::fs_file::ExtentKind::Data(at) => at
                    .checked_add(cursor - extent.offset)
                    .ok_or_else(|| unsupported("NTFS FILE physical range"))?,
                _ => return Err(unsupported("NTFS native FILE nonphysical MFT range")),
            };
            let n = (size - done).min(
                usize::try_from(extent.length - (cursor - extent.offset)).unwrap_or(usize::MAX),
            );
            if n == 0 || fragments.len() >= limits.fragments {
                return Err(exhausted("NTFS FILE physical fragment ceiling"));
            }
            reject_log_overlap(
                physical,
                n,
                captures.clone().flat_map(|capture| capture.ranges()),
                w,
                r,
            )?;
            admit_fragment_bytes(fragments, n, limits.bytes, w, r)?;
            charge(
                w,
                n.checked_mul(4)
                    .ok_or_else(|| exhausted("NTFS FILE retained source work"))?,
                r,
            )?;
            let lease = r.memory.reserve(
                (n as u64)
                    .checked_mul(2)
                    .ok_or_else(|| exhausted("NTFS FILE source memory"))?,
            )?;
            let mut original = bytes(n)?;
            let mut after = bytes(n)?;
            let mut complete = false;
            let result =
                context.read_native_physical_observed(physical, &mut original, r, &mut complete);
            if !complete {
                result?;
                return Err(unsupported("NTFS FILE source completion unavailable"));
            }
            after.copy_from_slice(&original);
            let fragment = fragments.len();
            fragments.push(NtfsLogRedoFragment {
                lsn,
                offset: physical,
                original,
                after,
                written: false,
                _lease: lease,
            });
            files[index].segments.push((physical, done, n, fragment));
            result?;
            let (prior, current) = fragments.split_at_mut(fragment);
            let current = &mut current[0];
            for previous in prior {
                charge(w, 1, r)?;
                let lo = physical.max(previous.offset);
                let hi = (physical + n as u64).min(previous.offset + previous.after.len() as u64);
                if lo < hi {
                    charge(w, (hi - lo) as usize, r)?;
                    current.after[(lo - physical) as usize..(hi - physical) as usize]
                        .copy_from_slice(
                            &previous.after
                                [(lo - previous.offset) as usize..(hi - previous.offset) as usize],
                        );
                }
            }
            charge(w, n, r)?;
            files[index].raw[done..done + n].copy_from_slice(&current.after);
            done += n;
            cursor = cursor
                .checked_add(n as u64)
                .ok_or_else(|| unsupported("NTFS FILE MFT scatter overflow"))?;
        }
        files[index].fixup_mismatch = restore(&mut files[index].raw, w, r)?;
        files[index].loaded = true;
        index
    };
    // All effects remain private shadows. Persistent bytes and cache differ at USA.
    if !mutate(
        &mut files[index].raw,
        mutation,
        redo_lsn,
        dirty_volume,
        w,
        r,
    )? {
        return Ok(false);
    }
    charge(w, size, r)?;
    let _lease = r.memory.reserve(size as u64)?;
    let mut disk = bytes(size)?;
    protect(&mut files[index].raw, &mut disk, w, r)?;
    for &(physical, start, n, source) in &files[index].segments {
        charge(w, 1, r)?;
        reject_log_overlap(
            physical,
            n,
            captures.clone().flat_map(|capture| capture.ranges()),
            w,
            r,
        )?;
        if fragments.len() >= limits.fragments {
            return Err(exhausted("NTFS FILE write fragment ceiling"));
        }
        admit_fragment_bytes(fragments, n, limits.bytes, w, r)?;
        charge(
            w,
            n.checked_mul(4)
                .ok_or_else(|| exhausted("NTFS FILE write fragment work"))?,
            r,
        )?;
        let lease = r.memory.reserve(
            (n as u64)
                .checked_mul(2)
                .ok_or_else(|| exhausted("NTFS FILE write fragment memory"))?,
        )?;
        let mut original = bytes(n)?;
        let mut after = bytes(n)?;
        original.copy_from_slice(&fragments[source].original);
        after.copy_from_slice(&disk[start..start + n]);
        fragments.push(NtfsLogRedoFragment {
            lsn,
            offset: physical,
            original,
            after,
            written: true,
            _lease: lease,
        });
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initialize_cached_file_bypasses_header_validation_and_preserves_null_lsn() {
        let r = Resources {
            memory: crate::fs_core::Budget::new(8192),
            cancellation: Default::default(),
        };
        let mut w = Work {
            used: 0,
            maximum: 8192,
        };
        let mut cache = vec![0; 1024];
        cache[..4].copy_from_slice(b"BAAD");
        cache[4..6].copy_from_slice(&48u16.to_le_bytes());
        cache[6..8].copy_from_slice(&3u16.to_le_bytes());
        cache[8..16].copy_from_slice(&900u64.to_le_bytes());
        cache[48..50].copy_from_slice(&7u16.to_le_bytes());
        let mut dirty = false;
        assert!(
            mutate(
                &mut cache,
                Mutation::Initialize {
                    offset: 510,
                    data: b"TAIL"
                },
                Some(12),
                &mut dirty,
                &mut w,
                &r
            )
            .unwrap()
        );
        assert_eq!(le64(&cache, 8), 12); // no native check_lsn gate
        assert_eq!(&cache[..4], b"BAAD"); // no check_file_record
        assert!(
            mutate(
                &mut cache,
                Mutation::Initialize {
                    offset: 100,
                    data: b"UNDO"
                },
                None,
                &mut dirty,
                &mut w,
                &r
            )
            .unwrap()
        );
        assert_eq!(le64(&cache, 8), 12);
        assert_eq!(&cache[100..104], b"UNDO");
        let mut disk = vec![0; 1024];
        protect(&mut cache, &mut disk, &mut w, &r).unwrap();
        assert_eq!(&cache[510..512], b"TA");
        assert_eq!(&disk[50..52], b"TA");
        assert_eq!(le16(&disk, 510), 8);
        let before = cache.clone();
        assert!(
            !mutate(
                &mut cache,
                Mutation::Initialize {
                    offset: 1023,
                    data: b"BAD"
                },
                Some(13),
                &mut dirty,
                &mut w,
                &r
            )
            .unwrap()
        );
        assert!(dirty);
        assert_eq!(cache, before); // dirty_vol returns before LSN/write effects
    }

    #[test]
    fn cached_file_write_rejects_new_undo_query_overlap_and_accepts_adjacent_ranges() {
        let r = Resources {
            memory: crate::fs_core::Budget::new(64),
            cancellation: Default::default(),
        };
        let mut w = Work {
            used: 0,
            maximum: 16,
        };
        let error =
            reject_log_overlap(100, 10, [(80, 20), (109, 1)].into_iter(), &mut w, &r).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert_eq!(w.used, 2);
        reject_log_overlap(100, 10, [(80, 20), (110, 20)].into_iter(), &mut w, &r).unwrap();
        assert_eq!(w.used, 4);
    }
    #[test]
    fn native_simple_usa_deallocate_and_cached_disk_separation() {
        let r = Resources {
            memory: crate::fs_core::Budget::new(8192),
            cancellation: Default::default(),
        };
        let mut w = Work {
            used: 0,
            maximum: 8192,
        };
        let mut cache = vec![0; 1024];
        cache[..4].copy_from_slice(b"BAAD");
        cache[4..6].copy_from_slice(&48u16.to_le_bytes());
        cache[6..8].copy_from_slice(&2u16.to_le_bytes()); // simple read derives3
        cache[16..18].copy_from_slice(&u16::MAX.to_le_bytes());
        cache[22..24].copy_from_slice(&3u16.to_le_bytes());
        cache[28..32].copy_from_slice(&1024u32.to_le_bytes());
        cache[48..50].copy_from_slice(&0x7fffu16.to_le_bytes());
        cache[50..54].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        cache[510..512].copy_from_slice(&0x7fffu16.to_le_bytes());
        cache[1022..1024].copy_from_slice(&1u16.to_le_bytes());
        assert!(restore(&mut cache, &mut w, &r).unwrap());
        assert_eq!(&cache[510..512], &[0x12, 0x34]);
        assert_eq!(&cache[1022..1024], &[0x56, 0x78]);
        deallocate(&mut cache, Some(99), &mut w, &r).unwrap();
        assert_eq!(le16(&cache, 16), 0);
        assert_eq!(le16(&cache, 22), 2);
        assert_eq!(le64(&cache, 8), 99);
        // Saved USA words in cache are not refreshed by the native writer.
        cache[510..512].copy_from_slice(&[0xaa, 0xbb]);
        let mut disk = vec![0; 1024];
        protect(&mut cache, &mut disk, &mut w, &r).unwrap();
        assert_eq!(le16(&cache, 48), 1);
        assert_eq!(&cache[50..52], &[0x12, 0x34]);
        assert_eq!(&disk[50..52], &[0xaa, 0xbb]);
        assert_eq!(le16(&disk, 510), 1);
        assert_eq!(&cache[510..512], &[0xaa, 0xbb]);
    }
}
