//! Source-ordered native run_unpack/run_add_entry projection; no disk writes.
use super::*;
/// A native cluster run before EOF/initialized-size clipping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogNativeRun {
    /// First native virtual cluster.
    pub vcn: u64,
    /// First physical cluster; None is native SPARSE_LCN.
    pub lcn: Option<u64>,
    /// Native cluster length.
    pub clusters: u64,
}
struct Work {
    used: usize,
    maximum: usize,
}
impl Work {
    fn add(&mut self, n: usize, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        self.used = self
            .used
            .checked_add(n)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| exhausted("NTFS native target run work"))?;
        Ok(())
    }
}
fn end(run: NtfsLogNativeRun) -> Result<u64> {
    run.vcn
        .checked_add(run.clusters)
        .ok_or_else(|| unsupported("NTFS native target run end overflow"))
}
fn piece(run: NtfsLogNativeRun, start: u64, stop: u64) -> Result<NtfsLogNativeRun> {
    Ok(NtfsLogNativeRun {
        vcn: start,
        clusters: stop - start,
        lcn: run
            .lcn
            .map(|l| {
                l.checked_add(start - run.vcn)
                    .ok_or_else(|| unsupported("NTFS native target LCN overflow"))
            })
            .transpose()?,
    })
}
fn replace(
    map: &mut Vec<NtfsLogNativeRun>,
    scratch: &mut Vec<NtfsLogNativeRun>,
    new: NtfsLogNativeRun,
    capacity: usize,
    w: &mut Work,
    r: &Resources,
) -> Result<()> {
    scratch.clear();
    let stop = end(new)?;
    let mut inserted = false;
    for old in map.iter().copied() {
        w.add(1, r)?;
        let oldstop = end(old)?;
        if oldstop <= new.vcn {
            scratch.push(old);
            continue;
        }
        if old.vcn >= stop {
            if !inserted {
                scratch.push(new);
                inserted = true;
            }
            scratch.push(old);
            continue;
        }
        if old.vcn < new.vcn {
            scratch.push(piece(old, old.vcn, new.vcn)?);
        }
        if !inserted {
            scratch.push(new);
            inserted = true;
        }
        if oldstop > stop {
            scratch.push(piece(old, stop, oldstop)?);
        }
    }
    if !inserted {
        scratch.push(new);
    }
    if scratch.len() > capacity {
        return Err(exhausted("NTFS native target normalized run ceiling"));
    }
    // Coalesce equivalent neighbors, exactly preserving sparse versus physical.
    let mut out = 0usize;
    for i in 0..scratch.len() {
        w.add(1, r)?;
        let next = scratch[i];
        let merge = out > 0
            && end(scratch[out - 1])? == next.vcn
            && match (scratch[out - 1].lcn, next.lcn) {
                (None, None) => true,
                (Some(l), Some(n)) => l.checked_add(scratch[out - 1].clusters) == Some(n),
                _ => false,
            };
        if merge {
            scratch[out - 1].clusters = scratch[out - 1]
                .clusters
                .checked_add(next.clusters)
                .ok_or_else(|| unsupported("NTFS native merged run overflow"))?;
        } else {
            scratch[out] = next;
            out += 1;
        }
    }
    scratch.truncate(out);
    core::mem::swap(map, scratch);
    Ok(())
}
pub(super) fn decode_target_runs(
    attributes: &[NtfsNativeAttribute],
    input: &[usize],
    volume_clusters: u64,
    limits: NtfsStreamLimits,
    r: &Resources,
) -> Result<Budgeted<Vec<NtfsLogNativeRun>>> {
    let capacity = limits
        .runs
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| exhausted("NTFS native target run capacity"))?;
    let bytes = capacity
        .checked_mul(core::mem::size_of::<NtfsLogNativeRun>())
        .ok_or_else(|| exhausted("NTFS native target run inventory"))?;
    let _scratchlease = r.memory.reserve(bytes as u64)?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(capacity)
        .map_err(|_| exhausted("NTFS native run scratch allocation"))?;
    if scratch.capacity() > capacity {
        return Err(exhausted("NTFS native run scratch capacity"));
    }
    let mut w = Work {
        used: 0,
        maximum: limits.work,
    };
    let mut count = 0usize;
    Budgeted::try_new(&r.memory, bytes as u64, || {
        let mut map = Vec::new();
        map.try_reserve_exact(capacity)
            .map_err(|_| exhausted("NTFS native run map allocation"))?;
        if map.capacity() > capacity {
            return Err(exhausted("NTFS native run map capacity"));
        }
        for index in input {
            w.add(1, r)?;
            let attribute = attributes
                .get(*index)
                .ok_or_else(|| invalid("NTFS native run input provenance"))?;
            if !attribute.nonresident {
                continue;
            }
            let b = &attribute.raw;
            let first = u64::from_le_bytes(b[16..24].try_into().unwrap());
            let last = u64::from_le_bytes(b[24..32].try_into().unwrap());
            if last.wrapping_add(1) == first {
                continue;
            }
            let finish = last
                .checked_add(1)
                .ok_or_else(|| unsupported("NTFS native run terminal overflow"))?;
            if last < first {
                return Err(invalid("NTFS native run VCN order"));
            }
            let mut at = usize::from(u16::from_le_bytes(b[32..34].try_into().unwrap()));
            if at > b.len() {
                return Err(invalid("NTFS native run offset"));
            }
            let mut vcn = first;
            let mut previous = 0i128;
            while at < b.len() {
                w.add(1, r)?;
                let header = b[at];
                at += 1;
                let n = usize::from(header & 15);
                let m = usize::from(header >> 4);
                if n == 0 {
                    break;
                }
                if n > 8 || m > 8 || at.checked_add(n + m).is_none_or(|n| n > b.len()) {
                    return Err(invalid("NTFS native mapping-pair framing"));
                }
                w.add(n + m, r)?;
                let mut raw = [0u8; 8];
                raw[..n].copy_from_slice(&b[at..at + n]);
                at += n;
                let clusters = u64::from_le_bytes(raw);
                if clusters == 0 {
                    return Err(invalid("NTFS native zero run"));
                }
                let lcn = if m == 0 {
                    None
                } else {
                    let mut raw = if b[at + m - 1] & 128 != 0 {
                        [255; 8]
                    } else {
                        [0; 8]
                    };
                    raw[..m].copy_from_slice(&b[at..at + m]);
                    at += m;
                    let delta = i64::from_le_bytes(raw);
                    if delta == 0 {
                        return Err(invalid("NTFS native zero run delta"));
                    }
                    previous = previous
                        .checked_add(i128::from(delta))
                        .ok_or_else(|| unsupported("NTFS native LCN arithmetic"))?;
                    let lcn = u64::try_from(previous)
                        .map_err(|_| invalid("NTFS native negative run LCN"))?;
                    if lcn
                        .checked_add(clusters)
                        .is_none_or(|end| end > volume_clusters)
                    {
                        return Err(invalid("NTFS native run outside volume"));
                    }
                    Some(lcn)
                };
                let next = vcn
                    .checked_add(clusters)
                    .filter(|n| *n <= finish)
                    .ok_or_else(|| invalid("NTFS native run exceeds end VCN"))?;
                if next > 0x1_0000_0000
                    || lcn.is_some_and(|l| {
                        l.checked_add(clusters)
                            .is_none_or(|end| end > 0x1_0000_0000)
                    })
                {
                    return Err(unsupported(
                        "NTFS native cluster width configuration unresolved",
                    ));
                }
                count = count
                    .checked_add(1)
                    .filter(|n| *n <= limits.runs)
                    .ok_or_else(|| exhausted("NTFS native target decoded run ceiling"))?;
                replace(
                    &mut map,
                    &mut scratch,
                    NtfsLogNativeRun { vcn, lcn, clusters },
                    capacity,
                    &mut w,
                    r,
                )?;
                vcn = next;
            }
            if vcn != finish {
                return Err(invalid("NTFS native run terminal VCN"));
            }
        }
        r.cancellation.check()?;
        Ok(map)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> NtfsStreamLimits {
        NtfsStreamLimits {
            extension_records: 1,
            list_entries: 16,
            list_bytes: 4096,
            attributes: 16,
            runs: 16,
            work: 10000,
        }
    }
    fn attribute(first: u64, last: u64, pairs: &[u8]) -> NtfsNativeAttribute {
        let mut raw = vec![0; 64 + pairs.len()];
        raw[16..24].copy_from_slice(&first.to_le_bytes());
        raw[24..32].copy_from_slice(&last.to_le_bytes());
        raw[32..34].copy_from_slice(&64u16.to_le_bytes());
        raw[64..].copy_from_slice(pairs);
        let id = ObjectId {
            source: 1,
            generation: 7,
            native: 2u64.to_le_bytes().to_vec(),
        };
        NtfsNativeAttribute {
            owner: id.clone(),
            record: id,
            offset: 64,
            kind: 0x80,
            instance: 1,
            name: Vec::new(),
            flags: 0,
            nonresident: true,
            raw,
        }
    }
    #[test]
    fn native_physical_runs_preserve_continuations_and_replace_source_order_without_eof_clip() {
        let r = resources();
        let attributes = [
            attribute(10, 12, &[0x11, 3, 20, 0]),
            attribute(11, 11, &[0x11, 1, 50, 0]),
        ];
        let map = decode_target_runs(&attributes, &[0, 1], 1024, limits(), &r).unwrap();
        assert_eq!(
            map.get().as_slice(),
            &[
                NtfsLogNativeRun {
                    vcn: 10,
                    lcn: Some(20),
                    clusters: 1
                },
                NtfsLogNativeRun {
                    vcn: 11,
                    lcn: Some(50),
                    clusters: 1
                },
                NtfsLogNativeRun {
                    vcn: 12,
                    lcn: Some(22),
                    clusters: 1
                }
            ]
        );
        drop(map);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn native_sparse_run_does_not_reset_previous_physical_delta() {
        let r = resources();
        let a = attribute(0, 6, &[0x11, 2, 30, 0x01, 3, 0x11, 2, 5, 0]);
        let map = decode_target_runs(&[a], &[0], 1024, limits(), &r).unwrap();
        assert_eq!(
            map.get().as_slice(),
            &[
                NtfsLogNativeRun {
                    vcn: 0,
                    lcn: Some(30),
                    clusters: 2
                },
                NtfsLogNativeRun {
                    vcn: 2,
                    lcn: None,
                    clusters: 3
                },
                NtfsLogNativeRun {
                    vcn: 5,
                    lcn: Some(35),
                    clusters: 2
                }
            ]
        );
        drop(map);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn native_empty_run_and_native_zero_delta_are_distinct() {
        let r = resources();
        let empty =
            decode_target_runs(&[attribute(0, u64::MAX, &[])], &[0], 1024, limits(), &r).unwrap();
        assert!(empty.is_empty());
        drop(empty);
        assert_eq!(
            decode_target_runs(
                &[attribute(0, 0, &[0x11, 1, 0, 0])],
                &[0],
                1024,
                limits(),
                &r
            )
            .err()
            .unwrap()
            .kind,
            ErrorKind::InvalidData
        );
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn native_run_ceiling_work_and_cancellation_refund_all_maps() {
        for kind in 0..3 {
            let r = resources();
            let mut l = limits();
            if kind == 0 {
                l.runs = 0;
            } else if kind == 1 {
                l.work = 0;
            } else {
                r.cancellation.cancel();
            }
            let error =
                decode_target_runs(&[attribute(0, 0, &[0x11, 1, 30, 0])], &[0], 1024, l, &r)
                    .err()
                    .unwrap();
            assert_eq!(
                error.kind,
                if kind == 2 {
                    ErrorKind::Cancelled
                } else {
                    ErrorKind::BudgetExhausted
                }
            );
            assert_eq!(r.memory.used(), 0);
        }
    }
}
