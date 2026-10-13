//! Private source-derived Linux v6.15 attribute selection and physical run input.
use super::*;

pub(crate) struct NativeLogSelection {
    pub(crate) attributes: Budgeted<Vec<NtfsNativeAttribute>>,
    pub(crate) winner: Option<usize>,
    pub(crate) directory: bool,
    pub(crate) run_inputs: Budgeted<Vec<usize>>,
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
            .filter(|v| *v <= self.maximum)
            .ok_or_else(|| budget("NTFS native target selection work"))?;
        Ok(())
    }
}
fn exact_name(record: &NtfsRecord, a: Attribute, name: &[u16]) -> bool {
    let raw = native_name(record, a);
    raw.len() == name.len() * 2
        && raw
            .chunks_exact(2)
            .zip(name)
            .all(|(a, b)| u16le(a, 0) == *b)
}
// Native mi_find_attr returns at the first higher type, in physical FILE order.
fn physical_winner(
    record: &NtfsRecord,
    kind: u32,
    name: &[u16],
    instance: Option<u16>,
    w: &mut Work,
    r: &Resources,
) -> Result<Option<Attribute>> {
    for a in &record.attributes {
        w.add(name.len() + 1, r)?;
        if a.kind > kind {
            return Ok(None);
        }
        if a.kind == kind
            && exact_name(record, *a, name)
            && instance.is_none_or(|id| u16le(attribute_bytes(record, *a), 14) == id)
        {
            return Ok(Some(*a));
        }
    }
    Ok(None)
}
fn collate(raw: &[u8], name: &[u16], upper: &[u8]) -> core::cmp::Ordering {
    let mut original = core::cmp::Ordering::Equal;
    let mut folded = core::cmp::Ordering::Equal;
    for (a, b) in raw.chunks_exact(2).zip(name) {
        let a = u16le(a, 0);
        if original == core::cmp::Ordering::Equal {
            original = a.cmp(b);
        }
        let fold = |c: u16| {
            if c < u16::from(b'a') {
                c
            } else if c <= u16::from(b'z') {
                c - 32
            } else {
                u16le(upper, usize::from(c) * 2)
            }
        };
        if folded == core::cmp::Ordering::Equal {
            folded = fold(a).cmp(&fold(*b));
        }
    }
    folded.then(original)
}
impl NtfsVolume {
    pub(crate) fn native_log_selection(
        &self,
        object: &ObjectId,
        kind: u32,
        name: &[u16],
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<NativeLogSelection> {
        let mut w = Work {
            used: 0,
            maximum: limits.work,
        };
        let envelope = limits
            .attributes
            .checked_mul(limits.attributes)
            .and_then(|n| n.checked_add(limits.list_entries.checked_mul(limits.attributes)?))
            .and_then(|n| n.checked_add(limits.runs.checked_mul(limits.attributes)?))
            .ok_or_else(|| budget("NTFS native target resolution envelope"))?;
        w.add(envelope, r)?;
        let resolved = self.resolve_stream_record(object, limits, r)?;
        let base = &resolved.records[0];
        w.add(base.attributes.len(), r)?;
        let standard = base
            .attributes
            .iter()
            .find(|a| a.kind == 0x10)
            .copied()
            .ok_or_else(|| unsupported("NTFS native inode STANDARD_INFORMATION unavailable"))?;
        if standard.nonresident || base.value(standard)?.len() < 48 {
            return Err(unsupported("NTFS native inode STANDARD_INFORMATION form"));
        }
        let mut native_regular = false;
        let mut names = 0usize;
        let mut directory_root = false;
        for located in &resolved.attributes {
            w.add(1, r)?;
            let record = &resolved.records[located.record];
            let a = located.attribute;
            let raw = attribute_bytes(record, a);
            let low = if a.nonresident { u64le(raw, 16) } else { 0 };
            if low != 0 {
                continue;
            }
            if a.nonresident && (u64le(raw, 48) > u64le(raw, 40) || u64le(raw, 56) > u64le(raw, 40))
            {
                return Err(bad("NTFS native inode nonresident sizes"));
            }
            if a.kind == 0x80 && native_name(record, a).is_empty() {
                native_regular = true;
            }
            match a.kind {
                0x30 => {
                    if a.nonresident || record.value(a)?.len() < 66 {
                        return Err(bad("NTFS native inode FILE_NAME form"));
                    }
                    names += 1;
                }
                0x90 if base.is_directory() && exact_name(record, a, &[0x24, 0x49, 0x33, 0x30]) => {
                    if a.nonresident {
                        return Err(bad("NTFS native inode root form"));
                    }
                    let value = record.value(a)?;
                    if value.len() < 32 || u32le(value, 0) != 0x30 || u32le(value, 4) != 1 {
                        return Err(bad("NTFS native inode root collation"));
                    }
                    directory_root = true;
                }
                0xc0 | 0xd0 | 0xe0 | 0xf0 | 0x100 => {
                    return Err(unsupported(
                        "NTFS native inode special mode effects incomplete",
                    ));
                }
                _ => {}
            }
        }
        if base.is_directory() {
            return Err(unsupported(
                "NTFS native directory index initialization admission incomplete",
            ));
        }
        if !native_regular {
            return Err(unsupported(
                "NTFS native special inode mode admission incomplete",
            ));
        }
        if names == 0 || base.is_directory() && !directory_root {
            return Err(unsupported(
                "NTFS native inode names/directory mode unavailable",
            ));
        }

        w.add(base.attributes.len(), r)?;
        let mut list_bytes = 0;
        if let Some(a) = base.attributes.iter().find(|a| a.kind == 0x20) {
            list_bytes = if a.nonresident {
                u64le(attribute_bytes(base, *a), 48)
            } else {
                base.value(*a)?.len() as u64
            };
        }
        let uses_list = list_bytes != 0 && !(name.is_empty() && matches!(kind, 0x10 | 0x20));
        let mut upper = Vec::new();
        let _upper_lease = r.memory.reserve(if uses_list && !name.is_empty() {
            131072
        } else {
            0
        })?;
        if uses_list && !name.is_empty() {
            w.add(131072 + 65536, r)?;
            w.add(envelope, r)?;
            let id = self.stream_identity(10, r)?;
            w.add(envelope, r)?;
            let streams = self.data_streams(&id, limits, r)?;
            if streams.len() != 1
                || !streams[0].name.is_empty()
                || streams[0].initialized != 131072
                || streams[0].length != 131072
                || streams[0].sparse
                || streams[0].compressed
            {
                return Err(unsupported(
                    "NTFS source UpCase fully initialized stream profile",
                ));
            }
            let file = self.open_native_attribute_stream(&id, 0x80, &[], limits, r)?;
            if file.len() != 131072 {
                return Err(unsupported("NTFS source UpCase selection size"));
            }
            upper = vector(131072)?;
            if upper.capacity() > 131072 {
                return Err(budget("NTFS source UpCase selection capacity"));
            }
            upper.resize(131072, 0);
            if file.read_at(0, &mut upper, r)? != upper.len() {
                return Err(bad("NTFS source UpCase selection truncated"));
            }
            for i in 0..65536usize {
                r.cancellation.check()?;
                let mapped = usize::from(u16le(&upper, i * 2));
                if u16le(&upper, mapped * 2) != mapped as u16 {
                    return Err(bad("NTFS source UpCase selection idempotence"));
                }
            }
        }
        let chosen = if !uses_list {
            physical_winner(base, kind, name, None, &mut w, r)?.map(|a| (0, a))
        } else {
            let mut selected = None;
            // Resolved.attributes preserves actual ListWalk order, validated against
            // exact record/instance/name/VCN. No header sort or successor inference.
            for located in &resolved.attributes {
                w.add(name.len() + 1, r)?;
                let rec = &resolved.records[located.record];
                let a = located.attribute;
                if a.kind < kind {
                    continue;
                }
                if a.kind > kind {
                    break;
                }
                let actual = native_name(rec, a);
                if actual.len() != name.len() * 2 {
                    continue;
                }
                let low = if a.nonresident {
                    u64le(attribute_bytes(rec, a), 16)
                } else {
                    0
                };
                if low == 0 && !name.is_empty() {
                    match collate(actual, name, &upper) {
                        core::cmp::Ordering::Less => continue,
                        core::cmp::Ordering::Greater => break,
                        core::cmp::Ordering::Equal => {}
                    }
                }
                let id = u16le(attribute_bytes(rec, a), 14);
                selected = physical_winner(rec, kind, name, Some(id), &mut w, r)?
                    .filter(|a| !a.nonresident || u64le(attribute_bytes(rec, *a), 16) == 0)
                    .map(|a| (located.record, a));
                break;
            }
            selected
        };
        let mut output_index = None;
        let mut at = 0;
        for (ri, record) in resolved.records.iter().enumerate() {
            for a in &record.attributes {
                w.add(
                    a.length
                        .checked_mul(2)
                        .ok_or_else(|| budget("NTFS target raw work"))?,
                    r,
                )?;
                if chosen.is_some_and(|(index, found)| index == ri && found.start == a.start) {
                    output_index = Some(at);
                }
                at += 1;
            }
        }
        let run_inputs = Budgeted::try_new(
            &r.memory,
            limits
                .attributes
                .checked_mul(core::mem::size_of::<usize>())
                .ok_or_else(|| budget("NTFS native run-input inventory"))? as u64,
            || {
                let mut input = vector(limits.attributes)?;
                if input.capacity() > limits.attributes {
                    return Err(budget("NTFS native run-input capacity"));
                }
                if let Some(winner) = output_index {
                    let number = u64le(&object.native, 0);
                    let shared_file = !base.is_directory() && kind == 0x80 && name.is_empty();
                    let shared_dir =
                        base.is_directory() && kind == 0xa0 && name == [0x24, 0x49, 0x33, 0x30];
                    if shared_file || shared_dir {
                        for located in &resolved.attributes {
                            w.add(
                                limits
                                    .attributes
                                    .checked_mul(2)
                                    .and_then(|n| n.checked_add(name.len() + 1))
                                    .ok_or_else(|| budget("NTFS run-input scan work"))?,
                                r,
                            )?;
                            let rec = &resolved.records[located.record];
                            let a = located.attribute;
                            let raw = attribute_bytes(rec, a);
                            if !a.nonresident {
                                continue;
                            }
                            let low = u64le(raw, 16);
                            let actual = native_name(rec, a);
                            let ordinary = if shared_file {
                                a.kind == 0x80
                                    && (actual.is_empty()
                                        || number == 8
                                            && actual == [b'$', 0, b'B', 0, b'a', 0, b'd', 0]
                                        || number == 9
                                            && actual == [b'$', 0, b'S', 0, b'D', 0, b'S', 0])
                                    && u64le(raw, 40) != 0
                                    && number != 6
                            } else {
                                a.kind == 0xa0 && exact_name(rec, a, name)
                            };
                            let include = if uses_list && low != 0 {
                                number == 0 && a.kind == 0x80 && shared_file
                            } else {
                                ordinary
                            };
                            if include {
                                let index = resolved.records[..located.record]
                                    .iter()
                                    .map(|r| r.attributes.len())
                                    .sum::<usize>()
                                    + rec
                                        .attributes
                                        .iter()
                                        .position(|x| x.start == a.start)
                                        .ok_or_else(|| bad("NTFS native run-input provenance"))?;
                                input.push(index);
                            }
                        }
                    } else {
                        input.push(winner);
                    }
                }
                Ok(input)
            },
        )?;
        let attributes = self.retain_native_attributes(&resolved, object, limits, r)?;
        r.cancellation.check()?;
        Ok(NativeLogSelection {
            attributes,
            winner: output_index,
            directory: base.is_directory(),
            run_inputs,
        })
    }
}
