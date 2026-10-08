//! Private staged MFT bootstrap: read extensions only through proven mappings.
use super::*;
struct PartialMft {
    extents: Vec<FileExtent>,
    physical: Vec<(u64, u64)>,
    length: u64,
    allocated: u64,
    runs: usize,
    limits: NtfsReadLimits,
    geometry: NtfsGeometry,
    _reservation: Reservation,
}
impl PartialMft {
    fn new(
        first: &[u8],
        geometry: NtfsGeometry,
        limits: NtfsReadLimits,
        r: &Resources,
    ) -> Result<Self> {
        if first.len() < 64
            || first[8] != 1
            || first[9] != 0
            || u16le(first, 12) != 0
            || u64le(first, 16) != 0
        {
            return Err(unsupported("NTFS first MFT mapping profile"));
        }
        let length = u64le(first, 48);
        let allocated = u64le(first, 40);
        if u64le(first, 56) > length {
            return Err(bad("NTFS MFT initialized size exceeds logical length"));
        }
        if u64le(first, 56) != length {
            return Err(unsupported("NTFS MFT uninitialized bootstrap suffix"));
        }
        if length == 0
            || !length.is_multiple_of(geometry.record_bytes as u64)
            || !allocated.is_multiple_of(geometry.cluster_bytes)
            || length > allocated
        {
            return Err(bad("NTFS bootstrap MFT global sizes"));
        }
        let reservation = r.memory.reserve(
            map_charge(limits.runs)?
                .checked_add(geometry.record_bytes as u64)
                .ok_or_else(|| budget("NTFS bootstrap envelope overflow"))?,
        )?;
        let mut map = Self {
            extents: vector(limits.runs)?,
            physical: vector(limits.runs)?,
            length,
            allocated,
            runs: 0,
            limits,
            geometry,
            _reservation: reservation,
        };
        map.add(first, r)?;
        let start = map
            .geometry
            .mft_cluster
            .checked_mul(map.geometry.cluster_bytes)
            .ok_or_else(|| bad("NTFS boot MFT overflow"))?;
        if map.extents.first().is_none_or(|e| {
            e.offset != 0
                || e.kind != MapKind::Data(start)
                || e.length < map.geometry.record_bytes as u64
        }) {
            return Err(bad("NTFS bootstrap disagrees with boot record0"));
        }
        Ok(map)
    }
    fn add(&mut self, attribute: &[u8], r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if attribute.len() < 64
            || attribute[8] != 1
            || attribute[9] != 0
            || u16le(attribute, 12) != 0
        {
            return Err(unsupported("NTFS MFT continuation flags/form/name"));
        }
        let low = u64le(attribute, 16);
        let high = u64le(attribute, 24);
        let span = high
            .checked_sub(low)
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| bad("NTFS bootstrap VCN range"))?;
        let start = low
            .checked_mul(self.geometry.cluster_bytes)
            .ok_or_else(|| bad("NTFS bootstrap logical overflow"))?;
        let bytes = span
            .checked_mul(self.geometry.cluster_bytes)
            .ok_or_else(|| bad("NTFS bootstrap segment bytes"))?;
        let end = start
            .checked_add(bytes)
            .filter(|n| *n <= self.allocated)
            .ok_or_else(|| bad("NTFS MFT segment escapes allocation"))?;
        if self
            .extents
            .iter()
            .any(|e| e.offset < end && start < e.offset + e.length)
        {
            return Err(bad("NTFS duplicate MFT segment VCN"));
        }
        let mut normalized = vector(attribute.len())?;
        normalized.extend_from_slice(attribute);
        normalized[16..24].fill(0);
        normalized[24..32].copy_from_slice(&(span - 1).to_le_bytes());
        for at in [40, 48, 56] {
            normalized[at..at + 8].copy_from_slice(&bytes.to_le_bytes());
        }
        let available = self
            .limits
            .runs
            .checked_sub(self.runs)
            .ok_or_else(|| budget("NTFS bootstrap aggregate runs"))?;
        let mut segment = stream::decode_segment(
            &normalized,
            &self.geometry,
            NtfsReadLimits {
                runs: available,
                ..self.limits
            },
            r,
            false,
        )?;
        if segment
            .extents
            .iter()
            .any(|e| !matches!(e.kind, MapKind::Data(_)))
        {
            return Err(bad("NTFS MFT sparse/uninitialized segment"));
        }
        for (at, length) in &segment.physical {
            if self
                .physical
                .iter()
                .any(|(old, size)| *old < at + length && *at < old + size)
            {
                return Err(bad("NTFS MFT physical segment alias"));
            }
        }
        self.runs += segment.runs;
        self.physical.extend_from_slice(&segment.physical);
        for extent in &mut segment.extents {
            extent.offset += start;
        }
        self.extents.extend(segment.extents);
        self.extents.sort_unstable_by_key(|e| e.offset);
        Ok(())
    }
    fn read_record(
        &self,
        number: u64,
        context: &Context,
        r: &Resources,
    ) -> Result<Budgeted<Vec<u8>>> {
        context.check(r)?;
        if number >= self.length / self.geometry.record_bytes as u64 {
            return Err(bad("NTFS bootstrap record outside MFT"));
        }
        let start = number * self.geometry.record_bytes as u64;
        let end = start + self.geometry.record_bytes as u64;
        let mut covered = start;
        for e in &self.extents {
            if e.offset > covered {
                break;
            }
            if e.offset + e.length > covered {
                covered = (e.offset + e.length).min(end);
            }
            if covered == end {
                break;
            }
        }
        if covered != end {
            return Err(unsupported(
                "NTFS extension requires unavailable bootstrap mapping",
            ));
        }
        Budgeted::try_new(&r.memory, self.geometry.record_bytes as u64, || {
            let mut output = vector(self.geometry.record_bytes)?;
            output.resize(self.geometry.record_bytes, 0);
            let mut cursor = start;
            for e in &self.extents {
                r.cancellation.check()?;
                let MapKind::Data(at) = e.kind else {
                    return Err(bad("NTFS MFT bootstrap nondata extent"));
                };
                let from = cursor.max(e.offset);
                let to = end.min(e.offset + e.length);
                if to <= from {
                    continue;
                }
                context
                    .source
                    .read_exact_at(
                        at + from - e.offset,
                        &mut output[(from - start) as usize..(to - start) as usize],
                    )
                    .map_err(|e| Error::io("NTFS bootstrap extension payload", e))?;
                cursor = to;
                if cursor == end {
                    break;
                }
            }
            Ok(output)
        })
    }
    fn resolve_extensions(
        &mut self,
        list: &[u8],
        base: &NtfsRecord,
        context: &Context,
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<Budgeted<Vec<NtfsRecord>>> {
        if list.len() > limits.list_bytes {
            return Err(budget("NTFS bootstrap list byte ceiling"));
        }
        let charge = (limits.list_entries as u64)
            .checked_mul(96)
            .and_then(|n| {
                n.checked_add(
                    (limits.extension_records as u64)
                        .checked_mul(std::mem::size_of::<NtfsRecord>() as u64)?,
                )
            })
            .ok_or_else(|| budget("NTFS bootstrap reference envelope"))?;
        Budgeted::try_new(&r.memory, charge, || {
            let mut work = list.len();
            if work > limits.work {
                return Err(budget("NTFS bootstrap list framing work"));
            }
            let mut walk = stream::ListWalk::new(list, limits.list_entries);
            let mut pending = vector(limits.list_entries)?;
            while let Some(entry) = walk.next(r)? {
                pending.push(entry);
            }
            let mut resolved = vector(limits.list_entries)?;
            let mut records: Vec<NtfsRecord> = vector(limits.extension_records)?;
            let base_reference = u64le(&base.identity.native, 0) | (base.identity.generation << 48);
            while !pending.is_empty() {
                let mut progress = false;
                let mut index = 0;
                while index < pending.len() {
                    r.cancellation.check()?;
                    work = work
                        .checked_add(1)
                        .and_then(|n| n.checked_add(records.len()))
                        .and_then(|n| n.checked_add(self.limits.attributes))
                        .and_then(|n| n.checked_add(pending.len()))
                        .and_then(|n| n.checked_add(resolved.len()))
                        .and_then(|n| n.checked_add(self.extents.len().checked_mul(4)?))
                        .and_then(|n| n.checked_add(self.physical.len()))
                        .and_then(|n| n.checked_add(self.geometry.record_bytes / 2))
                        .filter(|n| *n <= limits.work)
                        .ok_or_else(|| budget("NTFS bootstrap reference work ceiling"))?;
                    let entry = pending[index];
                    let number = entry.reference & 0x0000_ffff_ffff_ffff;
                    let record = if number == u64le(&base.identity.native, 0) {
                        base
                    } else {
                        let position = records
                            .iter()
                            .position(|record| u64le(&record.identity.native, 0) == number);
                        let position = if let Some(position) = position {
                            position
                        } else {
                            let raw = match self.read_record(number, context, r) {
                                Ok(raw) => raw,
                                Err(error) if error.kind == ErrorKind::Unsupported => {
                                    index += 1;
                                    continue;
                                }
                                Err(error) => return Err(error),
                            };
                            if records.len() == limits.extension_records {
                                return Err(budget("NTFS bootstrap extension count"));
                            }
                            let mut bytes = vector(raw.get().len())?;
                            bytes.extend_from_slice(raw.get());
                            let record = parse_record_mode(
                                bytes,
                                number,
                                context,
                                &self.geometry,
                                self.limits,
                                r,
                                RecordProfile::Extension(base_reference),
                            )?;
                            if record.attributes.iter().any(|a| a.kind == 0x20) {
                                return Err(unsupported("NTFS bootstrap recursive extension list"));
                            }
                            let attributes = records
                                .iter()
                                .try_fold(base.attributes.len(), |n, record| {
                                    n.checked_add(record.attributes.len())
                                })
                                .and_then(|n| n.checked_add(record.attributes.len()))
                                .filter(|n| *n <= limits.attributes)
                                .ok_or_else(|| {
                                    budget("NTFS bootstrap aggregate attribute ceiling")
                                })?;
                            let _ = attributes;
                            records.push(record);
                            records.len() - 1
                        };
                        &records[position]
                    };
                    if record.identity.generation != entry.reference >> 48 {
                        return Err(Error::new(
                            ErrorKind::StalePlan,
                            "NTFS bootstrap extension sequence",
                        ));
                    }
                    let attribute = record
                        .attributes
                        .iter()
                        .find(|a| u16le(&record.bytes[a.start..], 14) == entry.instance)
                        .copied()
                        .ok_or_else(|| bad("NTFS bootstrap missing listed instance"))?;
                    let b = &record.bytes[attribute.start..attribute.start + attribute.length];
                    let name_at = usize::from(u16le(b, 10));
                    let name = if b[9] == 0 {
                        &[][..]
                    } else {
                        &b[name_at..name_at + usize::from(b[9]) * 2]
                    };
                    if attribute.kind != entry.kind
                        || name != entry.name
                        || if attribute.nonresident {
                            u64le(b, 16) != entry.low
                        } else {
                            entry.low != 0
                        }
                    {
                        return Err(bad("NTFS bootstrap listed attribute contradiction"));
                    }
                    if resolved.contains(&(number, entry.instance)) {
                        return Err(bad("NTFS bootstrap duplicate listed instance"));
                    }
                    if entry.kind == 0x80 && entry.name.is_empty() && entry.low != 0 {
                        self.add(b, r)?;
                    }
                    resolved.push((number, entry.instance));
                    pending.remove(index);
                    progress = true;
                }
                if !progress {
                    return Err(unsupported(
                        "NTFS bootstrap unresolved mapping dependency cycle",
                    ));
                }
            }
            for record in std::iter::once(base).chain(records.iter()) {
                work = work
                    .checked_add(
                        record
                            .attributes
                            .len()
                            .checked_mul(resolved.len())
                            .ok_or_else(|| budget("NTFS bootstrap completeness work overflow"))?,
                    )
                    .filter(|n| *n <= limits.work)
                    .ok_or_else(|| budget("NTFS bootstrap completeness work"))?;
                for a in &record.attributes {
                    if a.kind == 0x20 && record.identity == base.identity {
                        continue;
                    }
                    let key = (
                        u64le(&record.identity.native, 0),
                        u16le(&record.bytes[a.start..], 14),
                    );
                    if !resolved.contains(&key) {
                        return Err(bad("NTFS bootstrap unlisted native attribute"));
                    }
                }
            }
            Ok(records)
        })
    }
    fn complete(self, context: &Context, r: &Resources) -> Result<(ExtentFile, Reservation)> {
        context.check(r)?;
        let mut covered = 0;
        for e in &self.extents {
            if e.offset != covered {
                return Err(bad("NTFS complete MFT VCN gap"));
            }
            covered += e.length;
        }
        if covered != self.allocated {
            return Err(bad("NTFS incomplete MFT allocation coverage"));
        }
        let mut extents = self.extents;
        extents.retain(|e| e.offset < self.length);
        for e in &mut extents {
            e.length = e.length.min(self.length - e.offset);
        }
        let file = ExtentFile::new(
            context.source.clone(),
            self.length,
            extents,
            self.limits.runs,
        )
        .map_err(|e| Error::io("NTFS complete bootstrapped MFT", e))?;
        Ok((file, self._reservation))
    }
}
pub(super) fn mapped_mft(
    record: &NtfsRecord,
    context: &Context,
    geometry: &NtfsGeometry,
    read: NtfsReadLimits,
    limits: NtfsStreamLimits,
    r: &Resources,
) -> Result<(ExtentFile, Reservation)> {
    if record.attributes.len() > limits.attributes {
        return Err(budget("NTFS bootstrap attributes"));
    }
    let read = NtfsReadLimits {
        runs: read.runs.min(limits.runs),
        ..read
    };
    let first = record
        .attributes
        .iter()
        .filter(|a| a.kind == 0x80 && !a.named && a.nonresident)
        .find(|a| u64le(&record.bytes[a.start..], 16) == 0)
        .copied()
        .ok_or_else(|| bad("NTFS MFT bootstrap lacks initial DATA"))?;
    let mut map = PartialMft::new(
        &record.bytes[first.start..first.start + first.length],
        geometry.clone(),
        read,
        r,
    )?;
    let mut list_attribute = None;
    for a in &record.attributes {
        if a.kind == 0x20 && list_attribute.replace(*a).is_some() {
            return Err(unsupported("NTFS split MFT ATTRIBUTE_LIST bootstrap"));
        }
    }
    if let Some(a) = list_attribute {
        if a.named || a.flags != 0 {
            return Err(bad("NTFS MFT ATTRIBUTE_LIST name/flags"));
        }
        let charge = limits.list_bytes as u64;
        let list = Budgeted::try_new(&r.memory, charge, || {
            if !a.nonresident {
                let value = record.value(a)?;
                if value.len() > limits.list_bytes {
                    return Err(budget("NTFS bootstrap list bytes"));
                }
                let mut bytes = vector(value.len())?;
                bytes.extend_from_slice(value);
                return Ok(bytes);
            }
            let lease = r.memory.reserve(map_charge(read.runs)?)?;
            let (length, extents) = runs(
                &record.bytes[a.start..a.start + a.length],
                geometry,
                read,
                r,
            )?;
            if length > limits.list_bytes as u64 {
                return Err(budget("NTFS bootstrap list bytes"));
            }
            if extents.iter().any(|e| !matches!(e.kind, MapKind::Data(_))) {
                return Err(unsupported("NTFS bootstrap sparse/uninitialized list"));
            }
            let file = ExtentFile::new(
                context.source.clone(),
                length,
                extents,
                read.runs.saturating_mul(2),
            )
            .map_err(|e| Error::io("NTFS bootstrap list map", e))?;
            let mut bytes = vector(length as usize)?;
            bytes.resize(length as usize, 0);
            if file
                .read_at(0, &mut bytes)
                .map_err(|e| Error::io("NTFS bootstrap list payload", e))?
                != bytes.len()
            {
                return Err(bad("NTFS bootstrap list truncated"));
            }
            drop(file);
            drop(lease);
            Ok(bytes)
        })?;
        let extensions = map.resolve_extensions(list.get(), record, context, limits, r)?;
        drop(extensions);
        drop(list);
    } else if record
        .attributes
        .iter()
        .filter(|a| a.kind == 0x80 && !a.named)
        .count()
        != 1
    {
        return Err(bad("NTFS MFT split DATA without list"));
    }
    map.complete(context, r)
}
#[test]
fn partial_mapping_never_guesses_unknown_extensions_and_finishes_indexed() {
    use std::{io, sync::atomic::AtomicUsize};
    struct Source {
        bytes: Vec<u8>,
        reads: AtomicUsize,
    }
    impl ReadAt for Source {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let start = offset as usize;
            out.copy_from_slice(
                self.bytes
                    .get(start..start + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
    }
    fn segment(low: u64, high: u64, lcn: u8) -> Vec<u8> {
        let mut b = vec![0; 72];
        b[8] = 1;
        b[16..24].copy_from_slice(&low.to_le_bytes());
        b[24..32].copy_from_slice(&high.to_le_bytes());
        b[32..34].copy_from_slice(&64u16.to_le_bytes());
        for at in [40, 48, 56] {
            b[at..at + 8].copy_from_slice(&8192u64.to_le_bytes());
        }
        b[64..68].copy_from_slice(&[0x11, (high - low + 1) as u8, lcn, 0]);
        b
    }
    let r = Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    };
    let mut bytes = vec![0; 65536];
    bytes[2048..6144].fill(0x31);
    bytes[10240..14336].fill(0x72);
    let source = Arc::new(Source {
        bytes,
        reads: AtomicUsize::new(0),
    });
    let context = Context {
        original: source.clone(),
        source: source.clone(),
        length: 65536,
        scope: 4 << 64,
    };
    let geometry = NtfsGeometry {
        cluster_bytes: 512,
        record_bytes: 1024,
        volume_bytes: 65536,
        mft_cluster: 4,
        index_bytes: 1024,
        mirror_cluster: 100,
    };
    let limits = NtfsReadLimits {
        attributes: 32,
        names: 8,
        runs: 16,
    };
    let mut map = PartialMft::new(&segment(0, 7, 4), geometry, limits, &r).unwrap();
    assert_eq!(
        map.read_record(6, &context, &r).err().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    assert!(
        map.read_record(0, &context, &r)
            .unwrap()
            .get()
            .iter()
            .all(|n| *n == 0x31)
    );
    assert!(map.add(&segment(0, 7, 4), &r).is_err());
    assert!(map.add(&segment(8, 15, 4), &r).is_err());
    map.add(&segment(8, 15, 20), &r).unwrap();
    assert!(
        map.read_record(6, &context, &r)
            .unwrap()
            .get()
            .iter()
            .all(|n| *n == 0x72)
    );
    let (file, lease) = map.complete(&context, &r).unwrap();
    let before = source.reads.load(Ordering::Relaxed);
    let mut out = [0; 8];
    assert_eq!(file.read_at(7000, &mut out).unwrap(), 8);
    assert_eq!(out, [0x72; 8]);
    assert_eq!(source.reads.load(Ordering::Relaxed) - before, 1);
    drop(file);
    drop(lease);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn unresolved_mapping_dependency_is_bounded_and_never_guessed() {
    use std::io;
    struct Source(Vec<u8>);
    impl ReadAt for Source {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, b: &mut [u8]) -> io::Result<()> {
            let start = offset as usize;
            b.copy_from_slice(
                self.0
                    .get(start..start + b.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
    }
    let r = Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    };
    let source: Arc<dyn ReadAt> = Arc::new(Source(vec![0; 65536]));
    let context = Context {
        original: source.clone(),
        source,
        length: 65536,
        scope: 4 << 64,
    };
    let geometry = NtfsGeometry {
        cluster_bytes: 512,
        record_bytes: 1024,
        volume_bytes: 65536,
        mft_cluster: 4,
        index_bytes: 1024,
        mirror_cluster: 100,
    };
    let limits = NtfsReadLimits {
        attributes: 32,
        names: 8,
        runs: 16,
    };
    let mut attribute = vec![0; 72];
    attribute[8] = 1;
    attribute[24..32].copy_from_slice(&7u64.to_le_bytes());
    attribute[32..34].copy_from_slice(&64u16.to_le_bytes());
    for at in [40, 48, 56] {
        attribute[at..at + 8].copy_from_slice(&8192u64.to_le_bytes());
    }
    attribute[64..68].copy_from_slice(&[0x11, 8, 4, 0]);
    let mut map = PartialMft::new(&attribute, geometry, limits, &r).unwrap();
    let base = NtfsRecord {
        identity: identity(&context, 0, 1),
        bytes: vec![0; 1024],
        attributes: vec![],
        names: vec![],
        flags: 1,
        standard: None,
        file_flags: None,
        _reservation: r.memory.reserve(1024).unwrap(),
    };
    let mut list = vec![0; 32];
    list[..4].copy_from_slice(&0x80u32.to_le_bytes());
    list[4..6].copy_from_slice(&32u16.to_le_bytes());
    list[8..16].copy_from_slice(&8u64.to_le_bytes());
    list[16..24].copy_from_slice(&(6u64 | (1 << 48)).to_le_bytes());
    let selected = NtfsStreamLimits {
        extension_records: 2,
        list_entries: 8,
        list_bytes: 1024,
        attributes: 32,
        runs: 16,
        work: 4096,
    };
    assert_eq!(
        map.resolve_extensions(&list, &base, &context, selected, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    let mut excessive = selected;
    excessive.work = 0;
    assert_eq!(
        map.resolve_extensions(&list, &base, &context, excessive, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    drop(base);
    drop(map);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_reference_fixpoint_loads_later_mapped_filename_and_complete_mft() {
    use std::io;
    fn put16(b: &mut [u8], p: usize, n: u16) {
        b[p..p + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn put32(b: &mut [u8], p: usize, n: u32) {
        b[p..p + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn put64(b: &mut [u8], p: usize, n: u64) {
        b[p..p + 8].copy_from_slice(&n.to_le_bytes());
    }
    fn data(low: u64, high: u64, lcn: u8, id: u16) -> Vec<u8> {
        let mut b = vec![0; 72];
        put32(&mut b, 0, 0x80);
        put32(&mut b, 4, 72);
        b[8] = 1;
        put16(&mut b, 14, id);
        put64(&mut b, 16, low);
        put64(&mut b, 24, high);
        put16(&mut b, 32, 64);
        for at in [40, 48, 56] {
            put64(&mut b, at, 8192);
        }
        b[64..68].copy_from_slice(&[0x11, (high - low + 1) as u8, lcn, 0]);
        b
    }
    fn raw(number: u32, base: u64, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0; 1024];
        b[..4].copy_from_slice(b"FILE");
        put16(&mut b, 4, 48);
        put16(&mut b, 6, 3);
        put16(&mut b, 16, 1);
        put16(&mut b, 18, 1);
        put16(&mut b, 20, 56);
        put16(&mut b, 22, 1);
        put32(&mut b, 28, 1024);
        put64(&mut b, 32, base);
        put32(&mut b, 44, number);
        let mut at = 56;
        for a in attributes {
            b[at..at + a.len()].copy_from_slice(a);
            at += a.len();
        }
        put32(&mut b, at, u32::MAX);
        put32(&mut b, 24, (at + 4) as u32);
        put16(&mut b, 48, 0xabcd);
        for i in 1..=2 {
            let old = u16le(&b, i * 512 - 2);
            put16(&mut b, 48 + i * 2, old);
            put16(&mut b, i * 512 - 2, 0xabcd);
        }
        b
    }
    struct Source(Vec<u8>, std::sync::atomic::AtomicUsize);
    impl ReadAt for Source {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let at = o as usize;
            b.copy_from_slice(
                self.0
                    .get(at..at + b.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
    }
    let mut filename = vec![0; 96];
    put32(&mut filename, 0, 0x30);
    put32(&mut filename, 4, 96);
    put16(&mut filename, 14, 2);
    put32(&mut filename, 16, 68);
    put16(&mut filename, 20, 24);
    put64(&mut filename, 24, 5 | (1 << 48));
    filename[24 + 64] = 1;
    filename[24 + 65] = 1;
    put16(&mut filename, 24 + 66, 0x78);
    let first = data(0, 7, 4, 3);
    let mut list = vec![0; 96];
    for (index, (kind, low, number, id)) in [
        (0x30u32, 0u64, 6u64, 2u16),
        (0x80, 0, 0, 3),
        (0x80, 8, 3, 9),
    ]
    .into_iter()
    .enumerate()
    {
        let at = index * 32;
        put32(&mut list, at, kind);
        put16(&mut list, at + 4, 32);
        put64(&mut list, at + 8, low);
        put64(&mut list, at + 16, number | (1 << 48));
        put16(&mut list, at + 24, id);
    }
    let mut image = vec![0; 65536];
    image[2048..3072].copy_from_slice(&raw(0, 0, std::slice::from_ref(&first)));
    image[2048 + 3072..2048 + 4096].copy_from_slice(&raw(3, 1 << 48, &[data(8, 15, 20, 9)]));
    image[10240 + 2048..10240 + 3072].copy_from_slice(&raw(6, 1 << 48, &[filename]));
    let counted = Arc::new(Source(image, std::sync::atomic::AtomicUsize::new(0)));
    let source: Arc<dyn ReadAt> = counted.clone();
    let context = Context {
        original: source.clone(),
        source,
        length: 65536,
        scope: 4 << 64,
    };
    let geometry = NtfsGeometry {
        cluster_bytes: 512,
        record_bytes: 1024,
        volume_bytes: 65536,
        mft_cluster: 4,
        index_bytes: 1024,
        mirror_cluster: 100,
    };
    let read = NtfsReadLimits {
        attributes: 32,
        names: 8,
        runs: 16,
    };
    let selected = NtfsStreamLimits {
        extension_records: 4,
        list_entries: 8,
        list_bytes: 1024,
        attributes: 32,
        runs: 16,
        work: 4096,
    };
    let r = Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    };
    let mut bytes = vec![0; 1024];
    context.source.read_exact_at(2048, &mut bytes).unwrap();
    let base = parse_record_mode(
        bytes,
        0,
        &context,
        &geometry,
        read,
        &r,
        RecordProfile::CompleteBase,
    )
    .unwrap();
    {
        let before = counted.1.load(std::sync::atomic::Ordering::Relaxed);
        let mut capped = PartialMft::new(&first, geometry.clone(), read, &r).unwrap();
        let error = capped
            .resolve_extensions(
                &list,
                &base,
                &context,
                NtfsStreamLimits {
                    work: 2000,
                    ..selected
                },
                &r,
            )
            .err()
            .unwrap();
        assert_eq!(error.kind, ErrorKind::BudgetExhausted);
        // Mapping extension3 was read; the late FILE_NAME extension6 was not.
        assert_eq!(
            counted.1.load(std::sync::atomic::Ordering::Relaxed) - before,
            1
        );
    }
    let mut map = PartialMft::new(&first, geometry, read, &r).unwrap();
    let extensions = map
        .resolve_extensions(&list, &base, &context, selected, &r)
        .unwrap();
    assert_eq!(extensions.get().len(), 2);
    assert_eq!(extensions.get()[0].identity.native, 3u64.to_le_bytes());
    assert_eq!(extensions.get()[1].identity.native, 6u64.to_le_bytes());
    assert_eq!(
        extensions.get()[1].native_file_names().next().unwrap().name,
        [0x78, 0]
    );
    let (mft, lease) = map.complete(&context, &r).unwrap();
    let mut record = [0; 1024];
    assert_eq!(mft.read_at(6 * 1024, &mut record).unwrap(), 1024);
    assert_eq!(&record[..4], b"FILE");
    drop(mft);
    drop(lease);
    drop(extensions);
    drop(base);
    assert_eq!(r.memory.used(), 0);
}
