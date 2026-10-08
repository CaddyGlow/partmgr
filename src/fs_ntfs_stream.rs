//! Isolated draft: exact DATA streams and bounded attribute-list resolution.
use super::*;
/// Additional aggregate ceilings, independent of per-record decoder limits.
#[derive(Clone, Copy, Debug)]
pub struct NtfsStreamLimits {
    /// Extension records retained while resolving one object.
    pub extension_records: usize,
    /// Total entries in the object's ATTRIBUTE_LIST.
    pub list_entries: usize,
    /// Maximum logical ATTRIBUTE_LIST value bytes.
    pub list_bytes: usize,
    /// Aggregate attributes across base and extension records.
    pub attributes: usize,
    /// Aggregate allocation runs in one DATA stream.
    pub runs: usize,
    /// Conservative maximum bounded attribute-resolution/map comparison work.
    pub work: usize,
}
/// One exact native DATA stream, with its owning base identity unchanged.
#[derive(Clone, Debug)]
pub struct NtfsDataStream {
    /// Exact UTF16 units; empty identifies the unnamed stream.
    pub name: Vec<u16>,
    /// Logical bytes, independent of valid-data length.
    pub length: u64,
    /// Initialized logical prefix; the remaining mapped bytes read as zeros.
    pub initialized: u64,
    /// Native sparse flag, not a claim of compression support.
    pub sparse: bool,
    /// Attribute occurrences contributing to this stream.
    pub segments: usize,
}
/// Exact fixed-up attribute occurrence; interpretation and physical ownership are separate.
#[derive(Clone, Debug)]
pub struct NtfsNativeAttribute {
    /// Base owner, distinct from the extension record carrying this occurrence.
    pub owner: ObjectId,
    /// Physical MFT record/sequence provenance for this occurrence.
    pub record: ObjectId,
    /// Byte offset within the fixed-up FILE record.
    pub offset: usize,
    /// Native type code and per-record instance number.
    pub kind: u32,
    /// Attribute instance, not a global identifier.
    pub instance: u16,
    /// Exact attribute name units, independent of FILE_NAME names.
    pub name: Vec<u16>,
    /// Native flags retained without converting metadata semantics.
    pub flags: u16,
    /// Native form selector; nonresident bytes contain validated framing, not decoded content.
    pub nonresident: bool,
    /// Full encoded attribute, after the containing record's USA fixups.
    pub raw: Vec<u8>,
}
/// Native STANDARD_INFORMATION, keeping MFT-change time distinct from modification.
#[derive(Clone, Copy, Debug)]
pub struct NtfsNativeStandardInformation<'a> {
    /// Exact resident value, including otherwise uninterpreted version/quota/USN fields.
    pub raw: &'a [u8],
    /// Creation, modification, MFT-change, access signed100ns ticks since1601UTC.
    pub timestamps: [i64; 4],
    /// Exact native attributes.
    pub flags: u32,
    /// Store-local security index in the72-byte encoding; absent in48-byte encoding.
    pub security_id: Option<u32>,
}
/// FILE_NAME timestamps are observations independent of STANDARD_INFORMATION.
#[derive(Clone, Copy, Debug)]
pub struct NtfsNativeFileName<'a> {
    /// Exact resident value including native sizes/flags/reparse-or-EA field.
    pub raw: &'a [u8],
    /// Native parent reference, preserving sequence bits.
    pub parent: u64,
    /// Creation, modification, MFT-change, access signed100ns ticks since1601UTC.
    pub timestamps: [i64; 4],
    /// POSIX/Win32/DOS/combined native namespace selector.
    pub namespace: u8,
    /// Exact UTF16LE name bytes, including non-Unicode code units.
    pub name: &'a [u8],
}
fn standard_view(value: &[u8]) -> Option<NtfsNativeStandardInformation<'_>> {
    if !matches!(value.len(), 48 | 72) {
        return None;
    }
    Some(NtfsNativeStandardInformation {
        raw: value,
        timestamps: [
            qword_signed(value, 0),
            qword_signed(value, 8),
            qword_signed(value, 16),
            qword_signed(value, 24),
        ],
        flags: u32le(value, 32),
        security_id: (value.len() == 72).then(|| u32le(value, 52)),
    })
}
fn filename_view(value: &[u8]) -> Option<NtfsNativeFileName<'_>> {
    if value.len() < 66 || value.len() != 66 + usize::from(value[64]) * 2 {
        return None;
    }
    Some(NtfsNativeFileName {
        raw: value,
        parent: u64le(value, 0),
        timestamps: [
            qword_signed(value, 8),
            qword_signed(value, 16),
            qword_signed(value, 24),
            qword_signed(value, 32),
        ],
        namespace: value[65],
        name: &value[66..],
    })
}
fn qword_signed(value: &[u8], at: usize) -> i64 {
    u64le(value, at) as i64
}
impl NtfsRecord {
    /// Full native STANDARD_INFORMATION view; no lossy three-timestamp mapping.
    pub fn native_standard_information(&self) -> Option<NtfsNativeStandardInformation<'_>> {
        self.attributes
            .iter()
            .find(|a| a.kind == 0x10)
            .and_then(|a| self.value(*a).ok())
            .and_then(standard_view)
    }
    /// Every base-record FILE_NAME timestamp set, independently of standard-information.
    pub fn native_file_names(&self) -> impl Iterator<Item = NtfsNativeFileName<'_>> {
        self.attributes
            .iter()
            .filter(|a| a.kind == 0x30)
            .filter_map(|a| self.value(*a).ok().and_then(filename_view))
    }
}
impl NtfsNativeAttribute {
    fn resident_value(&self) -> Option<&[u8]> {
        if self.nonresident || self.raw.len() < 24 {
            return None;
        }
        let start = usize::from(u16le(&self.raw, 20));
        let length = u32le(&self.raw, 16) as usize;
        self.raw.get(start..start.checked_add(length)?)
    }
    /// Typed native SI view of retained evidence, preserving every raw field.
    pub fn standard_information(&self) -> Option<NtfsNativeStandardInformation<'_>> {
        if self.kind != 0x10 {
            return None;
        }
        standard_view(self.resident_value()?)
    }
    /// Typed native FILE_NAME view, retaining its distinct timestamp observations.
    pub fn file_name(&self) -> Option<NtfsNativeFileName<'_>> {
        if self.kind != 0x30 {
            return None;
        }
        filename_view(self.resident_value()?)
    }
}
#[derive(Clone, Copy)]
struct Located {
    record: usize,
    attribute: Attribute,
}
struct Resolved {
    records: Vec<NtfsRecord>,
    attributes: Vec<Located>,
    _reservation: Reservation,
}
fn attribute_bytes(record: &NtfsRecord, a: Attribute) -> &[u8] {
    &record.bytes[a.start..a.start + a.length]
}
fn native_name(record: &NtfsRecord, a: Attribute) -> &[u8] {
    let b = attribute_bytes(record, a);
    let start = usize::from(u16le(b, 10));
    if b[9] == 0 {
        &[]
    } else {
        &b[start..start + usize::from(b[9]) * 2]
    }
}
fn same_name(record: &NtfsRecord, a: Attribute, units: &[u16]) -> bool {
    let b = native_name(record, a);
    b.len() / 2 == units.len()
        && b.as_chunks::<2>()
            .0
            .iter()
            .zip(units)
            .all(|(b, u)| u16::from_le_bytes(*b) == *u)
}
#[derive(Clone, Copy)]
pub(super) struct ListEntry<'a> {
    pub(super) kind: u32,
    pub(super) low: u64,
    pub(super) reference: u64,
    pub(super) instance: u16,
    pub(super) name: &'a [u8],
}
pub(super) struct ListWalk<'a> {
    bytes: &'a [u8],
    at: usize,
    count: usize,
    maximum: usize,
    previous: u32,
}
impl<'a> ListWalk<'a> {
    pub(super) fn new(bytes: &'a [u8], maximum: usize) -> Self {
        Self {
            bytes,
            at: 0,
            count: 0,
            maximum,
            previous: 0,
        }
    }
    pub(super) fn next(&mut self, r: &Resources) -> Result<Option<ListEntry<'a>>> {
        r.cancellation.check()?;
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        if self.count == self.maximum {
            return Err(budget("NTFS ATTRIBUTE_LIST entry limit"));
        }
        let b = &self.bytes[self.at..];
        if b.len() < 26 {
            return Err(bad("NTFS truncated ATTRIBUTE_LIST entry"));
        }
        let kind = u32le(b, 0);
        let length = usize::from(u16le(b, 4));
        let name_bytes = usize::from(b[6]) * 2;
        let name_at = usize::from(b[7]);
        let low = u64le(b, 8);
        if kind == 0
            || kind > 0x100
            || !kind.is_multiple_of(16)
            || kind < self.previous
            || length < 26
            || !length.is_multiple_of(8)
            || length > b.len()
            || low > i64::MAX as u64
            || name_bytes != 0
                && (name_at < 26
                    || !name_at.is_multiple_of(2)
                    || name_at.checked_add(name_bytes).is_none_or(|n| n > length))
        {
            return Err(bad("NTFS ATTRIBUTE_LIST framing/order/name"));
        }
        self.at += length;
        self.count += 1;
        self.previous = kind;
        Ok(Some(ListEntry {
            kind,
            low,
            reference: u64le(b, 16),
            instance: u16le(b, 24),
            name: if name_bytes == 0 {
                &[]
            } else {
                &b[name_at..name_at + name_bytes]
            },
        }))
    }
}
impl NtfsVolume {
    /// Inspect a base-record identity for the explicit stream/attribute-list profile.
    /// Resolution and referenced-record validation occur when streams/metadata are opened.
    pub fn stream_identity(&self, number: u64, r: &Resources) -> Result<ObjectId> {
        Ok(self
            .complete_record(number, RecordProfile::CompleteBase, r)?
            .identity)
    }

    fn complete_record(
        &self,
        number: u64,
        profile: RecordProfile,
        r: &Resources,
    ) -> Result<NtfsRecord> {
        self.context.check(r)?;
        if number >= self.record_count() {
            return Err(bad("NTFS extension reference outside MFT"));
        }
        let _scratch = r.memory.reserve(self.geometry.record_bytes as u64)?;
        let mut bytes = vector(self.geometry.record_bytes)?;
        bytes.resize(self.geometry.record_bytes, 0);
        if self
            .mft
            .read_at(number * self.geometry.record_bytes as u64, &mut bytes)
            .map_err(|e| Error::io("NTFS complete FILE read", e))?
            != bytes.len()
        {
            return Err(bad("NTFS short complete FILE record"));
        }
        parse_record_mode(
            bytes,
            number,
            &self.context,
            &self.geometry,
            self.limits,
            r,
            profile,
        )
    }
    fn resolve_stream_record(
        &self,
        object: &ObjectId,
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<Resolved> {
        self.context.check(r)?;
        let required_work = limits
            .attributes
            .checked_mul(limits.attributes)
            .and_then(|n| n.checked_add(limits.list_entries.checked_mul(limits.attributes)?))
            .and_then(|n| n.checked_add(limits.runs.checked_mul(limits.attributes)?))
            .ok_or_else(|| budget("NTFS resolution work envelope overflow"))?;
        if required_work > limits.work {
            return Err(budget("NTFS resolution work envelope ceiling"));
        }
        if object.source != self.context.scope || object.native.len() != 8 {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS foreign stream owner",
            ));
        }
        let base =
            self.complete_record(u64le(&object.native, 0), RecordProfile::CompleteBase, r)?;
        if base.identity != *object {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "NTFS recycled stream owner",
            ));
        }
        let records_cap = limits
            .extension_records
            .checked_add(1)
            .ok_or_else(|| budget("NTFS resolved record cap overflow"))?;
        let charge = (records_cap as u64)
            .checked_mul(std::mem::size_of::<NtfsRecord>() as u64)
            .and_then(|n| {
                n.checked_add(
                    (limits.attributes as u64).checked_mul(std::mem::size_of::<Located>() as u64)?,
                )
            })
            .and_then(|n| n.checked_add(limits.list_bytes as u64))
            .and_then(|n| n.checked_add((limits.list_entries as u64).checked_mul(32)?))
            .and_then(|n| {
                n.checked_add(
                    (self.limits.attributes as u64)
                        .checked_mul(std::mem::size_of::<Attribute>() as u64)?,
                )
            })
            .ok_or_else(|| budget("NTFS resolution charge overflow"))?;
        let reservation = r.memory.reserve(charge)?;
        let mut records = vector(records_cap)?;
        let mut attributes = vector(limits.attributes)?;
        let mut lists = vector(self.limits.attributes)?;
        lists.extend(base.attributes.iter().filter(|a| a.kind == 0x20).copied());
        if lists.len() > 1 {
            return Err(unsupported("NTFS split/multiple ATTRIBUTE_LIST value"));
        }
        let mut list = Vec::new();
        if let Some(a) = lists.first().copied() {
            if a.named || a.flags != 0 {
                return Err(bad("NTFS named/flagged ATTRIBUTE_LIST"));
            }
            if a.nonresident {
                let lease = r.memory.reserve(map_charge(self.limits.runs)?)?;
                let (length, map) =
                    runs(attribute_bytes(&base, a), &self.geometry, self.limits, r)?;
                if length > limits.list_bytes as u64 {
                    return Err(budget("NTFS ATTRIBUTE_LIST byte limit"));
                }
                if map.iter().any(|e| !matches!(e.kind, MapKind::Data(_))) {
                    return Err(unsupported("NTFS sparse/uninitialized ATTRIBUTE_LIST"));
                }
                let file = ExtentFile::new(
                    self.context.source.clone(),
                    length,
                    map,
                    self.limits.runs.saturating_mul(2),
                )
                .map_err(|e| Error::io("NTFS ATTRIBUTE_LIST map", e))?;
                list = vector(length as usize)?;
                list.resize(length as usize, 0);
                if file
                    .read_at(0, &mut list)
                    .map_err(|e| Error::io("NTFS ATTRIBUTE_LIST read", e))?
                    != list.len()
                {
                    return Err(bad("NTFS ATTRIBUTE_LIST truncated"));
                }
                drop(lease);
            } else {
                let value = base.value(a)?;
                if value.len() > limits.list_bytes {
                    return Err(budget("NTFS ATTRIBUTE_LIST byte limit"));
                }
                list = vector(value.len())?;
                list.extend_from_slice(value);
            }
        }
        let base_reference = u64le(&object.native, 0) | (object.generation << 48);
        records.push(base);
        if lists.is_empty() {
            if records[0].attributes.len() > limits.attributes {
                return Err(budget("NTFS resolved attribute ceiling"));
            }
            for a in &records[0].attributes {
                attributes.push(Located {
                    record: 0,
                    attribute: *a,
                });
            }
        } else {
            let mut walk = ListWalk::new(&list, limits.list_entries);
            while let Some(ListEntry {
                kind,
                low,
                reference,
                instance,
                name,
            }) = walk.next(r)?
            {
                let number = reference & 0x0000_ffff_ffff_ffff;
                let sequence = (reference >> 48) as u16;
                let index = if number == u64le(&object.native, 0) {
                    0
                } else if let Some(index) = records
                    .iter()
                    .position(|rec| u64le(&rec.identity.native, 0) == number)
                {
                    index
                } else {
                    if records.len() == records_cap {
                        return Err(budget("NTFS extension record limit"));
                    }
                    records.push(self.complete_record(
                        number,
                        RecordProfile::Extension(base_reference),
                        r,
                    )?);
                    records.len() - 1
                };
                let record = &records[index];
                if record.identity.generation != u64::from(sequence) {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "NTFS ATTRIBUTE_LIST stale sequence",
                    ));
                }
                let found = record
                    .attributes
                    .iter()
                    .find(|a| u16le(attribute_bytes(record, **a), 14) == instance)
                    .copied()
                    .ok_or_else(|| bad("NTFS ATTRIBUTE_LIST missing instance"))?;
                let bytes = attribute_bytes(record, found);
                if found.kind != kind
                    || native_name(record, found) != name
                    || if found.nonresident {
                        u64le(bytes, 16) != low
                    } else {
                        low != 0
                    }
                {
                    return Err(bad("NTFS ATTRIBUTE_LIST target/type/name/VCN mismatch"));
                }
                if attributes
                    .iter()
                    .any(|a: &Located| a.record == index && a.attribute.start == found.start)
                {
                    return Err(bad("NTFS duplicate ATTRIBUTE_LIST target"));
                }
                if attributes.len() == limits.attributes {
                    return Err(budget("NTFS resolved attribute ceiling"));
                }
                attributes.push(Located {
                    record: index,
                    attribute: found,
                });
            }
            // Every loaded attribute must be accounted for; a list need not list itself.
            for (index, record) in records.iter().enumerate() {
                for a in &record.attributes {
                    if a.kind == 0x20 && index == 0 {
                        continue;
                    }
                    if a.kind == 0x20
                        || !attributes
                            .iter()
                            .any(|found| found.record == index && found.attribute.start == a.start)
                    {
                        return Err(bad(
                            "NTFS ATTRIBUTE_LIST unlisted or recursive extension attribute",
                        ));
                    }
                }
            }
        }
        Ok(Resolved {
            records,
            attributes,
            _reservation: reservation,
        })
    }
    /// Retain every loaded native attribute, including the base ATTRIBUTE_LIST.
    /// This does not promise security interpretation, stream decode or capture completeness
    /// for otherwise unsupported compressed/encrypted/MFT-bootstrap profiles.
    pub fn native_attributes(
        &self,
        object: &ObjectId,
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<Budgeted<Vec<NtfsNativeAttribute>>> {
        let resolved = self.resolve_stream_record(object, limits, r)?;
        let count = resolved
            .records
            .iter()
            .try_fold(0usize, |n, record| n.checked_add(record.attributes.len()))
            .filter(|n| *n <= limits.attributes)
            .ok_or_else(|| budget("NTFS native attribute aggregate cap"))?;
        let charge = resolved
            .records
            .iter()
            .try_fold(0u64, |n, record| n.checked_add(record.bytes.len() as u64))
            .and_then(|n| n.checked_add((count as u64).checked_mul(1024)?))
            .ok_or_else(|| budget("NTFS native attribute capture charge"))?;
        Budgeted::try_new(&r.memory, charge, || {
            let mut output = vector(count)?;
            for record in &resolved.records {
                for attribute in &record.attributes {
                    r.cancellation.check()?;
                    let b = attribute_bytes(record, *attribute);
                    let mut raw = vector(b.len())?;
                    raw.extend_from_slice(b);
                    let name_bytes = native_name(record, *attribute);
                    let mut name = vector(name_bytes.len() / 2)?;
                    name.extend(
                        name_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|b| u16::from_le_bytes(*b)),
                    );
                    output.push(NtfsNativeAttribute {
                        owner: object.clone(),
                        record: record.identity.clone(),
                        offset: attribute.start,
                        kind: attribute.kind,
                        instance: u16le(b, 14),
                        name,
                        flags: attribute.flags,
                        nonresident: attribute.nonresident,
                        raw,
                    });
                }
            }
            Ok(output)
        })
    }
    /// Inspect DATA/ADS without normalizing stream names. Does not expand tree/audit admission.
    pub fn data_streams(
        &self,
        object: &ObjectId,
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<Budgeted<Vec<NtfsDataStream>>> {
        let resolved = self.resolve_stream_record(object, limits, r)?;
        let charge = (limits.attributes as u64)
            .checked_mul(1024)
            .ok_or_else(|| budget("NTFS stream descriptors charge"))?;
        Budgeted::try_new(&r.memory, charge, || {
            let mut streams = vector(limits.attributes)?;
            for located in &resolved.attributes {
                r.cancellation.check()?;
                let record = &resolved.records[located.record];
                let a = located.attribute;
                if a.kind != 0x80 {
                    continue;
                }
                let bytes = attribute_bytes(record, a);
                if a.nonresident && u64le(bytes, 16) != 0 {
                    continue;
                }
                let raw_name = native_name(record, a);
                let mut name = vector(raw_name.len() / 2)?;
                name.extend(
                    raw_name
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|b| u16::from_le_bytes(*b)),
                );
                if streams.iter().any(|s: &NtfsDataStream| s.name == name) {
                    return Err(bad("NTFS duplicate DATA stream start"));
                }
                let (content, segments, initialized, sparse, _map_lease) =
                    self.stream_content(&resolved, 0x80, &name, limits, r)?;
                let length = match content {
                    Content::Resident(ref b) => b.len() as u64,
                    Content::Mapped(ref f) => f.len(),
                };
                streams.push(NtfsDataStream {
                    name,
                    length,
                    initialized,
                    sparse,
                    segments,
                });
            }
            if resolved
                .attributes
                .iter()
                .filter(|a| a.attribute.kind == 0x80)
                .any(|a| {
                    !streams
                        .iter()
                        .any(|s| same_name(&resolved.records[a.record], a.attribute, &s.name))
                })
            {
                return Err(bad("NTFS DATA continuation missing start"));
            }
            Ok(streams)
        })
    }
    /// Deferred indexed reads of an exact UTF16 stream; directories may own named DATA.
    pub fn open_stream(
        &self,
        object: &ObjectId,
        name: &[u16],
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<NtfsFile> {
        let resolved = self.resolve_stream_record(object, limits, r)?;
        if resolved.records[0].is_directory() && name.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "NTFS unnamed directory DATA unavailable",
            ));
        }
        if resolved.records[0]
            .file_flags
            .is_some_and(|f| f & (0x400 | 0x800 | 0x1000 | 0x4000) != 0)
        {
            return Err(unsupported("NTFS special object stream capture"));
        }
        let (content, _, _, _, reservation) =
            self.stream_content(&resolved, 0x80, name, limits, r)?;
        Ok(NtfsFile {
            identity: object.clone(),
            context: self.context.clone(),
            content,
            _reservation: reservation,
        })
    }
    /// Open a fresh internally resolved native attribute value for bounded inspection.
    /// Supported selectors are SI10, security50, DATA80, index90/A0 and bitmapB0.
    /// This returns framed bytes; descriptor/index semantics require their own decoder.
    pub fn open_native_attribute_stream(
        &self,
        object: &ObjectId,
        kind: u32,
        name: &[u16],
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<NtfsFile> {
        if !matches!(kind, 0x10 | 0x50 | 0x80 | 0x90 | 0xa0 | 0xb0) {
            return Err(unsupported("NTFS native attribute stream selector"));
        }
        let resolved = self.resolve_stream_record(object, limits, r)?;
        let (content, _, _, _, reservation) =
            self.stream_content(&resolved, kind, name, limits, r)?;
        Ok(NtfsFile {
            identity: object.clone(),
            context: self.context.clone(),
            content,
            _reservation: reservation,
        })
    }
    fn stream_content(
        &self,
        resolved: &Resolved,
        kind: u32,
        name: &[u16],
        limits: NtfsStreamLimits,
        r: &Resources,
    ) -> Result<(Content, usize, u64, bool, Reservation)> {
        let selected_charge = (limits.attributes as u64)
            .checked_mul(std::mem::size_of::<Located>() as u64)
            .ok_or_else(|| budget("NTFS selected segment charge"))?;
        let _selected_lease = r.memory.reserve(selected_charge)?;
        let mut selected = vector(limits.attributes)?;
        for a in &resolved.attributes {
            if a.attribute.kind == kind && same_name(&resolved.records[a.record], a.attribute, name)
            {
                selected.push(*a);
            }
        }
        if selected.is_empty() {
            return Err(bad("NTFS requested DATA stream missing"));
        }
        selected.sort_unstable_by_key(|a| {
            let b = attribute_bytes(&resolved.records[a.record], a.attribute);
            if a.attribute.nonresident {
                u64le(b, 16)
            } else {
                0
            }
        });
        let first = selected[0];
        let first_record = &resolved.records[first.record];
        let first_bytes = attribute_bytes(first_record, first.attribute);
        if !first.attribute.nonresident {
            if selected.len() != 1 || first.attribute.flags != 0 {
                return Err(bad("NTFS duplicate/mixed resident DATA stream"));
            }
            let value = first_record.value(first.attribute)?;
            let lease = r.memory.reserve(value.len() as u64 + 512)?;
            let mut bytes = vector(value.len())?;
            bytes.extend_from_slice(value);
            return Ok((
                Content::Resident(bytes),
                1,
                value.len() as u64,
                false,
                lease,
            ));
        }
        if u64le(first_bytes, 16) != 0 {
            return Err(bad("NTFS DATA lacks VCN0"));
        }
        let length = u64le(first_bytes, 48);
        let initialized = u64le(first_bytes, 56);
        let allocated = u64le(first_bytes, 40);
        let sparse = first.attribute.flags & 0x8000 != 0;
        if initialized > length || !allocated.is_multiple_of(self.geometry.cluster_bytes) {
            return Err(bad("NTFS stream sizes"));
        }
        let map_lease = r.memory.reserve(
            map_charge(limits.runs)?
                .checked_add(2 * self.geometry.record_bytes as u64)
                .ok_or_else(|| budget("NTFS stream working charge"))?,
        )?;
        let mut extents = vector(
            limits
                .runs
                .checked_mul(2)
                .ok_or_else(|| budget("NTFS stream extent cap overflow"))?,
        )?;
        let mut physical = vector(limits.runs)?;
        let mut next = 0u64;
        let mut run_count = 0usize;
        for located in &selected {
            r.cancellation.check()?;
            let a = located.attribute;
            let b = attribute_bytes(&resolved.records[located.record], a);
            if !a.nonresident || a.flags != first.attribute.flags || u64le(b, 16) != next {
                return Err(bad("NTFS DATA segment residency/flags/VCN gap"));
            }
            let high = u64le(b, 24);
            let clusters = if high == u64::MAX && next == 0 && length == 0 {
                0
            } else {
                high.checked_sub(next)
                    .and_then(|n| n.checked_add(1))
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or_else(|| bad("NTFS continuation VCN range"))?
            };
            let segment_bytes = clusters
                .checked_mul(self.geometry.cluster_bytes)
                .ok_or_else(|| bad("NTFS continuation byte overflow"))?;
            let offset = next
                .checked_mul(self.geometry.cluster_bytes)
                .ok_or_else(|| bad("NTFS continuation offset overflow"))?;
            let mut normalized = vector(b.len())?;
            normalized.extend_from_slice(b);
            normalized[16..24].fill(0);
            normalized[24..32].copy_from_slice(&clusters.wrapping_sub(1).to_le_bytes());
            for at in [40, 48, 56] {
                normalized[at..at + 8].copy_from_slice(&segment_bytes.to_le_bytes());
            }
            // Segment headers carry whole-stream physical size only at VCN0.
            if sparse {
                normalized[64..72].fill(0);
            }
            let remaining = limits
                .runs
                .checked_sub(run_count)
                .ok_or_else(|| budget("NTFS stream run cap"))?;
            // Decode a segment's runlist structurally; aggregate physical accounting below.
            let mapping = decode_segment(
                &normalized,
                &self.geometry,
                NtfsReadLimits {
                    runs: remaining,
                    ..self.limits
                },
                r,
                sparse,
            )?;
            run_count = run_count
                .checked_add(mapping.runs)
                .filter(|n| *n <= limits.runs)
                .ok_or_else(|| budget("NTFS aggregate stream runs"))?;
            physical.extend_from_slice(&mapping.physical);
            for e in mapping.extents {
                let start = offset
                    .checked_add(e.offset)
                    .ok_or_else(|| bad("NTFS continuation logical overflow"))?;
                let end = start
                    .checked_add(e.length)
                    .ok_or_else(|| bad("NTFS continuation end overflow"))?
                    .min(length);
                let split = end.min(initialized).max(start);
                if split > start {
                    extents.push(FileExtent {
                        offset: start,
                        length: split - start,
                        kind: e.kind,
                    });
                }
                if end > split {
                    extents.push(FileExtent {
                        offset: split,
                        length: end - split,
                        kind: if e.kind == MapKind::Hole {
                            MapKind::Hole
                        } else {
                            MapKind::Unwritten
                        },
                    });
                }
            }
            next = next
                .checked_add(clusters)
                .ok_or_else(|| bad("NTFS aggregate VCN overflow"))?;
        }
        if next.checked_mul(self.geometry.cluster_bytes) != Some(allocated) || length > allocated {
            return Err(bad("NTFS aggregate DATA allocation coverage"));
        }
        physical.sort_unstable();
        if physical.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
            return Err(bad("NTFS overlapping DATA segment allocations"));
        }
        if sparse {
            let sum = physical
                .iter()
                .try_fold(0u64, |n, (_, len)| n.checked_add(*len))
                .ok_or_else(|| bad("NTFS sparse physical sum"))?;
            if u64le(first_bytes, 64) != sum {
                return Err(bad("NTFS aggregate sparse physical size"));
            }
        }
        let file = ExtentFile::new(
            self.context.source.clone(),
            length,
            extents,
            limits.runs.saturating_mul(2),
        )
        .map_err(|e| Error::io("NTFS assembled stream map", e))?;
        Ok((
            Content::Mapped(file),
            selected.len(),
            initialized,
            sparse,
            map_lease,
        ))
    }
}
// Existing structural mapping decoder validates sparse accounting per segment;
// normalized sparse sizes are measured from the independently parsed runlist.
pub(super) fn decode_segment(
    b: &[u8],
    g: &NtfsGeometry,
    limits: NtfsReadLimits,
    r: &Resources,
    sparse: bool,
) -> Result<NtfsRawMap> {
    if !sparse {
        return decode_runs(b, g, limits, r, false);
    }
    let mut copy = vector(b.len())?;
    copy.extend_from_slice(b);
    let mut at = usize::from(u16le(b, 32));
    let mut physical = 0u64;
    let mut count = 0;
    loop {
        r.cancellation.check()?;
        let header = *b
            .get(at)
            .ok_or_else(|| bad("NTFS sparse segment run terminator"))?;
        at += 1;
        if header == 0 {
            break;
        }
        count += 1;
        if count > limits.runs {
            return Err(budget("NTFS sparse segment run cap"));
        }
        let n = usize::from(header & 15);
        let m = usize::from(header >> 4);
        if n == 0 || n > 8 || m > 8 || at.checked_add(n + m).is_none_or(|end| end > b.len()) {
            return Err(bad("NTFS sparse segment widths"));
        }
        if m != 0 {
            let mut raw = [0; 8];
            raw[..n].copy_from_slice(&b[at..at + n]);
            physical = physical
                .checked_add(
                    u64::from_le_bytes(raw)
                        .checked_mul(g.cluster_bytes)
                        .ok_or_else(|| bad("NTFS sparse segment overflow"))?,
                )
                .ok_or_else(|| bad("NTFS sparse segment sum"))?;
        }
        at += n + m;
    }
    copy[64..72].copy_from_slice(&physical.to_le_bytes());
    decode_runs(&copy, g, limits, r, false)
}
