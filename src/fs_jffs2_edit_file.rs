//! Bounded inode-preserving regular-file range transactions.
use super::*;
impl<F: FlashStorage> Jffs2Editor<F> {
    /// Replace a contiguous range from a deferred source, then publish explicit final length.
    /// All native hardlinks retain their inode. Unwritten extension gaps read as zero.
    /// Mode, ownership, flags and access seconds survive; modification/change seconds are explicit.
    pub fn write_range(
        &self,
        object: &ObjectId,
        offset: u64,
        payload: &dyn FileRead,
        final_length: u64,
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.file_range(object, offset, Some(payload), final_length, timestamp, r)
    }
    /// Publish an explicit regular-file length, preserving hardlinks and zero-filling extension.
    pub fn truncate(
        &self,
        object: &ObjectId,
        final_length: u64,
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.file_range(object, 0, None, final_length, timestamp, r)
    }
    fn file_range(
        &self,
        object: &ObjectId,
        offset: u64,
        payload: Option<&dyn FileRead>,
        final_length: u64,
        timestamp: u32,
        r: &Resources,
    ) -> Result<Jffs2EditPlan> {
        self.check(r)?;
        let lease = self.limits.reserve(r)?;
        let old = inode(&self.decoded, self.number(object)?)?;
        if self.decoded.endian.dword(&old.raw, 20) & 0xf000 != 0x8000 {
            return Err(invalid("JFFS2 range requires reachable regular file"));
        }
        let length = payload.map_or(0, FileRead::len);
        if final_length > u64::from(u32::MAX)
            || offset
                .checked_add(length)
                .is_none_or(|end| end > final_length)
            || length > self.limits.journal_bytes
        {
            return Err(cap("JFFS2 range length/intent cap"));
        }
        let offset = if length == 0 { 0 } else { offset };
        let chunk = self
            .limits
            .file_bytes
            .min((self.decoded.geometry.erase_bytes as usize).saturating_sub(80));
        if length > 0 && chunk == 0 {
            return Err(cap("JFFS2 range node payload cap"));
        }
        let old_size = u64::from(self.decoded.endian.dword(&old.raw, 28));
        let end = offset + length;
        let gaps = [
            (old_size, offset.min(final_length)),
            (old_size.max(end), final_length),
        ];
        let count = if length == 0 {
            0
        } else {
            length.div_ceil(chunk as u64)
        }
        .checked_add(1 + gaps.iter().filter(|(a, b)| a < b).count() as u64)
        .ok_or_else(|| cap("JFFS2 range node count"))?;
        if count > self.limits.slots as u64 {
            return Err(cap("JFFS2 range slot cap"));
        }
        let source_identity = payload.map(FileRead::identity);
        let identity_bytes = source_identity.map_or(0, |id| id.native.len());
        if identity_bytes as u64 > self.limits.read.native_bytes as u64 {
            return Err(cap("JFFS2 range source identity cap"));
        }
        let _identity_lease = r.memory.reserve(identity_bytes as u64)?;
        let identity = if let Some(id) = source_identity {
            let mut native = vec_bytes(identity_bytes, 0)?;
            native.copy_from_slice(&id.native);
            Some(ObjectId {
                source: id.source,
                generation: id.generation,
                native,
            })
        } else {
            None
        };
        let mut records = Vec::new();
        records
            .try_reserve_exact(count as usize)
            .map_err(|_| cap("JFFS2 range records"))?;
        let mut retained = 1024u64;
        let mut push = |offset: u64, bytes: &[u8], hole: u64| -> Result<()> {
            let version = old
                .namespace_version()
                .checked_add(records.len() as u32 + 1)
                .ok_or_else(|| cap("JFFS2 range version overflow"))?;
            let mut node = file_node(
                self.decoded.endian,
                old,
                old.number,
                version,
                bytes,
                Some(timestamp),
            )?;
            put(self.decoded.endian, &mut node, 28, final_length as u32);
            put(self.decoded.endian, &mut node, 44, offset as u32);
            if hole > 0 {
                node[56] = 1;
                put(self.decoded.endian, &mut node, 52, hole as u32);
            }
            finish(self.decoded.endian, &mut node, 0xe002, 68 + bytes.len());
            retained = retained
                .checked_add(16 + node.len() as u64)
                .ok_or_else(|| cap("JFFS2 range journal overflow"))?;
            if retained > self.limits.journal_bytes {
                return Err(cap("JFFS2 range journal cap"));
            }
            records.push(node);
            Ok(())
        };
        if gaps[0].0 < gaps[0].1 {
            push(gaps[0].0, &[], gaps[0].1 - gaps[0].0)?;
        }
        let mut done = 0;
        while done < length {
            self.check(r)?;
            if let Some(p) = payload
                && (p.len() != length || Some(p.identity()) != identity.as_ref())
            {
                return Err(Error::new(
                    ErrorKind::StalePlan,
                    "JFFS2 range source identity/length changed",
                ));
            }
            let n = (length - done).min(chunk as u64) as usize;
            let mut bytes = vec_bytes(n, 0)?;
            let mut read = 0;
            while read < n {
                self.check(r)?;
                let source = payload.unwrap();
                if source.len() != length || Some(source.identity()) != identity.as_ref() {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "JFFS2 range source changed before short read",
                    ));
                }
                let got = source.read_at(done + read as u64, &mut bytes[read..], r)?;
                self.check(r)?;
                if source.len() != length || Some(source.identity()) != identity.as_ref() {
                    return Err(Error::new(
                        ErrorKind::StalePlan,
                        "JFFS2 range source changed after short read",
                    ));
                }
                if got == 0 || got > n - read {
                    return Err(invalid("JFFS2 range deferred source progress"));
                }
                read += got;
            }
            push(offset + done, &bytes, 0)?;
            done += n as u64;
        }
        if gaps[1].0 < gaps[1].1 {
            push(gaps[1].0, &[], gaps[1].1 - gaps[1].0)?;
        }
        push(0, &[], 0)?;
        if let Some(p) = payload
            && (p.len() != length || Some(p.identity()) != identity.as_ref())
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "JFFS2 range source changed after reads",
            ));
        }
        self.plan(
            allocate(&self.decoded, records, None, self.limits)?,
            None,
            Jffs2EditOperation::FileRange,
            lease,
            r,
        )
    }
}
fn mapping_identity(
    kind: ExtentKind,
    registry: Option<&crate::fs_jffs2::compression::Registry>,
) -> Result<(ExtentKind, Option<crate::fs_jffs2::compression::Node>)> {
    if let ExtentKind::Data(address) = kind {
        if let Some((node, offset)) = registry.map(|r| r.resolve(address)).transpose()?.flatten() {
            return Ok((ExtentKind::Data(offset as u64), Some(node)));
        }
        if address & (1 << 63) != 0 {
            return Err(invalid("JFFS2 range compressed map without registry"));
        }
    }
    Ok((kind, None))
}
#[allow(clippy::too_many_arguments)]
fn expect_map(
    actual_registry: Option<&crate::fs_jffs2::compression::Registry>,
    expected_registry: Option<&crate::fs_jffs2::compression::Registry>,
    expected_node: Option<crate::fs_jffs2::compression::Node>,
    map: &[crate::fs_file::FileExtent],
    mut at: u64,
    end: u64,
    expected: ExtentKind,
    work: &mut u64,
    limit: u64,
    r: &Resources,
) -> Result<()> {
    let base = at;
    while at < end {
        r.cancellation.check()?;
        *work = work
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 range validation work"))?;
        if *work > limit {
            return Err(cap("JFFS2 range validation work cap"));
        }
        let index = map
            .partition_point(|m| m.offset <= at)
            .checked_sub(1)
            .ok_or_else(|| invalid("JFFS2 range map gap"))?;
        let m = &map[index];
        if at >= m.offset + m.length {
            return Err(invalid("JFFS2 range map gap"));
        }
        let actual = match m.kind {
            ExtentKind::Data(p) => ExtentKind::Data(p + at - m.offset),
            k => k,
        };
        let wanted = match expected {
            ExtentKind::Data(p) => ExtentKind::Data(p + at - base),
            k => k,
        };
        let expected_identity = match (wanted, expected_node) {
            (ExtentKind::Data(address), Some(node)) => {
                let offset = address
                    .checked_sub(node.physical)
                    .ok_or_else(|| invalid("JFFS2 range authored codec offset"))?;
                if offset >= u64::from(node.decoded) {
                    return Err(invalid("JFFS2 range authored codec bound"));
                }
                (ExtentKind::Data(offset), Some(node))
            }
            (_, Some(_)) => return Err(invalid("JFFS2 range authored codec kind")),
            (_, None) => mapping_identity(wanted, expected_registry)?,
        };
        if mapping_identity(actual, actual_registry)? != expected_identity {
            return Err(invalid(
                "JFFS2 range logical mapping changed outside intent",
            ));
        }
        at = end.min(m.offset + m.length);
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn validate(
    i: &Intent,
    b: &Decoded,
    a: &Jffs2AuditReport,
    c: &Decoded,
    ca: &Jffs2AuditReport,
    _baseline: &impl DecodeRead,
    _after: &impl DecodeRead,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    let e = i.endian;
    let first = &i.slots[0].bytes;
    if first.len() < 68 {
        return Err(invalid("JFFS2 range short first node"));
    }
    let number = e.dword(first, 12);
    let old = inode(b, number)?;
    let index = b
        .inodes
        .binary_search_by_key(&number, |n| n.number)
        .unwrap();
    if !a.reachable[index]
        || e.dword(&old.raw, 20) & 0xf000 != 0x8000
        || b.inodes.len() != c.inodes.len()
        || a.reachable_inodes() != ca.reachable_inodes()
    {
        return Err(invalid("JFFS2 range reachable inode profile"));
    }
    let size = u64::from(e.dword(first, 28));
    let mut start = None;
    let mut end = 0;
    let mut work = 0;
    let new = inode(c, number)?;
    let mut zeros = Vec::new();
    zeros
        .try_reserve_exact(2)
        .map_err(|_| cap("JFFS2 range zero inventory"))?;
    for (index, slot) in i.slots.iter().enumerate() {
        r.cancellation.check()?;
        let f = &slot.bytes;
        if f.len() < 68 {
            return Err(invalid("JFFS2 range short node"));
        }
        let n = e.dword(f, 52) as usize;
        let compressed = e.dword(f, 48) as usize;
        let last = index + 1 == i.slots.len();
        let offset = u64::from(e.dword(f, 44));
        let zero = f[56] == 1;
        if e.word(f, 2) != 0xe002
            || e.dword(f, 12) != number
            || e.dword(f, 16)
                != old
                    .namespace_version()
                    .checked_add(index as u32 + 1)
                    .ok_or_else(|| cap("JFFS2 range version"))?
            || e.dword(f, 28) as u64 != size
            || f.len() != ((68 + compressed + 3) & !3)
            || e.dword(f, 4) as usize != 68 + compressed
            || f[57] != 0
            || f[20..28] != old.raw[20..28]
            || f[32..36] != old.raw[32..36]
            || f[58..60] != old.raw[58..60]
            || e.dword(f, 36) != e.dword(first, 36)
            || e.dword(f, 40) != e.dword(first, 36)
            || (last && (n != 0 || compressed != 0 || offset != 0 || f[56] != 0))
            || (!last && n == 0)
            || (!zero
                && !compression_edit::data_shape(i.compression, f[56], compressed, n, l.file_bytes))
            || (zero && compressed != 0)
        {
            return Err(invalid("JFFS2 range exact node semantic profile"));
        }
        if last {
            continue;
        }
        let next = offset
            .checked_add(n as u64)
            .ok_or_else(|| cap("JFFS2 range end overflow"))?;
        if next > size {
            return Err(invalid("JFFS2 range exceeds final size"));
        }
        if zero {
            if zeros.len() == 2 {
                return Err(invalid("JFFS2 range excess ZERO records"));
            }
            zeros.push((offset, next));
            expect_map(
                c.codecs.as_ref(),
                None,
                None,
                &new.map,
                offset,
                next,
                ExtentKind::Hole,
                &mut work,
                l.read.work,
                r,
            )?;
        } else {
            if start.is_none() {
                start = Some(offset);
                end = offset;
            }
            if offset != end {
                return Err(invalid("JFFS2 range noncontiguous data records"));
            }
            let certificate = (f[56] != 0).then_some(crate::fs_jffs2::compression::Node {
                physical: slot.offset + 68,
                encoded: compressed as u32,
                decoded: n as u32,
                codec: f[56],
                checksum: e.dword(f, 60),
            });
            expect_map(
                c.codecs.as_ref(),
                None,
                certificate,
                &new.map,
                offset,
                next,
                ExtentKind::Data(slot.offset + 68),
                &mut work,
                l.read.work,
                r,
            )?;
            end = next;
        }
    }
    let start = start.unwrap_or(0);
    let old_size = u64::from(e.dword(&old.raw, 28));
    let gaps = [(old_size, size.min(start)), (old_size.max(end), size)];
    if zeros
        .iter()
        .copied()
        .ne(gaps.into_iter().filter(|(a, b)| a < b))
    {
        return Err(invalid("JFFS2 range exact ZERO extension gaps"));
    }
    for old_inode in &b.inodes {
        r.cancellation.check()?;
        let new_inode = inode(c, old_inode.number)?;
        if old_inode.number != number && old_inode.raw != new_inode.raw {
            return Err(invalid("JFFS2 range changed unrelated metadata"));
        }
        for (x, y) in [
            (&old_inode.children, &new_inode.children),
            (&old_inode.deleted, &new_inode.deleted),
        ] {
            if x.len() != y.len()
                || x.iter().zip(y).any(|(x, y)| {
                    x.name != y.name
                        || x.inode != y.inode
                        || x.file_type != y.file_type
                        || x.version() != y.version()
                        || x.timestamp() != y.timestamp()
                })
            {
                return Err(invalid("JFFS2 range changed namespace"));
            }
        }
    }
    for m in &old.map {
        let stop = (m.offset + m.length).min(size);
        for (left, right) in [(m.offset, stop.min(start)), (m.offset.max(end), stop)] {
            if left < right {
                let kind = match m.kind {
                    ExtentKind::Data(p) => ExtentKind::Data(p + left - m.offset),
                    k => k,
                };
                expect_map(
                    c.codecs.as_ref(),
                    b.codecs.as_ref(),
                    None,
                    &new.map,
                    left,
                    right,
                    kind,
                    &mut work,
                    l.read.work,
                    r,
                )?;
            }
        }
    }
    let old_size = u64::from(e.dword(&old.raw, 28));
    for (left, right) in [(old_size, size.min(start)), (old_size.max(end), size)] {
        if left < right {
            expect_map(
                c.codecs.as_ref(),
                None,
                None,
                &new.map,
                left,
                right,
                ExtentKind::Hole,
                &mut work,
                l.read.work,
                r,
            )?;
        }
    }
    Ok(())
}
