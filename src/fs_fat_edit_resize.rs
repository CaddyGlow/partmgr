//! Allocation plans are derived only from the retained exclusive-session audit.
use super::*;
use crate::{fs_core::FileRead, fs_fat::FatFamily};

/// Reviewable resize outcome. Times, attributes, names and unrelated slots are preserved.
#[derive(Clone, Debug)]
pub struct FatResizeReport {
    /// Original logical size.
    pub old_length: u64,
    /// Resulting logical size.
    pub new_length: u64,
    /// Newly allocated clusters, fully initialized before reference publication.
    pub allocated_clusters: usize,
    /// Verified owned clusters released without overwriting their data.
    pub freed_clusters: usize,
    /// Known stale FAT32 FSInfo free counts reconciled with the complete audit.
    pub reconciled_fsinfo: bool,
    /// Explicit forensic policy: retain all native time fields rather than guessing current time.
    pub timestamps_preserved: bool,
}

type AppendReader<'a> = dyn FnMut(u64, &mut [u8], usize) -> Result<usize> + 'a;

pub(super) struct Planner<'a, S: Storage> {
    pub(super) target: &'a Region<S>,
    pub(super) limits: FatEditLimits,
    pub(super) resources: &'a Resources,
    pub(super) edits: Vec<(u64, u8, u8)>,
    pub(super) patches: Vec<WriteRange>,
    pub(super) bytes: u64,
    pub(super) work: usize,
}
impl<S: Storage> Planner<'_, S> {
    pub(super) fn tick(&mut self, n: usize) -> Result<()> {
        self.resources.cancellation.check()?;
        self.work = self
            .work
            .checked_add(n)
            .ok_or_else(|| exhausted("resize work overflow"))?;
        if self.work > self.limits.work {
            return Err(exhausted("FAT resize work ceiling"));
        }
        Ok(())
    }
    pub(super) fn patch(&mut self, at: u64, after: Vec<u8>) -> Result<()> {
        self.tick(1)?;
        self.bytes = self
            .bytes
            .checked_add(after.len() as u64)
            .ok_or_else(|| exhausted("resize bytes overflow"))?;
        if self.bytes > self.limits.affected_bytes
            || self.patches.len() >= self.limits.undo.patches as usize
        {
            return Err(exhausted("FAT resize patch/byte ceiling"));
        }
        let mut before = zeros(after.len())?;
        self.target.read_exact_at(at, &mut before).map_err(native)?;
        self.patches
            .push(WriteRange::new(at, before, after).map_err(native)?);
        Ok(())
    }
    pub(super) fn edit(&mut self, at: u64, after: &[u8]) -> Result<()> {
        self.tick(after.len())?;
        for (index, &value) in after.iter().enumerate() {
            let position = at + index as u64;
            match self.edits.binary_search_by_key(&position, |e| e.0) {
                Ok(i) => self.edits[i].2 = value,
                Err(i) => {
                    self.tick(self.edits.len() - i)?;
                    if self.edits.len() >= self.limits.work {
                        return Err(exhausted("FAT resize metadata ceiling"));
                    }
                    let mut old = [0];
                    self.target
                        .read_exact_at(position, &mut old)
                        .map_err(native)?;
                    self.edits.insert(i, (position, old[0], value));
                }
            }
        }
        Ok(())
    }
    pub(super) fn current(&mut self, at: u64, buffer: &mut [u8]) -> Result<()> {
        self.tick(buffer.len())?;
        self.target.read_exact_at(at, buffer).map_err(native)?;
        for (index, value) in buffer.iter_mut().enumerate() {
            if let Ok(i) = self
                .edits
                .binary_search_by_key(&(at + index as u64), |e| e.0)
            {
                *value = self.edits[i].2;
            }
        }
        Ok(())
    }
    pub(super) fn fat(
        &mut self,
        g: &FatGeometry,
        copy: u8,
        cluster: u32,
        value: u32,
    ) -> Result<()> {
        let base = g.fat_offset() + u64::from(copy) * g.fat_bytes();
        match g.family() {
            FatFamily::Fat12 => {
                let at = base + u64::from(cluster) * 3 / 2;
                let mut bytes = [0; 2];
                self.current(at, &mut bytes)?;
                let old = u16::from_le_bytes(bytes);
                let new = if cluster & 1 == 0 {
                    (old & 0xf000) | value as u16
                } else {
                    (old & 0x000f) | ((value as u16) << 4)
                };
                self.edit(at, &new.to_le_bytes())?;
            }
            FatFamily::Fat16 => {
                self.edit(base + u64::from(cluster) * 2, &(value as u16).to_le_bytes())?
            }
            FatFamily::Fat32 => {
                let at = base + u64::from(cluster) * 4;
                let mut bytes = [0; 4];
                self.current(at, &mut bytes)?;
                self.edit(
                    at,
                    &((u32::from_le_bytes(bytes) & 0xf000_0000) | value).to_le_bytes(),
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn fsinfo(
        &mut self,
        g: &FatGeometry,
        free_ranges: &[crate::fs_fat_audit::FatFreeRange],
        free_count: u64,
        allocated: &[u32],
        freed: &[u32],
    ) -> Result<bool> {
        let cb = g.cluster_bytes();
        let mut reconciled = false;
        if g.family() == FatFamily::Fat32 {
            let sector = u64::from(g.fsinfo_sector().ok_or_else(|| {
                Error::new(ErrorKind::Unsupported, "FAT32 resize requires FSInfo")
            })?);
            if sector != 1 || g.backup_sector().is_some_and(|sector| sector != 6) {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "FAT32 resize supports FSInfo sector one and backup zero/six only",
                ));
            }
            let mut sectors = [
                Some(sector),
                g.backup_sector().map(|backup| u64::from(backup) + sector),
            ];
            if sectors[1] == sectors[0] {
                sectors[1] = None;
            }
            let new_free = free_count + freed.len() as u64 - allocated.len() as u64;
            let mut hint = freed.first().copied().unwrap_or(0xffff_ffff);
            'ranges: for range in free_ranges {
                self.tick(1)?;
                let start = ((range.offset - g.data_offset()) / cb + 2) as u32;
                for i in 0..range.length / cb {
                    self.tick(1 + allocated.len())?;
                    let candidate = start + i as u32;
                    if !allocated.contains(&candidate) {
                        hint = candidate;
                        break 'ranges;
                    }
                }
            }
            for sector in sectors.into_iter().flatten() {
                self.tick(1)?;
                let at = sector * u64::from(g.bytes_per_sector());
                if at + 512 > g.fat_offset() {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "FAT32 backup FSInfo outside reserved region",
                    ));
                }
                let mut info = [0; 512];
                self.target.read_exact_at(at, &mut info).map_err(native)?;
                let word = |offset| {
                    u32::from_le_bytes(
                        info[offset..offset + 4]
                            .try_into()
                            .expect("fixed FSInfo slice"),
                    )
                };
                if word(0) != 0x4161_5252
                    || word(484) != 0x6141_7272
                    || word(508) != 0xaa55_0000
                    || info[4..484].iter().any(|&byte| byte != 0)
                    || info[496..508].iter().any(|&byte| byte != 0)
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "FAT32 resize requires valid FSInfo signatures",
                    ));
                }
                if (word(488) != 0xffff_ffff && word(488) > g.cluster_count())
                    || (word(492) != 0xffff_ffff
                        && !(2..=g.cluster_count() + 1).contains(&word(492)))
                {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "FAT32 FSInfo counter/hint out of range",
                    ));
                }
                reconciled |= word(488) != 0xffff_ffff && u64::from(word(488)) != free_count;
                self.edit(at + 488, &(new_free as u32).to_le_bytes())?;
                self.edit(at + 492, &hint.to_le_bytes())?;
            }
        }
        Ok(reconciled)
    }
    pub(super) fn finish_metadata(&mut self) -> Result<()> {
        let mut start = 0;
        while start < self.edits.len() {
            let mut end = start + 1;
            while end < self.edits.len() && self.edits[end].0 == self.edits[end - 1].0 + 1 {
                end += 1;
            }
            let mut after = zeros(end - start)?;
            for (out, edit) in after.iter_mut().zip(&self.edits[start..end]) {
                *out = edit.2;
            }
            self.patch(self.edits[start].0, after)?;
            start = end;
        }
        Ok(())
    }
}
pub(super) fn zeros(length: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(exhausted)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
impl<S: Storage, J: Storage> FatEditor<S, J> {
    /// Append bounded initialized bytes, allocating only audit-confirmed free clusters.
    /// Native timestamps are preserved; FAT32 FSInfo counts are reconciled to the audit.
    pub fn plan_extend_bytes(
        &self,
        file: &FatEditFile,
        bytes: &[u8],
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.resize_plan(
            file,
            file.len()
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| exhausted("FAT size overflow"))?,
            r,
            &mut |at, out, remaining| {
                if remaining == 0 {
                    return Err(exhausted("FAT append read ceiling"));
                }
                out.copy_from_slice(&bytes[at as usize..at as usize + out.len()]);
                Ok(1)
            },
        )
    }
    /// Append a deferred immutable stream, checking its identity and length around each read.
    /// The caller must guarantee input stability and independence from the mutable target.
    pub fn plan_extend(
        &self,
        file: &FatEditFile,
        input: &dyn FileRead,
        r: &Resources,
    ) -> Result<FatEditBatch> {
        self.check_file(file, r)?;
        if input.identity().native.len() > 64 {
            return Err(exhausted("FAT append input identity ceiling"));
        }
        let length = input.len();
        let _identity = r.memory.reserve(64)?;
        let id = input.identity().clone();
        if id.source == self.scope {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT append source aliases editor session",
            ));
        }
        let check = || {
            if input.identity() != &id || input.len() != length {
                Err(Error::new(ErrorKind::StalePlan, "FAT append input changed"))
            } else {
                Ok(())
            }
        };
        self.resize_plan(
            file,
            file.len()
                .checked_add(length)
                .ok_or_else(|| exhausted("FAT size overflow"))?,
            r,
            &mut |at, out, remaining| {
                let mut done = 0;
                let mut reads = 0usize;
                while done < out.len() {
                    r.cancellation.check()?;
                    reads = reads
                        .checked_add(1)
                        .ok_or_else(|| exhausted("FAT append work overflow"))?;
                    if reads > remaining {
                        return Err(exhausted("FAT append read ceiling"));
                    }
                    check()?;
                    let n = input.read_at(at + done as u64, &mut out[done..], r)?;
                    check()?;
                    if n == 0 || n > out.len() - done {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "FAT append input short/oversized read",
                        ));
                    }
                    done += n;
                }
                Ok(reads)
            },
        )
    }
    /// Shorten an existing file, releasing only its verified owned chain suffix.
    /// Native timestamps and freed payload bytes are preserved; zero length has cluster zero.
    pub fn plan_truncate(
        &self,
        file: &FatEditFile,
        length: u64,
        r: &Resources,
    ) -> Result<FatEditBatch> {
        if length >= file.len() {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT truncate must shorten a file",
            ));
        }
        self.resize_plan(file, length, r, &mut |_, _, _| {
            unreachable!("truncate has no input")
        })
    }
    fn resize_plan(
        &self,
        file: &FatEditFile,
        length: u64,
        r: &Resources,
        read: &mut AppendReader<'_>,
    ) -> Result<FatEditBatch> {
        self.check_file(file, r)?;
        if length == file.len() || length > u64::from(u32::MAX) {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT resize requires a different representable size",
            ));
        }
        let g = &self.geometry;
        let cb = g.cluster_bytes();
        let count = length.div_ceil(cb);
        if count > self.limits.file_clusters as u64 {
            return Err(exhausted("FAT resize file cluster ceiling"));
        }
        let charge = self
            .limits
            .affected_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add((self.limits.work as u64).checked_mul(32)?))
            .and_then(|n| n.checked_add((self.limits.file_clusters as u64).checked_mul(4)?))
            .and_then(|n| {
                n.checked_add(
                    (self.limits.undo.patches as u64)
                        .checked_mul(std::mem::size_of::<WriteRange>() as u64)?,
                )
            })
            .ok_or_else(|| exhausted("FAT resize reservation overflow"))?;
        let planning = r.memory.reserve(charge)?;
        let mut p = Planner {
            target: &self.target,
            limits: self.limits,
            resources: r,
            edits: Vec::new(),
            patches: Vec::new(),
            bytes: 0,
            work: 0,
        };
        p.edits
            .try_reserve_exact(self.limits.work)
            .map_err(exhausted)?;
        p.patches
            .try_reserve_exact(self.limits.undo.patches as usize)
            .map_err(exhausted)?;
        let mut chain = Vec::new();
        chain
            .try_reserve_exact(self.limits.file_clusters)
            .map_err(exhausted)?;
        for extent in &file.map.extents {
            p.tick(1)?;
            let ExtentKind::Data(at) = extent.kind else {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "FAT resize non-data extent",
                ));
            };
            chain.push(((at - g.data_offset()) / cb + 2) as u32);
        }
        let old_count = chain.len();
        let audit = self.audit.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidOperation,
                "FAT resize lacks current audit",
            )
        })?;
        let mut free_count = 0u64;
        for range in audit.free_ranges() {
            p.tick(1)?;
            free_count = free_count
                .checked_add(range.length / cb)
                .ok_or_else(|| exhausted("FAT free count overflow"))?;
            let need = count.saturating_sub(chain.len() as u64);
            for i in 0..need.min(range.length / cb) {
                p.tick(1)?;
                chain.push(((range.offset - g.data_offset()) / cb + i + 2) as u32);
            }
        }
        if chain.len() < count as usize {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FAT volume has insufficient free clusters",
            ));
        }
        let allocated = (count as usize).saturating_sub(old_count);
        let freed = old_count.saturating_sub(count as usize);
        if length > file.len() {
            let first = file.len() / cb;
            for index in first..count {
                p.tick(1)?;
                let logical = index * cb;
                let start = file.len().saturating_sub(logical);
                let at = g.data_offset() + u64::from(chain[index as usize] - 2) * cb + start;
                // Initialize all newly exposed bytes and the complete remaining cluster tail.
                let size = usize::try_from(cb - start).map_err(exhausted)?;
                if p.bytes + size as u64 > self.limits.affected_bytes {
                    return Err(exhausted("FAT resize initialization ceiling"));
                }
                let mut after = zeros(size)?;
                let payload = (length - logical - start).min(size as u64) as usize;
                let calls = read(
                    logical + start - file.len(),
                    &mut after[..payload],
                    p.limits.work - p.work,
                )?;
                p.tick(calls)?;
                p.patch(at, after)?;
            }
        }
        let initialized = p.patches.len();
        let eoc = match g.family() {
            FatFamily::Fat12 => 0xfff,
            FatFamily::Fat16 => 0xffff,
            FatFamily::Fat32 => 0x0fff_ffff,
        };
        if freed != 0 {
            let sorting = freed
                .checked_mul((usize::BITS - freed.leading_zeros()) as usize)
                .ok_or_else(|| exhausted("FAT free sort work overflow"))?;
            p.tick(sorting)?;
            chain[count as usize..old_count].sort_unstable();
        }
        for copy in 0..g.fat_count() {
            if g.active_fat().is_some_and(|active| copy != active) {
                continue;
            }
            if allocated != 0 {
                let first = old_count.saturating_sub(1);
                for index in first..count as usize {
                    p.fat(
                        g,
                        copy,
                        chain[index],
                        chain
                            .get(index + 1)
                            .filter(|_| index + 1 < count as usize)
                            .copied()
                            .unwrap_or(eoc),
                    )?;
                }
            } else if freed != 0 {
                if count != 0 {
                    p.fat(g, copy, chain[count as usize - 1], eoc)?;
                }
                for &cluster in &chain[count as usize..old_count] {
                    p.fat(g, copy, cluster, 0)?;
                }
            }
        }
        let slot = u64::from_le_bytes(
            file.identity
                .native
                .as_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "FAT file slot identity"))?,
        );
        let first = if count == 0 { 0 } else { chain[0] };
        p.edit(slot + 26, &(first as u16).to_le_bytes())?;
        if g.family() == FatFamily::Fat32 {
            p.edit(slot + 20, &((first >> 16) as u16).to_le_bytes())?;
        }
        p.edit(slot + 28, &(length as u32).to_le_bytes())?;
        let reconciled = p.fsinfo(
            g,
            audit.free_ranges(),
            free_count,
            &chain[old_count..],
            if freed == 0 {
                &[]
            } else {
                &chain[count as usize..old_count]
            },
        )?;
        p.finish_metadata()?;
        let metadata = p.patches.len() - initialized;
        Ok(FatEditBatch {
            source: self.scope,
            generation: self.generation,
            patches: p.patches,
            bytes: p.bytes,
            stages: Some(if initialized == 0 {
                vec![metadata]
            } else {
                vec![initialized, metadata]
            }),
            namespace: None,
            resize: Some(FatResizeReport {
                old_length: file.len(),
                new_length: length,
                allocated_clusters: allocated,
                freed_clusters: freed,
                reconciled_fsinfo: reconciled,
                timestamps_preserved: true,
            }),
            _planning: planning,
        })
    }
}
