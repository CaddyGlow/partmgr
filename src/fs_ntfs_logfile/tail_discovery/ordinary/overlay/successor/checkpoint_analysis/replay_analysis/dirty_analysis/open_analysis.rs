//! Source-ordered native open table and name effects; runtime pointers are absent.
use super::*;
/// Finite native open-table and exact retained-name ceilings.
#[derive(Clone, Copy, Debug)]
pub struct NtfsLogOpenAnalysisLimits {
    /// Maximum physical native slots, including free slots and cushion extensions.
    pub entries: usize,
    /// Maximum source-native slot stride (at least40 bytes).
    pub entry_bytes: usize,
    /// Maximum combined live name bytes, including replacement allocation overlap.
    pub name_bytes: usize,
}
struct Name {
    bytes: Vec<u8>,
    _lease: Reservation,
}
/// Source-derived open table and exact names; no native pointer is dereferenced.
pub struct OpenState {
    table: Vec<u8>,
    names: Vec<Option<Name>>,
    name_bytes: usize,
    limits: NtfsLogOpenAnalysisLimits,
    names_stop: NtfsLogNameStop,
    _lease: Reservation,
}
/// Exact native initial-name loop stopping observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogNameStop {
    /// No names dump or no original open table.
    Absent,
    /// Native zero target terminator.
    Terminator,
    /// Native bounds branch ignores the remaining names bytes.
    IgnoredTruncatedTail,
    /// All source bytes consumed; native next prefix check stops the loop.
    EndOfBytes,
}
impl OpenState {
    /// Derived slot/free-chain bytes; runtime pointer bytes are zero placeholders.
    pub fn table_bytes(&self) -> &[u8] {
        &self.table
    }
    /// Full copied source name bytes, preserving odd trailing bytes and duplicates.
    pub fn name_bytes(&self, index: usize) -> Option<&[u8]> {
        self.names.get(index)?.as_ref().map(|n| n.bytes.as_slice())
    }
    /// Native effective name-unit count, including its actual u8 assignment.
    pub fn native_name_units(&self, index: usize) -> Option<u8> {
        (index < slots(&self.table) && allocated(&self.table, index))
            .then(|| self.table[offset(&self.table, index) + 14])
    }
    /// Exact stopping branch of the initial native name overlay.
    pub fn initial_names_stop(&self) -> NtfsLogNameStop {
        self.names_stop
    }
    fn replace_name(
        &mut self,
        index: usize,
        bytes: &[u8],
        kind: u8,
        w: &mut Work,
        r: &Resources,
    ) -> Result<()> {
        let peak = self
            .name_bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limits.name_bytes)
            .ok_or_else(|| exhausted("NTFS open name peak bytes"))?;
        charge(w, bytes.len() + 1, r)?;
        let lease = r.memory.reserve(bytes.len() as u64)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(bytes.len())
            .map_err(|_| exhausted("NTFS open name allocation"))?;
        if raw.capacity() > bytes.len() {
            return Err(exhausted("NTFS open name capacity"));
        }
        raw.extend_from_slice(bytes);
        let previous = self.names[index].as_ref().map_or(0, |n| n.bytes.len());
        self.names[index] = Some(Name {
            bytes: raw,
            _lease: lease,
        });
        self.name_bytes = peak - previous;
        let at = offset(&self.table, index);
        self.table[at + 13] = kind;
        self.table[at + 14] = (bytes.len() / 2) as u8;
        self.table[at + 32..at + 40].fill(0);
        Ok(())
    }
    pub(super) fn load(
        replay: &NtfsLogReplayAnalysisReport,
        limits: NtfsLogOpenAnalysisLimits,
        w: &mut Work,
        r: &Resources,
    ) -> Result<Self> {
        if limits.entries > usize::from(u16::MAX)
            || limits.entry_bytes < 40
            || limits.entry_bytes > usize::from(u16::MAX)
        {
            return Err(exhausted("NTFS open native encoding ceilings"));
        }
        let tablebytes = limits
            .entries
            .checked_mul(limits.entry_bytes)
            .and_then(|n| n.checked_add(24))
            .filter(|n| *n <= u32::MAX as usize)
            .ok_or_else(|| exhausted("NTFS open table bytes"))?;
        let nodes = limits
            .entries
            .checked_mul(core::mem::size_of::<Option<Name>>())
            .and_then(|n| n.checked_add(tablebytes))
            .ok_or_else(|| exhausted("NTFS open inventory bytes"))?;
        let lease = r.memory.reserve(nodes as u64)?;
        let mut table = Vec::new();
        table
            .try_reserve_exact(tablebytes)
            .map_err(|_| exhausted("NTFS open table allocation"))?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(limits.entries)
            .map_err(|_| exhausted("NTFS open name nodes"))?;
        if table.capacity() > tablebytes || names.capacity() > limits.entries {
            return Err(exhausted("NTFS open inventory capacity"));
        }
        for _ in 0..limits.entries {
            charge(w, 1, r)?;
            names.push(None);
        }
        let mut state = Self {
            table,
            names,
            name_bytes: 0,
            limits,
            names_stop: NtfsLogNameStop::Absent,
            _lease: lease,
        };
        let dumps = replay.dumps.as_ref();
        let original = dumps.is_some_and(|d| d.dumps()[0].record().is_some());
        let mut original_open_bytes = 0usize;
        if original {
            let client = dumps
                .ok_or_else(|| invalid("NTFS open dumps absent"))?
                .dump_client(0)?;
            let raw = client.redo();
            original_open_bytes = raw.len();
            let stride = usize::from(le16(raw, 0));
            let count = usize::from(le16(raw, 2));
            if stride < 40 || stride > limits.entry_bytes || count > limits.entries {
                return Err(exhausted("NTFS initial open table bounds"));
            }
            charge(w, 24 + stride * count, r)?;
            state.table.extend_from_slice(&raw[..24 + stride * count]);
            for i in 0..count {
                charge(w, 1, r)?;
                if allocated(&state.table, i) {
                    let at = offset(&state.table, i);
                    state.table[at + 13] = 0;
                    state.table[at + 32..at + 40].fill(0);
                }
            }
        }
        if original && dumps.is_some_and(|d| d.dumps()[1].record().is_some()) {
            let client = dumps
                .ok_or_else(|| invalid("NTFS names dump absent"))?
                .dump_client(1)?;
            let raw = client.redo();
            let mut pos = 0;
            loop {
                charge(w, 1, r)?;
                if raw.len() - pos < 4 {
                    state.names_stop = if pos == raw.len() {
                        NtfsLogNameStop::EndOfBytes
                    } else {
                        NtfsLogNameStop::IgnoredTruncatedTail
                    };
                    break;
                }
                let target = usize::from(le16(raw, pos));
                if target == 0 {
                    state.names_stop = NtfsLogNameStop::Terminator;
                    break;
                }
                if target
                    .checked_add(40)
                    .is_none_or(|end| end > original_open_bytes)
                {
                    state.names_stop = NtfsLogNameStop::IgnoredTruncatedTail;
                    break;
                }
                let length = usize::from(le16(raw, pos + 2));
                let start = pos + 4;
                let end = start
                    .checked_add(length)
                    .ok_or_else(|| invalid("NTFS initial name range"))?;
                if end > raw.len() {
                    state.names_stop = NtfsLogNameStop::IgnoredTruncatedTail;
                    break;
                }
                let stride = usize::from(le16(&state.table, 0));
                if target < 24 || !(target - 24).is_multiple_of(stride) {
                    return Err(unsupported("NTFS initial name non-slot target"));
                }
                let i = (target - 24) / stride;
                if i >= slots(&state.table) {
                    return Err(unsupported(
                        "NTFS initial name target outside declared slots",
                    ));
                }
                state.replace_name(i, &raw[start..end], 2, w, r)?;
                pos = end;
            }
        }
        if !original {
            if limits.entries < 8 {
                return Err(exhausted("NTFS initial open8slots"));
            }
            initialize(&mut state.table, 40, 8, w, r)?;
        }
        Ok(state)
    }
    fn extend(&mut self, count: usize, w: &mut Work, r: &Resources) -> Result<()> {
        let oldcount = slots(&self.table);
        if count <= oldcount {
            return Ok(());
        }
        if count > self.limits.entries || count > usize::from(u16::MAX) {
            return Err(exhausted("NTFS native open extension slots"));
        }
        let stride = usize::from(le16(&self.table, 0));
        let oldbytes = self.table.len();
        let oldfirst = le32(&self.table, 16);
        let oldlast = le32(&self.table, 20);
        charge(w, (count - oldcount) * stride, r)?;
        self.table.resize(24 + count * stride, 0);
        put16(&mut self.table, 2, count as u16);
        put32(&mut self.table, 12, u32::MAX);
        if oldfirst == 0 {
            put32(&mut self.table, 16, oldbytes as u32);
        } else {
            put32(&mut self.table, oldlast as usize, oldbytes as u32);
        }
        put32(&mut self.table, 20, (24 + (count - 1) * stride) as u32);
        for i in oldcount..count - 1 {
            charge(w, 1, r)?;
            put32(
                &mut self.table,
                24 + i * stride,
                (24 + (i + 1) * stride) as u32,
            );
        }
        Ok(())
    }
    fn specific(&mut self, target: usize, w: &mut Work, r: &Resources) -> Result<usize> {
        let stride = usize::from(le16(&self.table, 0));
        if target < 24 || !(target - 24).is_multiple_of(stride) {
            return Err(unsupported("NTFS open non-slot target"));
        }
        if target >= self.table.len() {
            let count = target / stride + 10;
            self.extend(count, w, r)?;
        }
        let i = (target - 24) / stride;
        if allocated(&self.table, i) {
            return Ok(i);
        }
        let mut current = le32(&self.table, 16) as usize;
        let mut previous = None;
        while current != target {
            charge(w, 1, r)?;
            if current == 0 {
                return Err(invalid("NTFS open missing free slot"));
            }
            previous = Some(current);
            current = le32(&self.table, current) as usize;
        }
        charge(w, stride, r)?;
        let next = le32(&self.table, target);
        if let Some(previous) = previous {
            put32(&mut self.table, previous, next);
        } else {
            put32(&mut self.table, 16, next);
        }
        if le32(&self.table, 20) == target as u32 {
            put32(&mut self.table, 20, previous.unwrap_or(0) as u32);
        }
        if le32(&self.table, 16) == 0 {
            put32(&mut self.table, 20, 0);
        }
        self.table[target..target + stride].fill(0);
        put32(&mut self.table, target, u32::MAX);
        let total = le16(&self.table, 4)
            .checked_add(1)
            .ok_or_else(|| unsupported("NTFS open allocated overflow"))?;
        put16(&mut self.table, 4, total);
        Ok(i)
    }
    pub(super) fn apply(
        &mut self,
        client: &crate::fs_ntfs_logfile::NtfsLogClientRecord<'_>,
        w: &mut Work,
        r: &Resources,
    ) -> Result<()> {
        let raw = client.raw();
        let redo = usize::from(le16(raw, 4));
        let end = redo
            .checked_add(40)
            .filter(|end| *end <= raw.len())
            .ok_or_else(|| invalid("NTFS open source entry bounds"))?;
        if redo < client.header_bytes().len() {
            return Err(unsupported("NTFS open source entry header overlap"));
        }
        if le32(raw, redo) != u32::MAX {
            return Err(unsupported("NTFS open source allocated sentinel"));
        }
        let undo = usize::from(le16(raw, 8));
        let length = usize::from(le16(raw, 10));
        let undoend = if length == 0 {
            undo
        } else {
            undo.checked_add(length)
                .filter(|end| *end <= raw.len())
                .ok_or_else(|| invalid("NTFS open source name bounds"))?
        };
        if length != 0 && undo < client.header_bytes().len() {
            return Err(unsupported("NTFS open name header overlap"));
        }
        let index = self.specific(usize::from(client.target_attribute), w, r)?;
        let at = offset(&self.table, index);
        charge(w, 40, r)?;
        self.table[at..at + 40].copy_from_slice(&raw[redo..end]);
        if length != 0 {
            self.replace_name(index, &raw[undo..undoend], 1, w, r)?;
        } else {
            self.name_bytes -= self.names[index].as_ref().map_or(0, |n| n.bytes.len());
            self.names[index] = None;
            self.table[at + 13] = 0;
            self.table[at + 32..at + 40].fill(0);
        }
        Ok(())
    }
}
/// Derive combined dirty and open/name fields in exact native suffix order.
/// Geometry and stream identity originate exclusively from the native context.
pub fn inspect_logfile_native_open_analysis(
    context: NtfsLogNativeAnalysisContext,
    replay: NtfsLogReplayAnalysisReport,
    dirty: NtfsLogDirtyAnalysisLimits,
    open: NtfsLogOpenAnalysisLimits,
    r: &Resources,
) -> Result<NtfsLogDirtyAnalysisReport> {
    inspect_combined(context, replay, dirty, Some(open), r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    #[test]
    fn exact_open_slot_extension_keeps_native_cushion_and_free_queue() {
        let r = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        let limits = NtfsLogOpenAnalysisLimits {
            entries: 32,
            entry_bytes: 40,
            name_bytes: 128,
        };
        let lease = r
            .memory
            .reserve(32 * (40 + core::mem::size_of::<Option<Name>>()) as u64 + 24)
            .unwrap();
        let mut table = Vec::with_capacity(24 + 32 * 40);
        let names = (0..32).map(|_| None).collect();
        let mut work = Work {
            used: 0,
            maximum: 10000,
        };
        initialize(&mut table, 40, 8, &mut work, &r).unwrap();
        let mut state = OpenState {
            table,
            names,
            name_bytes: 0,
            limits,
            names_stop: NtfsLogNameStop::Absent,
            _lease: lease,
        };
        assert_eq!(state.specific(24 + 12 * 40, &mut work, &r).unwrap(), 12);
        assert_eq!(slots(&state.table), 22);
        assert_eq!(le16(&state.table, 4), 1);
        assert_eq!(le32(&state.table, 16), 24);
        assert_eq!(le32(&state.table, 20), 24 + 21 * 40);
        assert_eq!(le32(&state.table, 24 + 11 * 40), 24 + 13 * 40);
        assert_eq!(le32(&state.table, 24 + 12 * 40), u32::MAX);
        assert_eq!(le32(&state.table, 12), u32::MAX);
        drop(state);
        assert_eq!(r.memory.used(), 0);
    }
}
