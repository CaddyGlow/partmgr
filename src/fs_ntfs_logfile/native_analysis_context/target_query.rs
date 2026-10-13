//! Source-owned target observations, including native provisional fake_attr intent.
use super::*;
mod target_runs;
use crate::fs_core::{Budgeted, ObjectId};
use crate::fs_ntfs::{NtfsNativeAttribute, NtfsStreamLimits};
pub use target_runs::NtfsLogNativeRun;
use target_runs::decode_target_runs;
/// Native lookup observation; none grants allocation or replay permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsLogTargetObservation {
    /// Target exceeds the source-owned logical MFT; native physical/cached lookup unresolved.
    ObservedOutsideMft,
    /// Source-owned FILE slot is unused/zero; native cold/cached admission unresolved.
    ObservedUnusedFile,
    /// Allocated FILE sequence conflicts; native cold/cached admission unresolved.
    ObservedSequenceConflict,
    /// Exact source-owned attribute type/name has no occurrence.
    ProvisionalMissingAttribute,
    /// Native physical/list early-stop or continuation check returns no winner.
    ProvisionalNativeSelectionMiss,
    /// One or more native attribute occurrences match; no winner/map authority.
    ExistingAttributeCandidates,
    /// Original native lookup/validation error remains retained and incomplete.
    LookupFailed,
}
/// Exact target query and consumed physical provenance, without fabricated owner.
pub struct NtfsLogNativeTargetEvidence {
    source: Arc<dyn ReadAt>,
    source_len: u64,
    capture: Capture,
    open_offset: u32,
    reference: u64,
    attribute_type: u32,
    name: Vec<u16>,
    owner: Option<ObjectId>,
    attributes: Option<Budgeted<Vec<NtfsNativeAttribute>>>,
    matching: Vec<usize>,
    provisional: Option<Vec<u8>>,
    winner: Option<usize>,
    native_runs: Option<Budgeted<Vec<NtfsLogNativeRun>>>,
    directory: bool,
    observation: NtfsLogTargetObservation,
    error: Option<Error>,
    _lease: Reservation,
}
impl NtfsLogNativeTargetEvidence {
    /// Exact byte offset of the source-derived native open-table slot.
    pub fn open_slot_offset(&self) -> u32 {
        self.open_offset
    }
    /// Raw FILE reference from the sealed source-derived open slot.
    pub fn file_reference(&self) -> u64 {
        self.reference
    }
    /// Exact source-derived native attribute type.
    pub fn attribute_type(&self) -> u32 {
        self.attribute_type
    }
    /// Exact native effective UTF16 name, without pointer dereference.
    pub fn name(&self) -> &[u16] {
        &self.name
    }
    /// Actual source-owned owner only after successful sequence-bound lookup.
    pub fn owner(&self) -> Option<&ObjectId> {
        self.owner.as_ref()
    }
    /// All exact source-owned native attribute occurrences, including opaque bytes.
    pub fn attributes(&self) -> Option<&[NtfsNativeAttribute]> {
        self.attributes.as_ref().map(|a| a.get().as_slice())
    }
    /// Matching occurrence indices in source resolution order, not native winner proof.
    pub fn matching_occurrences(&self) -> &[usize] {
        &self.matching
    }
    /// Existing/provisional branch from actual source lookup.
    pub fn observation(&self) -> NtfsLogTargetObservation {
        self.observation
    }
    /// Native in-memory zero-size fake_attr descriptor for a proved provisional branch.
    /// This is an intent, never an allocated or on-disk attribute.
    pub fn provisional_attribute(&self) -> Option<&[u8]> {
        self.provisional.as_deref()
    }
    /// Exact ni_find_attr occurrence from source physical/list order and UpCase.
    pub fn selected_occurrence(&self) -> Option<usize> {
        self.winner
    }
    /// Physical native run cache before EOF or initialized-size clipping.
    pub fn native_runs(&self) -> Option<&[NtfsLogNativeRun]> {
        self.native_runs.as_ref().map(|r| r.get().as_slice())
    }
    /// Directory form observed from the source-owned base FILE record.
    pub fn is_directory(&self) -> bool {
        self.directory
    }
    /// Original lookup error; errors are never converted into proved absence.
    pub fn stopping_error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
    /// Exact captured target physical-read count.
    pub fn source_observations(&self) -> usize {
        self.capture.guards.len()
    }
    /// Query physical work, including original capture and one repeat comparison.
    pub(crate) fn physical_work(&self) -> Result<usize> {
        self.capture
            .work
            .checked_add(
                self.capture
                    .bytes
                    .checked_mul(3)
                    .and_then(|n| n.checked_add(self.capture.guards.len()))
                    .ok_or_else(|| exhausted("NTFS target repeat work"))?,
            )
            .ok_or_else(|| exhausted("NTFS target aggregate work"))
    }
    pub(crate) fn check_source(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        let length = self.source.len();
        r.cancellation.check()?;
        if length != self.source_len {
            return Err(stale());
        }
        repeat_capture(&self.capture, self.source.as_ref(), r)?;
        let length = self.source.len();
        r.cancellation.check()?;
        if length != self.source_len {
            return Err(stale());
        }
        Ok(())
    }
    /// No existing or provisional target observation proves recovery readiness.
    pub fn recovery_complete(&self) -> bool {
        false
    }
}
impl NtfsLogNativeAnalysisContext {
    pub(crate) fn inspect_target(
        &self,
        identity: (u32, u64, u32),
        name: &[u16],
        streams: NtfsStreamLimits,
        limits: NtfsLogNativeContextLimits,
        r: &Resources,
    ) -> Result<NtfsLogNativeTargetEvidence> {
        let (open_offset, reference, attribute_type) = identity;
        r.cancellation.check()?;
        let inventory = streams
            .attributes
            .checked_mul(core::mem::size_of::<usize>())
            .and_then(|n| n.checked_add(name.len().checked_mul(4)?.checked_add(80)?))
            .ok_or_else(|| exhausted("NTFS target inventory"))?;
        if name.len() > 255 {
            return Err(unsupported("NTFS target native name units"));
        }
        let lease = r.memory.reserve(inventory as u64)?;
        let guardbytes = limits
            .reads
            .checked_mul(core::mem::size_of::<Guard>())
            .ok_or_else(|| exhausted("NTFS target guard inventory"))?;
        let guardlease = r.memory.reserve(guardbytes as u64)?;
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(limits.reads)
            .map_err(|_| exhausted("NTFS target guard allocation"))?;
        let mut matching = Vec::new();
        matching
            .try_reserve_exact(streams.attributes)
            .map_err(|_| exhausted("NTFS target matches allocation"))?;
        let mut retained_name = Vec::new();
        retained_name
            .try_reserve_exact(name.len())
            .map_err(|_| exhausted("NTFS target name allocation"))?;
        if guards.capacity() > limits.reads
            || matching.capacity() > streams.attributes
            || retained_name.capacity() > name.len()
        {
            return Err(exhausted("NTFS target retained capacity"));
        }
        retained_name.extend_from_slice(name);
        {
            let mut capture = self
                .recorder
                .capture
                .lock()
                .map_err(|_| invalid("NTFS target capture lock poisoned"))?;
            if capture.is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "NTFS target capture already active",
                ));
            }
            *capture = Some(Capture {
                resources: r.clone(),
                guards,
                bytes: 0,
                work: 0,
                limits,
                _lease: guardlease,
            });
        }
        let mut evidence = NtfsLogNativeTargetEvidence {
            source: self.source.clone(),
            source_len: self.source_len,
            capture: Capture {
                resources: r.clone(),
                guards: Vec::new(),
                bytes: 0,
                work: 0,
                limits,
                _lease: r.memory.reserve(0)?,
            },
            open_offset,
            reference,
            attribute_type,
            name: retained_name,
            owner: None,
            attributes: None,
            matching,
            provisional: None,
            winner: None,
            native_runs: None,
            directory: false,
            observation: NtfsLogTargetObservation::LookupFailed,
            error: None,
            _lease: lease,
        };
        let result = (|| -> Result<NtfsLogTargetObservation> {
            let number = reference & 0x0000ffffffffffff;
            let sequence = (reference >> 48) as u16;
            if number >= self.volume.record_count() {
                return Ok(NtfsLogTargetObservation::ObservedOutsideMft);
            }
            let (used, observed, _base) = self.volume.audit_slot_reference(number, r)?;
            if !used {
                return Ok(NtfsLogTargetObservation::ObservedUnusedFile);
            }
            if observed != sequence {
                return Ok(NtfsLogTargetObservation::ObservedSequenceConflict);
            }
            let owner = self.volume.stream_identity(number, r)?;
            let selection: crate::fs_ntfs::stream::NativeLogSelection = self
                .volume
                .native_log_selection(&owner, attribute_type, name, streams, r)?;
            let attributes = selection.attributes;
            evidence.winner = selection.winner;
            evidence.directory = selection.directory;
            evidence.native_runs = Some(decode_target_runs(
                &attributes,
                &selection.run_inputs,
                self.volume.geometry().volume_bytes() / self.volume.geometry().cluster_bytes(),
                streams,
                r,
            )?);
            for (index, attribute) in attributes.iter().enumerate() {
                r.cancellation.check()?;
                if attribute.kind == attribute_type && attribute.name == name {
                    evidence.matching.push(index);
                }
            }
            evidence.owner = Some(owner);
            evidence.attributes = Some(attributes);
            Ok(if evidence.winner.is_none() {
                if evidence.matching.is_empty() {
                    NtfsLogTargetObservation::ProvisionalMissingAttribute
                } else {
                    NtfsLogTargetObservation::ProvisionalNativeSelectionMiss
                }
            } else {
                NtfsLogTargetObservation::ExistingAttributeCandidates
            })
        })();
        evidence.capture = self
            .recorder
            .capture
            .lock()
            .map_err(|_| invalid("NTFS target capture lock poisoned"))?
            .take()
            .ok_or_else(|| invalid("NTFS target capture vanished"))?;
        match result {
            Ok(observation) => {
                evidence.observation = observation;
                if matches!(
                    observation,
                    NtfsLogTargetObservation::ObservedOutsideMft
                        | NtfsLogTargetObservation::ObservedUnusedFile
                        | NtfsLogTargetObservation::ObservedSequenceConflict
                ) {
                    evidence.error = Some(unsupported(
                        "NTFS native cold/cached target admission unresolved",
                    ));
                }
                if matches!(
                    observation,
                    NtfsLogTargetObservation::ProvisionalMissingAttribute
                        | NtfsLogTargetObservation::ProvisionalNativeSelectionMiss
                ) {
                    match provisional_attribute(attribute_type, name) {
                        Ok(raw) => evidence.provisional = Some(raw),
                        Err(error) => evidence.error = Some(error),
                    }
                }
            }
            Err(error) => evidence.error = Some(error),
        }
        if let Err(error) = r
            .cancellation
            .check()
            .and_then(|()| evidence.check_source(r))
        {
            evidence.error.get_or_insert(error);
        }
        Ok(evidence)
    }
}

// Linux fslog.c2986–3030, fake_attr calls size0/flags0. No allocation runs,
// FILE identity, write authority or fabricated physical ownership are introduced.
fn provisional_attribute(kind: u32, name: &[u16]) -> Result<Vec<u8>> {
    let size = 64usize
        .checked_add(
            name.len()
                .checked_mul(2)
                .ok_or_else(|| exhausted("NTFS fake name size"))?
                .next_multiple_of(8),
        )
        .ok_or_else(|| exhausted("NTFS fake attribute size"))?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(size)
        .map_err(|_| exhausted("NTFS fake attribute allocation"))?;
    if raw.capacity() > size {
        return Err(exhausted("NTFS fake attribute capacity"));
    }
    raw.resize(size, 0);
    raw[..4].copy_from_slice(&kind.to_le_bytes());
    raw[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    raw[8] = 1;
    raw[9] = name.len() as u8;
    raw[10..12].copy_from_slice(&64u16.to_le_bytes());
    raw[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    raw[32..34].copy_from_slice(&(size as u16).to_le_bytes());
    for (i, unit) in name.iter().enumerate() {
        raw[64 + 2 * i..66 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(raw)
}
