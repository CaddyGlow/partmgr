//! Exclusive logical replacements backed by an external ciphertext undo journal.
//!
//! Both stores must be exclusively held, disjoint and independently durable.
//! This module does not implement `Storage` for a decrypted view: filesystem
//! journals must not accidentally retain plaintext. Native Windows qualification
//! is separate from the synthetic transaction tests.
use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use zeroize::Zeroizing;

use crate::{
    bitlocker::{
        self, Identifier, Inspection, KeyEvidence, Limits, MetadataSelection, RecoveryPassword,
        StorageSource, VolumeInfo,
    },
    bitlocker_crypto::SectorCipher,
    fs_core::{Reservation, Resources},
    fs_undo::{self, UndoBinding, UndoFailure, UndoLimits, UndoPlan, UndoState, UndoStatus},
    storage::{Storage, WriteRange},
};

/// Session acquisition policy and externally verified recovery identity.
#[derive(Clone, Copy, Debug)]
pub struct SessionOptions {
    /// Explicit metadata selection policy.
    pub selection: MetadataSelection,
    /// Portable parser and cumulative backend read limits.
    pub limits: Limits,
    /// Maximum retained ciphertext transaction size.
    pub undo_limits: UndoLimits,
    /// Caller-verified identity of this bounded volume (including its container).
    pub volume: [u8; 32],
    /// Caller-assigned exclusive acquisition generation, retained for cold recovery.
    pub generation: u64,
}

/// Failure preserving the portable parser or durable undo cause.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Inspection, key authentication, mapping, or resource error.
    BitLocker(bitlocker::Error),
    /// Undo preflight or journal inspection error.
    Journal(crate::fs_core::Error),
    /// Durable transaction failure; the session becomes recovery-only.
    Commit(UndoFailure),
    /// Explicit recovery and a newly inspected session are required.
    RecoveryRequired,
    /// The plan belongs to another session or an earlier successful transaction.
    StalePlan,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BitLocker(e) => e.fmt(f),
            Self::Journal(e) => e.fmt(f),
            Self::Commit(e) => e.fmt(f),
            Self::RecoveryRequired => {
                f.write_str("BitLocker ciphertext recovery and reinspection required")
            }
            Self::StalePlan => f.write_str("stale BitLocker ciphertext plan"),
        }
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BitLocker(e) => Some(e),
            Self::Journal(e) => Some(e),
            Self::Commit(e) => Some(e),
            _ => None,
        }
    }
}
impl From<bitlocker::Error> for Error {
    fn from(value: bitlocker::Error) -> Self {
        Self::BitLocker(value)
    }
}
impl From<crate::fs_core::Error> for Error {
    fn from(value: crate::fs_core::Error) -> Self {
        Self::Journal(value)
    }
}
/// Result for exclusive encrypted editing.
pub type Result<T> = core::result::Result<T, Error>;

/// An owned encrypted target and external ciphertext journal. No backend aliases
/// are retained or published. Failed commits permanently fence this acquisition;
/// extract the stores, recover, then inspect and unlock a fresh session.
pub struct BitLockerSession<S, J> {
    storage: S,
    journal: J,
    inspection: Inspection,
    cipher: SectorCipher,
    evidence: KeyEvidence,
    options: SessionOptions,
    token: Arc<()>,
    revision: u64,
    recovery_required: bool,
    _reservation: Reservation,
}

/// Retained old/new ciphertext and metadata/session preconditions; no plaintext.
pub struct CiphertextPlan {
    undo: UndoPlan,
    binding: UndoBinding,
    token: Arc<()>,
    revision: u64,
}
impl CiphertextPlan {
    /// Exact identity required for credential-free cold recovery.
    pub fn binding(&self) -> UndoBinding {
        self.binding
    }
    /// Minimum external journal capacity required by this plan.
    pub fn journal_bytes(&self) -> u64 {
        self.undo.journal_bytes()
    }
}

/// Failed acquisition retaining both exclusive stores for retry or recovery.
/// Debug formatting never exposes storage contents.
pub struct OpenFailure<S, J> {
    /// Original exclusive encrypted target.
    pub storage: S,
    /// Original external recovery medium.
    pub journal: J,
    /// Causal acquisition failure.
    pub error: Error,
}
impl<S, J> fmt::Debug for OpenFailure<S, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<S, J> fmt::Display for OpenFailure<S, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl<S, J> core::error::Error for OpenFailure<S, J> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}
/// Acquisition result which retains backend ownership on failure.
pub type OpenResult<S, J> = core::result::Result<BitLockerSession<S, J>, OpenFailure<S, J>>;

impl<S: Storage, J: Storage> BitLockerSession<S, J> {
    /// Open with a diagnostic, unauthenticated supplied FVEK. Ownership alone
    /// cannot enforce exclusivity if the caller created independent aliases.
    pub fn open_fvek(
        storage: S,
        journal: J,
        options: SessionOptions,
        fvek: &[u8],
        resources: &Resources,
    ) -> OpenResult<S, J> {
        Self::open(storage, journal, options, resources, |inspection| {
            Ok((
                SectorCipher::new(inspection.info.encryption_method, fvek)?,
                KeyEvidence::CallerSupplied,
            ))
        })
    }
    /// Authenticate the explicitly selected numerical recovery protector through
    /// the owned backend, retaining only its sector key schedules.
    pub fn open_recovery(
        storage: S,
        journal: J,
        options: SessionOptions,
        identifier: Identifier,
        password: &RecoveryPassword,
        resources: &Resources,
    ) -> OpenResult<S, J> {
        Self::open(storage, journal, options, resources, |inspection| {
            let key = inspection.recovery_key(identifier, password)?;
            Ok((
                SectorCipher::new(inspection.info.encryption_method, &key)?,
                KeyEvidence::AuthenticatedKeyRecord,
            ))
        })
    }
    /// Authenticate the wrapped FVEK using an explicitly supplied VMK.
    pub fn open_vmk(
        storage: S,
        journal: J,
        options: SessionOptions,
        vmk: &[u8],
        resources: &Resources,
    ) -> OpenResult<S, J> {
        Self::open(storage, journal, options, resources, |inspection| {
            let key = inspection.vmk_key(vmk)?;
            Ok((
                SectorCipher::new(inspection.info.encryption_method, &key)?,
                KeyEvidence::AuthenticatedKeyRecord,
            ))
        })
    }
    /// Explicitly select a suspended volume's clear-key protector.
    pub fn open_clear(
        storage: S,
        journal: J,
        options: SessionOptions,
        identifier: Identifier,
        resources: &Resources,
    ) -> OpenResult<S, J> {
        Self::open(storage, journal, options, resources, |inspection| {
            let key = inspection.clear_key(identifier)?;
            Ok((
                SectorCipher::new(inspection.info.encryption_method, &key)?,
                KeyEvidence::AuthenticatedKeyRecord,
            ))
        })
    }
    fn open(
        storage: S,
        journal: J,
        options: SessionOptions,
        resources: &Resources,
        unlock: impl FnOnce(&Inspection) -> Result<(SectorCipher, KeyEvidence)>,
    ) -> OpenResult<S, J> {
        let result = (|| {
            // Recovery never needs a key; reject outstanding rollback before KDF.
            if fs_undo::inspect(&journal, resources)?.state == UndoState::Prepared {
                return Err(Error::RecoveryRequired);
            }
            let inspection = Inspection::inspect(
                &StorageSource(&storage),
                options.selection,
                options.limits,
                resources,
            )?;
            inspection.readable(&StorageSource(&storage))?;
            let (cipher, evidence) = unlock(&inspection)?;
            let reservation = resources
                .memory
                .reserve(core::mem::size_of::<Self>() as u64)?;
            Ok((inspection, cipher, evidence, reservation))
        })();
        match result {
            Ok((inspection, cipher, evidence, reservation)) => Ok(Self {
                storage,
                journal,
                inspection,
                cipher,
                evidence,
                options,
                token: Arc::new(()),
                revision: 0,
                recovery_required: false,
                _reservation: reservation,
            }),
            Err(error) => Err(OpenFailure {
                storage,
                journal,
                error,
            }),
        }
    }
    /// Selected non-secret volume profile.
    pub fn info(&self) -> &VolumeInfo {
        &self.inspection.info
    }
    /// Actual key acceptance evidence; XTS data sectors are not authenticated.
    pub fn key_evidence(&self) -> KeyEvidence {
        self.evidence
    }
    /// Whether this acquisition has a sticky recovery obligation.
    pub fn recovery_required(&self) -> bool {
        self.recovery_required
    }
    /// Consume the session for explicit credential-free recovery or final disposal.
    /// A recovery obligation is not cleared by extracting these stores.
    pub fn into_parts(self) -> (S, J) {
        (self.storage, self.journal)
    }

    fn check(&self) -> Result<()> {
        if self.recovery_required {
            return Err(Error::RecoveryRequired);
        }
        self.inspection
            .policy
            .check(&StorageSource(&self.storage))?;
        Ok(())
    }
    fn physical(&self, logical: u64) -> Result<u64> {
        let metadata = &self.inspection.metadata;
        let boot_length = metadata.boot_length(self.info().sector_size)?;
        let additional = metadata.additional_reserved_region(self.info().sector_size)?;
        if metadata
            .offsets
            .iter()
            .any(|&at| logical >= at && logical - at < 65_536)
            || (logical >= metadata.boot_offset && logical - metadata.boot_offset < boot_length)
            || additional.is_some_and(|(at, length)| logical >= at && logical - at < length)
        {
            return Err(
                bitlocker::unsupported("cannot write synthesized BitLocker regions").into(),
            );
        }
        Ok(if logical < boot_length {
            metadata.boot_offset + logical
        } else {
            logical
        })
    }
    /// Prepare one bounded logical replacement without changing either store.
    /// All affected sectors are validated before any plaintext is decrypted.
    /// `transaction` must be unique for this acquisition and retained for recovery.
    pub fn plan_replace(
        &self,
        offset: u64,
        replacement: &[u8],
        transaction: [u8; 16],
    ) -> Result<CiphertextPlan> {
        self.check()?;
        let end = offset
            .checked_add(replacement.len() as u64)
            .filter(|&end| end <= self.info().encrypted_length)
            .ok_or_else(|| bitlocker::invalid("BitLocker logical write range"))?;
        if replacement.is_empty() {
            return Err(bitlocker::invalid("empty BitLocker replacement").into());
        }
        let size = u64::from(self.info().sector_size);
        let first = offset / size * size;
        let count = (end - 1) / size - first / size + 1;
        let body_bytes = count
            .checked_mul(16 + 2 * size)
            .ok_or_else(|| bitlocker::invalid("ciphertext plan size overflow"))?;
        if count > u64::from(self.options.undo_limits.patches)
            || body_bytes > self.options.undo_limits.body_bytes
        {
            return Err(bitlocker::Error::new(
                bitlocker::ErrorKind::ResourceLimit,
                "ciphertext plan limit",
            )
            .into());
        }
        for i in 0..count {
            self.inspection.policy.resources.cancellation.check()?;
            self.physical(first + i * size)?;
        }
        let r = &self.inspection.policy.resources;
        let charge = body_bytes
            .checked_add(count * core::mem::size_of::<WriteRange>() as u64)
            .and_then(|v| v.checked_add(4096))
            .ok_or_else(|| bitlocker::invalid("ciphertext plan memory overflow"))?;
        let _temporary = r.memory.reserve(charge)?;
        let mut patches = Vec::new();
        patches.try_reserve_exact(count as usize).map_err(|_| {
            bitlocker::Error::new(
                bitlocker::ErrorKind::ResourceLimit,
                "ciphertext patch allocation",
            )
        })?;
        let mut scratch = Zeroizing::new([0u8; 4096]);
        for i in 0..count {
            let logical = first + i * size;
            let physical = self.physical(logical)?;
            let bytes = &mut scratch[..size as usize];
            self.inspection
                .policy
                .read(&StorageSource(&self.storage), physical, bytes)?;
            let old = copy_ciphertext(bytes)?;
            self.cipher.decrypt(bytes, physical / size);
            let start = logical.max(offset);
            let stop = (logical + size).min(end);
            bytes[(start - logical) as usize..(stop - logical) as usize]
                .copy_from_slice(&replacement[(start - offset) as usize..(stop - offset) as usize]);
            self.cipher.encrypt(bytes, physical / size);
            let new = copy_ciphertext(bytes)?;
            patches.push(
                WriteRange::new(physical, old, new)
                    .map_err(|e| bitlocker::Error::backend("ciphertext patch", e))?,
            );
        }
        let binding = UndoBinding {
            volume: self.options.volume,
            generation: self.options.generation,
            transaction,
        };
        let undo = UndoPlan::new(
            binding,
            self.inspection.policy.source_length,
            patches,
            self.options.undo_limits,
            r,
        )?;
        Ok(CiphertextPlan {
            undo,
            binding,
            token: self.token.clone(),
            revision: self.revision,
        })
    }
    /// Reinspect metadata and geometry, then durably commit exact ciphertext.
    /// Any undo failure fences this session, including uncertain journal barriers.
    pub fn commit(&mut self, plan: CiphertextPlan) -> Result<UndoStatus> {
        self.check()?;
        if !Arc::ptr_eq(&self.token, &plan.token) || self.revision != plan.revision {
            return Err(Error::StalePlan);
        }
        let next_revision = self.revision.checked_add(1).ok_or(Error::StalePlan)?;
        let fresh = Inspection::inspect_with_policy(
            &StorageSource(&self.storage),
            self.options.selection,
            self.inspection.policy.clone(),
        )?;
        if fresh.info != self.inspection.info
            || !fresh.metadata.same_generation(&self.inspection.metadata)
        {
            return Err(Error::StalePlan);
        }
        drop(fresh);
        let mut target = ChargedTarget {
            storage: &mut self.storage,
            policy: &self.inspection.policy,
        };
        match plan.undo.commit(
            &mut target,
            &mut self.journal,
            &self.inspection.policy.resources,
        ) {
            Ok(status) => {
                self.revision = next_revision;
                Ok(status)
            }
            Err(error) => {
                self.recovery_required = true;
                Err(Error::Commit(error))
            }
        }
    }
}
// Keep undo verification reads under the same cumulative target-read policy.
struct ChargedTarget<'a, S> {
    storage: &'a mut S,
    policy: &'a bitlocker::Policy,
}
impl<S: Storage> Storage for ChargedTarget<'_, S> {
    fn len(&self) -> crate::io::Result<u64> {
        self.storage.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> crate::io::Result<()> {
        self.policy
            .read(&StorageSource(&*self.storage), at, out)
            .map_err(|error| crate::io::Error::new(crate::io::ErrorKind::Other, error))
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> crate::io::Result<usize> {
        self.storage.write_at(at, bytes)
    }
    fn flush(&mut self) -> crate::io::Result<()> {
        self.storage.flush()
    }
}
fn copy_ciphertext(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len()).map_err(|_| {
        bitlocker::Error::new(bitlocker::ErrorKind::ResourceLimit, "ciphertext allocation")
    })?;
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Recover old ciphertext without a password or FVEK. Verify the externally
/// retained volume/generation/transaction binding against the selected bounded
/// target before calling. Afterwards acquire and inspect a fresh session.
/// This uses the same raw undo protocol as `fs_undo::recover`.
pub fn recover_ciphertext(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    limits: UndoLimits,
    resources: &Resources,
) -> core::result::Result<UndoStatus, UndoFailure> {
    fs_undo::recover(target, journal, binding, limits, resources)
}
