//! Bounded discovery of a volume envelope before selecting an inner filesystem.
//!
//! Candidates are signatures, not validation or authorization to unlock. An
//! encrypted candidate must be inspected and explicitly unlocked before passing
//! its decrypted reader to filesystem dispatch.

use crate::{
    fs_core::{Budgeted, Error, ErrorKind, Resources, Result},
    fs_image::{self, ReadFormat},
    io::ReadAt,
};
use alloc::vec::Vec;

/// Recognized encryption envelope, regardless of enabled unlocking features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitLockerEnvelope {
    /// Conventional fixed-volume signature.
    Fixed,
    /// Legacy removable-volume discovery signature.
    ToGo,
}

/// Discovery outcome without filesystem validity or encryption support claims.
pub enum Candidate {
    /// No recognized envelope or filesystem signature.
    Unknown,
    /// Possible inner filesystems; ambiguous signatures require explicit choice.
    Plaintext(Budgeted<Vec<ReadFormat>>),
    /// Encrypted envelope; no filesystem fallback is performed.
    BitLocker(BitLockerEnvelope),
}

/// Examine bounded signatures, giving encryption envelopes precedence.
///
/// Available without the `bitlocker` feature so encrypted input remains explicit
/// even when this build cannot unlock it. Unknown does not establish plaintext.
pub fn probe(source: &dyn ReadAt, resources: &Resources) -> Result<Candidate> {
    resources.cancellation.check()?;
    let length = source.len();
    let identity = source.source_identity();
    let envelope = {
        let _reservation = resources.memory.reserve(512)?;
        let mut boot = [0; 512];
        let n = length.min(512) as usize;
        source
            .read_exact_at(0, &mut boot[..n])
            .map_err(|error| Error::io("volume envelope probe", error))?;
        if n >= 11 && &boot[3..11] == b"-FVE-FS-" {
            Some(BitLockerEnvelope::Fixed)
        } else if n >= 464
            && boot[424..440]
                == [
                    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39,
                    0xe3, 0xd0, 1,
                ]
        {
            Some(BitLockerEnvelope::ToGo)
        } else {
            None
        }
    };
    let candidate = if let Some(envelope) = envelope {
        Candidate::BitLocker(envelope)
    } else {
        let formats = fs_image::probe(source, resources)?;
        if formats.get().is_empty() {
            Candidate::Unknown
        } else {
            Candidate::Plaintext(formats)
        }
    };
    resources.cancellation.check()?;
    if source.len() != length || source.source_identity() != identity {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "source changed during volume envelope probe",
        ));
    }
    Ok(candidate)
}
