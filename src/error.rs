//! Domain failures retaining original I/O errors as sources.
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
use crate::platform::{fmt, io};
use crate::storage::CommitError;
/// Errors grouped by the operation and its recovery implications.
#[derive(Debug)]
pub enum Error {
    /// Untrusted metadata failed strict validation.
    InvalidData(io::Error),
    /// Valid or recognized data uses unsupported semantics.
    Unsupported(io::Error),
    /// An edit would violate layout invariants.
    InvalidEdit(io::Error),
    /// Storage I/O failed outside an in-progress commit.
    Io(io::Error),
    /// Preconditions changed before writes started.
    StalePlan(CommitError),
    /// A commit failed after writes may have started.
    PartialCommit(CommitError),
}
impl Error {
    pub(crate) fn inspection(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => Self::InvalidData(error),
            io::ErrorKind::Unsupported => Self::Unsupported(error),
            _ => Self::Io(error),
        }
    }
    pub(crate) fn edit(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::Unsupported {
            Self::Unsupported(error)
        } else {
            Self::InvalidEdit(error)
        }
    }
}
impl From<CommitError> for Error {
    fn from(value: CommitError) -> Self {
        match value {
            e @ CommitError::Stale { .. } => Self::StalePlan(e),
            CommitError::Preflight(e) => Self::Io(e),
            e @ CommitError::Interrupted { .. } => Self::PartialCommit(e),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidData(e) => write!(f, "invalid partition data: {e}"),
            Self::Unsupported(e) => write!(f, "unsupported partition semantics: {e}"),
            Self::InvalidEdit(e) => write!(f, "invalid partition edit: {e}"),
            Self::Io(e) => write!(f, "storage I/O: {e}"),
            Self::StalePlan(e) | Self::PartialCommit(e) => e.fmt(f),
        }
    }
}
impl crate::platform::error::Error for Error {
    fn source(&self) -> Option<&(dyn crate::platform::error::Error + 'static)> {
        Some(match self {
            Self::InvalidData(e) | Self::Unsupported(e) | Self::InvalidEdit(e) | Self::Io(e) => e,
            Self::StalePlan(e) | Self::PartialCommit(e) => e,
        })
    }
}
/// Strict owned inspection with classified domain errors.
pub fn inspect(
    source: &dyn crate::io::ReadAt,
    sector_size: u32,
) -> Result<crate::layout::DiskLayout, Error> {
    crate::layout::DiskLayout::inspect(source, sector_size).map_err(Error::inspection)
}
