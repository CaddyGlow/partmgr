//! Source-bound native directory continuation mechanics.
use crate::fs_core::{Error, ErrorKind, ObjectId, Result};
use crate::platform::ops::Range;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(crate) fn token(id: &ObjectId, index: usize) -> Result<Vec<u8>> {
    let index = u64::try_from(index)
        .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "directory page cursor size"))?;
    let mut token = Vec::new();
    token.try_reserve_exact(32 + id.native.len()).map_err(|_| {
        Error::new(
            ErrorKind::BudgetExhausted,
            "directory page token allocation",
        )
    })?;
    token.extend_from_slice(&id.source.to_be_bytes());
    token.extend_from_slice(&id.generation.to_be_bytes());
    token.extend_from_slice(&id.native);
    token.extend_from_slice(&index.to_be_bytes());
    Ok(token)
}

pub(crate) fn range(
    id: &ObjectId,
    continuation: Option<&[u8]>,
    maximum: usize,
    count: usize,
) -> Result<Range<usize>> {
    if maximum == 0 {
        return Err(Error::new(
            ErrorKind::BudgetExhausted,
            "zero directory page maximum",
        ));
    }
    let prefix = 24 + id.native.len();
    let start = if let Some(token) = continuation {
        if token.len() != prefix + 8
            || token[..16] != id.source.to_be_bytes()
            || token[16..24] != id.generation.to_be_bytes()
            || token[24..prefix] != id.native
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "foreign directory page continuation",
            ));
        }
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&token[prefix..]);
        usize::try_from(u64::from_be_bytes(bytes))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "directory page cursor size"))?
    } else {
        0
    };
    if start > count {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "directory page cursor bounds",
        ));
    }
    Ok(start..start + maximum.min(count - start))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    #[test]
    fn continuation_binds_source_generation_and_native_identity() {
        let id = ObjectId {
            source: 42,
            generation: 17,
            native: vec![1, 2, 3],
        };
        let cursor = token(&id, 2).unwrap();
        assert_eq!(range(&id, Some(&cursor), 2, 5).unwrap(), 2..4);
        assert_eq!(
            range(&id, Some(&token(&id, 5).unwrap()), 2, 5).unwrap(),
            5..5
        );
        for at in [0, 16, 24] {
            let mut foreign = cursor.clone();
            foreign[at] ^= 1;
            assert_eq!(
                range(&id, Some(&foreign), 2, 5).unwrap_err().kind,
                ErrorKind::StalePlan
            );
        }
        assert!(range(&id, Some(&cursor[..cursor.len() - 1]), 2, 5).is_err());
        assert!(range(&id, Some(&token(&id, 6).unwrap()), 2, 5).is_err());
        assert!(range(&id, None, 0, 5).is_err());
        assert_eq!(range(&id, None, usize::MAX, 5).unwrap(), 0..5);
    }
}
