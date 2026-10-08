//! Positional emission primitives; format-specific orchestration retains mutation state.
use crate::{
    fs_core::{Error, ErrorKind, Resources, Result},
    storage::Storage,
};
use std::io;

pub(crate) fn write_all(
    storage: &mut (impl Storage + ?Sized),
    offset: u64,
    bytes: &[u8],
    resources: &Resources,
    mutated: &mut bool,
    context: &str,
) -> Result<()> {
    let mut done = 0;
    while done < bytes.len() {
        resources.cancellation.check()?;
        // A failed write may have modified storage before returning its error.
        *mutated = true;
        let count = storage
            .write_at(offset + done as u64, &bytes[done..])
            .map_err(|error| Error::io(context, error))?;
        resources.cancellation.check()?;
        if count == 0 || count > bytes.len() - done {
            return Err(Error::io(context, io::ErrorKind::WriteZero.into()));
        }
        done += count;
    }
    Ok(())
}

pub(crate) fn flush(
    storage: &mut (impl Storage + ?Sized),
    resources: &Resources,
    context: &str,
) -> Result<()> {
    resources.cancellation.check()?;
    storage.flush().map_err(|cause| {
        let mut error = Error::io(context, cause);
        error.kind = ErrorKind::UncertainDurability;
        error
    })?;
    Ok(())
}

pub(crate) fn verify(
    storage: &(impl Storage + ?Sized),
    offset: u64,
    expected: &[u8],
    actual: &mut [u8],
    resources: &Resources,
    context: &str,
    mismatch: &str,
) -> Result<()> {
    resources.cancellation.check()?;
    storage
        .read_exact_at(offset, actual)
        .map_err(|error| Error::io(context, error))?;
    resources.cancellation.check()?;
    if actual != expected {
        return Err(Error::new(ErrorKind::InvalidData, mismatch));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};

    struct Target {
        bytes: Vec<u8>,
        count: usize,
        fail_flush: bool,
        cancel_write: Option<Cancellation>,
    }
    impl Storage for Target {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let n = self.count.min(bytes.len());
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if let Some(cancel) = &self.cancel_write {
                cancel.cancel();
            }
            Ok(self.count.min(bytes.len()))
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("durability cause"))
            } else {
                Ok(())
            }
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1024),
            cancellation: Cancellation::default(),
        }
    }
    fn target() -> Target {
        Target {
            bytes: vec![0; 8],
            count: 2,
            fail_flush: false,
            cancel_write: None,
        }
    }
    #[test]
    fn short_writes_are_completed_and_readback_mismatch_is_rejected() {
        let r = resources();
        let mut t = target();
        let mut mutated = false;
        write_all(&mut t, 1, &[1, 2, 3, 4, 5], &r, &mut mutated, "write").unwrap();
        assert!(mutated);
        let mut actual = [0; 5];
        verify(
            &t,
            1,
            &[1, 2, 3, 4, 5],
            &mut actual,
            &r,
            "verify",
            "mismatch",
        )
        .unwrap();
        assert_eq!(
            verify(
                &t,
                1,
                &[1, 2, 3, 4, 6],
                &mut actual,
                &r,
                "verify",
                "mismatch"
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidData
        );
    }
    #[test]
    fn cancelled_callback_and_zero_writes_retain_mutation_state() {
        let r = resources();
        let mut t = target();
        t.cancel_write = Some(r.cancellation.clone());
        let mut mutated = false;
        assert_eq!(
            write_all(&mut t, 0, &[1, 2, 3], &r, &mut mutated, "write")
                .unwrap_err()
                .kind,
            ErrorKind::Cancelled
        );
        assert!(mutated);
        assert_eq!(&t.bytes[..3], &[1, 2, 0]);
        t.cancel_write = None;
        t.count = 0;
        let r = resources();
        let error = write_all(&mut t, 0, &[1], &r, &mut mutated, "zero write").unwrap_err();
        assert_eq!(error.kind, ErrorKind::Io);
        assert!(mutated);
    }
    #[test]
    fn flush_failure_keeps_cause_and_uncertain_durability() {
        let r = resources();
        let mut t = target();
        t.fail_flush = true;
        let error = flush(&mut t, &r, "flush").unwrap_err();
        assert_eq!(error.kind, ErrorKind::UncertainDurability);
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .to_string()
                .contains("durability cause")
        );
    }
}
