//! Copy metadata on demand while the owner keeps arbitrary exclusive storage on its thread.
use crate::{
    fs_core::{Error, ErrorKind, Resources, Result},
    storage::Storage,
};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, mpsc},
};
use virtdisk::ReadAt;

pub(crate) type Pages<const N: usize> = Vec<(u64, Arc<[u8; N]>)>;

enum Request<const N: usize> {
    Page(u64, mpsc::SyncSender<Result<Arc<[u8; N]>>>),
    Done(Result<()>),
}
struct Cache<const N: usize> {
    pages: Pages<N>,
    index: HashMap<u64, usize>,
}
struct Source<const N: usize> {
    length: u64,
    pages: Mutex<Cache<N>>,
    requests: mpsc::Sender<Request<N>>,
    resources: Resources,
    charge: Arc<dyn Fn(u64) -> Result<()> + Send + Sync>,
}
impl<const N: usize> ReadAt for Source<N> {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.resources
            .cancellation
            .check()
            .map_err(io::Error::other)?;
        (self.charge)(out.len() as u64).map_err(io::Error::other)?;
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut pages = self
            .pages
            .lock()
            .map_err(|_| io::Error::other("metadata discovery cache poisoned"))?;
        let mut done = 0;
        while done < out.len() {
            self.resources
                .cancellation
                .check()
                .map_err(io::Error::other)?;
            let position = at + done as u64;
            let number = position / N as u64;
            let index = match pages.index.get(&number).copied() {
                Some(index) => index,
                None => {
                    let (reply, response) = mpsc::sync_channel(1);
                    self.requests
                        .send(Request::Page(number, reply))
                        .map_err(|_| io::Error::other("metadata discovery owner unavailable"))?;
                    let page = response
                        .recv()
                        .map_err(|_| io::Error::other("metadata discovery reply unavailable"))?
                        .map_err(io::Error::other)?;
                    let index = pages.pages.len();
                    pages.pages.push((number, page));
                    pages.index.insert(number, index);
                    index
                }
            };
            let within = (position % N as u64) as usize;
            let count = (N - within).min(out.len() - done);
            out[done..done + count].copy_from_slice(&pages.pages[index].1[within..within + count]);
            done += count;
        }
        Ok(())
    }
}

/// Caller reserves the complete page/index envelope before calling. Only the
/// metadata decoder may read this source; its result is discarded before sealing.
/// A final decode of the returned immutable pages establishes retained bindings.
/// `attempts` preserves the old bound of newly copied pages plus a successful decode.
pub(crate) fn discover<const N: usize>(
    target: &dyn Storage,
    length: u64,
    mut pages: Pages<N>,
    limits: (usize, usize),
    resources: &Resources,
    charge: Arc<dyn Fn(u64) -> Result<()> + Send + Sync>,
    decode: impl FnOnce(Arc<dyn ReadAt>) -> Result<()> + Send,
) -> Result<Pages<N>> {
    let (maximum_pages, attempts) = limits;
    if N == 0 || pages.len() > maximum_pages || attempts == 0 {
        return Err(Error::new(
            ErrorKind::BudgetExhausted,
            "metadata discovery limits",
        ));
    }
    pages
        .try_reserve_exact(maximum_pages - pages.len())
        .map_err(|_| {
            Error::new(
                ErrorKind::BudgetExhausted,
                "metadata discovery index allocation",
            )
        })?;
    if pages.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "metadata discovery seed ordering",
        ));
    }
    let mut index = HashMap::new();
    index.try_reserve(maximum_pages).map_err(|_| {
        Error::new(
            ErrorKind::BudgetExhausted,
            "metadata discovery lookup allocation",
        )
    })?;
    for (slot, page) in pages.iter().enumerate() {
        index.insert(page.0, slot);
    }
    let initial = pages.len();
    let (requests, receiver) = mpsc::channel();
    let source = Arc::new(Source {
        length,
        pages: Mutex::new(Cache { pages, index }),
        requests: requests.clone(),
        resources: resources.clone(),
        charge: charge.clone(),
    });
    let input = source.clone();
    // The backend never crosses the thread boundary and needs neither Send nor Sync.
    // Requests only copy checked pages; the worker has no mutable storage authority.
    let result = std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("partmgr-metadata".into())
            .spawn_scoped(scope, move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode(input)))
                        .unwrap_or_else(|_| {
                            Err(Error::new(
                                ErrorKind::Io,
                                "metadata discovery decoder panicked",
                            ))
                        });
                let _ = requests.send(Request::Done(result));
            })
            .map_err(|error| Error::io("metadata discovery worker", error))?;
        let mut copied = initial;
        let mut owner_failure: Option<Error> = None;
        let result = loop {
            match receiver.recv() {
                Ok(Request::Done(result)) => break result,
                Ok(Request::Page(number, reply)) => {
                    let page = (|| {
                        if let Some(error) = &owner_failure {
                            return Err(Error::new(error.kind, "metadata discovery owner failed"));
                        }
                        resources.cancellation.check()?;
                        if copied == maximum_pages || copied - initial >= attempts - 1 {
                            return Err(Error::new(
                                ErrorKind::BudgetExhausted,
                                "metadata discovery page/attempt ceiling",
                            ));
                        }
                        let at = number
                            .checked_mul(N as u64)
                            .filter(|at| at.checked_add(N as u64).is_some_and(|end| end <= length))
                            .ok_or_else(|| {
                                Error::new(ErrorKind::InvalidData, "metadata discovery page bounds")
                            })?;
                        if target
                            .len()
                            .map_err(|e| Error::io("metadata discovery geometry", e))?
                            != length
                        {
                            return Err(Error::new(
                                ErrorKind::StalePlan,
                                "metadata discovery source length changed",
                            ));
                        }
                        charge(N as u64)?;
                        let mut page = [0; N];
                        target
                            .read_exact_at(at, &mut page)
                            .map_err(|e| Error::io("metadata discovery copy", e))?;
                        resources.cancellation.check()?;
                        copied += 1;
                        Ok(Arc::new(page))
                    })();
                    // Signal the category to the decoder; retain the original owner error below.
                    let page = match page {
                        Ok(page) => Ok(page),
                        Err(error) => {
                            let kind = error.kind;
                            if owner_failure.is_none() {
                                owner_failure = Some(error);
                            }
                            Err(Error::new(kind, "metadata discovery owner failed"))
                        }
                    };
                    let _ = reply.send(page);
                }
                Err(_) => {
                    break Err(Error::new(
                        ErrorKind::Io,
                        "metadata discovery decoder disconnected",
                    ));
                }
            }
        };
        worker
            .join()
            .map_err(|_| Error::new(ErrorKind::Io, "metadata discovery decoder panicked"))?;
        match owner_failure {
            Some(error) => Err(error),
            None => result,
        }
    });
    result?;
    if target
        .len()
        .map_err(|e| Error::io("metadata discovery final geometry", e))?
        != length
    {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "metadata discovery final source length changed",
        ));
    }
    let source = Arc::try_unwrap(source).map_err(|_| {
        Error::new(
            ErrorKind::InvalidOperation,
            "metadata discovery source escaped decoder",
        )
    })?;
    let mut pages = source
        .pages
        .into_inner()
        .map_err(|_| Error::new(ErrorKind::Io, "metadata discovery cache poisoned"))?
        .pages;
    pages.sort_unstable_by_key(|page| page.0);
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    use std::{cell::Cell, rc::Rc};
    struct Owner {
        calls: Rc<Cell<usize>>,
        fail: bool,
    }
    impl Storage for Owner {
        fn len(&self) -> io::Result<u64> {
            Ok(16)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(io::Error::from_raw_os_error(5));
            }
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = (at + i as u64) as u8;
            }
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("discovery must never write")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("discovery must never flush")
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(4096),
            cancellation: Cancellation::default(),
        }
    }
    #[test]
    fn non_send_owner_copies_each_requested_page_once() {
        let calls = Rc::new(Cell::new(0));
        let owner = Owner {
            calls: calls.clone(),
            fail: false,
        };
        let pages = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 4),
            &resources(),
            Arc::new(|_| Ok(())),
            |source| {
                for at in [0, 1, 4, 8, 2, 9] {
                    let mut byte = [0];
                    source
                        .read_exact_at(at, &mut byte)
                        .map_err(|e| Error::io("test decoder", e))?;
                    assert_eq!(byte[0], at as u8);
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 3);
        assert_eq!(pages.iter().map(|p| p.0).collect::<Vec<_>>(), [0, 1, 2]);
    }
    #[test]
    fn failed_owner_retains_original_os_error_and_attempt_cap_precedes_reads() {
        let calls = Rc::new(Cell::new(0));
        let owner = Owner {
            calls: calls.clone(),
            fail: true,
        };
        let decode = |source: Arc<dyn ReadAt>| {
            source
                .read_exact_at(0, &mut [0])
                .map_err(|e| Error::io("test decoder", e))
        };
        let error = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 4),
            &resources(),
            Arc::new(|_| Ok(())),
            decode,
        )
        .unwrap_err();
        assert_eq!(error.source.unwrap().raw_os_error(), Some(5));
        let error = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 1),
            &resources(),
            Arc::new(|_| Ok(())),
            decode,
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::BudgetExhausted);
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn decoder_panic_terminates_without_waiting_for_a_page() {
        let owner = Owner {
            calls: Rc::new(Cell::new(0)),
            fail: false,
        };
        let error = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 4),
            &resources(),
            Arc::new(|_| Ok(())),
            |_| panic!("decoder failure"),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Io);
    }
    #[test]
    fn pre_cancelled_discovery_reads_no_backend_pages() {
        let calls = Rc::new(Cell::new(0));
        let owner = Owner {
            calls: calls.clone(),
            fail: false,
        };
        let resources = resources();
        resources.cancellation.cancel();
        let error = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 4),
            &resources,
            Arc::new(|_| Ok(())),
            |source| {
                source
                    .read_exact_at(0, &mut [0])
                    .map_err(|e| Error::io("cancelled decoder", e))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled);
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn cancellation_during_owner_read_does_not_publish_copied_page() {
        struct CancellingOwner {
            owner: Owner,
            cancellation: Cancellation,
        }
        impl Storage for CancellingOwner {
            fn len(&self) -> io::Result<u64> {
                self.owner.len()
            }
            fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
                self.owner.read_exact_at(at, out)?;
                self.cancellation.cancel();
                Ok(())
            }
            fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
                panic!("discovery must never write")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("discovery must never flush")
            }
        }
        let calls = Rc::new(Cell::new(0));
        let resources = resources();
        let owner = CancellingOwner {
            owner: Owner {
                calls: calls.clone(),
                fail: false,
            },
            cancellation: resources.cancellation.clone(),
        };
        let error = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 4),
            &resources,
            Arc::new(|_| Ok(())),
            |source| {
                let mut out = [0xa5];
                let failure = source.read_exact_at(0, &mut out).unwrap_err();
                assert_eq!(out, [0xa5]);
                Err(Error::io("cancelled owner reply", failure))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn cached_page_cancellation_preserves_category_without_backend_reread() {
        let calls = Rc::new(Cell::new(0));
        let owner = Owner {
            calls: calls.clone(),
            fail: false,
        };
        let resources = resources();
        let cancellation = resources.cancellation.clone();
        let error = discover::<4>(
            &owner,
            16,
            Vec::new(),
            (4, 4),
            &resources,
            Arc::new(|_| Ok(())),
            move |source| {
                source
                    .read_exact_at(0, &mut [0])
                    .map_err(|e| Error::io("first page", e))?;
                cancellation.cancel();
                let mut out = [0xa5];
                let failure = source.read_exact_at(1, &mut out).unwrap_err();
                assert_eq!(out, [0xa5]);
                Err(Error::io("cancelled cached page", failure))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled);
        assert_eq!(calls.get(), 1);
    }
}
