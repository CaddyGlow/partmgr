//! Independent common-tree source: no filesystem decoder or native image input.
use partmgr::fs_core::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[derive(Default)]
pub struct Controls {
    pub reads: AtomicUsize,
    pub stale: AtomicBool,
    pub fail: AtomicBool,
    pub malformed: AtomicBool,
    pub utf16: AtomicBool,
    pub collision: AtomicBool,
    pub special: AtomicBool,
    pub cycle: AtomicBool,
    pub named: AtomicBool,
    pub directory_named: AtomicBool,
    pub root_named: AtomicBool,
    pub changed_length: AtomicBool,
    pub reverse: AtomicBool,
    pub versions: AtomicBool,
}
pub struct Tree {
    pub files: usize,
    pub controls: Arc<Controls>,
}
impl Tree {
    pub fn new(files: usize) -> Self {
        assert!(files >= 3);
        Self {
            files,
            controls: Arc::new(Controls::default()),
        }
    }
    pub fn id(&self, n: usize) -> ObjectId {
        ObjectId {
            source: 91,
            generation: 7 + if self.controls.versions.load(Ordering::Acquire) {
                n as u64
            } else {
                0
            },
            native: (n as u64).to_le_bytes().to_vec(),
        }
    }
    fn number(&self, id: &ObjectId, r: &Resources) -> Result<usize> {
        self.revalidate(id, r)?;
        Ok(u64::from_le_bytes(id.native.as_slice().try_into().unwrap()) as usize)
    }
}
fn absent() -> Metadata {
    Metadata {
        created: MetadataField::Absent,
        modified: MetadataField::Absent,
        accessed: MetadataField::Absent,
        owner: MetadataField::Absent,
        mode: MetadataField::Absent,
        security: MetadataField::Absent,
        attributes: vec![(
            NativeName::Bytes(b"fixture.opaque".to_vec()),
            MetadataField::Opaque {
                bytes: vec![1, 2, 3],
                interpretation: "test-only uninterpreted source metadata".into(),
            },
        )],
        native_flags: MetadataField::Absent,
        symlink_target: MetadataField::Absent,
        reparse_data: MetadataField::Absent,
    }
}
impl TreeSource for Tree {
    fn root(&self) -> ObjectId {
        self.id(0)
    }
    fn stability(&self) -> SourceStability {
        SourceStability::ChangeDetectionOnly
    }
    fn revalidate(&self, id: &ObjectId, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        if self.controls.stale.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "modeled independent tree generation change",
            ));
        }
        if id.source != 91 || id.native.len() != 8 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "foreign test tree identity",
            ));
        }
        let n = u64::from_le_bytes(id.native.as_slice().try_into().unwrap());
        if id.generation
            != 7 + if self.controls.versions.load(Ordering::Acquire) {
                n
            } else {
                0
            }
        {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "test tree object generation mismatch",
            ));
        }
        if n > self.files as u64 + 2 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "test tree identity bounds",
            ));
        }
        Ok(())
    }
    fn metadata(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(id, r)?;
        Budgeted::try_new(&r.memory, 1024, || Ok(absent()))
    }
    fn directory_page(
        &self,
        id: &ObjectId,
        continuation: Option<&[u8]>,
        maximum: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        let n = self.number(id, r)?;
        let total = if n == 0 {
            self.files + 1
        } else if n == self.files + 1 {
            2
        } else {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "test tree not directory",
            ));
        };
        let start = continuation.map_or(Ok(0), |t| {
            let b: [u8; 8] = t
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "test tree cursor"))?;
            usize::try_from(u64::from_le_bytes(b))
                .map_err(|_| Error::new(ErrorKind::InvalidData, "test tree cursor bounds"))
        })?;
        if start > total || maximum == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "test tree page bounds",
            ));
        }
        let count = maximum.min(total - start);
        let reservation = r.memory.reserve(count as u64 * 1024 + 128)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| Error::new(ErrorKind::BudgetExhausted, "test tree page allocation"))?;
        for i in start..start + count {
            let i = if self.controls.reverse.load(Ordering::Acquire) {
                total - 1 - i
            } else {
                i
            };
            let (name, child, kind) = if n == 0 {
                if i == self.files {
                    (b"Box".to_vec(), self.files + 1, ObjectKind::Directory)
                } else {
                    let child = i + 1;
                    let name = match child {
                        1 => b"A\xc3\xa9-file".to_vec(),
                        2 => b"Empty".to_vec(),
                        3 => b"Clone".to_vec(),
                        _ => format!("File-{child:04}").into_bytes(),
                    };
                    (name, child, ObjectKind::File)
                }
            } else if i == 0 {
                (b"Alias".to_vec(), 1, ObjectKind::File)
            } else {
                (b"Child".to_vec(), self.files + 2, ObjectKind::File)
            };
            let name = if n == 0 && i == 1 && self.controls.collision.load(Ordering::Acquire) {
                b"A\xc3\xa9-file".to_vec()
            } else {
                name
            };
            let native = if n == 0 && i == 0 && self.controls.utf16.load(Ordering::Acquire) {
                NativeName::Utf16("Aé-file".encode_utf16().collect())
            } else {
                NativeName::Bytes(name)
            };
            entries.push(DirectoryEntry {
                name: native,
                object: if kind == ObjectKind::Directory
                    && self.controls.cycle.load(Ordering::Acquire)
                {
                    self.root()
                } else {
                    self.id(child)
                },
                kind: if n == 0 && i == 0 && self.controls.special.load(Ordering::Acquire) {
                    ObjectKind::Special
                } else {
                    kind
                },
            });
        }
        Ok(DirectoryPage {
            entries,
            next: if start + count < total {
                Some(((start + count) as u64).to_le_bytes().to_vec())
            } else {
                None
            },
            reservation,
        })
    }
    fn streams(&self, id: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        let n = self.number(id, r)?;
        Budgeted::try_new(&r.memory, 1024, || {
            if n == 0 || n == self.files + 1 {
                return Ok(
                    if (n == 0 && self.controls.root_named.load(Ordering::Acquire))
                        || (n != 0 && self.controls.directory_named.load(Ordering::Acquire))
                    {
                        vec![StreamInfo {
                            kind: StreamKind::Named(NativeName::Bytes(
                                "user/directory.é".as_bytes().to_vec(),
                            )),
                            length: 7001,
                        }]
                    } else {
                        Vec::new()
                    },
                );
            }
            let length = if n == 1 || n == 3 {
                16397
            } else if n == 2 {
                0
            } else if n == self.files + 2 {
                7
            } else {
                1
            };
            let mut s = vec![StreamInfo {
                kind: StreamKind::Data,
                length,
            }];
            if self.controls.named.load(Ordering::Acquire) {
                s.push(StreamInfo {
                    kind: StreamKind::Named(NativeName::Bytes(b"alternate".to_vec())),
                    length: 1,
                });
            }
            if n == 1 || n == 3 {
                s.push(StreamInfo {
                    kind: StreamKind::ResourceFork,
                    length: 8,
                });
            }
            Ok(s)
        })
    }
    fn open_stream(
        &self,
        id: &ObjectId,
        kind: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        let streams = self.streams(id, r)?;
        let length = streams
            .iter()
            .find(|s| s.kind == *kind)
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "test stream absent"))?
            .length;
        let lease = r.memory.reserve(512)?;
        Ok(Arc::new(File {
            identity: id.clone(),
            length,
            fork: *kind == StreamKind::ResourceFork,
            named: matches!(kind, StreamKind::Named(_)),
            controls: self.controls.clone(),
            resources: r.clone(),
            _lease: lease,
        }))
    }
}
struct File {
    identity: ObjectId,
    length: u64,
    fork: bool,
    named: bool,
    controls: Arc<Controls>,
    resources: Resources,
    _lease: Reservation,
}
impl FileRead for File {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.length + u64::from(self.controls.changed_length.load(Ordering::Acquire))
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.controls.fail.load(Ordering::Acquire) {
            return Err(Error::io(
                "modeled independent payload failure",
                partmgr::io::Error::other("fixture read cause"),
            ));
        }
        self.controls.reads.fetch_add(1, Ordering::Relaxed);
        let n = (self.length.saturating_sub(at)).min(out.len() as u64) as usize;
        for (i, b) in out[..n].iter_mut().enumerate() {
            let p = at + i as u64;
            *b = if self.fork {
                b"resource"[p as usize]
            } else if self.named {
                ((p * 13 + 7) % 251) as u8
            } else if self.length == 7 {
                b"nested!"[p as usize]
            } else if (4096..8192).contains(&p) || (12288..16384).contains(&p) {
                0
            } else {
                (p % 4096 * 17 % 251) as u8
            };
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visit: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.resources.cancellation.check()?;
        r.cancellation.check()?;
        if self.length == 0 {
            return Ok(());
        }
        if self.controls.malformed.load(Ordering::Acquire) {
            return visit(LogicalExtent {
                offset: 1,
                length: self.length,
                kind: ExtentKind::Data,
            });
        }
        if self.length == 16397 && !self.fork && !self.named {
            for (offset, length, kind) in [
                (0, 4096, ExtentKind::Data),
                (4096, 4096, ExtentKind::Hole),
                (8192, 4096, ExtentKind::Data),
                (12288, 4096, ExtentKind::Hole),
                (16384, 13, ExtentKind::Data),
            ] {
                visit(LogicalExtent {
                    offset,
                    length,
                    kind,
                })?;
            }
            Ok(())
        } else {
            visit(LogicalExtent {
                offset: 0,
                length: self.length,
                kind: ExtentKind::Data,
            })
        }
    }
}
