//! Private empty-object birth preparation with explicit native metadata.
use super::super::super::metadata_builder::{self, CatalogMetadata};
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
#[derive(Clone, Copy)]
pub(crate) struct CreateRequest<'a> {
    pub(crate) parent: &'a [NativeName],
    pub(crate) name: &'a [u16],
    pub(crate) directory: bool,
    pub(crate) metadata: Option<&'a CatalogMetadata>,
}
impl<S: Storage> Prepared<S> {
    pub(crate) fn commit_create_entry(
        self,
        request: CreateRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        undo: UndoLimits,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, RenameFailure<S>> {
        let plan = self.plan_create_entry(request, r);
        self.commit_catalog_plan(plan, journal, binding, undo, r)
    }

    fn plan_create_entry(&self, request: CreateRequest<'_>, r: &Resources) -> Result<RenamePlan> {
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "HFS+ creation requires recovery",
            ));
        }
        let CreateRequest {
            parent,
            name,
            directory,
            metadata,
        } = request;
        if name.is_empty() || name.len() > 127 || name.iter().any(|&u| u == 0 || u == 47) {
            return Err(bad("HFS+ creation native name bounds"));
        }
        self.revalidate(r)?;
        let parent_id = self.volume.lookup(parent, r)?;
        self.volume.verify_catalog_record(&parent_id, r)?;
        let folder = self.volume.node(&parent_id)?;
        if !folder.directory {
            return Err(bad("HFS+ creation parent not a directory"));
        }
        let cnid = native::be32(self.volume.header(), 64);
        if cnid < 16 || cnid == u32::MAX {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "HFS+ creation CNID exhaustion/reuse",
            ));
        }
        for &id in self.volume.inner.nodes.keys() {
            r.cancellation.check()?;
            self.snapshot.work.charge(1)?;
            if id >= cnid {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HFS+ creation CNID exhaustion/reuse",
                ));
            }
        }
        let g = self.volume.geometry();
        let fork = &self.volume.inner.system[2];
        if fork.length > self.range_bytes {
            return Err(budget("HFS+ creation catalog ceiling"));
        }
        let lease = r.memory.reserve(
            fork.length
                .checked_mul(6)
                .and_then(|n| n.checked_add(self.limits.read.records as u64 * 2048))
                .ok_or_else(|| budget("HFS+ creation charge"))?,
        )?;
        let map = native::map(self.snapshot.clone(), fork, g, self.limits.read.extents)?;
        let mut work = native::Work {
            limits: self.limits.read,
            work: 0,
            nodes: 0,
            records: 0,
            extents: 0,
        };
        let tree = native::tree(
            &map,
            0,
            native::be16(self.volume.header(), 0) == 0x4858,
            &mut work,
            r,
        )?;
        let mut records = vector(
            tree.records
                .len()
                .checked_add(2)
                .ok_or_else(|| budget("HFS+ creation record count"))?,
        )?;
        let mut parents = 0;
        for record in tree.records {
            r.cancellation.check()?;
            self.snapshot
                .work
                .charge((record.key.len() + record.data.len() + 520) as u64)?;
            let mut bytes = vector(record.key.len() + record.data.len() + 2)?;
            bytes.extend_from_slice(&(record.key.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&record.key);
            bytes.extend_from_slice(&record.data);
            if native::be16(&record.data, 0) == 1 && native::be32(&record.data, 8) == folder.id {
                parents += 1;
                let offset = 2 + record.key.len();
                for field in [4, 84] {
                    if field == 84 && (!directory || native::be16(&record.data, 2) & 0x10 == 0) {
                        continue;
                    }
                    let value = native::be32(&record.data, field)
                        .checked_add(1)
                        .ok_or_else(|| bad("HFS+ creation parent count overflow"))?;
                    bytes[offset + field..offset + field + 4].copy_from_slice(&value.to_be_bytes());
                }
            }
            records.push((native::key(&record.key, 0, g.binary)?, bytes));
        }
        if parents != 1 {
            return Err(bad("HFS+ creation parent provenance"));
        }
        let mut body = vector(if directory { 88 } else { 248 })?;
        body.resize(if directory { 88 } else { 248 }, 0);
        body[..2].copy_from_slice(&(if directory { 1u16 } else { 2u16 }).to_be_bytes());
        body[2..4].copy_from_slice(
            &(if directory {
                if g.binary { 16u16 } else { 0u16 }
            } else {
                2u16
            })
            .to_be_bytes(),
        );
        body[8..12].copy_from_slice(&cnid.to_be_bytes());
        metadata_builder::apply(&mut body, directory, metadata)?;
        let (mut object, _key_lease) =
            super::super::super::catalog_key(folder.id, name, g.binary, r)?;
        object
            .try_reserve_exact(body.len())
            .map_err(|_| budget("HFS+ creation object allocation"))?;
        object.extend_from_slice(&body);
        let end = 2 + usize::from(native::be16(&object, 0));
        records.push((native::key(&object[2..end], 0, g.binary)?, object));
        let (mut thread, _thread_lease) = super::super::super::catalog_key(cnid, &[], g.binary, r)?;
        thread
            .try_reserve_exact(10 + name.len() * 2)
            .map_err(|_| budget("HFS+ creation thread allocation"))?;
        thread.extend_from_slice(&(if directory { 3u16 } else { 4u16 }).to_be_bytes());
        thread.extend_from_slice(&[0; 2]);
        thread.extend_from_slice(&folder.id.to_be_bytes());
        thread.extend_from_slice(&(name.len() as u16).to_be_bytes());
        for u in name {
            thread.extend_from_slice(&u.to_be_bytes());
        }
        let end = 2 + usize::from(native::be16(&thread, 0));
        records.push((native::key(&thread[2..end], 0, g.binary)?, thread));
        let mut patches = self.stage_catalog_records(records, r)?;
        let count_field = if directory { 36usize } else { 32usize };
        let count = native::be32(self.volume.header(), count_field)
            .checked_add(1)
            .ok_or_else(|| bad("HFS+ creation volume count overflow"))?;
        for (field, new) in [(count_field, count), (64, cnid + 1)] {
            let old = native::be32(self.volume.header(), field);
            for base in [1024, self.snapshot.length - 1024] {
                r.cancellation.check()?;
                self.snapshot.work.charge(4)?;
                let mut before = vector(4)?;
                before.resize(4, 0);
                self.target
                    .read_exact_at(base + field as u64, &mut before)
                    .map_err(|e| Error::io("HFS+ creation mirrored header", e))?;
                if before != old.to_be_bytes() {
                    return Err(bad("HFS+ creation mirrored field mismatch"));
                }
                let mut after = vector(4)?;
                after.extend_from_slice(&new.to_be_bytes());
                patches.push(
                    WriteRange::new(base + field as u64, before, after)
                        .map_err(|e| Error::io("HFS+ creation header patch", e))?,
                );
            }
        }
        let proof = Prepared::open(
            Projected {
                target: &self.target,
                patches: &patches,
                before: false,
            },
            self.limits,
            r,
        )?;
        let mut path = vector(parent.len() + 1)?;
        for component in parent {
            let NativeName::Utf16(units) = component else {
                return Err(bad("HFS+ creation native parent path"));
            };
            let mut copy = vector(units.len())?;
            copy.extend_from_slice(units);
            path.push(NativeName::Utf16(copy));
        }
        let mut copy = vector(name.len())?;
        copy.extend_from_slice(name);
        path.push(NativeName::Utf16(copy));
        let id = proof.volume.lookup(&path, r)?;
        let born = proof.volume.node(&id)?;
        if born.id != cnid || born.directory != directory || born.raw != body {
            return Err(bad("HFS+ creation projected object disagreement"));
        }
        drop(proof);
        self.revalidate(r)?;
        Ok(RenamePlan {
            patches,
            _lease: lease,
        })
    }
}
pub(crate) fn recover_create_entry(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: CreateRequest<'_>,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    let proof = (|| -> Result<_> {
        let length = target
            .len()
            .map_err(|e| Error::io("HFS+ cold creation length", e))?;
        let lease = r.memory.reserve(
            undo.body_bytes
                .checked_mul(3)
                .and_then(|n| n.checked_add(undo.patches as u64 * 256))
                .ok_or_else(|| budget("HFS+ cold creation charge"))?,
        )?;
        let mut saved = Collector {
            patches: vector(undo.patches as usize)?,
        };
        let status = fs_undo::validate_recovery(journal, length, binding, undo, r, &mut saved)?;
        let original = Prepared::open(
            Projected {
                target,
                patches: &saved.patches,
                before: true,
            },
            limits,
            r,
        )?;
        if status.state == UndoState::Empty {
            drop(original);
            return Ok((status, None, lease));
        }
        let rename = original.plan_create_entry(request, r)?;
        let mut expected = framed(rename.patches, original.volume.header()[6], length)?;
        expected.sort_unstable_by_key(WriteRange::offset);
        if expected.len() != saved.patches.len()
            || expected.iter().zip(&saved.patches).any(|(a, b)| {
                a.offset() != b.offset()
                    || a.expected() != b.expected()
                    || a.replacement() != b.replacement()
            })
        {
            return Err(bad("HFS+ cold creation operation mismatch"));
        }
        drop(original);
        Ok((status, Some(expected), lease))
    })();
    let (status, expected, _lease) =
        proof.map_err(|e| fail(e, "HFS+ cold creation proof", true))?;
    match expected {
        None => Ok(status),
        Some(expected) => super::transaction::recovery::recover_patches(
            target, journal, binding, limits, undo, r, &expected,
        ),
    }
}

#[cfg(feature = "std")]
#[test]
fn typed_empty_file_directory_creation_preparation_no_writes() {
    use super::super::transaction::recovery::cuts::{Clock, Model};
    use crate::platform::sync::{Arc, Mutex};
    for binary in [false, true] {
        for directory in [false, true] {
            let r = Resources {
                memory: Budget::new(16 << 20),
                cancellation: Cancellation::default(),
            };
            let limits = Limits {
                pages: 256,
                attempts: 257,
                work: 1 << 36,
                range_bytes: 1 << 20,
                read: HfsPlusReadLimits {
                    blocks: 256,
                    nodes: 32,
                    records: 32,
                    extents: 64,
                    work: 1 << 20,
                },
                audit: HfsPlusAuditLimits {
                    blocks: 256,
                    objects: 16,
                    depth: 8,
                    findings: 16,
                    work: 1 << 20,
                },
            };
            let original = super::super::super::independent::hfsplus_seed(binary);
            let prepared = Prepared::open(
                Model::new(original.clone(), Arc::new(Mutex::new(Clock::default()))),
                limits,
                &r,
            )
            .unwrap();
            let parent = [NativeName::Utf16("Dir".encode_utf16().collect())];
            let name: Vec<u16> = "Born".encode_utf16().collect();
            let metadata = CatalogMetadata {
                uid: 123,
                gid: 456,
                permissions: 0o750,
                created: 17,
                modified: 19,
                attributes_modified: 23,
                accessed: 29,
                backup: 31,
            };
            let plan = prepared
                .plan_create_entry(
                    CreateRequest {
                        parent: &parent,
                        name: &name,
                        directory,
                        metadata: Some(&metadata),
                    },
                    &r,
                )
                .unwrap();
            let proof = Prepared::open(
                Projected {
                    target: &prepared.target,
                    patches: &plan.patches,
                    before: false,
                },
                limits,
                &r,
            )
            .unwrap();
            let path = [parent[0].clone(), NativeName::Utf16(name)];
            let id = proof.volume.lookup(&path, &r).unwrap();
            let born = proof.volume.node(&id).unwrap();
            assert_eq!(born.id, 19);
            assert_eq!(native::be32(&born.raw, 32), 123);
            assert_eq!(native::be32(&born.raw, 36), 456);
            assert_eq!(native::be16(&born.raw, 42) & 0o7777, 0o750);
            assert_eq!(native::be32(proof.volume.header(), 64), 20);
            assert_eq!(
                proof.volume.geometry().free,
                prepared.volume.geometry().free
            );

            if !directory {
                for kind in [StreamKind::Data, StreamKind::ResourceFork] {
                    let bytes = b"atomic birth payload";
                    let (payload, metadata) =
                        proof.stage_birth_fork(&path, &kind, bytes, &r).unwrap();
                    let payload_view = Projected {
                        target: &proof.target,
                        patches: &payload.patches,
                        before: false,
                    };
                    let final_view = Projected {
                        target: &payload_view,
                        patches: &metadata.patches,
                        before: false,
                    };
                    let populated = Prepared::open(final_view, limits, &r).unwrap();
                    let id = populated.volume.lookup(&path, &r).unwrap();
                    let node = populated.volume.node(&id).unwrap();
                    let index = usize::from(kind == StreamKind::ResourceFork);
                    assert_eq!(node.forks[index].length, bytes.len() as u64);
                    assert_eq!(node.forks[1 - index].length, 0);
                    let at = u64::from(node.forks[index].extents[0].start)
                        * u64::from(populated.volume.geometry().block_size());
                    let mut actual = vec![0; bytes.len()];
                    populated.target.read_exact_at(at, &mut actual).unwrap();
                    assert_eq!(actual, bytes);
                    drop(populated);
                }
            }
            drop(proof);
            drop(plan);
            if !directory {
                let populated = prepared
                    .plan_populated_birth(
                        CreateRequest {
                            parent: &parent,
                            name: &"Born".encode_utf16().collect::<Vec<_>>(),
                            directory: false,
                            metadata: Some(&metadata),
                        },
                        b"born DATA",
                        b"born RESOURCE",
                        &r,
                    )
                    .unwrap();
                assert!(!populated.patches.is_empty());
                drop(populated);
            }

            assert!(
                prepared
                    .plan_create_entry(
                        CreateRequest {
                            parent: &parent,
                            name: &"child".encode_utf16().collect::<Vec<_>>(),
                            directory,
                            metadata: None
                        },
                        &r
                    )
                    .is_err()
            );
            for invalid in [vec![], vec![0], vec![47], vec![65; 128]] {
                assert!(
                    prepared
                        .plan_create_entry(
                            CreateRequest {
                                parent: &parent,
                                name: &invalid,
                                directory,
                                metadata: None,
                            },
                            &r,
                        )
                        .is_err()
                );
            }
            let file_parent = [
                parent[0].clone(),
                NativeName::Utf16("child".encode_utf16().collect()),
            ];
            assert!(
                prepared
                    .plan_create_entry(
                        CreateRequest {
                            parent: &file_parent,
                            name: &"Born".encode_utf16().collect::<Vec<_>>(),
                            directory,
                            metadata: None,
                        },
                        &r,
                    )
                    .is_err()
            );
            assert_eq!(prepared.target.bytes, original);
            assert_eq!(prepared.target.writes, 0);
            let mut journal = Model::new(vec![0; 1 << 20], Arc::new(Mutex::new(Clock::default())));
            let committed = commit_public_create(
                prepared,
                CreateRequest {
                    parent: &parent,
                    name: &"Born".encode_utf16().collect::<Vec<_>>(),
                    directory,
                    metadata: Some(&metadata),
                },
                &mut journal,
                UndoBinding {
                    volume: [0x55; 32],
                    generation: 1,
                    transaction: [0x77; 16],
                },
                UndoLimits {
                    patches: 64,
                    body_bytes: 1 << 19,
                },
                &r,
            )
            .unwrap_or_else(|failure| panic!("{}", failure.error.source));
            let path = [
                parent[0].clone(),
                NativeName::Utf16("Born".encode_utf16().collect()),
            ];
            let id = committed.volume.lookup(&path, &r).unwrap();
            assert_eq!(committed.volume.node(&id).unwrap().id, 19);
            assert!(committed.target.writes > 0);
            let Prepared {
                mut target,
                snapshot,
                volume,
                proof,
                ..
            } = committed;
            drop((snapshot, volume, proof));
            let binding = UndoBinding {
                volume: [0x55; 32],
                generation: 1,
                transaction: [0x77; 16],
            };
            let undo = UndoLimits {
                patches: 64,
                body_bytes: 1 << 19,
            };
            let writes = (target.writes, journal.writes);
            assert!(
                recover_public_create(
                    &mut target,
                    &mut journal,
                    CreateRequest {
                        parent: &parent,
                        name: &"Other".encode_utf16().collect::<Vec<_>>(),
                        directory,
                        metadata: Some(&metadata),
                    },
                    binding,
                    limits,
                    undo,
                    &r,
                )
                .is_err()
            );
            assert_eq!((target.writes, journal.writes), writes);
            let status = recover_public_create(
                &mut target,
                &mut journal,
                CreateRequest {
                    parent: &parent,
                    name: &"Born".encode_utf16().collect::<Vec<_>>(),
                    directory,
                    metadata: Some(&metadata),
                },
                binding,
                limits,
                undo,
                &r,
            )
            .unwrap();
            assert_eq!(status.state, UndoState::Committed);
            assert_eq!((target.writes, journal.writes), writes);
            drop(target);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn every_creation_commit_cut_cold_recovers_exact_image() {
    creation_commit_cuts(None, false);
}
#[cfg(all(test, feature = "std"))]
fn creation_commit_cuts(native: Option<&CreationNativeCuts>, populated: bool) {
    use super::super::transaction::recovery::cuts::{Clock, Model};
    use crate::platform::sync::{Arc, Mutex};
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    let undo = UndoLimits {
        patches: 64,
        body_bytes: 1 << 19,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x77; 16],
    };
    let data = vec![0x5a; 10003];
    let resource = vec![0xa5; 5007];
    for binary in [false, true] {
        for &directory in if populated {
            &[false][..]
        } else {
            &[false, true][..]
        } {
            let original = native.map_or_else(
                || super::super::super::independent::hfsplus_seed(binary),
                |gate| gate.source(binary),
            );
            let parent = [NativeName::Utf16(
                (if native.is_some() { "DIR" } else { "Dir" })
                    .encode_utf16()
                    .collect(),
            )];
            let name: Vec<u16> = "Born".encode_utf16().collect();
            let request = || CreateRequest {
                parent: &parent,
                name: &name,
                directory,
                metadata: None,
            };
            let run = |cut, keep_target, keep_journal, expected: Option<&Vec<u8>>| {
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let clock = Arc::new(Mutex::new(Clock {
                    events: 0,
                    fail: cut,
                }));
                let prepared =
                    Prepared::open(Model::new(original.clone(), clock.clone()), limits, &r)
                        .unwrap();
                let mut journal = Model::new(vec![0; 1 << 20], clock.clone());
                let mut target = match commit_creation_case(
                    prepared,
                    (
                        request(),
                        populated.then_some((data.as_slice(), resource.as_slice())),
                    ),
                    &mut journal,
                    binding,
                    undo,
                    &r,
                ) {
                    Ok(ready) => {
                        assert!(cut.is_none());
                        ready.into_storage()
                    }
                    Err(failure) => {
                        assert!(cut.is_some());
                        failure.target
                    }
                };
                let events = clock.lock().unwrap().events;
                let committed = target.bytes.clone();
                target.crash(keep_target);
                journal.crash(keep_journal);
                clock.lock().unwrap().fail = None;
                let before = (target.writes, journal.writes);
                match recover_creation_case(
                    &mut target,
                    &mut journal,
                    (
                        request(),
                        populated.then_some((data.as_slice(), resource.as_slice())),
                    ),
                    binding,
                    limits,
                    undo,
                    &r,
                ) {
                    Ok(status) if status.state == UndoState::Committed => {
                        assert_eq!(&target.bytes, expected.unwrap_or(&committed))
                    }
                    Ok(_) => assert_eq!(target.bytes, original),
                    Err(failure) => {
                        assert_eq!(failure.source.kind, ErrorKind::InvalidData);
                        assert_eq!(target.bytes, original);
                        assert_eq!((target.writes, journal.writes), before);
                    }
                }
                let proof =
                    Prepared::open(Model::new(target.bytes.clone(), clock), limits, &r).unwrap();
                drop(proof);
                if let Some(gate) = native {
                    gate.check(binary, directory, &target.bytes);
                }
                assert_eq!(r.memory.used(), 0);
                (events, committed)
            };
            let (events, expected) = run(None, false, false, None);
            for keep_target in [false, true] {
                for keep_journal in [false, true] {
                    for cut in 1..=events {
                        run(Some(cut), keep_target, keep_journal, Some(&expected));
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn every_creation_rollback_cut_second_restart_restores_original() {
    creation_rollback_cuts(None, false);
}
#[cfg(all(test, feature = "std"))]
fn creation_rollback_cuts(native: Option<&CreationNativeCuts>, populated: bool) {
    use super::super::transaction::recovery::cuts::{Clock, Model};
    use crate::platform::sync::{Arc, Mutex};
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    let undo = UndoLimits {
        patches: 64,
        body_bytes: 1 << 19,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x77; 16],
    };

    let data = vec![0x5a; 10003];
    let resource = vec![0xa5; 5007];
    for binary in [false, true] {
        for &directory in if populated {
            &[false][..]
        } else {
            &[false, true][..]
        } {
            let original = native.map_or_else(
                || super::super::super::independent::hfsplus_seed(binary),
                |gate| gate.source(binary),
            );
            let parent = [NativeName::Utf16(
                (if native.is_some() { "DIR" } else { "Dir" })
                    .encode_utf16()
                    .collect(),
            )];
            let name: Vec<u16> = "Born".encode_utf16().collect();
            let request = || CreateRequest {
                parent: &parent,
                name: &name,
                directory,
                metadata: None,
            };
            let r = Resources {
                memory: Budget::new(16 << 20),
                cancellation: Cancellation::default(),
            };
            let clock = Arc::new(Mutex::new(Clock::default()));
            let mut target = Model::new(original.clone(), clock.clone());
            target.stop_at = Some(
                u64::from(u32::from_be_bytes(original[1312..1316].try_into().unwrap()))
                    * u64::from(u32::from_be_bytes(original[1064..1068].try_into().unwrap())),
            );
            let mut prepared = Prepared::open(target, limits, &r).unwrap();
            if populated {
                let plan = prepared
                    .plan_populated_birth(request(), &data, &resource, &r)
                    .unwrap();
                prepared.target.stop_at = Some(plan.patches[0].offset());
            }
            let mut journal = Model::new(vec![0; 1 << 20], clock.clone());
            let failed = match commit_creation_case(
                prepared,
                (
                    request(),
                    populated.then_some((data.as_slice(), resource.as_slice())),
                ),
                &mut journal,
                binding,
                undo,
                &r,
            ) {
                Ok(_) => panic!("catalog interruption missed"),
                Err(failure) => failure,
            };
            assert!(failed.error.recovery_required);
            let stopped = failed.target.bytes.clone();
            let saved = journal.bytes.clone();
            drop((failed, journal));
            assert_eq!(r.memory.used(), 0);
            let run = |cut, keep_target, keep_journal| {
                *clock.lock().unwrap() = Clock {
                    events: 0,
                    fail: cut,
                };
                let mut target = Model::new(stopped.clone(), clock.clone());
                let mut journal = Model::new(saved.clone(), clock.clone());
                let result = recover_creation_case(
                    &mut target,
                    &mut journal,
                    (
                        request(),
                        populated.then_some((data.as_slice(), resource.as_slice())),
                    ),
                    binding,
                    limits,
                    undo,
                    &r,
                );
                let events = clock.lock().unwrap().events;
                if cut.is_some() {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap().state, UndoState::RolledBack);
                }
                target.crash(keep_target);
                journal.crash(keep_journal);
                clock.lock().unwrap().fail = None;
                assert_eq!(
                    recover_creation_case(
                        &mut target,
                        &mut journal,
                        (
                            request(),
                            populated.then_some((data.as_slice(), resource.as_slice()))
                        ),
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .unwrap()
                    .state,
                    UndoState::RolledBack
                );
                assert_eq!(target.bytes, original);
                assert_eq!(target.durable, original);
                if let Some(gate) = native {
                    gate.check(binary, directory, &target.bytes);
                }
                let before = (target.writes, journal.writes);
                assert_eq!(
                    recover_creation_case(
                        &mut target,
                        &mut journal,
                        (
                            request(),
                            populated.then_some((data.as_slice(), resource.as_slice()))
                        ),
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .unwrap()
                    .state,
                    UndoState::RolledBack
                );
                assert_eq!((target.writes, journal.writes), before);
                assert_eq!(r.memory.used(), 0);
                events
            };
            let events = run(None, false, false);
            for keep_target in [false, true] {
                for keep_journal in [false, true] {
                    for cut in 1..=events {
                        run(Some(cut), keep_target, keep_journal);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native empty-object creation gate"]
fn native_empty_object_creation_namespace() {
    use super::super::transaction::recovery::cuts::{Clock, Model};
    use crate::platform::{
        fs,
        path::PathBuf,
        process::Command,
        sync::{Arc, Mutex},
    };
    let output = PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_CREATE_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    fs::create_dir(&output).unwrap();
    let checker =
        "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus";
    let fls = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/fls";
    let icat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/icat";
    let istat = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin/istat";
    let extract = |image: &crate::platform::path::Path| {
        let result = Command::new(icat)
            .args(["-f", "hfs"])
            .arg(image)
            .arg("17")
            .output()
            .unwrap();
        assert!(result.status.success());
        result.stdout
    };
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    let undo = UndoLimits {
        patches: 64,
        body_bytes: 1 << 19,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x77; 16],
    };

    for binary in [false, true] {
        let family = if binary { "hfsx" } else { "hfsplus" };
        let source = PathBuf::from(format!(
            "/data/cache/partmgr-hfsplus-public-builder-native-v2/{family}-source.img"
        ));
        let original = fs::read(&source).unwrap();
        let payload = extract(&source);
        assert!(!payload.is_empty());
        let born_id = native::be32(&original[1024..1536], 64);

        let source_check = Command::new(checker)
            .arg("-fn")
            .arg(&source)
            .output()
            .unwrap();
        assert!(source_check.status.success(), "{source_check:?}");
        fs::write(
            output.join(format!("{family}-source-fsck.stdout")),
            source_check.stdout,
        )
        .unwrap();
        for directory in [false, true] {
            for interrupted in [false, true] {
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let clock = Arc::new(Mutex::new(Clock::default()));
                let mut storage = Model::new(original.clone(), clock.clone());
                if interrupted {
                    storage.stop_at = Some(
                        u64::from(u32::from_be_bytes(original[1312..1316].try_into().unwrap()))
                            * u64::from(u32::from_be_bytes(
                                original[1064..1068].try_into().unwrap(),
                            )),
                    );
                }
                let prepared = Prepared::open(storage, limits, &r).unwrap();
                let parent = [NativeName::Utf16("DIR".encode_utf16().collect())];
                let name: Vec<u16> = "Born".encode_utf16().collect();
                let mut journal = Model::new(vec![0; 1 << 20], clock);
                let result = commit_public_create(
                    prepared,
                    CreateRequest {
                        parent: &parent,
                        name: &name,
                        directory,
                        metadata: None,
                    },
                    &mut journal,
                    binding,
                    undo,
                    &r,
                );
                let mut target = match result {
                    Ok(ready) => {
                        assert!(!interrupted);
                        ready.into_storage()
                    }
                    Err(failure) => {
                        assert!(interrupted);
                        failure.target
                    }
                };
                if interrupted {
                    target.stop_at = None;
                    assert_eq!(
                        recover_public_create(
                            &mut target,
                            &mut journal,
                            CreateRequest {
                                parent: &parent,
                                name: &name,
                                directory,
                                metadata: None,
                            },
                            binding,
                            limits,
                            undo,
                            &r
                        )
                        .unwrap()
                        .state,
                        UndoState::RolledBack
                    );
                    assert_eq!(target.bytes, original);
                }
                let stem = format!(
                    "{family}-{}-{interrupted}",
                    if directory { "directory" } else { "file" }
                );
                let image = output.join(format!("{stem}.img"));
                fs::write(&image, &target.bytes).unwrap();
                let check = Command::new(checker)
                    .arg("-fn")
                    .arg(&image)
                    .output()
                    .unwrap();
                fs::write(output.join(format!("{stem}-fsck.stdout")), &check.stdout).unwrap();
                fs::write(output.join(format!("{stem}-fsck.stderr")), &check.stderr).unwrap();
                assert!(check.status.success(), "{stem}: {check:?}");
                assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
                let listing = Command::new(fls)
                    .args(["-f", "hfs", "-r", "-p"])
                    .arg(&image)
                    .output()
                    .unwrap();
                fs::write(output.join(format!("{stem}-fls.stdout")), &listing.stdout).unwrap();
                assert!(listing.status.success());
                assert_eq!(
                    String::from_utf8_lossy(&listing.stdout).contains("DIR/Born"),
                    !interrupted
                );
                let actual_payload = extract(&image);
                assert_eq!(actual_payload, payload);
                fs::write(
                    output.join(format!("{stem}-child-data.stdout")),
                    actual_payload,
                )
                .unwrap();
                if !interrupted && !directory {
                    let inode = Command::new(istat)
                        .args(["-f", "hfs"])
                        .arg(&image)
                        .arg(born_id.to_string())
                        .output()
                        .unwrap();
                    fs::write(output.join(format!("{stem}-istat.stdout")), &inode.stdout).unwrap();
                    assert!(inode.status.success());
                    let text = String::from_utf8_lossy(&inode.stdout);
                    assert!(text.contains("Data Fork"));
                    assert!(text.contains("Resource fork size:\t0"));
                    let empty = Command::new(icat)
                        .args(["-f", "hfs"])
                        .arg(&image)
                        .arg(born_id.to_string())
                        .output()
                        .unwrap();
                    assert!(empty.status.success());
                    assert!(empty.stdout.is_empty());
                }
                assert_eq!(fs::read(&image).unwrap(), target.bytes);
                assert_eq!(fs::read(&source).unwrap(), original);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
struct CreationNativeCuts {
    populated: bool,
    output: crate::platform::path::PathBuf,
    count: crate::platform::cell::Cell<usize>,
}
#[cfg(all(test, feature = "std"))]
impl CreationNativeCuts {
    fn source(&self, binary: bool) -> Vec<u8> {
        crate::platform::fs::read(format!(
            "/data/cache/partmgr-hfsplus-public-builder-native-v2/{}-source.img",
            if binary { "hfsx" } else { "hfsplus" }
        ))
        .unwrap()
    }
    fn check(&self, binary: bool, directory: bool, bytes: &[u8]) {
        use crate::platform::{fs, process::Command};
        let n = self.count.get();
        self.count.set(n + 1);
        let stem = format!("{n}-{binary}-{directory}");
        let image = self.output.join(format!("{stem}.img"));
        fs::write(&image, bytes).unwrap();
        let check = Command::new(
            "/nix/store/kvh9g90h1506i4q3ah4mf7v23f5agvr8-hfsprogs-627.40.1-linux/bin/fsck.hfsplus",
        )
        .arg("-fn")
        .arg(&image)
        .output()
        .unwrap();
        fs::write(
            self.output.join(format!("{stem}-fsck.stdout")),
            &check.stdout,
        )
        .unwrap();
        fs::write(
            self.output.join(format!("{stem}-fsck.stderr")),
            &check.stderr,
        )
        .unwrap();
        assert!(check.status.success(), "{stem}: {check:?}");
        assert!(String::from_utf8_lossy(&check.stdout).contains("appears to be OK"));
        let toolroot = "/nix/store/4nb6hz08a0bw424zdr9kg6lqjfswkp6w-sleuthkit-4.14.0/bin";
        let data = |path: &crate::platform::path::Path| {
            let result = Command::new(format!("{toolroot}/icat"))
                .args(["-f", "hfs"])
                .arg(path)
                .arg("17")
                .output()
                .unwrap();
            assert!(result.status.success());
            result.stdout
        };
        let source = crate::platform::path::PathBuf::from(format!(
            "/data/cache/partmgr-hfsplus-public-builder-native-v2/{}-source.img",
            if binary { "hfsx" } else { "hfsplus" }
        ));
        let payload = data(&image);
        assert_eq!(payload, data(&source));
        fs::write(
            self.output.join(format!("{stem}-child-data.stdout")),
            payload,
        )
        .unwrap();

        let original = self.source(binary);
        let cnid = native::be32(&original[1024..1536], 64);
        let committed = native::be32(&bytes[1024..1536], 64) != cnid;
        let listing = Command::new(format!("{toolroot}/fls"))
            .args(["-f", "hfs", "-r", "-p"])
            .arg(&image)
            .output()
            .unwrap();
        assert!(listing.status.success());
        assert_eq!(
            String::from_utf8_lossy(&listing.stdout).contains("DIR/Born"),
            committed
        );
        fs::write(
            self.output.join(format!("{stem}-fls.stdout")),
            listing.stdout,
        )
        .unwrap();
        if self.populated && committed {
            for (fork, id, expected) in [
                ("data", format!("{cnid}-4352-0"), vec![0x5a; 10003]),
                ("resource", format!("{cnid}-4353-1"), vec![0xa5; 5007]),
            ] {
                let result = Command::new(format!("{toolroot}/icat"))
                    .args(["-f", "hfs"])
                    .arg(&image)
                    .arg(id)
                    .output()
                    .unwrap();
                fs::write(
                    self.output.join(format!("{stem}-born-{fork}.stdout")),
                    &result.stdout,
                )
                .unwrap();
                assert!(result.status.success(), "{stem}-{fork}: {result:?}");
                assert_eq!(result.stdout, expected);
            }
        }
        assert_eq!(fs::read(&image).unwrap(), bytes);
    }
}
#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native creation all-position commit and rollback gate"]
fn native_all_creation_commit_and_rollback_cuts() {
    let output = crate::platform::path::PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_CREATE_CUT_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    crate::platform::fs::create_dir(&output).unwrap();
    let gate = CreationNativeCuts {
        populated: false,
        output,
        count: crate::platform::cell::Cell::new(0),
    };
    creation_commit_cuts(Some(&gate), false);
    creation_rollback_cuts(Some(&gate), false);
    crate::platform::fs::write(
        gate.output.join("receipt.txt"),
        format!("resolved_images={}\n", gate.count.get()),
    )
    .unwrap();
}

#[cfg(all(test, feature = "std"))]
fn public_create_limits(
    limits: Limits,
    undo: UndoLimits,
) -> crate::fs_hfsplus::edit::HfsPlusEditLimits {
    crate::fs_hfsplus::edit::HfsPlusEditLimits {
        pages: limits.pages,
        attempts: limits.attempts,
        work: limits.work,
        range_bytes: limits.range_bytes,
        read: limits.read,
        audit: limits.audit,
        undo,
    }
}
#[cfg(all(test, feature = "std"))]
fn commit_public_create<S: Storage>(
    prepared: Prepared<S>,
    request: CreateRequest<'_>,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<Prepared<S>, RenameFailure<S>> {
    use crate::fs_hfsplus::edit::{HfsPlusCreateRequest, HfsPlusEditSession};
    let limits = prepared.limits;
    let session = HfsPlusEditSession::open(
        prepared.into_storage(),
        public_create_limits(limits, undo),
        r,
    )
    .unwrap_or_else(|e| panic!("public creation open: {e}"));
    match session.create_entry(
        HfsPlusCreateRequest {
            parent: request.parent,
            name: request.name,
            directory: request.directory,
            metadata: request.metadata,
        },
        journal,
        binding,
        r,
    ) {
        Ok(ready) => Ok(Prepared::open(ready.into_storage(), limits, r).unwrap()),
        Err(failed) => Err(RenameFailure {
            target: failed.storage,
            error: failed.failure,
        }),
    }
}
#[cfg(all(test, feature = "std"))]
fn recover_public_create(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: CreateRequest<'_>,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    crate::fs_hfsplus::edit::recover_create(
        target,
        journal,
        crate::fs_hfsplus::edit::HfsPlusCreateRequest {
            parent: request.parent,
            name: request.name,
            directory: request.directory,
            metadata: request.metadata,
        },
        binding,
        public_create_limits(limits, undo),
        r,
    )
}

impl<S: Storage> Prepared<S> {
    fn plan_populated_birth(
        &self,
        request: CreateRequest<'_>,
        data: &[u8],
        resource: &[u8],
        r: &Resources,
    ) -> Result<RenamePlan> {
        if request.directory {
            return Err(bad("HFS+ populated birth requires regular file"));
        }

        let path_charge = request.parent.iter().try_fold(
            128u64 + request.name.len() as u64 * 2,
            |charge, component| {
                let NativeName::Utf16(units) = component else {
                    return Err(bad("HFS+ birth native path"));
                };
                charge
                    .checked_add(64 + units.len() as u64 * 2)
                    .ok_or_else(|| budget("HFS+ birth path charge"))
            },
        )?;
        let _path_lease = r.memory.reserve(path_charge)?;
        let mut path = vector(request.parent.len() + 1)?;
        for component in request.parent {
            let NativeName::Utf16(units) = component else {
                return Err(bad("HFS+ birth native path"));
            };
            let mut copy = vector(units.len())?;
            copy.extend_from_slice(units);
            path.push(NativeName::Utf16(copy));
        }
        let mut name = vector(request.name.len())?;
        name.extend_from_slice(request.name);
        path.push(NativeName::Utf16(name));
        let birth = self.plan_create_entry(request, r)?;
        let born = Prepared::open(
            Projected {
                target: &self.target,
                patches: &birth.patches,
                before: false,
            },
            self.limits,
            r,
        )?;
        let (data_payload, data_metadata) =
            born.stage_birth_fork(&path, &StreamKind::Data, data, r)?;
        let data_view = Projected {
            target: &born.target,
            patches: &data_payload.patches,
            before: false,
        };
        let data_ready = Prepared::open(
            Projected {
                target: &data_view,
                patches: &data_metadata.patches,
                before: false,
            },
            self.limits,
            r,
        )?;
        let (resource_payload, resource_metadata) =
            data_ready.stage_birth_fork(&path, &StreamKind::ResourceFork, resource, r)?;
        let resource_view = Projected {
            target: &data_ready.target,
            patches: &resource_payload.patches,
            before: false,
        };
        let final_view = Projected {
            target: &resource_view,
            patches: &resource_metadata.patches,
            before: false,
        };
        let sets = [
            &birth.patches,
            &data_payload.patches,
            &data_metadata.patches,
            &resource_payload.patches,
            &resource_metadata.patches,
        ];
        let count = sets
            .iter()
            .try_fold(0usize, |n, p| n.checked_add(p.len()))
            .ok_or_else(|| budget("HFS+ birth patch count"))?;
        let bytes = sets
            .iter()
            .flat_map(|p| p.iter())
            .try_fold(0u64, |n, p| n.checked_add(p.expected().len() as u64))
            .ok_or_else(|| budget("HFS+ birth patch bytes"))?;
        if bytes > self.range_bytes {
            return Err(budget("HFS+ populated birth ceiling"));
        }
        let lease = r.memory.reserve(
            bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(count as u64 * 256))
                .ok_or_else(|| budget("HFS+ birth merged charge"))?,
        )?;
        let mut intervals = vector(count)?;
        for patch in sets.iter().flat_map(|p| p.iter()) {
            r.cancellation.check()?;
            intervals.push((
                patch.offset(),
                patch.offset() + patch.expected().len() as u64,
            ));
        }
        self.snapshot.work.charge(
            (count as u64)
                .checked_mul(u64::from(usize::BITS - count.leading_zeros()).max(1))
                .and_then(|n| n.checked_mul(16))
                .ok_or_else(|| budget("HFS+ birth interval work"))?,
        )?;
        intervals.sort_unstable();
        let mut merged: Vec<(u64, u64)> = vector(count)?;
        for (start, end) in intervals {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        let mut patches = vector(merged.len())?;
        for (start, end) in merged {
            r.cancellation.check()?;
            let len =
                usize::try_from(end - start).map_err(|_| budget("HFS+ birth merged length"))?;
            self.snapshot.work.charge(len as u64 * 2)?;
            let mut before = vector(len)?;
            before.resize(len, 0);
            self.target
                .read_exact_at(start, &mut before)
                .map_err(|e| Error::io("HFS+ birth original", e))?;
            let mut after = vector(len)?;
            after.resize(len, 0);
            final_view
                .read_exact_at(start, &mut after)
                .map_err(|e| Error::io("HFS+ birth projection", e))?;
            patches.push(
                WriteRange::new(start, before, after)
                    .map_err(|e| Error::io("HFS+ birth merged patch", e))?,
            );
        }
        let final_proof = Prepared::open(
            Projected {
                target: &self.target,
                patches: &patches,
                before: false,
            },
            self.limits,
            r,
        )?;
        let id = final_proof.volume.lookup(&path, r)?;
        let node = final_proof.volume.node(&id)?;
        if node.forks[0].length != data.len() as u64
            || node.forks[1].length != resource.len() as u64
        {
            return Err(bad("HFS+ populated birth fork disagreement"));
        }
        for (fork, bytes) in node.forks.iter().zip([data, resource]) {
            let mut logical = 0usize;
            for extent in &fork.extents {
                let start =
                    u64::from(extent.start) * u64::from(final_proof.volume.geometry().block_size());
                let n = (u64::from(extent.count)
                    * u64::from(final_proof.volume.geometry().block_size()))
                .min(bytes.len() as u64 - logical as u64) as usize;
                let _read_lease = r.memory.reserve(n as u64)?;
                r.cancellation.check()?;
                self.snapshot.work.charge(n as u64)?;
                let mut actual = vector(n)?;
                actual.resize(n, 0);
                final_proof
                    .target
                    .read_exact_at(start, &mut actual)
                    .map_err(|e| Error::io("HFS+ birth payload proof", e))?;
                if actual != bytes[logical..logical + n] {
                    return Err(bad("HFS+ birth payload disagreement"));
                }
                logical += n;
            }
            if logical != bytes.len() {
                return Err(bad("HFS+ birth payload coverage"));
            }
        }
        drop(final_proof);
        self.revalidate(r)?;
        Ok(RenamePlan {
            patches,
            _lease: lease,
        })
    }
}

pub(crate) fn recover_populated_birth(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: (CreateRequest<'_>, &[u8], &[u8]),
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    let proof = (|| -> Result<_> {
        let length = target
            .len()
            .map_err(|e| Error::io("HFS+ cold populated birth length", e))?;
        let lease = r.memory.reserve(
            undo.body_bytes
                .checked_mul(3)
                .and_then(|n| n.checked_add(undo.patches as u64 * 256))
                .ok_or_else(|| budget("HFS+ cold populated birth charge"))?,
        )?;
        let mut saved = Collector {
            patches: vector(undo.patches as usize)?,
        };
        let status = fs_undo::validate_recovery(journal, length, binding, undo, r, &mut saved)?;
        let original = Prepared::open(
            Projected {
                target,
                patches: &saved.patches,
                before: true,
            },
            limits,
            r,
        )?;
        if status.state == UndoState::Empty {
            drop(original);
            return Ok((status, None, lease));
        }
        let rename = original.plan_populated_birth(request.0, request.1, request.2, r)?;
        let mut expected = framed(rename.patches, original.volume.header()[6], length)?;
        expected.sort_unstable_by_key(WriteRange::offset);
        if expected.len() != saved.patches.len()
            || expected.iter().zip(&saved.patches).any(|(a, b)| {
                a.offset() != b.offset()
                    || a.expected() != b.expected()
                    || a.replacement() != b.replacement()
            })
        {
            return Err(bad("HFS+ cold populated birth operation mismatch"));
        }
        drop(original);
        Ok((status, Some(expected), lease))
    })();
    let (status, expected, _lease) =
        proof.map_err(|e| fail(e, "HFS+ cold populated birth proof", true))?;
    match expected {
        None => Ok(status),
        Some(expected) => super::transaction::recovery::recover_patches(
            target, journal, binding, limits, undo, r, &expected,
        ),
    }
}

impl<S: Storage> Prepared<S> {
    pub(crate) fn commit_populated_birth(
        self,
        request: (CreateRequest<'_>, &[u8], &[u8]),
        journal: &mut dyn Storage,
        binding: UndoBinding,
        undo: UndoLimits,
        r: &Resources,
    ) -> crate::platform::result::Result<Self, RenameFailure<S>> {
        let plan = self.plan_populated_birth(request.0, request.1, request.2, r);
        self.commit_catalog_plan(plan, journal, binding, undo, r)
    }
}

#[cfg(feature = "std")]
#[test]
fn populated_birth_commit_and_cold_recovery_both_forks() {
    use super::super::transaction::recovery::cuts::{Clock, Model};
    use crate::platform::sync::{Arc, Mutex};
    let limits = Limits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 20,
        read: HfsPlusReadLimits {
            blocks: 256,
            nodes: 32,
            records: 32,
            extents: 64,
            work: 1 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 256,
            objects: 16,
            depth: 8,
            findings: 16,
            work: 1 << 20,
        },
    };
    let undo = UndoLimits {
        patches: 64,
        body_bytes: 1 << 19,
    };
    let binding = UndoBinding {
        volume: [0x55; 32],
        generation: 1,
        transaction: [0x77; 16],
    };

    for binary in [false, true] {
        for stop in [false, true] {
            let r = Resources {
                memory: Budget::new(16 << 20),
                cancellation: Cancellation::default(),
            };
            let original = super::super::super::independent::hfsplus_seed(binary);
            let clock = Arc::new(Mutex::new(Clock::default()));
            let target = Model::new(original.clone(), clock.clone());
            let mut prepared = Prepared::open(target, limits, &r).unwrap();
            let parent = [NativeName::Utf16("Dir".encode_utf16().collect())];
            let name: Vec<u16> = "Born".encode_utf16().collect();
            let request = || CreateRequest {
                parent: &parent,
                name: &name,
                directory: false,
                metadata: None,
            };
            let data = b"born DATA";
            let resource = b"born RESOURCE";
            let mut journal = Model::new(vec![0; 1 << 20], clock.clone());
            if stop {
                let plan = prepared
                    .plan_populated_birth(request(), data, resource, &r)
                    .unwrap();
                prepared.target.stop_at = Some(plan.patches[0].offset());
            }
            let mut target = match prepared.commit_populated_birth(
                (request(), data, resource),
                &mut journal,
                binding,
                undo,
                &r,
            ) {
                Ok(ready) => {
                    assert!(!stop);
                    ready.into_storage()
                }
                Err(failure) => {
                    assert!(stop, "{}", failure.error.source);
                    assert!(failure.error.recovery_required);
                    failure.target
                }
            };
            target.stop_at = None;
            let expected = target.bytes.clone();
            let before = (target.writes, journal.writes);
            assert!(
                recover_populated_birth(
                    &mut target,
                    &mut journal,
                    (request(), b"wrong DATA", resource),
                    binding,
                    limits,
                    undo,
                    &r
                )
                .is_err()
            );
            assert_eq!((target.writes, journal.writes), before);
            let status = recover_populated_birth(
                &mut target,
                &mut journal,
                (request(), data, resource),
                binding,
                limits,
                undo,
                &r,
            )
            .unwrap();
            assert_eq!(
                status.state,
                if stop {
                    UndoState::RolledBack
                } else {
                    UndoState::Committed
                }
            );
            assert_eq!(target.bytes, if stop { original } else { expected });
            let before = (target.writes, journal.writes);
            recover_populated_birth(
                &mut target,
                &mut journal,
                (request(), data, resource),
                binding,
                limits,
                undo,
                &r,
            )
            .unwrap();
            assert_eq!((target.writes, journal.writes), before);
            drop(Prepared::open(target, limits, &r).unwrap());
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn every_populated_birth_commit_and_rollback_cut_recovers() {
    creation_commit_cuts(None, true);
    creation_rollback_cuts(None, true);
}
#[cfg(all(test, feature = "std"))]
fn commit_creation_case<S: Storage>(
    prepared: Prepared<S>,
    request: BirthSelection<'_>,
    journal: &mut dyn Storage,
    binding: UndoBinding,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<Prepared<S>, RenameFailure<S>> {
    match request.1 {
        Some((data, resource)) => {
            use crate::fs_hfsplus::edit::{HfsPlusCreateFileRequest, HfsPlusEditSession};
            let limits = prepared.limits;
            let session = HfsPlusEditSession::open(
                prepared.into_storage(),
                public_create_limits(limits, undo),
                r,
            )
            .unwrap();
            match session.create_file(
                HfsPlusCreateFileRequest {
                    parent: request.0.parent,
                    name: request.0.name,
                    metadata: request.0.metadata,
                    data,
                    resource,
                },
                journal,
                binding,
                r,
            ) {
                Ok(ready) => Ok(Prepared::open(ready.into_storage(), limits, r).unwrap()),
                Err(failure) => Err(RenameFailure {
                    target: failure.storage,
                    error: failure.failure,
                }),
            }
        }
        None => commit_public_create(prepared, request.0, journal, binding, undo, r),
    }
}
#[cfg(all(test, feature = "std"))]
fn recover_creation_case(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: BirthSelection<'_>,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> crate::platform::result::Result<UndoStatus, UndoFailure> {
    match request.1 {
        Some((data, resource)) => crate::fs_hfsplus::edit::recover_create_file(
            target,
            journal,
            crate::fs_hfsplus::edit::HfsPlusCreateFileRequest {
                parent: request.0.parent,
                name: request.0.name,
                metadata: request.0.metadata,
                data,
                resource,
            },
            binding,
            public_create_limits(limits, undo),
            r,
        ),
        None => recover_public_create(target, journal, request.0, binding, limits, undo, r),
    }
}

#[cfg(all(test, feature = "std"))]
type BirthSelection<'a> = (CreateRequest<'a>, Option<(&'a [u8], &'a [u8])>);

#[cfg(target_os = "linux")]
#[cfg(feature = "std")]
#[test]
#[ignore = "explicit native populated creation all-position gate"]
fn native_all_populated_birth_commit_and_rollback_cuts() {
    let output = crate::platform::path::PathBuf::from(
        crate::platform::env::var_os("PARTMGR_HFSPLUS_CREATE_CUT_EVIDENCE")
            .expect("fresh evidence required"),
    );
    assert!(!output.exists());
    crate::platform::fs::create_dir(&output).unwrap();
    let gate = CreationNativeCuts {
        populated: true,
        output,
        count: crate::platform::cell::Cell::new(0),
    };
    creation_commit_cuts(Some(&gate), true);
    creation_rollback_cuts(Some(&gate), true);
    crate::platform::fs::write(
        gate.output.join("receipt.txt"),
        format!("resolved_images={}\n", gate.count.get()),
    )
    .unwrap();
}
