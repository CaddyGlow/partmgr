//! Exclusive same-parent catalog rename with external undo and cold recovery.
use super::*;
use crate::fs_hfsplus as native;
struct RenamePlan {
    patches: Vec<WriteRange>,
    _lease: Reservation,
}
struct Projected<'a> {
    target: &'a dyn Storage,
    patches: &'a [WriteRange],
    before: bool,
}
impl Storage for Projected<'_> {
    fn len(&self) -> io::Result<u64> {
        self.target.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.target.read_exact_at(at, out)?;
        let end = at
            .checked_add(out.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        for patch in self.patches {
            let bytes = if self.before {
                patch.expected()
            } else {
                patch.replacement()
            };
            let last = patch.offset() + bytes.len() as u64;
            let first = at.max(patch.offset());
            let limit = end.min(last);
            if first < limit {
                out[(first - at) as usize..(limit - at) as usize].copy_from_slice(
                    &bytes[(first - patch.offset()) as usize..(limit - patch.offset()) as usize],
                );
            }
        }
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
impl<S: Storage> Prepared<S> {
    fn plan_rename(&self, path: &[NativeName], name: &[u16], r: &Resources) -> Result<RenamePlan> {
        self.plan_catalog_transition(path, None, name, r)
    }
    fn plan_catalog_transition(
        &self,
        path: &[NativeName],
        destination: Option<&[NativeName]>,
        name: &[u16],
        r: &Resources,
    ) -> Result<RenamePlan> {
        self.plan_catalog_edit(path, destination, name, false, r)
    }
    fn plan_catalog_edit(
        &self,
        path: &[NativeName],
        destination: Option<&[NativeName]>,
        name: &[u16],
        deleting: bool,
        r: &Resources,
    ) -> Result<RenamePlan> {
        r.cancellation.check()?;
        if self.uncertain {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "HFS+ rename requires recovery",
            ));
        }
        if path.is_empty()
            || (deleting && destination.is_some())
            || (!deleting
                && (name.is_empty() || name.len() > 127 || name.iter().any(|&u| u == 0 || u == 47)))
        {
            return Err(bad("HFS+ rename name/root bounds"));
        }
        self.revalidate(r)?;
        let id = self.volume.lookup(path, r)?;
        self.volume.verify_catalog_record(&id, r)?;
        let node = self.volume.node(&id)?;
        let inner = &self.volume.inner;
        if deleting
            && (if node.directory {
                inner.nodes.values().any(|child| child.parent == node.id)
            } else {
                node.forks
                    .iter()
                    .any(|fork| fork.length != 0 || fork.blocks != 0 || !fork.extents.is_empty())
            })
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "HFS+ catalog deletion requires an empty object",
            ));
        }
        let parent = match destination {
            Some(path) => {
                let id = self.volume.lookup(path, r)?;
                self.volume.verify_catalog_record(&id, r)?;
                let folder = self.volume.node(&id)?;
                if !folder.directory {
                    return Err(bad("HFS+ move destination is not a directory"));
                }
                folder.id
            }
            None => node.parent,
        };
        if node.directory {
            let mut ancestor = parent;
            for _ in 0..=inner.nodes.len() {
                r.cancellation.check()?;
                self.snapshot.work.charge(1)?;
                if ancestor == node.id {
                    return Err(bad("HFS+ move directory cycle"));
                }
                if ancestor == 2 {
                    break;
                }
                ancestor = inner
                    .nodes
                    .get(&ancestor)
                    .ok_or_else(|| bad("HFS+ move parent topology"))?
                    .parent;
            }
        }
        let g = self.volume.geometry();
        let fork = &inner.system[2];
        if fork.length > self.range_bytes {
            return Err(budget("HFS+ rename catalog ceiling"));
        }
        let lease = r.memory.reserve(
            fork.length
                .checked_mul(6)
                .and_then(|n| n.checked_add(self.limits.read.records as u64 * 2048))
                .ok_or_else(|| budget("HFS+ rename charge"))?,
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
        let mut records = vector(tree.records.len())?;
        let mut objects = 0;
        let mut threads = 0;
        for record in tree.records {
            r.cancellation.check()?;
            self.snapshot
                .work
                .charge((record.key.len() + record.data.len() + 520) as u64)?;
            let kind = native::be16(&record.data, 0);
            let object = matches!(kind, 1 | 2) && native::be32(&record.data, 8) == node.id;
            let thread = matches!(kind, 3 | 4) && native::be32(&record.key, 0) == node.id;
            if deleting && (object || thread) {
                objects += usize::from(object);
                threads += usize::from(thread);
                continue;
            }
            let mut bytes = vector(record.key.len() + record.data.len() + 520)?;
            if object {
                objects += 1;
                let (key, _charge) = super::super::catalog_key(parent, name, g.binary, r)?;
                bytes.extend_from_slice(&key);
                bytes.extend_from_slice(&record.data);
            } else {
                bytes.extend_from_slice(&(record.key.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&record.key);
                if thread {
                    threads += 1;
                    let old_end = 10 + usize::from(native::be16(&record.data, 8)) * 2;
                    bytes.extend_from_slice(&record.data[..4]);
                    bytes.extend_from_slice(&parent.to_be_bytes());
                    bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
                    for u in name {
                        bytes.extend_from_slice(&u.to_be_bytes());
                    }
                    bytes.extend_from_slice(&record.data[old_end..]);
                    if bytes.len() - (2 + record.key.len()) > 264 {
                        return Err(budget("HFS+ rename native thread capacity"));
                    }
                } else {
                    if (deleting || parent != node.parent)
                        && kind == 1
                        && [node.parent, parent].contains(&native::be32(&record.data, 8))
                    {
                        let mut data = vector(record.data.len())?;
                        data.extend_from_slice(&record.data);
                        let old_parent = native::be32(&data, 8) == node.parent;
                        for offset in [4usize, 84] {
                            if offset == 84
                                && (!node.directory || native::be16(&data, 2) & 0x10 == 0)
                            {
                                continue;
                            }
                            let old = native::be32(&data, offset);
                            let value = if old_parent {
                                old.checked_sub(1)
                            } else {
                                old.checked_add(1)
                            }
                            .ok_or_else(|| bad("HFS+ move parent count overflow"))?;
                            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
                        }
                        bytes.extend_from_slice(&data);
                    } else {
                        bytes.extend_from_slice(&record.data);
                    }
                }
            }
            let key_end = usize::from(native::be16(&bytes, 0)) + 2;
            records.push((native::key(&bytes[2..key_end], 0, g.binary)?, bytes));
        }
        if objects != 1 || threads != 1 {
            return Err(bad("HFS+ rename object/thread provenance"));
        }
        let mut patches = self.stage_catalog_records(records, r)?;
        if deleting {
            let offset = if node.directory { 36 } else { 32 };
            let old = native::be32(self.volume.header(), offset);
            let value = old
                .checked_sub(1)
                .ok_or_else(|| bad("HFS+ delete folder count"))?;
            for at in [
                1024 + offset as u64,
                self.snapshot.length - 1024 + offset as u64,
            ] {
                r.cancellation.check()?;
                self.snapshot.work.charge(4)?;
                let mut before = vector(4)?;
                before.resize(4, 0);
                self.target
                    .read_exact_at(at, &mut before)
                    .map_err(|e| Error::io("HFS+ delete header count", e))?;
                if before != old.to_be_bytes() {
                    return Err(bad("HFS+ delete mirrored counts"));
                }
                let mut after = vector(4)?;
                after.extend_from_slice(&value.to_be_bytes());
                patches.push(
                    WriteRange::new(at, before, after)
                        .map_err(|e| Error::io("HFS+ delete count patch", e))?,
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
        if deleting {
            if proof.volume.lookup(path, r).is_ok() {
                return Err(bad("HFS+ deletion retained object"));
            }
            drop(proof);
            self.revalidate(r)?;
            return Ok(RenamePlan {
                patches,
                _lease: lease,
            });
        }
        let parent_path = destination.unwrap_or(&path[..path.len() - 1]);
        let mut renamed = vector(parent_path.len() + 1)?;
        for component in parent_path {
            let NativeName::Utf16(units) = component else {
                return Err(bad("HFS+ rename native path"));
            };
            let mut copied = vector(units.len())?;
            copied.extend_from_slice(units);
            renamed.push(NativeName::Utf16(copied));
        }
        let mut copied = vector(name.len())?;
        copied.extend_from_slice(name);
        renamed.push(NativeName::Utf16(copied));
        let new_id = proof.volume.lookup(&renamed, r)?;
        if proof.volume.node(&new_id)?.raw != node.raw {
            return Err(bad("HFS+ rename changed native object body"));
        }
        drop(proof);
        self.revalidate(r)?;
        Ok(RenamePlan {
            patches,
            _lease: lease,
        })
    }
}

#[test]
fn rename_preparation_preserves_objects_threads_header_and_exclusive_target() {
    struct ReadOnly(Vec<u8>);
    impl Storage for ReadOnly {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(&self.0[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
            panic!("rename preparation wrote")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("rename preparation flushed")
        }
    }
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
    for binary in [false, true] {
        for directory in [false, true] {
            let r = Resources {
                memory: Budget::new(16 << 20),
                cancellation: Cancellation::default(),
            };
            let mut original = super::super::independent::hfsplus_seed(binary);
            let header = 4 * 4096;
            let ranges = native::offsets(&original[header..header + 4096]).unwrap();
            original[header + ranges[0].0 + 32..header + ranges[0].0 + 36]
                .copy_from_slice(&8192u32.to_be_bytes());
            original[header + ranges[1].0..header + ranges[1].1].fill(0x35);
            let old = if directory {
                "Dir".encode_utf16().collect()
            } else {
                super::super::independent::native_name(binary)
            };
            let name: Vec<u16> = if binary {
                vec![0x03a3, 0xd801, 66]
            } else {
                "Renamed".encode_utf16().collect()
            };
            let path = [NativeName::Utf16(old)];
            let prepared = Prepared::open(ReadOnly(original.clone()), limits, &r).unwrap();
            let plan = prepared.plan_rename(&path, &name, &r).unwrap();
            assert!(!plan.patches.is_empty());
            assert!(
                plan.patches.iter().all(|p| p.offset() >= 4 * 4096
                    && p.offset() + p.replacement().len() as u64 <= 8 * 4096)
            );
            let projected = Prepared::open(
                Projected {
                    target: &prepared.target,
                    patches: &plan.patches,
                    before: false,
                },
                limits,
                &r,
            )
            .unwrap();
            let renamed = [NativeName::Utf16(name.clone())];
            let new_id = projected.volume.lookup(&renamed, &r).unwrap();
            let old_id = prepared.volume.lookup(&path, &r).unwrap();
            assert_eq!(
                projected.volume.node(&new_id).unwrap().raw,
                prepared.volume.node(&old_id).unwrap().raw
            );
            if directory {
                let child = [
                    renamed[0].clone(),
                    NativeName::Utf16("child".encode_utf16().collect()),
                ];
                let id = projected.volume.lookup(&child, &r).unwrap();
                assert_eq!(projected.volume.node(&id).unwrap().id, 18);
            }
            let mut changed = original.clone();
            for patch in &plan.patches {
                let start = patch.offset() as usize;
                changed[start..start + patch.replacement().len()]
                    .copy_from_slice(patch.replacement());
            }
            let new_ranges = native::offsets(&changed[header..header + 4096]).unwrap();
            assert_eq!(
                &changed[header + new_ranges[0].0 + 30..header + new_ranges[0].0 + 106],
                &original[header + ranges[0].0 + 30..header + ranges[0].0 + 106]
            );
            assert_eq!(
                &changed[header + new_ranges[1].0..header + new_ranges[1].1],
                &original[header + ranges[1].0..header + ranges[1].1]
            );
            assert_eq!(prepared.target.0, original);
            drop(projected);
            drop(plan);
            let collision: Vec<u16> = if directory {
                super::super::independent::native_name(binary)
            } else {
                "Dir".encode_utf16().collect()
            };
            assert!(prepared.plan_rename(&path, &collision, &r).is_err());
            assert!(prepared.plan_rename(&[], &name, &r).is_err());
            assert!(prepared.plan_rename(&path, &[0], &r).is_err());
            assert!(prepared.plan_rename(&path, &[65; 128], &r).is_err());
            drop(prepared);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

use crate::fs_undo::{
    self, UndoBinding, UndoFailure, UndoLimits, UndoPlan, UndoRecoveryValidator, UndoState,
    UndoStatus,
};
pub(crate) struct RenameRequest<'a> {
    pub(crate) deleting: bool,
    pub(crate) destination: Option<&'a [NativeName]>,
    pub(crate) path: &'a [NativeName],
    pub(crate) name: &'a [u16],
}
pub(crate) struct RenameFailure<S> {
    pub(crate) target: S,
    pub(crate) error: UndoFailure,
}
struct Held<'a>(&'a mut dyn Storage);
impl Storage for Held<'_> {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
fn fail(source: Error, stage: &'static str, recovery_required: bool) -> UndoFailure {
    UndoFailure {
        source,
        stage,
        recovery_required,
        target_may_have_changed: false,
    }
}
fn framed(mut patches: Vec<WriteRange>, clean: u8, length: u64) -> Result<Vec<WriteRange>> {
    patches
        .try_reserve_exact(2)
        .map_err(|_| budget("HFS+ rename state patches"))?;
    for at in [1030, length - 1018] {
        patches.push(
            WriteRange::new(at, vec![clean], vec![clean])
                .map_err(|e| Error::io("HFS+ rename state framing", e))?,
        );
    }
    Ok(patches)
}
impl<S: Storage> Prepared<S> {
    pub(crate) fn commit_rename(
        self,
        request: RenameRequest<'_>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        undo: UndoLimits,
        r: &Resources,
    ) -> std::result::Result<Self, RenameFailure<S>> {
        let prepared = {
            if request.deleting {
                self.plan_delete_entry(request.path, r)
            } else {
                match request.destination {
                    None => self.plan_rename(request.path, request.name, r),
                    Some(destination) => self.plan_catalog_transition(
                        request.path,
                        Some(destination),
                        request.name,
                        r,
                    ),
                }
            }
        };
        self.commit_catalog_plan(prepared, journal, binding, undo, r)
    }

    fn commit_catalog_plan(
        mut self,
        prepared: Result<RenamePlan>,
        journal: &mut dyn Storage,
        binding: UndoBinding,
        undo: UndoLimits,
        r: &Resources,
    ) -> std::result::Result<Self, RenameFailure<S>> {
        let planned = (|| -> Result<_> {
            let rename = prepared?;
            let clean = self.volume.header()[6];
            if clean & 1 == 0 || self.volume.alternate(r)?[6] != clean {
                return Err(bad("HFS+ rename native state disagreement"));
            }
            let count = rename.patches.len();
            let plan = UndoPlan::new_staged(
                binding,
                self.snapshot.length,
                framed(rename.patches, clean, self.snapshot.length)?,
                &[count, 2],
                undo,
                r,
            )?;
            self.revalidate(r)?;
            Ok((plan, [(1030, clean), (self.snapshot.length - 1018, clean)]))
        })();
        let (plan, states) = match planned {
            Ok(v) => v,
            Err(source) => {
                return Err(RenameFailure {
                    target: self.target,
                    error: fail(source, "HFS+ rename preflight", false),
                });
            }
        };
        if let Err(error) = super::transaction::commit_dirty(
            &mut self.target,
            journal,
            &plan,
            states,
            self.limits,
            r,
        ) {
            return Err(RenameFailure {
                target: self.target,
                error,
            });
        }
        let limits = self.limits;
        match Prepared::open(Held(&mut self.target), limits, r) {
            Ok(ready) => {
                let Prepared {
                    snapshot,
                    volume,
                    proof,
                    range_bytes,
                    limits,
                    generation,
                    uncertain,
                    ..
                } = ready;
                Ok(Prepared {
                    target: self.target,
                    snapshot,
                    volume,
                    proof,
                    range_bytes,
                    limits,
                    generation,
                    uncertain,
                })
            }
            Err(source) => Err(RenameFailure {
                target: self.target,
                error: UndoFailure {
                    stage: "HFS+ rename renewed metadata",
                    source,
                    recovery_required: true,
                    target_may_have_changed: true,
                },
            }),
        }
    }
}
struct Collector {
    patches: Vec<WriteRange>,
}
impl UndoRecoveryValidator for Collector {
    fn validate_range(&mut self, at: u64, old: &[u8], new: &[u8]) -> Result<()> {
        let mut before = vector(old.len())?;
        before.extend_from_slice(old);
        let mut after = vector(new.len())?;
        after.extend_from_slice(new);
        self.patches.push(
            WriteRange::new(at, before, after)
                .map_err(|e| Error::io("HFS+ rename saved patch", e))?,
        );
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}
pub(crate) fn recover_rename(
    target: &mut dyn Storage,
    journal: &mut dyn Storage,
    request: RenameRequest<'_>,
    binding: UndoBinding,
    limits: Limits,
    undo: UndoLimits,
    r: &Resources,
) -> std::result::Result<UndoStatus, UndoFailure> {
    let proof = (|| -> Result<_> {
        let length = target
            .len()
            .map_err(|e| Error::io("HFS+ cold rename length", e))?;
        let lease = r.memory.reserve(
            undo.body_bytes
                .checked_mul(3)
                .and_then(|n| n.checked_add(undo.patches as u64 * 256))
                .ok_or_else(|| budget("HFS+ cold rename charge"))?,
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
        let rename = if request.deleting {
            original.plan_delete_entry(request.path, r)?
        } else {
            match request.destination {
                None => original.plan_rename(request.path, request.name, r)?,
                Some(destination) => original.plan_catalog_transition(
                    request.path,
                    Some(destination),
                    request.name,
                    r,
                )?,
            }
        };
        let mut expected = framed(rename.patches, original.volume.header()[6], length)?;
        expected.sort_unstable_by_key(WriteRange::offset);
        if expected.len() != saved.patches.len()
            || expected.iter().zip(&saved.patches).any(|(a, b)| {
                a.offset() != b.offset()
                    || a.expected() != b.expected()
                    || a.replacement() != b.replacement()
            })
        {
            return Err(bad("HFS+ cold rename operation mismatch"));
        }
        drop(original);
        Ok((status, Some(expected), lease))
    })();
    let (status, expected, _lease) = proof.map_err(|e| fail(e, "HFS+ cold rename proof", true))?;
    match expected {
        None => Ok(status),
        Some(expected) => super::transaction::recovery::recover_patches(
            target, journal, binding, limits, undo, r, &expected,
        ),
    }
}

#[test]
fn rename_consuming_commit_and_cold_semantic_recovery() {
    struct Memory {
        bytes: Vec<u8>,
        fail: bool,
        writes: usize,
        flushes: usize,
    }
    impl Storage for Memory {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(997);
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            self.writes += 1;
            if self.fail && at == 4 * 4096 {
                return Err(io::Error::from_raw_os_error(5));
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
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
        for directory in [false, true] {
            for stop in [false, true] {
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let original = super::super::independent::hfsplus_seed(binary);
                let path = [NativeName::Utf16(if directory {
                    "Dir".encode_utf16().collect()
                } else {
                    super::super::independent::native_name(binary)
                })];
                let name: Vec<u16> = "Renamed".encode_utf16().collect();
                let request = || RenameRequest {
                    deleting: false,
                    destination: None,
                    path: &path,
                    name: &name,
                };
                let prepared = Prepared::open(
                    Memory {
                        bytes: original.clone(),
                        fail: stop,
                        writes: 0,
                        flushes: 0,
                    },
                    limits,
                    &r,
                )
                .unwrap();
                let mut journal = Memory {
                    bytes: vec![0; 1 << 20],
                    fail: false,
                    writes: 0,
                    flushes: 0,
                };
                let result = prepared.commit_rename(request(), &mut journal, binding, undo, &r);
                let mut target = match result {
                    Ok(ready) => {
                        assert!(!stop);
                        let id = ready
                            .volume
                            .lookup(&[NativeName::Utf16(name.clone())], &r)
                            .unwrap();
                        assert_eq!(ready.volume.node(&id).unwrap().directory, directory);
                        ready.into_storage()
                    }
                    Err(failed) => {
                        assert!(stop, "{}", failed.error.source);
                        assert!(failed.error.recovery_required);
                        failed.target
                    }
                };
                target.fail = false;
                let committed = target.bytes.clone();
                let writes = (
                    target.writes,
                    target.flushes,
                    journal.writes,
                    journal.flushes,
                );
                assert!(
                    recover_rename(
                        &mut target,
                        &mut journal,
                        RenameRequest {
                            deleting: false,
                            destination: None,
                            path: &path,
                            name: &[88]
                        },
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .is_err()
                );
                assert_eq!(
                    (
                        target.writes,
                        target.flushes,
                        journal.writes,
                        journal.flushes
                    ),
                    writes
                );
                let status = recover_rename(
                    &mut target,
                    &mut journal,
                    request(),
                    binding,
                    limits,
                    undo,
                    &r,
                )
                .unwrap();
                if stop {
                    assert_eq!(status.state, UndoState::RolledBack);
                    assert_eq!(target.bytes, original);
                } else {
                    assert_eq!(status.state, UndoState::Committed);
                    assert_eq!(target.bytes, committed);
                }
                let writes = (
                    target.writes,
                    target.flushes,
                    journal.writes,
                    journal.flushes,
                );
                recover_rename(
                    &mut target,
                    &mut journal,
                    request(),
                    binding,
                    limits,
                    undo,
                    &r,
                )
                .unwrap();
                assert_eq!(
                    (
                        target.writes,
                        target.flushes,
                        journal.writes,
                        journal.flushes
                    ),
                    writes
                );
                let ready = Prepared::open(target, limits, &r).unwrap();
                drop(ready);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[cfg(test)]
#[path = "fs_hfsplus_owned_namespace_cuts.rs"]
mod cuts;

#[cfg(all(test, target_os = "linux"))]
#[path = "fs_hfsplus_owned_namespace_native.rs"]
mod native_gate;

#[test]
fn move_preparation_updates_parent_counts_threads_and_rejects_cycles() {
    for binary in [false, true] {
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
        let original = super::super::independent::hfsplus_seed(binary);
        struct ReadOnly(Vec<u8>);
        impl Storage for ReadOnly {
            fn len(&self) -> io::Result<u64> {
                Ok(self.0.len() as u64)
            }
            fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
                out.copy_from_slice(&self.0[at as usize..at as usize + out.len()]);
                Ok(())
            }
            fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
                panic!("preparation wrote")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("preparation flushed")
            }
        }
        let prepared = Prepared::open(ReadOnly(original.clone()), limits, &r).unwrap();
        let path = [NativeName::Utf16(super::super::independent::native_name(
            binary,
        ))];
        let directory = [NativeName::Utf16("Dir".encode_utf16().collect())];
        let name: Vec<u16> = "Moved".encode_utf16().collect();
        let plan = prepared
            .plan_catalog_transition(&path, Some(&directory), &name, &r)
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
        let moved = [directory[0].clone(), NativeName::Utf16(name.clone())];
        let id = proof.volume.lookup(&moved, &r).unwrap();
        assert_eq!(proof.volume.node(&id).unwrap().id, 16);
        assert!(proof.volume.lookup(&path, &r).is_err());
        drop(proof);
        drop(plan);
        assert!(
            prepared
                .plan_catalog_transition(&directory, Some(&directory), &name, &r)
                .is_err()
        );
        assert!(
            prepared
                .plan_catalog_transition(&directory, Some(&path), &name, &r)
                .is_err()
        );
        assert_eq!(prepared.target.0, original);
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn move_consuming_commit_and_cold_semantic_recovery() {
    struct Memory {
        bytes: Vec<u8>,
        fail: bool,
        writes: usize,
        flushes: usize,
    }
    impl Storage for Memory {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
            Ok(())
        }
        fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(997);
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            self.writes += 1;
            if self.fail && at == 4 * 4096 {
                return Err(io::Error::from_raw_os_error(5));
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
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
        for directory in [false] {
            for stop in [false, true] {
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let original = super::super::independent::hfsplus_seed(binary);
                let path = [NativeName::Utf16(if directory {
                    "Dir".encode_utf16().collect()
                } else {
                    super::super::independent::native_name(binary)
                })];
                let name: Vec<u16> = "Renamed".encode_utf16().collect();
                let destination = [NativeName::Utf16("Dir".encode_utf16().collect())];
                let request = || RenameRequest {
                    deleting: false,
                    destination: Some(&destination),
                    path: &path,
                    name: &name,
                };
                let prepared = Prepared::open(
                    Memory {
                        bytes: original.clone(),
                        fail: stop,
                        writes: 0,
                        flushes: 0,
                    },
                    limits,
                    &r,
                )
                .unwrap();
                let mut journal = Memory {
                    bytes: vec![0; 1 << 20],
                    fail: false,
                    writes: 0,
                    flushes: 0,
                };
                let result = prepared.commit_rename(request(), &mut journal, binding, undo, &r);
                let mut target = match result {
                    Ok(ready) => {
                        assert!(!stop);
                        let id = ready
                            .volume
                            .lookup(
                                &[destination[0].clone(), NativeName::Utf16(name.clone())],
                                &r,
                            )
                            .unwrap();
                        assert_eq!(ready.volume.node(&id).unwrap().directory, directory);
                        ready.into_storage()
                    }
                    Err(failed) => {
                        assert!(stop, "{}", failed.error.source);
                        assert!(failed.error.recovery_required);
                        failed.target
                    }
                };
                target.fail = false;
                let committed = target.bytes.clone();
                let writes = (
                    target.writes,
                    target.flushes,
                    journal.writes,
                    journal.flushes,
                );
                assert!(
                    recover_rename(
                        &mut target,
                        &mut journal,
                        RenameRequest {
                            deleting: false,
                            destination: Some(&destination),
                            path: &path,
                            name: &[88]
                        },
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .is_err()
                );
                assert_eq!(
                    (
                        target.writes,
                        target.flushes,
                        journal.writes,
                        journal.flushes
                    ),
                    writes
                );
                assert!(
                    recover_rename(
                        &mut target,
                        &mut journal,
                        RenameRequest {
                            deleting: false,
                            path: &path,
                            name: &name,
                            destination: Some(&[])
                        },
                        binding,
                        limits,
                        undo,
                        &r
                    )
                    .is_err()
                );
                assert_eq!(
                    (
                        target.writes,
                        target.flushes,
                        journal.writes,
                        journal.flushes
                    ),
                    writes
                );
                let status = recover_rename(
                    &mut target,
                    &mut journal,
                    request(),
                    binding,
                    limits,
                    undo,
                    &r,
                )
                .unwrap();
                if stop {
                    assert_eq!(status.state, UndoState::RolledBack);
                    assert_eq!(target.bytes, original);
                } else {
                    assert_eq!(status.state, UndoState::Committed);
                    assert_eq!(target.bytes, committed);
                }
                let writes = (
                    target.writes,
                    target.flushes,
                    journal.writes,
                    journal.flushes,
                );
                recover_rename(
                    &mut target,
                    &mut journal,
                    request(),
                    binding,
                    limits,
                    undo,
                    &r,
                )
                .unwrap();
                assert_eq!(
                    (
                        target.writes,
                        target.flushes,
                        journal.writes,
                        journal.flushes
                    ),
                    writes
                );
                let ready = Prepared::open(target, limits, &r).unwrap();
                drop(ready);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn empty_directory_deletion_preparation_audits_counters_and_rejects_nonempty() {
    use super::transaction::recovery::cuts::{Clock, Model};
    use std::sync::{Arc, Mutex};
    for binary in [false, true] {
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
        let original = super::super::independent::hfsplus_directory_seed(binary);
        let prepared = Prepared::open(
            Model::new(original.clone(), Arc::new(Mutex::new(Clock::default()))),
            limits,
            &r,
        )
        .unwrap();
        let target = [NativeName::Utf16("Target".encode_utf16().collect())];
        let plan = prepared
            .plan_catalog_edit(&target, None, &[65], true, &r)
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
        assert!(proof.volume.lookup(&target, &r).is_err());
        let child = [
            NativeName::Utf16("Dir".encode_utf16().collect()),
            NativeName::Utf16("child".encode_utf16().collect()),
        ];
        proof.volume.lookup(&child, &r).unwrap();
        assert_eq!(native::be32(proof.volume.header(), 36), 1);
        drop(proof);
        drop(plan);
        let nonempty = [NativeName::Utf16("Dir".encode_utf16().collect())];
        assert!(
            prepared
                .plan_catalog_edit(&nonempty, None, &[65], true, &r)
                .is_err()
        );
        assert!(
            prepared
                .plan_catalog_edit(&[], None, &[65], true, &r)
                .is_err()
        );
        assert_eq!(prepared.target.bytes, original);
        assert_eq!(prepared.target.writes, 0);
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
    }
}

impl<S: Storage> Prepared<S> {
    fn plan_delete_entry(&self, path: &[NativeName], r: &Resources) -> Result<RenamePlan> {
        self.revalidate(r)?;
        let id = self.volume.lookup(path, r)?;
        let node = self.volume.node(&id)?;
        if node.directory
            || node
                .forks
                .iter()
                .all(|fork| fork.blocks == 0 && fork.length == 0)
        {
            return self.plan_catalog_edit(path, None, &[], true, r);
        }
        let data = self.stage_zero_fork(path, &StreamKind::Data, r)?;
        let data_ready = Prepared::open(
            Projected {
                target: &self.target,
                patches: &data.patches,
                before: false,
            },
            self.limits,
            r,
        )?;
        let resource = data_ready.stage_zero_fork(path, &StreamKind::ResourceFork, r)?;
        let resource_ready = Prepared::open(
            Projected {
                target: &data_ready.target,
                patches: &resource.patches,
                before: false,
            },
            self.limits,
            r,
        )?;
        let catalog = resource_ready.plan_catalog_edit(path, None, &[], true, r)?;
        let view = Projected {
            target: &resource_ready.target,
            patches: &catalog.patches,
            before: false,
        };
        let count = data.patches.len() + resource.patches.len() + catalog.patches.len();
        let mut bytes = 0u64;
        for patch in data
            .patches
            .iter()
            .chain(&resource.patches)
            .chain(&catalog.patches)
        {
            r.cancellation.check()?;
            bytes = bytes
                .checked_add(patch.expected().len() as u64)
                .ok_or_else(|| budget("HFS+ delete patch charge"))?;
        }
        if bytes > self.range_bytes {
            return Err(budget("HFS+ delete metadata ceiling"));
        }
        let lease = r.memory.reserve(
            bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(count as u64 * 256))
                .ok_or_else(|| budget("HFS+ delete merged patch charge"))?,
        )?;
        let mut intervals = vector(count)?;
        for patch in data
            .patches
            .iter()
            .chain(&resource.patches)
            .chain(&catalog.patches)
        {
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
                .ok_or_else(|| budget("HFS+ delete interval sort"))?,
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
            let length =
                usize::try_from(end - start).map_err(|_| budget("HFS+ delete merged length"))?;
            self.snapshot.work.charge((length as u64) * 2)?;
            let mut before = vector(length)?;
            before.resize(length, 0);
            self.target
                .read_exact_at(start, &mut before)
                .map_err(|e| Error::io("HFS+ delete merged original", e))?;
            let mut after = vector(length)?;
            after.resize(length, 0);
            view.read_exact_at(start, &mut after)
                .map_err(|e| Error::io("HFS+ delete merged projection", e))?;
            patches.push(
                WriteRange::new(start, before, after)
                    .map_err(|e| Error::io("HFS+ delete merged patch", e))?,
            );
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
        if proof.volume.lookup(path, r).is_ok() {
            return Err(bad("HFS+ delete merged object remains"));
        }
        drop(proof);
        self.revalidate(r)?;
        Ok(RenamePlan {
            patches,
            _lease: lease,
        })
    }
}
#[test]
fn file_deletion_preparation_releases_both_forks_overflow_and_preserves_payload() {
    use super::transaction::recovery::cuts::{Clock, Model};
    use std::sync::{Arc, Mutex};
    for binary in [false, true] {
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
        let original = super::super::independent::hfsplus_seed(binary);
        let prepared = Prepared::open(
            Model::new(original.clone(), Arc::new(Mutex::new(Clock::default()))),
            limits,
            &r,
        )
        .unwrap();
        let path = [NativeName::Utf16(super::super::independent::native_name(
            binary,
        ))];
        let id = prepared.volume.lookup(&path, &r).unwrap();
        let old = prepared.volume.node(&id).unwrap();
        let released = old.forks[0].blocks + old.forks[1].blocks;
        let plan = prepared.plan_delete_entry(&path, &r).unwrap();
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
        assert!(proof.volume.lookup(&path, &r).is_err());
        assert_eq!(
            proof.volume.geometry().free,
            prepared.volume.geometry().free + released
        );
        assert_eq!(native::be32(proof.volume.header(), 32), 1);
        for fork in &old.forks {
            for extent in &fork.extents {
                let at = u64::from(extent.start) * 4096;
                let mut bytes = vec![0; extent.count as usize * 4096];
                proof.target.read_exact_at(at, &mut bytes).unwrap();
                assert_eq!(bytes, original[at as usize..at as usize + bytes.len()]);
            }
        }
        drop(proof);
        drop(plan);
        assert_eq!(prepared.target.bytes, original);
        assert_eq!(prepared.target.writes, 0);
        drop(prepared);
        assert_eq!(r.memory.used(), 0);
    }
}

impl<S: Storage> Prepared<S> {
    fn stage_catalog_records(
        &self,
        mut records: Vec<(native::Key, Vec<u8>)>,
        r: &Resources,
    ) -> Result<Vec<WriteRange>> {
        let inner = &self.volume.inner;
        let g = self.volume.geometry();
        let fork = &inner.system[2];
        let map = native::map(self.snapshot.clone(), fork, g, self.limits.read.extents)?;
        let sort_work = (records.len() as u64)
            .checked_mul(u64::from(usize::BITS - records.len().leading_zeros()).max(1))
            .and_then(|n| n.checked_mul(8 * 256))
            .ok_or_else(|| budget("HFS+ rename catalog sort work"))?;
        self.snapshot.work.charge(sort_work)?;
        records.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut refs = vector(records.len())?;
        refs.extend(records.iter().map(|(_, bytes)| bytes.as_slice()));
        let mut header = vector(4096)?;
        header.resize(4096, 0);
        native::mapped_read(&map, 0, &mut header, r)?;
        let node_size = usize::from(native::be16(&header, 32));
        header
            .try_reserve_exact(node_size.saturating_sub(header.len()))
            .map_err(|_| budget("HFS+ rename header allocation"))?;
        header.resize(node_size, 0);
        native::mapped_read(&map, 0, &mut header, r)?;
        let old_ranges = native::offsets(&header)?;
        let old_record = old_ranges[0].0;
        let nodes = native::be32(&header, old_record + 22);
        let (mut catalog, _tree_lease) = super::super::keyed_tree(
            node_size,
            nodes,
            usize::MAX,
            super::super::TreeKind::Catalog { binary: g.binary },
            &refs,
            r,
        )?;
        let new_ranges = native::offsets(&catalog[..node_size])?;
        let new_record = new_ranges[0].0;
        catalog[new_record + 30..new_record + 106]
            .copy_from_slice(&header[old_record + 30..old_record + 106]);
        catalog[new_ranges[1].0..new_ranges[1].1]
            .copy_from_slice(&header[old_ranges[1].0..old_ranges[1].1]);
        catalog[12..14].copy_from_slice(&header[12..14]);
        let mut patches = vector(fork.extents.len().saturating_add(4))?;
        let mut logical = 0usize;
        for extent in &fork.extents {
            let count = (u64::from(extent.count) * u64::from(g.block_size()))
                .min(fork.length - logical as u64) as usize;
            if count == 0 {
                break;
            }
            let at = u64::from(extent.start) * u64::from(g.block_size());
            let mut before = vector(count)?;
            before.resize(count, 0);
            self.snapshot.work.charge(count as u64)?;
            self.target
                .read_exact_at(at, &mut before)
                .map_err(|e| Error::io("HFS+ rename catalog preimage", e))?;
            let mut after = vector(count)?;
            after.extend_from_slice(&catalog[logical..logical + count]);
            patches.push(
                WriteRange::new(at, before, after)
                    .map_err(|e| Error::io("HFS+ rename catalog patch", e))?,
            );
            logical += count;
        }
        if logical != catalog.len() {
            return Err(bad("HFS+ rename catalog mapping coverage"));
        }
        Ok(patches)
    }
}

#[path = "fs_hfsplus_owned_create.rs"]
pub(crate) mod create;
