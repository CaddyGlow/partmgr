//! Exact-byte JFFS2 tree source with unfollowed symlink metadata and deferred file data.
use crate::{
    fs_core::*,
    fs_jffs2::{Jffs2Volume, budget, copy, invalid},
    fs_jffs2_audit::{Jffs2AuditLimits, Jffs2AuditReport, audit},
};
use std::sync::Arc;
/// Reachable checked namespace retaining complete audit evidence and scan resources.
pub struct Jffs2TreeSource {
    volume: Jffs2Volume,
    report: Jffs2AuditReport,
}
impl Jffs2TreeSource {
    /// Audit the complete reachable namespace; defects reject capture.
    pub fn inventory(volume: Jffs2Volume, limits: Jffs2AuditLimits, r: &Resources) -> Result<Self> {
        let report = audit(&volume, limits, r)?;
        if !report.is_clean() {
            return Err(invalid("JFFS2 malformed reachable namespace"));
        }
        Ok(Self { volume, report })
    }
    /// Complete logical NOR scan and namespace evidence; no erase/GC authority.
    pub fn audit_report(&self) -> &Jffs2AuditReport {
        &self.report
    }
    fn index(&self, o: &ObjectId) -> Result<usize> {
        if o.source != self.volume.scope || o.native.len() != 4 {
            return Err(Error::new(ErrorKind::StalePlan, "foreign JFFS2 identity"));
        }
        let number = u32::from_le_bytes(o.native[..4].try_into().unwrap());
        let i = self
            .volume
            .inodes
            .binary_search_by_key(&number, |i| i.number)
            .map_err(|_| Error::new(ErrorKind::StalePlan, "absent JFFS2 identity"))?;
        if !self.report.reachable[i] || o.generation != u64::from(self.volume.inodes[i].version) {
            return Err(Error::new(
                ErrorKind::StalePlan,
                "unreachable/stale JFFS2 identity",
            ));
        }
        Ok(i)
    }
}
fn time(t: u32) -> Result<MetadataField<NativeTimestamp>> {
    let mut epoch = String::new();
    epoch
        .try_reserve_exact(14)
        .map_err(|_| budget("JFFS2 time epoch"))?;
    epoch.push_str("Unix 1970 UTC");
    Ok(MetadataField::Known(NativeTimestamp {
        ticks: i128::from(t),
        ticks_per_second: 1,
        epoch,
    }))
}
impl TreeSource for Jffs2TreeSource {
    fn root(&self) -> ObjectId {
        self.volume.identity(1).expect("validated root")
    }
    fn stability(&self) -> SourceStability {
        SourceStability::CallerGuaranteedStable
    }
    fn revalidate(&self, o: &ObjectId, r: &Resources) -> Result<()> {
        self.volume.check_stability(r)?;
        self.index(o)?;
        Ok(())
    }
    fn metadata(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Metadata>> {
        self.revalidate(o, r)?;
        let i = &self.volume.inodes[self.index(o)?];
        let e = self.volume.endian;
        Budgeted::try_new(&r.memory, 4096, || {
            let mode = e.dword(&i.raw, 20);
            let synthetic = i.synthetic;
            let mut attributes = Vec::new();
            attributes
                .try_reserve_exact(1)
                .map_err(|_| budget("JFFS2 metadata"))?;
            let mut meaning = String::new();
            meaning
                .try_reserve_exact(128)
                .map_err(|_| budget("JFFS2 raw inode meaning"))?;
            meaning.push_str(if synthetic {
                "Synthetic kernel-compatible root defaults; no on-disk inode node"
            } else {
                "Exact latest JFFS2 raw inode header; relocation unsupported"
            });
            attributes.push((
                NativeName::Bytes(copy(b"jffs2.native_inode")?),
                MetadataField::Opaque {
                    bytes: copy(&i.raw)?,
                    interpretation: meaning,
                },
            ));
            let symlink_target = if mode & 0xf000 == 0xa000 {
                let f = self.volume.open_file(i.number, r)?;
                let bytes = read_all(&f, 254, r)?;
                if bytes.get().contains(&0) {
                    return Err(invalid("JFFS2 symlink embedded NUL"));
                }
                MetadataField::Known(NativeName::Bytes(copy(bytes.get())?))
            } else {
                MetadataField::Absent
            };
            Ok(Metadata {
                created: MetadataField::Absent,
                modified: time(i.dir_time.map(|(_, t)| t).unwrap_or(e.dword(&i.raw, 36)))?,
                accessed: time(e.dword(&i.raw, 32))?,
                owner: MetadataField::Known(copy(&i.raw[24..28])?),
                mode: MetadataField::Known(mode),
                security: MetadataField::Absent,
                attributes,
                native_flags: MetadataField::Known(copy(&i.raw[58..60])?),
                symlink_target,
                reparse_data: MetadataField::Absent,
            })
        })
    }
    fn directory_page(
        &self,
        o: &ObjectId,
        continuation: Option<&[u8]>,
        maximum_entries: usize,
        r: &Resources,
    ) -> Result<DirectoryPage> {
        self.revalidate(o, r)?;
        let i = &self.volume.inodes[self.index(o)?];
        if self.volume.endian.dword(&i.raw, 20) & 0xf000 != 0x4000 || maximum_entries == 0 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "JFFS2 directory page request",
            ));
        }
        let reservation = r
            .memory
            .reserve(maximum_entries.min(i.children.len()) as u64 * 1024 + 128)?;
        let mut prefix = Vec::new();
        prefix
            .try_reserve_exact(28)
            .map_err(|_| budget("JFFS2 token"))?;
        prefix.extend_from_slice(&o.source.to_le_bytes());
        prefix.extend_from_slice(&o.generation.to_le_bytes());
        prefix.extend_from_slice(&o.native);
        let start = match continuation {
            None => 0,
            Some(t) if t.len() == 36 && t[..28] == prefix => {
                usize::try_from(u64::from_le_bytes(t[28..36].try_into().unwrap()))
                    .map_err(|_| invalid("JFFS2 token ordinal"))?
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "foreign JFFS2 page token",
                ));
            }
        };
        if start > i.children.len() {
            return Err(invalid("JFFS2 page ordinal past end"));
        }
        let n = maximum_entries.min(i.children.len() - start);
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(n)
            .map_err(|_| budget("JFFS2 page"))?;
        for e in &i.children[start..start + n] {
            r.cancellation.check()?;
            entries.push(DirectoryEntry {
                name: NativeName::Bytes(copy(&e.name)?),
                object: self.volume.identity(e.inode)?,
                kind: match e.file_type {
                    4 => ObjectKind::Directory,
                    8 => ObjectKind::File,
                    10 => ObjectKind::Symlink,
                    _ => return Err(invalid("JFFS2 page type")),
                },
            });
        }
        let next = if start + n < i.children.len() {
            let mut t = Vec::new();
            t.try_reserve_exact(36)
                .map_err(|_| budget("JFFS2 page token"))?;
            t.extend_from_slice(&prefix);
            t.extend_from_slice(&((start + n) as u64).to_le_bytes());
            Some(t)
        } else {
            None
        };
        Ok(DirectoryPage {
            entries,
            next,
            reservation,
        })
    }
    fn streams(&self, o: &ObjectId, r: &Resources) -> Result<Budgeted<Vec<StreamInfo>>> {
        self.revalidate(o, r)?;
        let i = &self.volume.inodes[self.index(o)?];
        Budgeted::try_new(&r.memory, 128, || {
            let mut v = Vec::new();
            if self.volume.endian.dword(&i.raw, 20) & 0xf000 == 0x8000 {
                v.try_reserve_exact(1)
                    .map_err(|_| budget("JFFS2 stream list"))?;
                v.push(StreamInfo {
                    kind: StreamKind::Data,
                    length: u64::from(self.volume.endian.dword(&i.raw, 28)),
                });
            }
            Ok(v)
        })
    }
    fn open_stream(
        &self,
        o: &ObjectId,
        s: &StreamKind,
        r: &Resources,
    ) -> Result<Arc<dyn FileRead>> {
        self.revalidate(o, r)?;
        let i = &self.volume.inodes[self.index(o)?];
        if *s != StreamKind::Data || self.volume.endian.dword(&i.raw, 20) & 0xf000 != 0x8000 {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "JFFS2 ordinary file stream required",
            ));
        }
        Ok(Arc::new(self.volume.open_file(i.number, r)?))
    }
}
