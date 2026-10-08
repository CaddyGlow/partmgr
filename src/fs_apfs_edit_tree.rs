//! Bounded bottom-up native COW tree layout; no source payload is inspected.
use super::*;
struct Page {
    records: Records,
    level: u16,
}
pub(super) struct Tree {
    pages: Vec<Page>,
    fixed: Option<(usize, usize)>,
    totals: (u64, u64, usize, usize),
}
fn fits(
    records: &[(Vec<u8>, Vec<u8>)],
    fixed: Option<(usize, usize)>,
    level: u16,
    root: bool,
) -> Result<bool> {
    let stride = if fixed.is_some() { 4usize } else { 8 };
    let minimum = fixed.map_or(128, |(k, v)| {
        ((BLOCK - 56) / (k + if level == 0 { v } else { 8 } + 4)) * 4
    });
    let table = records
        .len()
        .checked_mul(stride)
        .ok_or_else(|| budget("APFS COW tree table"))?
        .max(minimum);
    let mut size = 56usize
        .checked_add(table)
        .and_then(|n| n.checked_add(if root { 40 } else { 0 }))
        .ok_or_else(|| budget("APFS COW tree size"))?;
    for (key, value) in records {
        if key.len() > u16::MAX as usize || value.len() > u16::MAX as usize {
            return Err(unavailable("APFS COW native record size"));
        }
        if let Some((k, v)) = fixed
            && (key.len() != k || value.len() != if level == 0 { v } else { 8 })
        {
            return Err(invalid("APFS COW fixed record shape"));
        }
        size = size
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(|| budget("APFS COW record size"))?;
    }
    Ok(size <= BLOCK)
}
impl Tree {
    pub(super) fn plan<S: Storage>(
        mut records: Records,
        fixed: Option<(usize, usize)>,
        owner: &ApfsEditor<S>,
        r: &Resources,
    ) -> Result<Self> {
        if records.len() > owner.limits.read.records {
            return Err(budget("APFS COW tree record ceiling"));
        }
        if fixed.is_some() {
            records.sort_by(|a, b| {
                u64le(&a.0, 0)
                    .cmp(&u64le(&b.0, 0))
                    .then(u64le(&a.0, 8).cmp(&u64le(&b.0, 8)))
            });
        } else {
            records.sort_by(|a, b| disk::compare(&a.0, &b.0));
        }
        let count = records.len() as u64;
        let maxk = records.iter().map(|p| p.0.len()).max().unwrap_or(0);
        let maxv = records.iter().map(|p| p.1.len()).max().unwrap_or(0);
        let cap = owner.limits.metadata_blocks.min(owner.limits.read.objects);
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(cap)
            .map_err(|_| budget("APFS COW tree pages"))?;
        let mut level = 0u16;
        loop {
            r.cancellation.check()?;
            owner
                .snapshot
                .work
                .charge(records.len() as u64 + BLOCK as u64)?;
            if fits(&records, fixed, level, true)? {
                if pages.len() == cap {
                    return Err(budget("APFS COW tree page ceiling"));
                }
                pages.push(Page { records, level });
                break;
            }
            if level == 8 {
                return Err(budget("APFS COW native tree depth"));
            }
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(records.len())
                .map_err(|_| budget("APFS COW tree parents"))?;
            let mut start = 0;
            while start < records.len() {
                r.cancellation.check()?;
                let mut end = start;
                while end < records.len() {
                    r.cancellation.check()?;
                    owner.snapshot.work.charge((end - start + 1) as u64)?;
                    if !fits(&records[start..=end], fixed, level, false)? {
                        break;
                    }
                    end += 1;
                }
                if end == start {
                    return Err(unavailable("APFS COW record exceeds native node"));
                }
                if pages.len() == cap {
                    return Err(budget("APFS COW tree page ceiling"));
                }
                let child = pages.len() as u64;
                parents.push((records[start].0.clone(), child.to_le_bytes().to_vec()));
                let mut part = Vec::new();
                part.try_reserve_exact(end - start)
                    .map_err(|_| budget("APFS COW tree records"))?;
                part.extend(records[start..end].iter().cloned());
                pages.push(Page {
                    records: part,
                    level,
                });
                start = end;
            }
            if parents.len() >= records.len() {
                return Err(unavailable("APFS COW index key cannot reduce tree"));
            }
            records = parents;
            level += 1;
        }
        let nodes = pages.len() as u64;
        Ok(Self {
            pages,
            fixed,
            totals: (count, nodes, maxk, maxv),
        })
    }
    pub(super) fn len(&self) -> usize {
        self.pages.len()
    }
    // Root occupies the first supplied address, preserving the existing one-leaf layout.
    fn address(&self, index: usize, addresses: &[u64]) -> u64 {
        addresses[if index + 1 == self.pages.len() {
            0
        } else {
            index + 1
        }]
    }
    pub(super) fn mappings(
        &self,
        root: u64,
        first_child: u64,
        addresses: &[u64],
    ) -> Result<Vec<(u64, u64)>> {
        if addresses.len() != self.len() {
            return Err(invalid("APFS COW tree address count"));
        }
        let mut maps = Vec::new();
        maps.try_reserve_exact(self.len())
            .map_err(|_| budget("APFS COW virtual mappings"))?;
        maps.push((root, addresses[0]));
        for i in 0..self.len() - 1 {
            maps.push((
                first_child
                    .checked_add(i as u64)
                    .ok_or_else(|| budget("APFS COW child OID"))?,
                self.address(i, addresses),
            ));
        }
        Ok(maps)
    }
    pub(super) fn render(
        mut self,
        root: u64,
        first_child: u64,
        storage: u32,
        subtype: u32,
        addresses: &[u64],
        xid: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        if addresses.len() != self.len() {
            return Err(invalid("APFS COW tree address count"));
        }
        let count = self.len();
        let native_id = |i: usize| -> Result<u64> {
            if i >= count {
                return Err(invalid("APFS COW child index"));
            }
            Ok(if storage == 0 {
                if i + 1 == count {
                    root
                } else {
                    first_child
                        .checked_add(i as u64)
                        .ok_or_else(|| budget("APFS COW child OID"))?
                }
            } else {
                addresses[if i + 1 == count { 0 } else { i + 1 }]
            })
        };
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| budget("APFS COW rendered nodes"))?;
        for (i, page) in self.pages.iter_mut().enumerate() {
            if page.level != 0 {
                for (_, value) in &mut page.records {
                    let child = usize::try_from(u64le(value, 0))
                        .map_err(|_| budget("APFS COW child ordinal"))?;
                    *value = native_id(child)?.to_le_bytes().to_vec();
                }
            }
            let mut bytes = disk::node(
                disk::NodeFields {
                    id: native_id(i)?,
                    storage,
                    subtype,
                    level: page.level,
                    root: i + 1 == count,
                    fixed: self.fixed,
                    totals: if i + 1 == count {
                        self.totals
                    } else {
                        (0, 0, 0, 0)
                    },
                },
                &page.records,
            )?;
            q(&mut bytes, 16, xid);
            seal(&mut bytes);
            output.push((addresses[if i + 1 == count { 0 } else { i + 1 }], bytes));
        }
        output.sort_by_key(|(at, _)| *at);
        Ok(output)
    }
}
