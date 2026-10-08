//! Complete bounded regular-file relocation groups using NONE and ZERO nodes.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_regular(
    decoded: &Decoded,
    old: &Jffs2Inode,
    e: Jffs2Endian,
    source: &impl DecodeRead,
    codec_work: &mut u64,
    l: Jffs2EditLimits,
    r: &Resources,
    erase_bytes: u32,
    mut add: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    let size = e.dword(&old.raw, 28);
    let chunk = l.file_bytes.min((erase_bytes as usize).saturating_sub(80));
    let mut ordinal = 0u32;
    let mut work = 0u64;
    let mut emit = |offset: u32, data: &[u8], hole: u32| -> Result<()> {
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 GC group ordinal"))?;
        let version = old
            .namespace_version()
            .checked_add(ordinal)
            .ok_or_else(|| cap("JFFS2 GC group version"))?;
        let mut node = file_node(e, old, old.number, version, data, None)?;
        put(e, &mut node, 28, size);
        put(e, &mut node, 44, offset);
        if hole > 0 {
            node[56] = 1;
            put(e, &mut node, 52, hole);
        }
        finish(e, &mut node, 0xe002, 68 + data.len());
        add(node)
    };
    for m in &old.map {
        source.check(r)?;
        work = work
            .checked_add(1)
            .ok_or_else(|| cap("JFFS2 GC emission work"))?;
        if work > l.read.work {
            return Err(cap("JFFS2 GC emission work cap"));
        }
        match m.kind {
            ExtentKind::Hole | ExtentKind::Unwritten => {
                emit(m.offset as u32, &[], m.length as u32)?
            }
            ExtentKind::Data(p) => {
                if chunk == 0 {
                    return Err(cap("JFFS2 GC data node cap"));
                }
                let mut done = 0;
                while done < m.length {
                    source.check(r)?;
                    work = work
                        .checked_add(1)
                        .ok_or_else(|| cap("JFFS2 GC emission work"))?;
                    if work > l.read.work {
                        return Err(cap("JFFS2 GC emission work cap"));
                    }
                    let n = (m.length - done).min(chunk as u64) as usize;
                    let mut data = vec_bytes(n, 0)?;
                    match &decoded.codecs {
                        Some(registry) => {
                            registry.read_mapping(source, p + done, &mut data, r, codec_work)?
                        }
                        None => source.read(p + done, &mut data)?,
                    }
                    emit((m.offset + done) as u32, &data, 0)?;
                    done += n as u64;
                }
            }
        }
    }
    emit(0, &[], 0)
}
pub(super) fn validate_regular(
    i: &Intent,
    old: &Jffs2Inode,
    group: &[(u32, usize)],
    l: Jffs2EditLimits,
) -> Result<()> {
    let e = i.endian;
    let size = e.dword(&old.raw, 28);
    let mut covered = 0u64;
    for (ordinal, (_, index)) in group.iter().enumerate() {
        let n = &i.slots[*index].bytes;
        if n.len() < 68 {
            return Err(invalid("JFFS2 GC short regular group node"));
        }
        let data = e.dword(n, 48) as usize;
        let logical = u64::from(e.dword(n, 52));
        let offset = u64::from(e.dword(n, 44));
        let last = ordinal + 1 == group.len();
        if e.dword(n, 28) != size
            || e.dword(n, 16)
                != old
                    .namespace_version()
                    .checked_add(ordinal as u32 + 1)
                    .ok_or_else(|| cap("JFFS2 GC regular version"))?
            || n.len() != ((68 + data + 3) & !3)
            || e.dword(n, 4) as usize != 68 + data
            || n[20..28] != old.raw[20..28]
            || n[32..44] != old.raw[32..44]
            || n[58..60] != old.raw[58..60]
            || n[57] != 0
            || (last && (logical != 0 || data != 0 || offset != 0 || n[56] != 0))
            || (!last && (logical == 0 || offset != covered))
            || (n[56] != 1
                && !compression_edit::data_shape(
                    i.compression,
                    n[56],
                    data,
                    logical as usize,
                    l.file_bytes,
                ))
            || (n[56] == 1 && data != 0)
        {
            return Err(invalid("JFFS2 GC regular group semantic profile"));
        }
        if !last {
            covered = covered
                .checked_add(logical)
                .ok_or_else(|| cap("JFFS2 GC coverage overflow"))?;
            if covered > u64::from(size) {
                return Err(invalid("JFFS2 GC regular group exceeds isize"));
            }
        }
    }
    if covered != u64::from(size) {
        return Err(invalid("JFFS2 GC regular group incomplete coverage"));
    }
    Ok(())
}
