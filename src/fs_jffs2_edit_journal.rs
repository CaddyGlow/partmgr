//! Private bounded external JFFS2 intent journal; never a NOR undo log.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;
const MAGIC: &[u8; 8] = b"JFF2TX01";
const COMPRESSED_MAGIC: &[u8; 8] = b"JFF2TX02";
pub(super) const BODY_AT: u64 = 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum State {
    Prepared = 1,
    Copied = 2,
    Complete = 3,
}
#[derive(Clone, Copy)]
pub(super) struct CompressionProfile {
    pub codec: u8,
    pub limits: crate::fs_jffs2::Jffs2CompressionLimits,
}
impl CompressionProfile {
    pub(super) fn validate(self) -> Result<()> {
        if !matches!(self.codec, 2 | 6)
            || self.limits.compressed_node_bytes == 0
            || self.limits.compressed_node_bytes > 65536
            || self.limits.decoded_node_bytes == 0
            || self.limits.decoded_node_bytes > 65536
        {
            return Err(invalid("JFFS2 compressed intent profile"));
        }
        Ok(())
    }
}
pub(super) struct Intent {
    pub compression: Option<CompressionProfile>,
    pub length: u64,
    pub operation: Jffs2EditOperation,
    pub geometry: FlashGeometry,
    pub endian: Jffs2Endian,
    pub binding: [u8; 32],
    pub inode_floor: u32,
    pub before: [u8; 32],
    pub copied: [u8; 32],
    pub after: [u8; 32],
    pub slots: Vec<Slot>,
    pub victim: Option<(u64, Vec<u8>)>,
    pub state: State,
    pub sequence: u64,
    pub _lease: Reservation,
}
pub(super) struct Slot {
    pub offset: u64,
    pub bytes: Vec<u8>,
}
fn q(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn d(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn putq(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
fn putd(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn header(i: &Intent, body: &[u8], state: State, seq: u64) -> [u8; 512] {
    let mut b = [0; 512];
    b[..8].copy_from_slice(if i.compression.is_some() {
        COMPRESSED_MAGIC
    } else {
        MAGIC
    });
    putq(&mut b, 8, seq);
    putd(&mut b, 16, state as u32);
    putd(&mut b, 20, i.operation as u32);
    putq(&mut b, 24, body.len() as u64);
    b[32..64].copy_from_slice(&sha(body));
    b[64..96].copy_from_slice(&i.binding);
    b[96..128].copy_from_slice(&i.before);
    b[128..160].copy_from_slice(&i.after);
    putq(&mut b, 160, i.length);
    putd(&mut b, 168, i.geometry.erase_bytes);
    putd(&mut b, 172, i.geometry.program_bytes);
    putd(
        &mut b,
        176,
        if i.endian == Jffs2Endian::Little {
            0
        } else {
            1
        },
    );
    putd(&mut b, 180, i.slots.len() as u32);
    if let Some((p, before)) = &i.victim {
        putq(&mut b, 184, *p);
        putq(&mut b, 192, before.len() as u64);
    }
    b[200..232].copy_from_slice(&i.copied);
    putd(&mut b, 232, i.inode_floor);
    if let Some(profile) = i.compression {
        putd(&mut b, 236, u32::from(profile.codec));
        putd(&mut b, 240, profile.limits.compressed_node_bytes as u32);
        putd(&mut b, 244, profile.limits.decoded_node_bytes as u32);
        putq(&mut b, 248, profile.limits.compressed_bytes);
        putq(&mut b, 256, profile.limits.decoded_bytes);
        putq(&mut b, 264, profile.limits.work);
    }
    let digest = sha(&b[..480]);
    b[480..].copy_from_slice(&digest);
    b
}
fn body(i: &Intent, l: Jffs2EditLimits) -> Result<Vec<u8>> {
    if let Some(profile) = i.compression {
        profile.validate()?;
    }
    let size = i
        .slots
        .iter()
        .try_fold(0usize, |n, s| n.checked_add(16)?.checked_add(s.bytes.len()))
        .and_then(|n| n.checked_add(i.victim.as_ref().map_or(0, |v| v.1.len())))
        .ok_or_else(|| cap("JFFS2 journal body overflow"))?;
    if size as u64 + BODY_AT > l.journal_bytes {
        return Err(cap("JFFS2 journal byte cap"));
    }
    let mut b = Vec::new();
    b.try_reserve_exact(size)
        .map_err(|_| cap("JFFS2 journal serialization"))?;
    for s in &i.slots {
        b.extend_from_slice(&s.offset.to_le_bytes());
        b.extend_from_slice(&(s.bytes.len() as u64).to_le_bytes());
        b.extend_from_slice(&s.bytes);
    }
    if let Some((_, before)) = &i.victim {
        b.extend_from_slice(before);
    }
    Ok(b)
}

fn write(j: &mut dyn Storage, p: u64, b: &[u8], r: &Resources) -> Result<()> {
    let mut done = 0;
    while done < b.len() {
        r.cancellation.check()?;
        let n = j
            .write_at(p + done as u64, &b[done..])
            .map_err(|e| Error::io("JFFS2 journal write", e))?;
        if n == 0 || n > b.len() - done {
            return Err(Error::io(
                "JFFS2 journal short write",
                io::ErrorKind::WriteZero.into(),
            ));
        }
        done += n;
    }
    Ok(())
}
fn flush(j: &mut dyn Storage, r: &Resources) -> Result<()> {
    r.cancellation.check()?;
    j.flush().map_err(|e| Error::io("JFFS2 journal flush", e))
}
fn compare(j: &dyn Storage, at: u64, expected: &[u8], r: &Resources) -> Result<()> {
    let mut scratch = [0u8; 512];
    let mut done = 0;
    while done < expected.len() {
        r.cancellation.check()?;
        let n = (expected.len() - done).min(scratch.len());
        j.read_exact_at(at + done as u64, &mut scratch[..n])
            .map_err(|e| Error::io("JFFS2 journal readback", e))?;
        if scratch[..n] != expected[done..done + n] {
            return Err(invalid("JFFS2 journal exact readback mismatch"));
        }
        done += n;
    }
    Ok(())
}
pub(super) fn prepare(
    j: &mut dyn Storage,
    i: &mut Intent,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    let b = body(i, l)?;
    if j.len().map_err(|e| Error::io("JFFS2 journal length", e))? < BODY_AT + b.len() as u64 {
        return Err(invalid("JFFS2 journal is not pre-sized"));
    }
    let mut old = [0; 1024];
    j.read_exact_at(0, &mut old)
        .map_err(|e| Error::io("JFFS2 journal headers", e))?;
    if old.iter().any(|v| *v != 0) {
        return Err(invalid(
            "JFFS2 transaction requires fresh zeroed journal headers",
        ));
    }
    write(j, BODY_AT, &b, r)?;
    flush(j, r)?;
    compare(j, BODY_AT, &b, r)?;
    let h = header(i, &b, State::Prepared, 1);
    write(j, 0, &h, r)?;
    flush(j, r)?;
    compare(j, 0, &h, r)?;
    i.state = State::Prepared;
    i.sequence = 1;
    Ok(())
}
pub(super) fn mark(
    j: &mut dyn Storage,
    i: &mut Intent,
    state: State,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<()> {
    let b = body(i, l)?;
    let seq = i
        .sequence
        .checked_add(1)
        .ok_or_else(|| invalid("JFFS2 journal sequence overflow"))?;
    compare(j, BODY_AT, &b, r)?;
    let h = header(i, &b, state, seq);
    write(j, ((seq - 1) % 2) * 512, &h, r)?;
    flush(j, r)?;
    compare(j, ((seq - 1) % 2) * 512, &h, r)?;
    i.sequence = seq;
    i.state = state;
    Ok(())
}
fn check_profile(header: &[u8], expected: Option<CompressionProfile>) -> Result<()> {
    match expected {
        None => {
            if header[..8] == COMPRESSED_MAGIC[..] {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "JFFS2 compressed intent requires explicit recovery profile",
                ));
            }
            if header[..8] != MAGIC[..] || header[236..480].iter().any(|v| *v != 0) {
                return Err(invalid("JFFS2 strict intent version/reserved fields"));
            }
        }
        Some(profile) => {
            profile.validate()?;
            if header[..8] != COMPRESSED_MAGIC[..]
                || d(header, 236) != u32::from(profile.codec)
                || d(header, 240) as usize != profile.limits.compressed_node_bytes
                || d(header, 244) as usize != profile.limits.decoded_node_bytes
                || q(header, 248) != profile.limits.compressed_bytes
                || q(header, 256) != profile.limits.decoded_bytes
                || q(header, 264) != profile.limits.work
                || header[272..480].iter().any(|v| *v != 0)
            {
                return Err(invalid("JFFS2 intent compressed profile mismatch"));
            }
        }
    }
    Ok(())
}
pub(super) fn load(
    j: &mut dyn Storage,
    binding: [u8; 32],
    geometry: FlashGeometry,
    endian: Jffs2Endian,
    length: u64,
    l: Jffs2EditLimits,
    r: &Resources,
) -> Result<Intent> {
    load_profile(j, binding, geometry, endian, length, l, None, r)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn load_profile(
    j: &mut dyn Storage,
    binding: [u8; 32],
    geometry: FlashGeometry,
    endian: Jffs2Endian,
    length: u64,
    l: Jffs2EditLimits,
    compression: Option<CompressionProfile>,
    r: &Resources,
) -> Result<Intent> {
    if let Some(profile) = compression {
        profile.validate()?;
    }
    r.cancellation.check()?;
    let lease = r.memory.reserve(
        l.journal_bytes
            .checked_mul(3)
            .and_then(|n| n.checked_add(l.slots as u64 * 256 + 65536))
            .ok_or_else(|| cap("JFFS2 journal accounting overflow"))?,
    )?;
    let jlen = j.len().map_err(|e| Error::io("JFFS2 journal length", e))?;
    if jlen < BODY_AT {
        return Err(invalid("JFFS2 truncated journal"));
    }
    let mut raw = [0; 1024];
    j.read_exact_at(0, &mut raw)
        .map_err(|e| Error::io("JFFS2 journal headers", e))?;
    let valid = |b: &[u8]| {
        (b[..8] == MAGIC[..] || b[..8] == COMPRESSED_MAGIC[..]) && b[480..] == sha(&b[..480])
    };
    let a = &raw[..512];
    let b = &raw[512..];
    let h = match (valid(a), valid(b)) {
        (false, false) => return Err(invalid("JFFS2 no valid intent header")),
        (true, false) => a,
        (false, true) => b,
        (true, true) => {
            if a[..8] != b[..8] || a[20..480] != b[20..480] || q(a, 8) == q(b, 8) {
                return Err(invalid("JFFS2 ambiguous journal headers"));
            }
            if q(a, 8) > q(b, 8) { a } else { b }
        }
    };
    check_profile(h, compression)?;
    if h[64..96] != binding
        || q(h, 160) != length
        || d(h, 168) != geometry.erase_bytes
        || d(h, 172) != geometry.program_bytes
        || d(h, 176) != if endian == Jffs2Endian::Little { 0 } else { 1 }
    {
        return Err(invalid("JFFS2 journal binding/geometry/reserved fields"));
    }
    let state = match d(h, 16) {
        1 => State::Prepared,
        2 => State::Copied,
        3 => State::Complete,
        _ => return Err(invalid("JFFS2 journal state")),
    };
    let seq = q(h, 8);
    let op = d(h, 20);
    if !(1..=7).contains(&op)
        || (op != 2 && (state == State::Copied || seq > 2))
        || (op == 2 && seq > 3)
        || seq == 0
        || (seq - 1) % 2
            != if crate::platform::ptr::eq(h.as_ptr(), a.as_ptr()) {
                0
            } else {
                1
            }
    {
        return Err(invalid("JFFS2 journal operation/sequence"));
    }
    let state_valid = if op == 2 {
        matches!(
            (state, seq),
            (State::Prepared, 1) | (State::Copied, 2) | (State::Complete, 3)
        )
    } else {
        matches!((state, seq), (State::Prepared, 1) | (State::Complete, 2))
    };
    if !state_valid {
        return Err(invalid("JFFS2 inconsistent state/sequence"));
    }
    let count = d(h, 180) as usize;
    if (count == 0 && op != 2) || count > l.slots {
        return Err(cap("JFFS2 intent slot cap"));
    }
    let n = q(h, 24);
    if n > l.journal_bytes.saturating_sub(BODY_AT) || n > jlen - BODY_AT {
        return Err(cap("JFFS2 journal body length"));
    }
    let mut body = vec_bytes(n as usize, 0)?;
    j.read_exact_at(BODY_AT, &mut body)
        .map_err(|e| Error::io("JFFS2 journal body read", e))?;
    if sha(&body) != h[32..64] {
        return Err(invalid("JFFS2 intent body digest"));
    }
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| cap("JFFS2 journal slots"))?;
    let mut at = 0usize;
    let mut end = 0;
    for _ in 0..count {
        if body.len().saturating_sub(at) < 16 {
            return Err(invalid("JFFS2 intent descriptor"));
        }
        let p = q(&body, at);
        let n = q(&body, at + 8);
        at += 16;
        let stop = p
            .checked_add(n)
            .ok_or_else(|| invalid("JFFS2 intent range overflow"))?;
        if n < 12
            || n > u64::from(geometry.erase_bytes)
            || !p.is_multiple_of(4)
            || !n.is_multiple_of(4)
            || p < end
            || stop > length
            || p / u64::from(geometry.erase_bytes) != (stop - 1) / u64::from(geometry.erase_bytes)
            || p % u64::from(geometry.erase_bytes) < 12
            || n > body.len().saturating_sub(at) as u64
        {
            return Err(invalid("JFFS2 intent range"));
        }
        slots.push(Slot {
            offset: p,
            bytes: copy(&body[at..at + n as usize])?,
        });
        at += n as usize;
        end = stop;
    }
    let victim = if op == 2 {
        let p = q(h, 184);
        let n = q(h, 192);
        if n != u64::from(geometry.erase_bytes)
            || !p.is_multiple_of(n)
            || p.checked_add(n).is_none_or(|e| e > length)
            || slots
                .iter()
                .any(|s| s.offset < p + n && s.offset + s.bytes.len() as u64 > p)
            || body.len() - at != n as usize
        {
            return Err(invalid("JFFS2 GC victim bounds"));
        }
        Some((p, copy(&body[at..])?))
    } else {
        if q(h, 184) != 0 || q(h, 192) != 0 || at != body.len() {
            return Err(invalid("JFFS2 append trailing intent bytes"));
        }
        None
    };
    Ok(Intent {
        compression,
        length,
        operation: match op {
            1 => Jffs2EditOperation::Replace,
            2 => Jffs2EditOperation::GarbageCollect,
            3 => Jffs2EditOperation::Create,
            4 => Jffs2EditOperation::Rename,
            5 => Jffs2EditOperation::Unlink,
            6 => Jffs2EditOperation::Link,
            7 => Jffs2EditOperation::FileRange,
            _ => unreachable!(),
        },
        geometry,
        endian,
        binding,
        inode_floor: d(h, 232),
        before: h[96..128].try_into().unwrap(),
        after: h[128..160].try_into().unwrap(),
        copied: h[200..232].try_into().unwrap(),
        slots,
        victim,
        state,
        sequence: seq,
        _lease: lease,
    })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn versioned_profile_requires_exact_codec_caps_and_reserved_bytes() {
        let profile = CompressionProfile {
            codec: 6,
            limits: crate::fs_jffs2::Jffs2CompressionLimits {
                compressed_node_bytes: 4096,
                decoded_node_bytes: 8192,
                compressed_bytes: 65536,
                decoded_bytes: 131072,
                work: 196608,
            },
        };
        let mut h = [0u8; 512];
        h[..8].copy_from_slice(COMPRESSED_MAGIC);
        putd(&mut h, 236, 6);
        putd(&mut h, 240, 4096);
        putd(&mut h, 244, 8192);
        putq(&mut h, 248, 65536);
        putq(&mut h, 256, 131072);
        putq(&mut h, 264, 196608);
        check_profile(&h, Some(profile)).unwrap();
        assert!(check_profile(&h, None).is_err());
        for offset in [236, 240, 244, 248, 256, 264, 272, 479] {
            let mut changed = h;
            changed[offset] ^= 1;
            assert!(check_profile(&changed, Some(profile)).is_err());
        }
        h[..8].copy_from_slice(MAGIC);
        assert!(check_profile(&h, Some(profile)).is_err());
        let mut invalid = profile;
        invalid.codec = 7;
        assert!(invalid.validate().is_err());
        invalid = profile;
        invalid.limits.decoded_node_bytes = 65537;
        assert!(invalid.validate().is_err());
    }
}
