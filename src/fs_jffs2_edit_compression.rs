//! Private deterministic codec authoring and authenticated node-shape policy.
use super::*;

pub(super) fn data_shape(
    profile: Option<journal::CompressionProfile>,
    codec: u8,
    encoded: usize,
    decoded: usize,
    maximum: usize,
) -> bool {
    decoded <= maximum
        && if codec == 0 {
            encoded == decoded
        } else {
            profile.is_some_and(|p| {
                codec == p.codec
                    && encoded < decoded
                    && encoded <= p.limits.compressed_node_bytes
                    && decoded <= p.limits.decoded_node_bytes
            })
        }
}

pub(super) fn encode_slots(
    slots: &mut [Slot],
    endian: Jffs2Endian,
    profile: journal::CompressionProfile,
    original: &Resources,
    r: &Resources,
) -> Result<()> {
    use crate::fs_jffs2_builder::Jffs2BuildCompression;
    let codec = match profile.codec {
        2 => Jffs2BuildCompression::Rtime,
        6 => Jffs2BuildCompression::Zlib,
        _ => return Err(invalid("JFFS2 owned authoring codec")),
    };
    let mut work = 0u64;
    for slot in slots {
        r.cancellation.check()?;
        original.cancellation.check()?;
        let node = &mut slot.bytes;
        if node.len() < 68
            || endian.word(node, 2) != 0xe002
            || endian.dword(node, 20) & 0xf000 != 0x8000
            || node[56] != 0
        {
            continue;
        }
        let size = endian.dword(node, 48) as usize;
        if size == 0 || size > profile.limits.decoded_node_bytes {
            continue;
        }
        work = work
            .checked_add(
                (size as u64)
                    .checked_mul(2)
                    .ok_or_else(|| cap("JFFS2 owned encoder work overflow"))?,
            )
            .ok_or_else(|| cap("JFFS2 owned encoder work overflow"))?;
        if work > profile.limits.work {
            return Err(cap("JFFS2 owned encoder byte-work cap"));
        }
        let input = node
            .get(68..68 + size)
            .ok_or_else(|| invalid("JFFS2 authoring payload bounds"))?;
        let _workspace = r.memory.reserve(
            codec
                .workspace()
                .checked_add(size as u64)
                .ok_or_else(|| cap("JFFS2 owned encoder accounting"))?,
        )?;
        let Some(encoded) = codec.encode(input, r)? else {
            continue;
        };
        if encoded.len() > profile.limits.compressed_node_bytes {
            continue;
        }
        let total = 68 + encoded.len();
        node[68..total].copy_from_slice(&encoded);
        node.truncate(total.next_multiple_of(4));
        node[total..].fill(255);
        node[56] = codec.native();
        put(endian, node, 48, encoded.len() as u32);
        put(endian, node, 60, crc(0, &encoded));
        finish(endian, node, 0xe002, total);
    }
    original.cancellation.check()?;
    r.cancellation.check()
}
