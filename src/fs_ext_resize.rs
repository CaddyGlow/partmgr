//! Bounded canonical ext4 resize-inode reserved-GDT ownership validator.
use super::{ExtDecodeRead, invalid, modern::ModernProof, u16le, u32le, unsupported};
use crate::fs_core::Resources;
use std::io;
#[derive(Debug)]
pub(super) struct ResizeOwnership {
    pub double_indirect: u32,
    pub shared_reserved_blocks: u32,
}
pub(super) fn validate<R: ExtDecodeRead>(
    source: &R,
    proof: &ModernProof,
    inode: &[u8; 256],
    resources: &Resources,
) -> io::Result<ResizeOwnership> {
    resources.cancellation.check().map_err(io::Error::other)?;
    if proof.compat & 0x10 == 0 {
        return Err(unsupported("ext resize-inode feature absent"));
    }
    proof
        .checksums
        .inode(7, &inode[..usize::from(proof.inode_size)])?;
    let pointers = proof.block_size / 4;
    let expected_size =
        (12 + u64::from(pointers) + u64::from(pointers).pow(2)) * u64::from(proof.block_size);
    let recorded_size = u64::from(u32le(inode, 4)) | (u64::from(u32le(inode, 108)) << 32);
    if !proof.is_allocated(7, true)
        || u16le(inode, 0) != 0o100600
        || u16le(inode, 26) != 1
        || u32le(inode, 20) != 0
        || u16le(inode, 2) != 0
        || u16le(inode, 24) != 0
        || u16le(inode, 120) != 0
        || u16le(inode, 122) != 0
        || u32le(inode, 32) != 0
        || u32le(inode, 104) != 0
        || inode[112..120].iter().any(|byte| *byte != 0)
        || recorded_size != expected_size
        || inode[40..100]
            .chunks_exact(4)
            .enumerate()
            .any(|(slot, bytes)| slot != 13 && u32le(bytes, 0) != 0)
    {
        return Err(unsupported("ext resize inode encoding/ownership profile"));
    }
    let count = u32::from(proof.reserved_gdt);
    if count > pointers {
        return Err(unsupported("ext resize reserved-GDT count profile"));
    }
    let descriptor_blocks = (proof.descriptors.len() as u64 * u64::from(proof.descriptor_size))
        .div_ceil(u64::from(proof.block_size)) as u32;
    let backup = |group: u32| {
        let power = |base: u32| {
            let mut n = group;
            while n > 1 && n.is_multiple_of(base) {
                n /= base;
            }
            n == 1
        };
        group != 0 && (proof.ro & 1 == 0 || group == 1 || power(3) || power(5) || power(7))
    };
    let backup_count = (1..proof.descriptors.len() as u32)
        .filter(|group| backup(*group))
        .count() as u32;
    if backup_count > pointers {
        return Err(unsupported("ext resize backup-pointer capacity"));
    }
    let root = u32le(inode, 92);
    if proof.metadata_block(root) || !proof.is_allocated(root, false) {
        return Err(invalid("ext resize double-indirect allocation"));
    }
    let mut indirect = [0; 4096];
    source.decode_read_exact_at(
        u64::from(root) * u64::from(proof.block_size),
        &mut indirect[..proof.block_size as usize],
    )?;
    for slot in 0..pointers {
        let relative = (slot + pointers - descriptor_blocks % pointers) % pointers;
        let expected = if relative < count {
            proof.first + 1 + descriptor_blocks + relative
        } else {
            0
        };
        if u32le(&indirect, slot as usize * 4) != expected {
            return Err(invalid("ext resize primary reserved-GDT mapping"));
        }
        if expected == 0 {
            continue;
        }
        resources.cancellation.check().map_err(io::Error::other)?;
        let mut leaf = [0; 4096];
        source.decode_read_exact_at(
            u64::from(expected) * u64::from(proof.block_size),
            &mut leaf[..proof.block_size as usize],
        )?;
        let mut index = 0;
        for group in 1..proof.descriptors.len() as u32 {
            if !backup(group) {
                continue;
            }
            let expected =
                proof.first + group * proof.blocks_per_group + 1 + descriptor_blocks + relative;
            if !proof.metadata_block(expected)
                || !proof.is_allocated(expected, false)
                || u32le(&leaf, index * 4) != expected
            {
                return Err(invalid("ext resize backup reserved-GDT mapping"));
            }
            index += 1;
        }
        if leaf[index * 4..proof.block_size as usize]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(invalid("ext resize reserved-GDT unused pointers"));
        }
    }
    let shared_reserved_blocks = count * (backup_count + 1);
    if u64::from(u32le(inode, 28))
        != u64::from(1 + shared_reserved_blocks) * u64::from(proof.block_size) / 512
    {
        return Err(invalid("ext resize inode sector accounting"));
    }
    Ok(ResizeOwnership {
        double_indirect: root,
        shared_reserved_blocks,
    })
}
