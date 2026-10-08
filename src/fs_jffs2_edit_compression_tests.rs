//! Independent borrowed-codec ownership proof fixtures; no mutable ReadAt adapter.
use super::*;
use crate::fs_jffs2::borrowed_fixture as fixture;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

struct Bytes(Vec<u8>);
impl DecodeRead for Bytes {
    fn length(&self) -> u64 {
        self.0.len() as u64
    }
    fn check(&self, r: &Resources) -> Result<()> {
        r.cancellation.check()
    }
    fn read(&self, p: u64, out: &mut [u8]) -> Result<()> {
        let start = usize::try_from(p).map_err(|_| invalid("fixture offset"))?;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| invalid("fixture range"))?;
        out.copy_from_slice(
            self.0
                .get(start..end)
                .ok_or_else(|| invalid("fixture bounds"))?,
        );
        Ok(())
    }
}
fn image(big: bool, value: u8) -> Bytes {
    let mut image = fixture::jffs2_seed(big);
    let mut data = fixture::inode((2, 4), (0x81a0, 64), 0, &[value, 63], 0, big);
    fixture::dword(&mut data, 52, 64, big);
    data[56] = 2;
    let checksum = fixture::crc(&data[..60]);
    fixture::dword(&mut data, 64, checksum, big);
    image[4108..4108 + data.len()].copy_from_slice(&data);
    // Latest metadata is outside the data victim: checking only latest headers is insufficient.
    let metadata = fixture::inode((2, 5), (0x81a0, 64), 0, &[], 0, big);
    image[2048..2048 + metadata.len()].copy_from_slice(&metadata);
    Bytes(image)
}

#[cfg(feature = "std")]
#[test]
fn borrowed_compressed_proofs_compare_logical_bytes_and_physical_victim_dependencies() {
    for big in [false, true] {
        let r = Resources {
            memory: Budget::new(4 << 20),
            cancellation: Cancellation::default(),
        };
        let endian = if big {
            Jffs2Endian::Big
        } else {
            Jffs2Endian::Little
        };
        let geometry = FlashGeometry {
            layout: crate::fs_flash::FlashLayout::LogicalNor,
            erase_bytes: 4096,
            program_bytes: 4,
            erased_byte: 255,
            programming: crate::fs_flash::FlashProgramming::ClearBitsOnly,
        };
        let limits = Jffs2EditLimits {
            read: Jffs2ReadLimits {
                scan_bytes: 32768,
                nodes: 128,
                inodes: 32,
                fragments: 128,
                native_bytes: 4096,
                work: 100000,
            },
            audit: Jffs2AuditLimits {
                entries: 128,
                work: 100000,
                findings: 16,
            },
            journal_bytes: 32768,
            slots: 32,
            file_bytes: 2048,
            scratch_bytes: 128,
        };
        let profile = journal::CompressionProfile {
            codec: 2,
            limits: crate::fs_jffs2::Jffs2CompressionLimits {
                compressed_node_bytes: 4096,
                decoded_node_bytes: 4096,
                compressed_bytes: 65536,
                decoded_bytes: 65536,
                work: 131072,
            },
        };
        let first = image(big, b'A');
        let second = image(big, b'B');
        assert!(inspect(&first, geometry, endian, limits, &r).is_err());
        let (a, aa) = inspect_profile(&first, geometry, endian, limits, Some(profile), &r).unwrap();
        let (b, ba) =
            inspect_profile(&second, geometry, endian, limits, Some(profile), &r).unwrap();
        assert_eq!(inode(&a, 2).unwrap().map, inode(&b, 2).unwrap().map);
        assert!(same_namespace(&a, &aa, &first, &a, &aa, &first, limits, &r).is_ok());
        assert!(same_namespace(&a, &aa, &first, &b, &ba, &second, limits, &r).is_err());
        assert!(no_victim_references(&a, &aa, 4096, 4096).is_err());
        let capped = journal::CompressionProfile {
            limits: crate::fs_jffs2::Jffs2CompressionLimits {
                work: 66,
                ..profile.limits
            },
            ..profile
        };
        let (bounded, bounded_audit) =
            inspect_profile(&first, geometry, endian, limits, Some(capped), &r).unwrap();
        let error = gc_edit::emit_regular(
            &bounded,
            inode(&bounded, 2).unwrap(),
            endian,
            &first,
            &mut 0,
            limits,
            &r,
            4096,
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::BudgetExhausted);
        drop((bounded, bounded_audit));
        let mut relocated = Vec::new();
        gc_edit::emit_regular(
            &a,
            inode(&a, 2).unwrap(),
            endian,
            &first,
            &mut 0,
            limits,
            &r,
            4096,
            |node| {
                relocated.push(node);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(relocated.len(), 6);
        let payload: Vec<u8> = relocated
            .iter()
            .flat_map(|n| &n[68..68 + endian.dword(n, 48) as usize])
            .copied()
            .collect();
        assert_eq!(payload, [b'A'; 64]);
        for (ordinal, node) in relocated.iter().enumerate() {
            assert_eq!(endian.dword(node, 12), 2);
            assert_eq!(endian.dword(node, 16), 6 + ordinal as u32);
            assert_eq!(node[56], 0);
        }
        for codec in [2, 6] {
            let authoring = journal::CompressionProfile { codec, ..profile };
            let mut slots: Vec<Slot> = relocated
                .iter()
                .enumerate()
                .map(|(index, bytes)| Slot {
                    offset: 8204 + index as u64 * 200,
                    bytes: bytes.clone(),
                })
                .collect();
            compression_edit::encode_slots(&mut slots, endian, authoring, &r, &r).unwrap();
            assert!(slots.iter().any(|s| s.bytes[56] == codec));
            assert_eq!(slots.last().unwrap().bytes[56], 0);
            let mut copied = first.0.clone();
            copied.resize(12288, 255);
            for slot in &slots {
                let start = slot.offset as usize;
                copied[start..start + slot.bytes.len()].copy_from_slice(&slot.bytes);
            }
            let copied = Bytes(copied);
            let (decoded, audit) =
                inspect_profile(&copied, geometry, endian, limits, Some(authoring), &r).unwrap();
            same_namespace(&a, &aa, &first, &decoded, &audit, &copied, limits, &r).unwrap();
            no_victim_references(&decoded, &audit, 4096, 4096).unwrap();
        }
        drop((a, aa, b, ba));
        assert_eq!(r.memory.used(), 0);
    }
}
