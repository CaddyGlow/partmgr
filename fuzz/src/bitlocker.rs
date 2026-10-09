//! Bounded inspection and fixed-key mapping fuzzing; never derives a password.
use crate::Bytes;
use partmgr::{
    bitlocker::{BitLockerVolume, Limits, MetadataSelection},
    fs_core::{Budget, Cancellation, Resources},
    io::ReadAt,
};
use std::sync::Arc;

fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn inspect(data: &[u8]) -> Option<BitLockerVolume> {
    if data.len() > 1 << 20 {
        return None;
    }
    BitLockerVolume::inspect(
        Arc::new(Bytes(data.to_vec())),
        MetadataSelection::RequireAgreement,
        Limits {
            max_read_bytes: 1 << 20,
            max_entries: 256,
            max_depth: 4,
            ..Limits::default()
        },
        &resources(),
    )
    .ok()
}
pub fn inspection(data: &[u8]) {
    if data.len() > 1 << 20 {
        return;
    }
    let _ = partmgr::volume_probe::probe(&Bytes(data.to_vec()), &resources());
    if let Some(volume) = inspect(data) {
        for protector in volume.protectors().take(256) {
            std::hint::black_box(protector);
        }
    }
}
pub fn reader(data: &[u8]) {
    let Some(volume) = inspect(data) else {
        return;
    };
    let key_length = match volume.info().encryption_method {
        0x8004 => 32,
        0x8005 => 64,
        _ => return,
    };
    let key = [0x42; 64];
    let Ok(reader) = volume.unlock_fvek(&key[..key_length]) else {
        return;
    };
    let mut output = [0; 8193];
    for offset in [
        0,
        1,
        511,
        4095,
        8191,
        0x40000,
        0x50000,
        reader.len().saturating_sub(1),
        reader.len(),
        u64::MAX,
    ] {
        let _ = reader.read_exact_at(offset, &mut output);
        let _ = reader.read_exact_at(offset, &mut []);
    }
}
fn put<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
    bytes[at..at + N].copy_from_slice(&value);
}
fn seed(method: u16, sector_size: u16) -> Vec<u8> {
    let mut image = vec![0; 1 << 20];
    image[3..11].copy_from_slice(b"-FVE-FS-");
    put(&mut image, 11, sector_size.to_le_bytes());
    put(
        &mut image,
        160,
        [
            0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3,
            0xd0, 1,
        ],
    );
    put(&mut image, 510, 0xaa55u16.to_le_bytes());
    let mut metadata = [0; 120];
    metadata[..8].copy_from_slice(b"-FVE-FS-");
    for (at, value) in [
        (8, 7u16),
        (10, 2),
        (12, 4),
        (14, 4),
        (100, method),
        (112, 8),
        (114, 1),
    ] {
        put(&mut metadata, at, value.to_le_bytes());
    }
    put(&mut metadata, 16, (image.len() as u64).to_le_bytes());
    put(&mut metadata, 28, 1u32.to_le_bytes());
    put(&mut metadata, 56, 0x40000u64.to_le_bytes());
    for (at, value) in [(64, 48u32), (68, 1), (72, 48), (76, 48)] {
        put(&mut metadata, at, value.to_le_bytes());
    }
    for (index, offset) in [0x50000u64, 0x60000, 0x70000].into_iter().enumerate() {
        put(&mut image, 176 + index * 8, offset.to_le_bytes());
        put(&mut metadata, 32 + index * 8, offset.to_le_bytes());
    }
    let mut crc = !0u32;
    for byte in &metadata[..112] {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    put(&mut metadata, 116, (!crc).to_le_bytes());
    for offset in [0x50000, 0x60000, 0x70000] {
        image[offset..offset + metadata.len()].copy_from_slice(&metadata);
    }
    image
}
pub fn seeds() -> Vec<Vec<u8>> {
    vec![
        seed(0x8004, 512),
        seed(0x8005, 4096),
        vec![],
        b"xxx-FVE-FS-".to_vec(),
    ]
}
#[cfg(test)]
mod tests {
    #[test]
    fn generated_seeds_reach_decrypted_mapping() {
        for seed in super::seeds().into_iter().take(2) {
            let volume = super::inspect(&seed).unwrap();
            let key_len = if volume.info().encryption_method == 0x8004 {
                32
            } else {
                64
            };
            let key = [0x42; 64];
            let reader = volume.unlock_fvek(&key[..key_len]).unwrap();
            let mut hidden = [1; 512];
            partmgr::io::ReadAt::read_exact_at(&reader, 0x50000, &mut hidden).unwrap();
            assert_eq!(hidden, [0; 512]);
            super::reader(&seed);
        }
    }
}
