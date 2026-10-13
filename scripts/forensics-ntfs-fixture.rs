//! Serialize the independent hand-authored integration fixture without production encoders.
#[path = "../tests/fixtures/ntfs_clean.rs"]
mod clean;
use std::{error::Error, path::Path};
fn deleted(cluster: u8) -> Vec<u8> {
    let mut disk = clean::ntfs_audit_seed();
    clean::put(
        &mut disk,
        24,
        &[clean::nonresident(
            &[0x11, 1, cluster, 0],
            1,
            100,
            100,
            false,
        )],
        false,
        1,
    );
    clean::w(&mut disk, 2048 + 24 * 1024 + 22, 0);
    let bitmap = 2048
        + 56
        + clean::resident(0x30, &clean::name_value("$MFT", 5), 2).len()
        + clean::nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false).len()
        + 24;
    disk[bitmap + 3] &= !1;
    disk[90 * 512..90 * 512 + 100].fill(b'C');
    disk[92 * 512..92 * 512 + 100].fill(b'D');
    disk
}
fn main() -> Result<(), Box<dyn Error>> {
    let destination = std::env::args()
        .nth(1)
        .ok_or("supply a fresh output directory")?;
    let destination = Path::new(&destination);
    std::fs::create_dir(destination)?;
    let live = clean::ntfs_audit_seed();
    std::fs::write(destination.join("live.dd"), &live)?;
    let mut dirty = live;
    let volume =
        2048 + 3 * 1024 + 56 + clean::resident(0x30, &clean::name_value("$Volume", 5), 2).len();
    clean::w(&mut dirty, volume + 24 + 10, 1);
    std::fs::write(destination.join("dirty.dd"), dirty)?;
    std::fs::write(destination.join("deleted-conflict.dd"), deleted(90))?;
    std::fs::write(destination.join("deleted-free.dd"), deleted(92))?;
    let mut missing = deleted(92);
    clean::put(
        &mut missing,
        6,
        &[clean::resident(0x30, &clean::name_value("$Bitmap", 5), 2)],
        false,
        1,
    );
    std::fs::write(destination.join("missing-bitmap.dd"), missing)?;
    Ok(())
}
