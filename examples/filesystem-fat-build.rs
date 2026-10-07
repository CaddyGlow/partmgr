//! Author a fresh FAT image with one root short-name file.
//! This example requires a stable immutable payload and never replaces an image.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_fat::FatFamily,
    fs_fat_builder::{FatBuildFile, FatBuildOptions, FatBuildPlan},
    storage::FileStorage,
};
use std::{fs::OpenOptions, sync::Arc};
use virtdisk::RawDisk;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let image = args
        .next()
        .ok_or("usage: filesystem-fat-build IMAGE FAMILY PAYLOAD")?;
    let (family, length) = match args.next().as_deref() {
        Some("12") => (FatFamily::Fat12, 1440 * 1024),
        Some("16") => (FatFamily::Fat16, 32 * 1024 * 1024),
        Some("32") => (FatFamily::Fat32, 64 * 1024 * 1024),
        _ => return Err("FAMILY must be 12, 16, or 32".into()),
    };
    let payload = args.next().ok_or("supply PAYLOAD path")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let resources = Resources {
        memory: Budget::new(16 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let file = FatBuildFile {
        name: "PAYLOAD.BIN".into(),
        source: Arc::new(RawDisk::open(payload)?),
    };
    let plan = FatBuildPlan::new(
        length,
        FatBuildOptions {
            family,
            sectors_per_cluster: 1,
            volume_id: 0x504d_4752,
        },
        &[file],
        &resources,
    )?;
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&image)?;
    output.set_len(length)?;
    output.sync_all()?;
    drop(output);
    let mut destination = FileStorage::open(image)?;
    plan.emit(&mut destination, &resources)?;
    println!("family={family:?} image_bytes={length}");
    Ok(())
}
