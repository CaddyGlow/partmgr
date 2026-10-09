//! Deterministic new-output nested EFI-shaped FAT fixture; payload is not boot code.
use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ObjectId, Resources},
    fs_fat::FatFamily,
    fs_fat_builder::{FatBuildOptions, FatBuildPlan, FatBuildTreeEntry, FatTreeMetadataPolicy},
    storage::FileStorage,
};
use std::{fs::OpenOptions, sync::Arc};
use virtdisk::{RawDisk, ReadAt};
struct Empty;
impl ReadAt for Empty {
    fn len(&self) -> u64 {
        0
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset != 0 || !out.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}
fn identity(n: u8) -> ObjectId {
    ObjectId {
        source: 0x54524545,
        generation: 1,
        native: vec![n],
    }
}
fn entry(
    n: u8,
    parent: Option<u8>,
    name: &str,
    source: Option<Arc<dyn ReadAt>>,
) -> FatBuildTreeEntry {
    FatBuildTreeEntry {
        identity: identity(n),
        parent: parent.map(identity),
        name: name.encode_utf16().collect(),
        source,
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let image = args
        .next()
        .ok_or("usage: filesystem-fat-build-tree IMAGE FAMILY PAYLOAD forward|reverse")?;
    let (family, length) = match args.next().as_deref() {
        Some("12") => (FatFamily::Fat12, 1440 * 1024),
        Some("16") => (FatFamily::Fat16, 32 * 1024 * 1024),
        Some("32") => (FatFamily::Fat32, 64 * 1024 * 1024),
        _ => return Err("FAMILY must be 12, 16 or 32".into()),
    };
    let payload: Arc<dyn ReadAt> =
        Arc::new(RawDisk::open(args.next().ok_or("supply PAYLOAD path")?)?);
    let reverse = match args.next().as_deref() {
        Some("forward") => false,
        Some("reverse") => true,
        _ => return Err("supply forward|reverse".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut entries = vec![entry(1, None, "EFI", None), entry(2, Some(1), "BOOT", None)];
    for (n, name) in [
        "BOOTX64.EFI",
        "Long boot payload sharing prefix alpha.txt",
        "Long boot payload sharing prefix beta.txt",
        "Long boot payload sharing prefix gamma.txt",
        "123456789.txt",
    ]
    .iter()
    .enumerate()
    {
        entries.push(entry(3 + n as u8, Some(2), name, Some(payload.clone())));
    }
    for n in 0..20 {
        entries.push(entry(
            20 + n,
            None,
            &format!("ROOT{n:03}"),
            Some(Arc::new(Empty)),
        ));
    }
    if reverse {
        entries.reverse();
    }
    let resources = Resources {
        memory: Budget::new(16 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let plan = FatBuildPlan::new_tree(
        length,
        FatBuildOptions {
            family,
            sectors_per_cluster: 1,
            volume_id: 0x504d5452,
        },
        &entries,
        FatTreeMetadataPolicy::DeterministicDefaults,
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
    let report = plan.emit(&mut FileStorage::open(image)?, &resources)?;
    println!(
        "profile=efi-shaped-tree-v1 family={family:?} image_bytes={length} files={} metadata=deterministic-defaults namespace=ascii-fold-exact-other-utf16",
        report.files
    );
    Ok(())
}
