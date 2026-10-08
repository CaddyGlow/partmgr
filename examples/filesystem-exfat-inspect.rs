//! Inspect exFAT boot regions independently of namespace or allocation claims.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_exfat::ExfatBoot,
};
use std::sync::Arc;
use virtdisk::{DiskView, RawDisk, ReadAt};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() != 4 {
        return Err("usage: filesystem-exfat-inspect IMAGE OFFSET LENGTH".into());
    }
    let disk: Arc<dyn ReadAt> = Arc::new(RawDisk::open(&arguments[1])?);
    let region = DiskView::new(disk, arguments[2].parse()?, arguments[3].parse()?)?;
    let resources = Resources {
        memory: Budget::new(8192),
        cancellation: Cancellation::default(),
    };
    let boot = ExfatBoot::inspect(&region, &resources)?;
    println!(
        "boot_regions=validated sector={} cluster={} volume={} clusters={} fats={} dirty={} media_failure={} namespace=unimplemented allocation_audit=unimplemented",
        boot.sector_bytes,
        boot.cluster_bytes,
        boot.volume_bytes,
        boot.clusters,
        boot.fats,
        boot.is_dirty(),
        boot.has_media_failure()
    );
    Ok(())
}
