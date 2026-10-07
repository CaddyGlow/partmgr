//! Rename a GPT partition while holding exclusive image access.
use partmgr::{
    codec, error,
    layout::DiskLayout,
    storage::{FileStorage, StorageReader},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: rename-gpt IMAGE LOGICAL_SECTOR_SIZE SLOT NAME".into());
    }
    let sector: u32 = args[2].parse()?;
    let slot: u32 = args[3].parse()?;
    let mut storage = FileStorage::open(&args[1])?;
    let old = error::inspect(&StorageReader::new(&storage)?, sector)?;
    let mut proposed = old.clone();
    let DiskLayout::Gpt(gpt) = &mut proposed else {
        return Err("image is not GPT".into());
    };
    gpt.rename(slot, &args[4])?;
    let plan = codec::edit_plan(&old, &proposed)?;
    for stage in plan.stages() {
        println!(
            "{}: {} exact metadata ranges, then durable flush",
            stage.name(),
            stage.writes().len()
        );
    }
    codec::commit_and_inspect(&plan, &mut storage, sector)?;
    Ok(())
}
