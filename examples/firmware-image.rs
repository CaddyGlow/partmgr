//! Generate representative table images for the independent firmware gate.
use partmgr::{
    codec::initialize_plan,
    guid::Guid,
    layout::{DiskLayout, Geometry, GptLayout, LbaRange, MbrLayout},
    storage::FileStorage,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let path = args.get(2).ok_or("usage: firmware-image gpt|mbr PATH")?;
    let file = std::fs::File::create(path)?;
    file.set_len(128 * 1024 * 1024)?;
    drop(file);
    let geometry = Geometry::new(128 * 1024 * 1024, 512)?;
    let range = LbaRange::new(2048, 2048 + 196608)?;
    let layout = match args.get(1).map(String::as_str) {
        Some("gpt") => {
            let mut layout = GptLayout::initialize(geometry, Guid::from_bytes([1; 16]), 128, 128)?;
            layout.create(
                1,
                "c12a7328-f81f-11d2-ba4b-00a0c93ec93b".parse()?,
                Guid::from_bytes([2; 16]),
                range,
            )?;
            DiskLayout::Gpt(layout)
        }
        Some("mbr") => {
            let mut layout = MbrLayout::initialize(geometry, 0x12345678);
            layout.create(1, 0xef, range, false)?;
            DiskLayout::Mbr(layout)
        }
        _ => return Err("expected gpt or mbr".into()),
    };
    let mut storage = FileStorage::open(path)?;
    let plan = initialize_plan(&virtdisk::RawDisk::open(path)?, &layout)?;
    plan.commit(&mut storage)?;
    Ok(())
}
