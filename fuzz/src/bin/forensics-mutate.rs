//! Reproducible bounded mutation fuzzing using the ordinary Cargo environment.
//! This is feedback-free mutation smoke, not sanitizer or coverage qualification.
use partmgr_fuzz::ObservedProfiles;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn add(total: &mut ObservedProfiles, seen: ObservedProfiles) {
    total.fat_slots += seen.fat_slots;
    total.fat_entries += seen.fat_entries;
    total.mft_slots += seen.mft_slots;
    total.file_records += seen.file_records;
    total.usn_records += seen.usn_records;
}
fn mutate(seed: &[u8], case: u64, state: &mut u64) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    if bytes.is_empty() {
        bytes.push(0);
    }
    let position = random(state) as usize % bytes.len();
    match case % 8 {
        0 => bytes[position] ^= 1 << (random(state) % 8),
        1 => bytes.truncate(position),
        2 => {
            for byte in bytes.iter_mut().skip(position).take(8) {
                *byte = random(state) as u8;
            }
        }
        3 => {
            for byte in bytes.iter_mut().skip(position).take(32) {
                *byte = 0;
            }
        }
        4 => {
            let copy = bytes[position..bytes.len().min(position + 32)].to_vec();
            bytes.splice(position..position, copy);
            bytes.truncate(1 << 20);
        }
        5 => {
            let position = random(state) as usize % bytes.len().min(128);
            for byte in bytes.iter_mut().skip(position).take(8) {
                *byte = 0xff;
            }
        }
        6 => {
            bytes.resize((random(state) as usize % 8192) + 1, 0);
            for byte in &mut bytes {
                *byte = random(state) as u8;
            }
        }
        _ => {
            let start = if bytes.len() > 512 { 512 } else { 0 };
            let position = start + random(state) as usize % (bytes.len() - start);
            bytes[position] ^= 0xff;
        }
    }
    bytes
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let iterations: u64 = args
        .next()
        .ok_or("usage: forensics-mutate ITERATIONS EVIDENCE_DIRECTORY")?
        .parse()?;
    let output = PathBuf::from(args.next().ok_or("missing evidence directory")?);
    if args.next().is_some() || iterations == 0 || iterations > 1_000_000 {
        return Err("iterations must be 1..=1000000".into());
    }
    fs::create_dir(&output)?;
    let seeds = partmgr_fuzz::seeds("forensics");
    let mut profiles = ObservedProfiles::default();
    let mut seed_hashes = Vec::new();
    for (index, seed) in seeds.iter().enumerate() {
        add(&mut profiles, partmgr_fuzz::forensics_with_profiles(seed));
        fs::write(output.join(format!("seed-{index:03}.bin")), seed)?;
        seed_hashes.push(format!("{:x}", Sha256::digest(seed)));
    }
    if profiles.fat_slots == 0
        || profiles.fat_entries == 0
        || profiles.mft_slots == 0
        || profiles.file_records == 0
        || profiles.usn_records == 0
    {
        return Err(format!("positive parser paths missing: {profiles:?}").into());
    }
    let mut state = 0x7061_7274_6d67_7231u64;
    let mut input_hash = Sha256::new();
    let mut completed = 0;
    let mut failure = None;
    for case in 0..iterations {
        let seed = &seeds[random(&mut state) as usize % seeds.len()];
        let bytes = mutate(seed, case, &mut state);
        input_hash.update(case.to_le_bytes());
        input_hash.update((bytes.len() as u64).to_le_bytes());
        input_hash.update(&bytes);
        match std::panic::catch_unwind(|| partmgr_fuzz::forensics_with_profiles(&bytes)) {
            Ok(seen) => {
                add(&mut profiles, seen);
                completed += 1;
            }
            Err(payload) => {
                fs::write(output.join(format!("finding-{case:06}.bin")), &bytes)?;
                failure = Some(
                    payload
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| payload.downcast_ref::<&str>().copied())
                        .unwrap_or("non-string panic")
                        .to_owned(),
                );
                break;
            }
        }
    }
    let binary_hash = format!("{:x}", Sha256::digest(fs::read(std::env::current_exe()?)?));
    let mut receipt = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("receipt.json"))?;
    write!(
        receipt,
        "{{\"version\":1,\"profile\":\"deterministic-feedback-free-mutation-v1\",\"instrumented\":false,\"iterations_requested\":{iterations},\"iterations_completed\":{completed},\"binary_sha256\":\"{binary_hash}\",\"input_sequence_sha256\":\"{:x}\",\"seed_sha256\":[",
        input_hash.finalize()
    )?;
    for (index, hash) in seed_hashes.iter().enumerate() {
        if index != 0 {
            receipt.write_all(b",")?;
        }
        write!(receipt, "\"{hash}\"")?;
    }
    write!(
        receipt,
        "],\"observed_profiles\":{{\"fat_slots\":{},\"fat_entries\":{},\"mft_slots\":{},\"file_records\":{},\"usn_records\":{}}},\"failure\":",
        profiles.fat_slots,
        profiles.fat_entries,
        profiles.mft_slots,
        profiles.file_records,
        profiles.usn_records
    )?;
    match &failure {
        Some(message) => partmgr::forensics_json::string(&mut receipt, message)?,
        None => receipt.write_all(b"null")?,
    }
    writeln!(
        receipt,
        ",\"passed\":{}}}",
        failure.is_none() && completed == iterations
    )?;
    receipt.sync_all()?;
    io::stdout().write_all(
        format!("mutation cases completed={completed}/{iterations}; profiles={profiles:?}\n")
            .as_bytes(),
    )?;
    if failure.is_some() {
        return Err("mutation campaign found a panic; retained input and receipt".into());
    }
    Ok(())
}
