//! Private closed-body integrity for native legacy JBD transactions.
//! This occupies unused commit padding; native journal features remain unchanged.
use super::*;
use sha2::{Digest, Sha256};
const MAGIC: &[u8; 16] = b"PMGRJBD2SHA256V1";
const FOOTER: usize = 640;
const DIGEST: usize = 672;
pub(super) struct Integrity {
    state: Sha256,
    count: u32,
    sequence: u32,
}
impl Integrity {
    pub(super) fn new(g: &Geometry, sequence: u32) -> Self {
        let mut state = Sha256::new();
        state.update(b"partmgr-native-legacy-jbd-v1\0");
        state.update(g.uuid);
        state.update(sequence.to_be_bytes());
        state.update((g.block_bytes as u32).to_be_bytes());
        Self {
            state,
            count: 0,
            sequence,
        }
    }
    pub(super) fn feed(&mut self, logical: u32, bytes: &[u8]) -> io::Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| budget("legacy JBD body record count"))?;
        self.state.update(logical.to_be_bytes());
        self.state.update(bytes);
        Ok(())
    }
    fn digest(&self, commit: &[u8]) -> [u8; 32] {
        let mut state = self.state.clone();
        state.update(&commit[..DIGEST]);
        state.update([0; 32]);
        state.update(&commit[DIGEST + 32..]);
        state.finalize().into()
    }
    pub(super) fn verify(&self, g: &Geometry, commit: &[u8]) -> io::Result<()> {
        if &commit[FOOTER..FOOTER + 16] != MAGIC {
            return Err(unsupported(
                "legacy owned recovery requires closed-body integrity marker",
            ));
        }
        if be32(commit, 656) != 1
            || be32(commit, 660) != 1
            || be32(commit, 664) != self.count
            || be32(commit, 668) != g.block_bytes as u32
            || commit[704..720] != g.uuid
            || be32(commit, 720) != self.sequence
            || commit[724..728] != [0; 4]
            || commit[DIGEST..DIGEST + 32] != self.digest(commit)
        {
            return Err(invalid("legacy JBD closed-body integrity/binding"));
        }
        Ok(())
    }
}
pub(super) fn stamp(g: &Geometry, blocks: &mut [LogBlock]) -> io::Result<()> {
    if !matches!(g.checksums, Checksums::None) {
        return Ok(());
    }
    let (commit, body) = blocks
        .split_last_mut()
        .ok_or_else(|| invalid("legacy JBD empty body"))?;
    let mut integrity = Integrity::new(g, g.sequence);
    for record in body {
        integrity.feed(record.logical, &record.bytes[..g.block_bytes])?;
    }
    let bytes = &mut commit.bytes[..g.block_bytes];
    bytes[FOOTER..FOOTER + 16].copy_from_slice(MAGIC);
    put32(bytes, 656, 1);
    put32(bytes, 660, 1);
    put32(bytes, 664, integrity.count);
    put32(bytes, 668, g.block_bytes as u32);
    bytes[704..720].copy_from_slice(&g.uuid);
    put32(bytes, 720, g.sequence);
    bytes[724..728].fill(0);
    bytes[DIGEST..DIGEST + 32].fill(0);
    let digest = integrity.digest(bytes);
    bytes[DIGEST..DIGEST + 32].copy_from_slice(&digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_core::{Budget, Cancellation};
    fn fixture() -> (Geometry, Vec<Vec<u8>>) {
        let g = Geometry {
            block_bytes: 1024,
            first: 1,
            maximum: 8,
            start: 1,
            sequence: 7,
            uuid: [0x31; 16],
            checksums: Checksums::None,
            revoke: false,
        };
        let mut blocks = vec![vec![0; 1024]; 8];
        for (logical, kind) in [(1usize, 1u32), (3, 2)] {
            blocks[logical][..4].copy_from_slice(&super::super::MAGIC.to_be_bytes());
            blocks[logical][4..8].copy_from_slice(&kind.to_be_bytes());
            blocks[logical][8..12].copy_from_slice(&7u32.to_be_bytes());
        }
        blocks[1][12..16].copy_from_slice(&99u32.to_be_bytes());
        blocks[1][16..20].copy_from_slice(&8u32.to_be_bytes());
        blocks[1][20..36].fill(0x31);
        blocks[2].fill(0x57);
        reseal(&g, &mut blocks);
        (g, blocks)
    }
    // Independent field assembly and one-shot SHA input; no production stamp/feed.
    fn reseal(g: &Geometry, blocks: &mut [Vec<u8>]) {
        let commit = &mut blocks[3];
        commit[640..656].copy_from_slice(b"PMGRJBD2SHA256V1");
        for (at, value) in [(656, 1u32), (660, 1), (664, 2), (668, 1024), (720, 7)] {
            commit[at..at + 4].copy_from_slice(&value.to_be_bytes());
        }
        commit[704..720].fill(0x31);
        commit[672..704].fill(0);
        let mut input = b"partmgr-native-legacy-jbd-v1\0".to_vec();
        input.extend_from_slice(&g.uuid);
        input.extend_from_slice(&7u32.to_be_bytes());
        input.extend_from_slice(&1024u32.to_be_bytes());
        for logical in [1, 2] {
            input.extend_from_slice(&(logical as u32).to_be_bytes());
            input.extend_from_slice(&blocks[logical]);
        }
        input.extend_from_slice(&blocks[3]);
        let digest = Sha256::digest(input);
        blocks[3][672..704].copy_from_slice(&digest);
    }
    #[test]
    fn independently_sealed_legacy_body_corruption_and_rehashed_semantics() {
        let r = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        let (g, blocks) = fixture();
        let inspect = |blocks: &[Vec<u8>]| {
            scan_owned(
                &g,
                4,
                100,
                &r,
                |logical, out| {
                    out.copy_from_slice(&blocks[logical as usize]);
                    Ok(())
                },
                |target| {
                    if target == 99 {
                        Ok(())
                    } else {
                        Err(invalid("fixture target binding"))
                    }
                },
            )
        };
        let plan = inspect(&blocks).unwrap();
        assert_eq!(plan.committed_transactions, 1);
        assert_eq!(plan.blocks[0].bytes[..1024], [0x57; 1024]);
        drop(plan);
        assert_eq!(r.memory.used(), 0);
        for (logical, at) in [(1, 50), (2, 17), (3, 700), (3, 300), (3, 720)] {
            let mut changed = blocks.clone();
            changed[logical][at] ^= 1;
            assert!(inspect(&changed).is_err());
            assert_eq!(r.memory.used(), 0);
        }
        let mut changed = blocks.clone();
        changed[1][16] = 1;
        reseal(&g, &mut changed);
        assert_eq!(
            inspect(&changed).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        let mut changed = blocks.clone();
        changed[1][15] = 98;
        reseal(&g, &mut changed);
        assert!(inspect(&changed).is_err());
        let mut changed = blocks.clone();
        changed[3][640..656].fill(0);
        assert_eq!(
            inspect(&changed).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn owned_legacy_native_prepare_publication_recovery_all_write_barrier_torn_cuts() {
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let mut bytes = bootstrap::tests::fixture().0;
        bytes[100 * 1024 + 40..100 * 1024 + 44].copy_from_slice(&1u32.to_be_bytes());
        bytes[100 * 1024 + 80] = 0;
        bytes[100 * 1024 + 252..100 * 1024 + 256].fill(0);
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let limits = session::Limits {
            audit: crate::fs_ext_audit::ExtAuditLimits {
                blocks: 2048,
                inodes: 128,
                work: 1000000,
                directory_blocks: 8,
                directory_entries: 32,
                findings: 8,
            },
            file_blocks: 256,
            affected_blocks: 256,
            affected_bytes: 1 << 20,
        };
        let planning = crate::fs_ext_edit::ExtEditLimits {
            audit: limits.audit,
            file_blocks: 256,
            directory_entries: 32,
            affected_bytes: 1 << 20,
            work: 100000,
            undo: crate::fs_undo::UndoLimits {
                patches: 1024,
                body_bytes: 4 << 20,
            },
        };
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
        let payload = vec![0x57; 4097];
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::CreateFile {
                    parent: &[],
                    name: b"legacy\xff",
                    metadata: &metadata,
                    payload: &payload,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        perform(&mut success).unwrap();
        let file = success
            .file_at(
                &[crate::fs_core::NativeName::Bytes(b"legacy\xff".to_vec())],
                &r.cancellation,
            )
            .unwrap();
        let mut actual = vec![0; payload.len()];
        assert_eq!(
            success
                .read_at(&file, 0, &mut actual, &r.cancellation)
                .unwrap(),
            payload.len()
        );
        assert_eq!(actual, payload);
        drop(file);
        let (success, _) = success.into_storage();
        assert_eq!(
            &success.durable[100 * 1024 + 40..100 * 1024 + 44],
            &1u32.to_be_bytes()
        );
        assert_eq!(success.durable[100 * 1024 + 80], 0);
        assert_eq!(
            &success.durable[100 * 1024 + 252..100 * 1024 + 256],
            &[0; 4]
        );
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=success.events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
                        target.visible.clone_from(&target.durable);
                        target.cut = usize::MAX;
                        recovery::recover(
                            &mut target,
                            18u128 << 64,
                            limits.audit,
                            limits.affected_blocks + 1,
                            &r,
                        )
                        .unwrap();
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial legacy home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}
