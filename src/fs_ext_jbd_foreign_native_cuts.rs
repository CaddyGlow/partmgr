//! Disposable native corpus cut artifacts; native recovery is verified separately.
use super::*;

#[derive(Clone, Copy)]
enum Cut {
    Prefix(usize),
    Mask(u8),
    Flush(bool),
}
struct Fault {
    visible: Vec<u8>,
    durable: Vec<u8>,
    event: usize,
    at: usize,
    immediate: bool,
    cut: Cut,
    hit: bool,
}
impl Storage for Fault {
    fn len(&self) -> io::Result<u64> {
        Ok(self.visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.visible
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.event += 1;
        let at = usize::try_from(at).map_err(io::Error::other)?;
        if self.event == self.at {
            self.hit = true;
            for (i, byte) in bytes.iter().enumerate() {
                let selected = match self.cut {
                    Cut::Prefix(n) => i < n,
                    Cut::Mask(mask) => i < 4 && mask & (1 << i) != 0,
                    Cut::Flush(_) => panic!("flush cut at write"),
                };
                if selected {
                    self.visible[at + i] = *byte;
                    if self.immediate {
                        self.durable[at + i] = *byte;
                    }
                }
            }
            return Err(io::Error::other("injected native cut write"));
        }
        self.visible[at..at + bytes.len()].copy_from_slice(bytes);
        if self.immediate {
            self.durable[at..at + bytes.len()].copy_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.event += 1;
        if self.event == self.at {
            self.hit = true;
            if matches!(self.cut, Cut::Flush(true)) {
                self.durable.clone_from(&self.visible);
            } else {
                assert!(matches!(self.cut, Cut::Flush(false)));
            }
            return Err(io::Error::other("injected native cut flush"));
        }
        self.durable.clone_from(&self.visible);
        Ok(())
    }
}
fn limits() -> Limits {
    Limits {
        journal_blocks: 65536,
        bootstrap_work: 32_000_000,
        records: 1024,
        scan_work: 32_000_000,
        audit: ExtAuditLimits {
            blocks: 65536,
            inodes: 16384,
            work: 64_000_000,
            directory_blocks: 65536,
            directory_entries: 65536,
            findings: 1024,
        },
    }
}
fn image(out: &Path, bytes: &[u8]) -> (String, String) {
    let digest = hash(bytes);
    let relative = format!("images/{digest}.raw");
    let path = out.join(&relative);
    if path.exists() {
        assert_eq!(fs::read(path).unwrap(), bytes);
    } else {
        fs::write(path, bytes).unwrap();
    }
    (digest, relative)
}
pub(super) fn run(out: &Path, bs: usize, dirty: &[u8], native: &[u8], journal_at: usize) {
    fs::create_dir_all(out.join("images")).unwrap();
    let manifest = out.join("cuts.tsv");
    let mut rows = if manifest.exists() {
        fs::read_to_string(&manifest).unwrap()
    } else {
        "block_bytes\tcase\tevent\tmodel\tfault_kind\tselector\tpre_sha256\tpre_path\tretried_sha256\tretried_path\trestart_sequence\n".into()
    };
    let scope = 18u128 << 64 | bs as u128;
    let mut baseline = Writable {
        bytes: dirty.to_vec(),
        writes: 0,
        flushes: 0,
    };
    let baseline_resources = Resources {
        memory: crate::fs_core::Budget::new(128 << 20),
        cancellation: crate::fs_core::Cancellation::default(),
    };
    super::super::recover::recover(&mut baseline, scope, limits(), &baseline_resources).unwrap();
    assert_eq!((baseline.writes, baseline.flushes), (4, 4));
    assert_eq!(baseline.bytes, native);
    assert_eq!(baseline_resources.memory.used(), 0);
    let mut case = 0;
    let home_at = if bs == 1024 { bs } else { 0 };
    let inside = if bs == 1024 { 0 } else { 1024 };
    let mut checkpoint = dirty.to_vec();
    checkpoint[home_at..home_at + bs].copy_from_slice(&native[home_at..home_at + bs]);
    checkpoint[1120] |= 4;
    let mut torn_home = false;
    // Current admitted one-home transaction has four writes and four barriers.
    for event in 1..=8 {
        let mut cuts = Vec::new();
        if event % 2 == 0 {
            cuts.extend([Cut::Flush(false), Cut::Flush(true)]);
        } else {
            let size = if event == 1 {
                bs
            } else if event == 7 {
                1
            } else {
                4
            };
            let mut prefixes = if event == 1 {
                vec![
                    0,
                    1,
                    511,
                    512,
                    1023,
                    bs / 2,
                    bs - 1,
                    bs,
                    inside + 137,
                    inside + 150,
                    inside + 199,
                ]
            } else {
                (0..=size).collect()
            };
            prefixes.retain(|n| *n <= size);
            prefixes.sort_unstable();
            prefixes.dedup();
            cuts.extend(prefixes.into_iter().map(Cut::Prefix));
            if size == 4 {
                cuts.extend((0..16).map(Cut::Mask));
            }
        }
        for immediate in [false, true] {
            for cut in &cuts {
                case += 1;
                let mut target = Fault {
                    visible: dirty.to_vec(),
                    durable: dirty.to_vec(),
                    event: 0,
                    at: event,
                    immediate,
                    cut: *cut,
                    hit: false,
                };
                let r = Resources {
                    memory: crate::fs_core::Budget::new(128 << 20),
                    cancellation: crate::fs_core::Cancellation::default(),
                };
                let error = super::super::recover::recover(&mut target, scope, limits(), &r)
                    .err()
                    .expect("cut must fail");
                assert!(target.hit);
                assert!(format!("{error:?}").contains("UncertainDurability"));
                assert_eq!(r.memory.used(), 0);
                if event == 1
                    && immediate
                    && target.durable != dirty
                    && target.durable != checkpoint
                {
                    torn_home = true;
                }
                let (pre_hash, pre_path) = image(out, &target.durable);
                // Power loss discards all volatile bytes before independent retry.
                let mut retry = Writable {
                    bytes: target.durable,
                    writes: 0,
                    flushes: 0,
                };
                let outcome =
                    super::super::recover::recover(&mut retry, scope, limits(), &r).unwrap();
                assert_eq!(r.memory.used(), 0);
                let mut normalized = retry.bytes.clone();
                normalized[journal_at + 24..journal_at + 28]
                    .copy_from_slice(&native[journal_at + 24..journal_at + 28]);
                assert_eq!(normalized, native, "cut {case} event {event}");
                let (retry_hash, retry_path) = image(out, &retry.bytes);
                let (kind, selector) = match cut {
                    Cut::Prefix(n) => ("write-prefix", *n),
                    Cut::Mask(n) => ("write-mask", *n as usize),
                    Cut::Flush(p) => (if *p { "flush-persist" } else { "flush-none" }, 0),
                };
                writeln!(rows,"{bs}\t{case}\t{event}\t{}\t{kind}\t{selector}\t{pre_hash}\t{pre_path}\t{retry_hash}\t{retry_path}\t{}",if immediate {"immediate"} else {"volatile"},outcome.restart_sequence).unwrap();
            }
        }
    }
    assert!(
        torn_home,
        "must retain a home image distinct from both old and complete redo"
    );
    fs::write(manifest, rows).unwrap();
}
