//! Bounded read-only NTFS compression-unit assembly using published LZNT1 decoding.
use super::*;

/// Caller-selected ceilings for NTFS compression-unit inspection.
#[derive(Clone, Copy, Debug)]
pub struct NtfsCompressionLimits {
    /// Maximum decoded unit size; supported native units never exceed 65536 bytes.
    pub max_unit_bytes: usize,
    /// Maximum compression units touched by one read.
    pub max_units_per_read: usize,
    /// Maximum extent transitions and units processed by one operation.
    pub max_work: usize,
}

pub(crate) struct CompressedContent {
    source: Arc<dyn ReadAt>,
    length: u64,
    initialized: u64,
    unit: u64,
    extents: Vec<FileExtent>,
    limits: NtfsCompressionLimits,
}
impl CompressedContent {
    pub(super) fn new(
        source: Arc<dyn ReadAt>,
        length: u64,
        initialized: u64,
        cluster_bytes: u64,
        compression_unit: u16,
        extents: Vec<FileExtent>,
        limits: NtfsCompressionLimits,
    ) -> Result<Self> {
        if compression_unit != 4
            || !(512..=4096).contains(&cluster_bytes)
            || !cluster_bytes.is_power_of_two()
            || initialized > length
        {
            return Err(unsupported("NTFS compression geometry/profile"));
        }
        let unit = cluster_bytes * 16;
        if unit > limits.max_unit_bytes as u64 {
            return Err(budget("NTFS compressed unit byte limit"));
        }
        if extents.len() > limits.max_work {
            return Err(budget("NTFS compressed map work limit"));
        }
        let mut end = 0u64;
        let mut previous_hole = false;
        for e in &extents {
            if e.offset != end || e.length == 0 || !e.length.is_multiple_of(cluster_bytes) {
                return Err(bad("NTFS compressed map framing"));
            }
            end = end
                .checked_add(e.length)
                .ok_or_else(|| bad("NTFS compressed map overflow"))?;
            match e.kind {
                MapKind::Data(p) => {
                    if !p.is_multiple_of(cluster_bytes)
                        || p.checked_add(e.length).is_none_or(|n| n > source.len())
                        || previous_hole && !e.offset.is_multiple_of(unit)
                    {
                        return Err(bad("NTFS compressed physical map/unit ordering"));
                    }
                    previous_hole = false;
                }
                MapKind::Hole => previous_hole = true,
                MapKind::Unwritten => {
                    return Err(bad("NTFS compression requires raw allocation map"));
                }
            }
        }
        if end < length {
            return Err(bad("NTFS compressed virtual coverage"));
        }
        if end != 0 && !end.is_multiple_of(unit) {
            return Err(unsupported(
                "NTFS partial compression-unit allocation profile",
            ));
        }
        Ok(Self {
            source,
            length,
            initialized,
            unit,
            extents,
            limits,
        })
    }
    pub(super) fn len(&self) -> u64 {
        self.length
    }

    fn segments(&self, start: u64) -> impl Iterator<Item = &FileExtent> {
        let index = self
            .extents
            .partition_point(|e| e.offset + e.length <= start);
        self.extents[index..]
            .iter()
            .take_while(move |e| e.offset < start + self.unit)
    }
    fn tick(&self, work: &mut usize, r: &Resources) -> Result<()> {
        r.cancellation.check()?;
        *work = work
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or_else(|| budget("NTFS compression work limit"))?;
        Ok(())
    }
    pub(super) fn read_at(&self, offset: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        if offset >= self.length || out.is_empty() {
            return Ok(0);
        }
        let count = (self.length - offset).min(out.len() as u64) as usize;
        let first = offset / self.unit;
        let last = (offset + count as u64 - 1) / self.unit;
        if last - first + 1 > self.limits.max_units_per_read as u64 {
            return Err(budget("NTFS compression read unit limit"));
        }
        let _lease = r.memory.reserve(self.unit * 2)?;
        let mut packed = vector(self.unit as usize)?;
        packed.resize(self.unit as usize, 0);
        let mut decoded = vector(self.unit as usize)?;
        decoded.resize(self.unit as usize, 0);
        let mut work = 0;
        let mut done = 0;
        while done < count {
            self.tick(&mut work, r)?;
            let at = offset + done as u64;
            let start = at / self.unit * self.unit;
            let within = (at - start) as usize;
            let n = (self.unit as usize - within).min(count - done);
            decoded.fill(0);
            if at < self.initialized {
                let mut allocated = 0usize;
                let mut hole = false;
                for extent in self.segments(start) {
                    self.tick(&mut work, r)?;
                    hole |= matches!(extent.kind, MapKind::Hole);
                }
                for e in self.segments(start) {
                    self.tick(&mut work, r)?;
                    let lo = start.max(e.offset);
                    let hi = (start + self.unit).min(e.offset + e.length);
                    let hi = if hole { hi } else { hi.min(self.initialized) };
                    if hi <= lo {
                        continue;
                    }
                    match e.kind {
                        MapKind::Data(p) => {
                            let bytes = (hi - lo) as usize;
                            self.source
                                .read_exact_at(
                                    p + (lo - e.offset),
                                    &mut packed[allocated..allocated + bytes],
                                )
                                .map_err(|e| Error::io("NTFS compressed unit read", e))?;
                            allocated += bytes;
                        }
                        MapKind::Hole => {}
                        MapKind::Unwritten => return Err(bad("NTFS compressed map changed")),
                    }
                }
                if allocated != 0 {
                    if !hole {
                        decoded[..allocated].copy_from_slice(&packed[..allocated]);
                    } else {
                        let (written, _) = ms_compress::lznt1::decompress_storage_unit(
                            &packed[..allocated],
                            &mut decoded,
                        )
                        .map_err(|_| bad("NTFS malformed LZNT1 compression unit"))?;
                        let required = (self.initialized.min(start + self.unit) - start) as usize;
                        if written < required {
                            return Err(bad("NTFS short LZNT1 compression unit"));
                        }
                    }
                }
                let initialized = (self.initialized.saturating_sub(start)).min(self.unit) as usize;
                decoded[initialized..].fill(0);
            }
            out[done..done + n].copy_from_slice(&decoded[within..within + n]);
            done += n;
        }
        Ok(count)
    }
    pub(super) fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        let mut start = 0;
        let mut work = 0;
        while start < self.length {
            self.tick(&mut work, r)?;
            let end = (start + self.unit).min(self.length);
            let mut data = false;
            for e in self.segments(start) {
                self.tick(&mut work, r)?;
                data |= matches!(e.kind, MapKind::Data(_));
            }
            let split = self.initialized.min(end).max(start);
            if split > start {
                visitor(LogicalExtent {
                    offset: start,
                    length: split - start,
                    kind: if data {
                        ExtentKind::Data
                    } else {
                        ExtentKind::Hole
                    },
                })?;
            }
            if end > split {
                visitor(LogicalExtent {
                    offset: split,
                    length: end - split,
                    kind: if data {
                        ExtentKind::Unwritten
                    } else {
                        ExtentKind::Hole
                    },
                })?;
            }
            start = end;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    struct Image(Vec<u8>);
    impl ReadAt for Image {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
            let at = offset as usize;
            out.copy_from_slice(
                self.0
                    .get(at..at + out.len())
                    .ok_or(crate::io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
    }
    fn resources() -> Resources {
        Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        }
    }
    fn limits() -> NtfsCompressionLimits {
        NtfsCompressionLimits {
            max_unit_bytes: 65536,
            max_units_per_read: 8,
            max_work: 128,
        }
    }
    #[test]
    fn huge_sparse_logical_offsets_do_not_overflow_physical_reads() {
        let unit = 8192u64;
        let end = u64::MAX / unit * unit;
        let start = end - unit;
        let file = CompressedContent::new(
            Arc::new(Image(vec![42; 4 * unit as usize])),
            end,
            end,
            512,
            4,
            vec![
                FileExtent {
                    offset: 0,
                    length: start,
                    kind: MapKind::Hole,
                },
                FileExtent {
                    offset: start,
                    length: unit,
                    kind: MapKind::Data(3 * unit),
                },
            ],
            limits(),
        )
        .unwrap();
        let mut out = [0; 16];
        assert_eq!(file.read_at(start, &mut out, &resources()).unwrap(), 16);
        assert_eq!(out, [42; 16]);
    }
    #[test]
    fn classification_pass_consumes_work_budget_before_payload_reads() {
        let file = CompressedContent::new(
            Arc::new(Image(vec![42; 8192])),
            8192,
            8192,
            512,
            4,
            vec![FileExtent {
                offset: 0,
                length: 8192,
                kind: MapKind::Data(0),
            }],
            NtfsCompressionLimits {
                max_work: 2,
                ..limits()
            },
        )
        .unwrap();
        let mut out = [7; 16];
        assert_eq!(
            file.read_at(0, &mut out, &resources()).unwrap_err().kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(out, [7; 16]);
    }
    #[test]
    fn compressed_unit_uses_published_decoder_and_hides_initialized_tail() {
        let mut bytes = vec![0; 512];
        bytes[..12].copy_from_slice(&[3, 0xb0, 2, b'A', 0xfc, 0x0f, 3, 0xb0, 2, b'A', 0xfc, 0x0f]);
        let file = CompressedContent::new(
            Arc::new(Image(bytes)),
            8192,
            5000,
            512,
            4,
            vec![
                FileExtent {
                    offset: 0,
                    length: 512,
                    kind: MapKind::Data(0),
                },
                FileExtent {
                    offset: 512,
                    length: 7680,
                    kind: MapKind::Hole,
                },
            ],
            limits(),
        )
        .unwrap();
        let r = resources();
        let mut out = vec![9; 4000];
        assert_eq!(file.read_at(4000, &mut out, &r).unwrap(), 4000);
        assert!(out[..1000].iter().all(|b| *b == b'A'));
        assert!(out[1000..].iter().all(|b| *b == 0));
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn malformed_unit_does_not_publish_partial_codec_output() {
        let mut bytes = vec![0; 512];
        bytes[..3].copy_from_slice(&[0, 0x30, b'A']);
        let file = CompressedContent::new(
            Arc::new(Image(bytes)),
            8192,
            8192,
            512,
            4,
            vec![
                FileExtent {
                    offset: 0,
                    length: 512,
                    kind: MapKind::Data(0),
                },
                FileExtent {
                    offset: 512,
                    length: 7680,
                    kind: MapKind::Hole,
                },
            ],
            limits(),
        )
        .unwrap();
        let r = resources();
        let mut out = [7; 16];
        assert!(file.read_at(0, &mut out, &r).is_err());
        assert_eq!(out, [7; 16]);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn raw_unit_reads_only_initialized_bytes_and_zero_units_need_no_payload() {
        struct Guarded;
        impl ReadAt for Guarded {
            fn len(&self) -> u64 {
                8192
            }
            fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> crate::io::Result<()> {
                assert!(offset + out.len() as u64 <= 100);
                out.fill(42);
                Ok(())
            }
        }
        let file = CompressedContent::new(
            Arc::new(Guarded),
            8192,
            100,
            512,
            4,
            vec![FileExtent {
                offset: 0,
                length: 8192,
                kind: MapKind::Data(0),
            }],
            limits(),
        )
        .unwrap();
        let r = resources();
        let mut out = [9; 200];
        file.read_at(50, &mut out, &r).unwrap();
        assert!(out[..50].iter().all(|b| *b == 42));
        assert!(out[50..].iter().all(|b| *b == 0));
        file.read_at(500, &mut out, &r).unwrap();
        assert_eq!(out, [0; 200]);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn hole_then_data_is_only_valid_at_unit_boundary() {
        let source: Arc<dyn ReadAt> = Arc::new(Image(vec![0; 8192]));
        assert!(
            CompressedContent::new(
                source.clone(),
                8192,
                8192,
                512,
                4,
                vec![
                    FileExtent {
                        offset: 0,
                        length: 512,
                        kind: MapKind::Hole
                    },
                    FileExtent {
                        offset: 512,
                        length: 7680,
                        kind: MapKind::Data(0)
                    }
                ],
                limits()
            )
            .is_err()
        );
        let file = CompressedContent::new(
            source,
            16384,
            16384,
            512,
            4,
            vec![
                FileExtent {
                    offset: 0,
                    length: 8192,
                    kind: MapKind::Hole,
                },
                FileExtent {
                    offset: 8192,
                    length: 8192,
                    kind: MapKind::Data(0),
                },
            ],
            limits(),
        )
        .unwrap();
        assert_eq!(file.len(), 16384);
    }
}
