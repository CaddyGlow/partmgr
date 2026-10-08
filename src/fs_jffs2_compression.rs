//! Bounded codec primitives shared by positional decoders; strict profiles remain unchanged.
use super::*;
const TAG: u64 = 1 << 63;
/// Per-node and complete-scan bounds for the opt-in compressed reader.
#[derive(Clone, Copy, Debug)]
pub struct Jffs2CompressionLimits {
    /// Maximum encoded bytes in one node (never above 65536).
    pub compressed_node_bytes: usize,
    /// Maximum inflated bytes in one node (never above 65536).
    pub decoded_node_bytes: usize,
    /// Maximum encoded bytes validated across accurate history.
    pub compressed_bytes: u64,
    /// Maximum inflated bytes validated across accurate history.
    pub decoded_bytes: u64,
    /// Maximum encoded plus decoded byte work for validation and each deferred node read.
    pub work: u64,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Node {
    pub(crate) physical: u64,
    pub(crate) encoded: u32,
    pub(crate) decoded: u32,
    pub(crate) codec: u8,
    pub(crate) checksum: u32,
}
pub(crate) struct Registry {
    limits: Jffs2CompressionLimits,
    nodes: Vec<Node>,
    encoded: u64,
    decoded: u64,
    _lease: Arc<Reservation>,
}
impl Registry {
    pub(super) fn new(l: Jffs2CompressionLimits, nodes: usize, r: &Resources) -> Result<Self> {
        if l.compressed_node_bytes == 0
            || l.compressed_node_bytes > 65536
            || l.decoded_node_bytes == 0
            || l.decoded_node_bytes > 65536
            || nodes >= 1 << 31
        {
            return Err(invalid("JFFS2 compressed profile bounds"));
        }
        Ok(Self {
            limits: l,
            nodes: Vec::new(),
            encoded: 0,
            decoded: 0,
            _lease: Arc::new(
                r.memory.reserve(
                    (nodes as u64)
                        .checked_mul(64)
                        .and_then(|n| n.checked_add(256))
                        .ok_or_else(|| budget("JFFS2 codec inventory accounting"))?,
                )?,
            ),
        })
    }
    /// Resolve a compressed address to its physical node and decoded offset.
    /// This certificate, never the scan-order index, identifies its storage dependency.
    pub(crate) fn resolve(&self, address: u64) -> Result<Option<(Node, usize)>> {
        if address & TAG == 0 {
            return Ok(None);
        }
        let index = ((address & !TAG) >> 32) as usize;
        let offset = (address & u64::from(u32::MAX)) as usize;
        let node = *self
            .nodes
            .get(index)
            .ok_or_else(|| invalid("JFFS2 compressed mapping index"))?;
        if offset > node.decoded as usize {
            return Err(invalid("JFFS2 compressed mapping offset"));
        }
        Ok(Some((node, offset)))
    }
    /// Read one physical or compressed mapping through a borrowed positional decoder.
    /// Virtual registry addresses are meaningful only in this registry.
    pub(crate) fn read_mapping(
        &self,
        source: &impl DecodeRead,
        address: u64,
        out: &mut [u8],
        r: &Resources,
        work: &mut u64,
    ) -> Result<()> {
        source.check(r)?;
        if let Some((node, offset)) = self.resolve(address)? {
            *work = work
                .checked_add(u64::from(node.encoded) + u64::from(node.decoded))
                .ok_or_else(|| budget("JFFS2 deferred codec work overflow"))?;
            if *work > self.limits.work {
                return Err(budget("JFFS2 deferred codec read work cap"));
            }
            let end = offset
                .checked_add(out.len())
                .ok_or_else(|| invalid("JFFS2 compressed mapping range overflow"))?;
            if end > node.decoded as usize {
                return Err(invalid("JFFS2 compressed mapping range"));
            }
            let decoded = decode_node(source, node, self.limits, r)?;
            out.copy_from_slice(&decoded.bytes[offset..end]);
        } else {
            source.read(address, out)?;
        }
        source.check(r)
    }
    pub(super) fn add(&mut self, source: &impl DecodeRead, n: Node, r: &Resources) -> Result<u64> {
        if n.encoded as usize > self.limits.compressed_node_bytes
            || n.decoded as usize > self.limits.decoded_node_bytes
        {
            return Err(budget("JFFS2 compressed node bound"));
        }
        self.encoded = self
            .encoded
            .checked_add(u64::from(n.encoded))
            .ok_or_else(|| budget("JFFS2 encoded total"))?;
        self.decoded = self
            .decoded
            .checked_add(u64::from(n.decoded))
            .ok_or_else(|| budget("JFFS2 decoded total"))?;
        if self.encoded > self.limits.compressed_bytes
            || self.decoded > self.limits.decoded_bytes
            || self
                .encoded
                .checked_add(self.decoded)
                .is_none_or(|n| n > self.limits.work)
        {
            return Err(budget("JFFS2 compression scan work"));
        }
        let _ = decode_node(source, n, self.limits, r)?;
        let address = TAG | ((self.nodes.len() as u64) << 32);
        self.nodes
            .try_reserve(1)
            .map_err(|_| budget("JFFS2 codec node allocation"))?;
        self.nodes.push(n);
        Ok(address)
    }
}
struct DecodedNode {
    bytes: Vec<u8>,
    _lease: Reservation,
}
fn decode_node(
    source: &impl DecodeRead,
    n: Node,
    l: Jffs2CompressionLimits,
    r: &Resources,
) -> Result<DecodedNode> {
    source.check(r)?;
    let work = u64::from(n.encoded) + u64::from(n.decoded);
    if n.encoded as usize > l.compressed_node_bytes
        || n.decoded as usize > l.decoded_node_bytes
        || work > l.work
    {
        return Err(budget("JFFS2 deferred codec caps"));
    }
    let memory = r.memory.reserve(
        work.checked_add(131072)
            .ok_or_else(|| budget("JFFS2 codec memory accounting"))?,
    )?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(n.encoded as usize)
        .map_err(|_| budget("JFFS2 encoded allocation"))?;
    input.resize(n.encoded as usize, 0);
    source.read(n.physical, &mut input)?;
    if crc(0, &input) != n.checksum {
        return Err(invalid("JFFS2 deferred compressed CRC"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(n.decoded as usize)
        .map_err(|_| budget("JFFS2 decoded allocation"))?;
    out.resize(n.decoded as usize, 0);
    match n.codec {
        2 => {
            let mut positions = [0u16; 256];
            let mut at = 0usize;
            let mut used = 0usize;
            while at < out.len() {
                source.check(r)?;
                let pair = input
                    .get(used..used + 2)
                    .ok_or_else(|| invalid("JFFS2 truncated RTIME pair"))?;
                used += 2;
                let value = pair[0];
                let repeat = usize::from(pair[1]);
                out[at] = value;
                at += 1;
                let mut back = usize::from(positions[value as usize]);
                positions[value as usize] = at as u16;
                if repeat > out.len() - at {
                    return Err(invalid("JFFS2 RTIME output overflow"));
                }
                let end = at + repeat;
                while at < end {
                    if back >= at {
                        return Err(invalid("JFFS2 RTIME invalid backreference"));
                    }
                    out[at] = out[back];
                    at += 1;
                    back += 1;
                }
            }
            if used != input.len() {
                return Err(invalid("JFFS2 RTIME trailing bytes"));
            }
        }
        6 => decode_zlib(&input, &mut out)?,
        _ => return Err(unsupported("JFFS2 codec not implemented")),
    }
    source.check(r)?;
    Ok(DecodedNode {
        bytes: out,
        _lease: memory,
    })
}
fn decode_zlib(input: &[u8], out: &mut [u8]) -> Result<()> {
    let mut decoder = flate2::Decompress::new(true);
    let status = decoder
        .decompress(input, out, flate2::FlushDecompress::Finish)
        .map_err(|_| invalid("JFFS2 invalid ZLIB stream"))?;
    if status != flate2::Status::StreamEnd
        || decoder.total_in() != input.len() as u64
        || decoder.total_out() != out.len() as u64
    {
        return Err(invalid("JFFS2 ZLIB exact stream/output length"));
    }
    Ok(())
}
pub(super) struct CodecSource {
    pub(super) source: Arc<Checked>,
    pub(super) registry: Registry,
    pub(super) r: Resources,
}
impl CodecSource {
    pub(super) fn read_file(
        &self,
        file: &ExtentFile,
        p: u64,
        out: &mut [u8],
        r: &Resources,
    ) -> Result<usize> {
        self.source.check(r)?;
        let count = (file.len() - p).min(out.len() as u64) as usize;
        let maps = file.extents();
        let mut index = maps.partition_point(|e| e.offset + e.length <= p);
        let mut done = 0usize;
        let mut work = 0u64;
        while done < count {
            self.source.check(r)?;
            let m = maps
                .get(index)
                .ok_or_else(|| invalid("JFFS2 deferred codec map gap"))?;
            let at = p + done as u64;
            let n = (m.offset + m.length - at).min((count - done) as u64) as usize;
            let dst = &mut out[done..done + n];
            match m.kind {
                MapKind::Data(base) => self.registry.read_mapping(
                    self.source.as_ref(),
                    base + at - m.offset,
                    dst,
                    r,
                    &mut work,
                )?,
                _ => dst.fill(0),
            }
            done += n;
            index += 1;
        }
        self.source.check(r)?;
        Ok(done)
    }
}
impl ReadAt for CodecSource {
    fn len(&self) -> u64 {
        u64::MAX
    }
    fn read_exact_at(&self, p: u64, out: &mut [u8]) -> io::Result<()> {
        self.registry
            .read_mapping(self.source.as_ref(), p, out, &self.r, &mut 0)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A borrowed positional source, deliberately without any ReadAt implementation.
    struct BorrowedBytes([u8; 8]);
    impl DecodeRead for BorrowedBytes {
        fn length(&self) -> u64 {
            self.0.len() as u64
        }
        fn check(&self, r: &Resources) -> Result<()> {
            r.cancellation.check()
        }
        fn read(&self, at: u64, out: &mut [u8]) -> Result<()> {
            let start = usize::try_from(at).map_err(|_| invalid("test offset"))?;
            let end = start
                .checked_add(out.len())
                .ok_or_else(|| invalid("test range"))?;
            out.copy_from_slice(
                self.0
                    .get(start..end)
                    .ok_or_else(|| invalid("test bounds"))?,
            );
            Ok(())
        }
    }

    #[test]
    fn borrowed_registry_certificates_do_not_equate_scan_order_addresses() {
        let r = Resources {
            memory: Budget::new(1 << 20),
            cancellation: Cancellation::default(),
        };
        let source = BorrowedBytes([b'a', 0, b'a', 3, b'b', 0, b'b', 3]);
        let limits = Jffs2CompressionLimits {
            compressed_node_bytes: 4,
            decoded_node_bytes: 5,
            compressed_bytes: 8,
            decoded_bytes: 10,
            work: 18,
        };
        let node = |physical: u64| Node {
            physical,
            encoded: 4,
            decoded: 5,
            codec: 2,
            checksum: crc(0, &source.0[physical as usize..physical as usize + 4]),
        };
        let mut first = Registry::new(limits, 2, &r).unwrap();
        let mut second = Registry::new(limits, 2, &r).unwrap();
        let a = first.add(&source, node(0), &r).unwrap();
        first.add(&source, node(4), &r).unwrap();
        let b = second.add(&source, node(4), &r).unwrap();
        second.add(&source, node(0), &r).unwrap();
        assert_eq!(a, b, "virtual addresses alone cannot prove equality");
        assert_eq!(first.resolve(a).unwrap().unwrap().0.physical, 0);
        assert_eq!(second.resolve(b).unwrap().unwrap().0.physical, 4);
        let mut left = [0; 3];
        let mut right = [0; 3];
        first
            .read_mapping(&source, a + 1, &mut left, &r, &mut 0)
            .unwrap();
        second
            .read_mapping(&source, b + 1, &mut right, &r, &mut 0)
            .unwrap();
        assert_eq!(left, *b"aaa");
        assert_eq!(right, *b"bbb");
        assert!(
            first
                .read_mapping(&source, a + 4, &mut left, &r, &mut 0)
                .is_err()
        );
        let mut work = 10;
        assert!(
            first
                .read_mapping(&source, a, &mut left, &r, &mut work)
                .is_err()
        );
        drop((first, second));
        assert_eq!(r.memory.used(), 0);
    }
}
