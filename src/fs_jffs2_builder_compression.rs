//! Deterministic bounded compressed-node encoding; output never exceeds NONE reservation.
use super::*;
/// Opt-in regular-file codec; ZERO and uncompressed symlink/metadata rules remain unchanged.
#[derive(Clone, Copy, Debug)]
pub enum Jffs2BuildCompression {
    /// Native RTIME literal/run coding with NONE fallback unless smaller.
    Rtime,
    /// RFC1950 ZLIB, level 3, with NONE fallback unless smaller.
    Zlib,
}
impl Jffs2BuildCompression {
    pub(crate) fn workspace(self) -> u64 {
        match self {
            Self::Rtime => 2048,
            Self::Zlib => 2 << 20,
        }
    }
    pub(crate) fn encode(self, input: &[u8], r: &Resources) -> Result<Option<Vec<u8>>> {
        r.cancellation.check()?;
        let mut out = Vec::new();
        out.try_reserve_exact(input.len())
            .map_err(|_| cap("JFFS2 bounded compressed output"))?;
        out.resize(input.len(), 0);
        let count = match self {
            Self::Rtime => {
                let mut positions = [0u16; 256];
                let mut at = 0usize;
                let mut produced = 0usize;
                while at < input.len() {
                    r.cancellation.check()?;
                    if produced + 2 > out.len() {
                        return Ok(None);
                    }
                    let value = input[at];
                    out[produced] = value;
                    at += 1;
                    let mut back = usize::from(positions[value as usize]);
                    positions[value as usize] = at as u16;
                    let mut repeat = 0u8;
                    while back < at && at < input.len() && input[at] == input[back] && repeat < 255
                    {
                        at += 1;
                        back += 1;
                        repeat += 1;
                    }
                    out[produced + 1] = repeat;
                    produced += 2;
                }
                produced
            }
            Self::Zlib => {
                let mut encoder = flate2::Compress::new(flate2::Compression::new(3), true);
                let status = encoder
                    .compress(input, &mut out, flate2::FlushCompress::Finish)
                    .map_err(|_| invalid("JFFS2 ZLIB encoder failed"))?;
                if status != flate2::Status::StreamEnd || encoder.total_in() != input.len() as u64 {
                    return Ok(None);
                }
                encoder.total_out() as usize
            }
        };
        r.cancellation.check()?;
        if count >= input.len() {
            return Ok(None);
        }
        out.truncate(count);
        Ok(Some(out))
    }
    pub(crate) fn native(self) -> u8 {
        match self {
            Self::Rtime => 2,
            Self::Zlib => 6,
        }
    }
}
