use partmgr::{
    fs_file::{ExtentFile, ExtentKind, FileExtent},
    io,
};
use std::sync::Arc;
struct Memory([u8; 4]);
impl io::ReadAt for Memory {
    fn len(&self) -> u64 {
        4
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let end = at
            .checked_add(out.len() as u64)
            .filter(|end| *end <= 4)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(&self.0[at as usize..end as usize]);
        Ok(())
    }
}
#[test]
fn upstream_reader_retains_extent_eof_and_sparse_contracts() {
    let source: Arc<dyn virtdisk::ReadAt> = Arc::new(Memory([1, 2, 3, 4]));
    let file = ExtentFile::new(
        source,
        4,
        vec![
            FileExtent {
                offset: 0,
                length: 2,
                kind: ExtentKind::Data(1),
            },
            FileExtent {
                offset: 2,
                length: 2,
                kind: ExtentKind::Hole,
            },
        ],
        2,
    )
    .unwrap();
    let mut out = [9; 4];
    assert_eq!(file.read_at(0, &mut out).unwrap(), 4);
    assert_eq!(out, [2, 3, 0, 0]);
    assert_eq!(file.read_at(4, &mut []).unwrap(), 0);
    assert_eq!(
        file.read_at(5, &mut []).unwrap_err().kind(),
        virtdisk::io::ErrorKind::UnexpectedEof
    );
}
