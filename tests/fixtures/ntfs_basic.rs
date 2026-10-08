// Independent hand-authored NTFS byte fixture, shared by host and portable tests.
pub(crate) fn w(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn d(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn q(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
// These bytes describe a separate hand-authored disk layout, without production builders.
pub(crate) fn resident(kind: u32, value: &[u8], id: u16) -> Vec<u8> {
    let mut a = vec![0; (24 + value.len()).next_multiple_of(8)];
    let n = a.len();
    d(&mut a, 0, kind);
    d(&mut a, 4, n as u32);
    w(&mut a, 14, id);
    d(&mut a, 16, value.len() as u32);
    w(&mut a, 20, 24);
    a[24..24 + value.len()].copy_from_slice(value);
    a
}
pub(crate) fn nonresident(
    mapping: &[u8],
    clusters: u64,
    length: u64,
    initialized: u64,
    sparse: bool,
) -> Vec<u8> {
    let h = if sparse { 72 } else { 64 };
    let mut a = vec![0; (h + mapping.len()).next_multiple_of(8)];
    let n = a.len();
    d(&mut a, 0, 0x80);
    d(&mut a, 4, n as u32);
    a[8] = 1;
    w(&mut a, 12, if sparse { 0x8000 } else { 0 });
    w(&mut a, 14, 3);
    q(&mut a, 24, clusters - 1);
    w(&mut a, 32, h as u16);
    q(&mut a, 40, clusters * 512);
    q(&mut a, 48, length);
    q(&mut a, 56, initialized);
    if sparse {
        q(&mut a, 64, (clusters - 1) * 512);
    }
    a[h..h + mapping.len()].copy_from_slice(mapping);
    a
}
pub(crate) fn record(number: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..4].copy_from_slice(b"FILE");
    w(&mut b, 4, 48);
    w(&mut b, 6, 3);
    w(&mut b, 16, 7);
    w(&mut b, 18, 1);
    w(&mut b, 20, 56);
    w(&mut b, 22, 1);
    d(&mut b, 28, 1024);
    d(&mut b, 44, number);
    let mut at = 56;
    for a in attrs {
        b[at..at + a.len()].copy_from_slice(a);
        at += a.len();
    }
    d(&mut b, at, u32::MAX);
    d(&mut b, 24, (at + 4) as u32);
    w(&mut b, 48, 0xa55a);
    for i in 1..=2 {
        let p = i * 512 - 2;
        let old = u16::from_le_bytes([b[p], b[p + 1]]);
        w(&mut b, 48 + i * 2, old);
        w(&mut b, p, 0xa55a);
    }
    b
}
pub(crate) fn fixture() -> Vec<u8> {
    let mut b = vec![0; 128 * 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    w(&mut b, 11, 512);
    b[13] = 1;
    q(&mut b, 40, 128);
    q(&mut b, 48, 4);
    q(&mut b, 56, 100);
    b[64] = (-10i8) as u8;
    b[68] = (-10i8) as u8;
    w(&mut b, 510, 0xaa55);
    let mft = nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false);
    let mut vol = vec![0; 12];
    vol[8] = 3;
    vol[9] = 1;
    let mut name = vec![0; 70];
    q(&mut name, 0, 5 | (7 << 48));
    name[64] = 2;
    name[65] = 1;
    w(&mut name, 66, 0x65e5);
    w(&mut name, 68, 0xd800);
    let attrs = vec![
        resident(0x10, &[0; 48], 1),
        resident(0x30, &name, 2),
        resident(0x80, b"hello", 3),
    ];
    for (n, a) in [
        (0, vec![mft]),
        (3, vec![resident(0x70, &vol, 1)]),
        (24, attrs),
        (
            25,
            vec![nonresident(
                &[0x11, 1, 90, 0x01, 1, 0x11, 1, 1, 0],
                3,
                1536,
                1280,
                true,
            )],
        ),
    ] {
        let p = 2048 + n * 1024;
        b[p..p + 1024].copy_from_slice(&record(n as u32, &a));
    }
    b[90 * 512..91 * 512].fill(0x31);
    b[91 * 512..92 * 512].fill(0x72);
    b
}
