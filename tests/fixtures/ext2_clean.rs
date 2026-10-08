//! Independent classic ext2 byte fixture shared by audit and dispatch tests.
fn w(b: &mut [u8], o: usize, n: u16) {
    b[o..o + 2].copy_from_slice(&n.to_le_bytes())
}
fn d(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes())
}
const ROOT: usize = 5 * 1024 + 128;
const FILE: usize = 5 * 1024 + 10 * 128;
pub(crate) fn fixture() -> Vec<u8> {
    let mut b = vec![0; 64 * 1024];
    let sb = &mut b[1024..2048];
    d(sb, 0, 16);
    d(sb, 4, 64);
    d(sb, 12, 55);
    d(sb, 16, 5);
    d(sb, 20, 1);
    d(sb, 32, 64);
    d(sb, 36, 64);
    d(sb, 40, 16);
    w(sb, 56, 0xef53);
    w(sb, 58, 1);
    d(sb, 76, 1);
    d(sb, 84, 11);
    w(sb, 88, 128);
    d(sb, 96, 2);
    d(&mut b, 2048, 3);
    d(&mut b, 2052, 4);
    d(&mut b, 2056, 5);
    w(&mut b, 2060, 55);
    w(&mut b, 2062, 5);
    w(&mut b, 2064, 1);
    b[3072] = 255;
    b[3079] = 128;
    b[3080..4096].fill(255);
    b[4096] = 255;
    b[4097] = 7;
    b[4098..5120].fill(255);
    w(&mut b, ROOT, 0x41ed);
    d(&mut b, ROOT + 4, 1024);
    w(&mut b, ROOT + 26, 2);
    d(&mut b, ROOT + 28, 2);
    d(&mut b, ROOT + 40, 7);
    w(&mut b, FILE, 0x81a4);
    d(&mut b, FILE + 4, 1024);
    w(&mut b, FILE + 26, 2);
    d(&mut b, FILE + 28, 2);
    d(&mut b, FILE + 40, 8);
    b[8192..9216].fill(73);
    let at = 7 * 1024;
    for (o, ino, len, name, kind) in [
        (0, 2, 12, b".".as_slice(), 2),
        (12, 2, 12, b"..".as_slice(), 2),
        (24, 11, 16, &[b'x', 255], 1),
        (40, 11, 984, b"alias".as_slice(), 1),
    ] {
        d(&mut b, at + o, ino);
        w(&mut b, at + o + 4, len);
        b[at + o + 6] = name.len() as u8;
        b[at + o + 7] = kind;
        b[at + o + 8..at + o + 8 + name.len()].copy_from_slice(name);
    }
    b
}
