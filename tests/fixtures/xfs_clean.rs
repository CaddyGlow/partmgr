//! Independent XFS v5 byte fixture; deliberately imports no production codecs.
fn w(b: &mut [u8], o: usize, n: u16) {
    b[o..o + 2].copy_from_slice(&n.to_be_bytes())
}
pub(crate) fn d(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_be_bytes())
}
pub(crate) fn q(b: &mut [u8], o: usize, n: u64) {
    b[o..o + 8].copy_from_slice(&n.to_be_bytes())
}
// Independent straightforward polynomial implementation; production uses a table.
pub(crate) fn crc(b: &mut [u8], offset: usize) {
    b[offset..offset + 4].fill(0);
    let mut c = u32::MAX;
    for &v in b.iter() {
        c ^= u32::from(v);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0x82f63b78 } else { 0 };
        }
    }
    b[offset..offset + 4].copy_from_slice(&(!c).to_le_bytes());
}
const UUID: [u8; 16] = [0x37; 16];
fn leaf(b: &mut [u8], magic: u32, ag: u32, physical: u64, records: &[u8]) {
    d(b, 0, magic);
    w(
        b,
        6,
        (records.len() / if magic == 0x49414233 { 16 } else { 8 }) as u16,
    );
    d(b, 8, u32::MAX);
    d(b, 12, u32::MAX);
    q(b, 16, physical * 8);
    b[32..48].copy_from_slice(&UUID);
    d(b, 48, ag);
    b[56..56 + records.len()].copy_from_slice(records);
    crc(b, 52);
}
pub(crate) fn short(parent: u32, entries: &[(&[u8], u32, u8)]) -> Vec<u8> {
    let mut b = vec![entries.len() as u8, 0];
    b.extend_from_slice(&parent.to_be_bytes());
    let mut off = 0x60u16;
    for (name, ino, kind) in entries {
        b.push(name.len() as u8);
        b.extend_from_slice(&off.to_be_bytes());
        b.extend_from_slice(name);
        b.push(*kind);
        b.extend_from_slice(&ino.to_be_bytes());
        off += (12 + name.len()).next_multiple_of(8) as u16;
    }
    b
}
fn inode(b: &mut [u8], number: u64, mode: u16, links: u32, size: u64, format: u8) {
    w(b, 0, 0x494e);
    w(b, 2, mode);
    b[4] = 3;
    b[5] = format;
    d(b, 8, 1234);
    d(b, 12, 5678);
    d(b, 16, links);
    q(b, 56, size);
    b[83] = 2;
    d(b, 92, 7);
    d(b, 96, u32::MAX);
    q(b, 152, number);
    b[160..176].copy_from_slice(&UUID);
    for at in [32, 40, 48, 144] {
        d(b, at, 946684800);
        d(b, at + 4, 123456789);
    }
}
// Independently constructed, compact four-AG XFS v5 structure; no production authoring.
/// Independent compact four-AG v5 fixture, with hardlinks and a sparse stream.
pub fn xfs_seed() -> Vec<u8> {
    let mut image = vec![0; 256 * 4096];
    let mut sb = [0; 512];
    sb[..4].copy_from_slice(b"XFSB");
    d(&mut sb, 4, 4096);
    q(&mut sb, 8, 256);
    sb[32..48].copy_from_slice(&UUID);
    q(&mut sb, 48, (2 << 6) + 12);
    q(&mut sb, 56, 64);
    q(&mut sb, 64, 65);
    q(&mut sb, 72, 66);
    d(&mut sb, 80, 1);
    d(&mut sb, 84, 64);
    d(&mut sb, 88, 4);
    d(&mut sb, 96, 8);
    w(&mut sb, 100, 0xb4a5);
    w(&mut sb, 102, 512);
    w(&mut sb, 104, 512);
    w(&mut sb, 106, 8);
    sb[120..125].copy_from_slice(&[12, 9, 9, 3, 6]);
    q(&mut sb, 128, 64);
    q(&mut sb, 136, 59);
    q(&mut sb, 144, 222);
    d(&mut sb, 180, 4);
    d(&mut sb, 196, 1);
    d(&mut sb, 200, 0x18a);
    d(&mut sb, 204, 0x18a);
    d(&mut sb, 216, 1);
    crc(&mut sb, 224);
    for ag in 0..4 {
        let at = ag * 64 * 4096;
        image[at..at + 512].copy_from_slice(&sb);
        let frees: Vec<(u32, u32)> = match ag {
            0 => vec![(18, 46)],
            2 => vec![(8, 4), (20, 44)],
            _ => vec![(8, 56)],
        };
        let free = frees.iter().map(|e| e.1).sum::<u32>();
        let f = &mut image[at + 512..at + 1024];
        f[..4].copy_from_slice(b"XAGF");
        d(f, 4, 1);
        d(f, 8, ag as u32);
        d(f, 12, 64);
        d(f, 16, 1);
        d(f, 20, 2);
        d(f, 28, 1);
        d(f, 32, 1);
        d(f, 40, 1);
        d(f, 44, 4);
        d(f, 48, 4);
        d(f, 52, free);
        d(f, 56, frees.iter().map(|e| e.1).max().unwrap());
        f[64..80].copy_from_slice(&UUID);
        crc(f, 216);
        let i = &mut image[at + 1024..at + 1536];
        i[..4].copy_from_slice(b"XAGI");
        d(i, 4, 1);
        d(i, 8, ag as u32);
        d(i, 12, 64);
        if ag == 0 {
            d(i, 16, 64);
            d(i, 28, 59);
        }
        d(i, 20, 3);
        d(i, 24, 1);
        i[40..296].fill(255);
        i[296..312].copy_from_slice(&UUID);
        crc(i, 312);
        let fl = &mut image[at + 1536..at + 2048];
        fl.fill(255);
        fl[..36].fill(0);
        fl[..4].copy_from_slice(b"XAFL");
        d(fl, 4, ag as u32);
        fl[8..24].copy_from_slice(&UUID);
        for n in 1..=4 {
            d(fl, 36 + n * 4, (n + 3) as u32);
        }
        crc(fl, 32);
        let mut records = Vec::new();
        for &(b, c) in &frees {
            records.extend_from_slice(&b.to_be_bytes());
            records.extend_from_slice(&c.to_be_bytes());
        }
        leaf(
            &mut image[at + 4096..at + 8192],
            0x41423342,
            ag as u32,
            (ag * 64 + 1) as u64,
            &records,
        );
        let mut counts = frees.clone();
        counts.sort_by_key(|e| (e.1, e.0));
        records.clear();
        for (b, c) in counts {
            records.extend_from_slice(&b.to_be_bytes());
            records.extend_from_slice(&c.to_be_bytes());
        }
        leaf(
            &mut image[at + 8192..at + 12288],
            0x41423343,
            ag as u32,
            (ag * 64 + 2) as u64,
            &records,
        );
        records.clear();
        if ag == 0 {
            records.extend_from_slice(&64u32.to_be_bytes());
            records.extend_from_slice(&59u32.to_be_bytes());
            records.extend_from_slice(&(u64::MAX << 5).to_be_bytes());
        }
        leaf(
            &mut image[at + 12288..at + 16384],
            0x49414233,
            ag as u32,
            (ag * 64 + 3) as u64,
            &records,
        );
    }
    for (number, mode, links, size, format) in [
        (64, 0x41ed, 3, 0, 1),
        (65, 0x8000, 1, 0, 2),
        (66, 0x8000, 1, 0, 2),
        (67, 0x81a0, 2, 16384, 2),
        (68, 0x41ed, 2, 0, 1),
    ] {
        let at = number * 512;
        inode(
            &mut image[at..at + 512],
            number as u64,
            mode,
            links,
            size,
            format,
        );
    }
    let root = short(64, &[(b"nested", 68, 2), (b"alias", 67, 1)]);
    let nested = short(64, &[(&[b'x', 255], 67, 1)]);
    for (n, dir) in [(64, root), (68, nested)] {
        let b = &mut image[n * 512..n * 512 + 512];
        q(b, 56, dir.len() as u64);
        b[176..176 + dir.len()].copy_from_slice(&dir);
    }
    let file = &mut image[67 * 512..68 * 512];
    q(file, 64, 2);
    d(file, 76, 1);
    q(file, 176, 1 << 9);
    q(file, 184, (16 << 21) | 2);
    w(&mut image[65 * 512..66 * 512], 90, 4);
    for n in 64..=68 {
        crc(&mut image[n * 512..n * 512 + 512], 100);
    }
    for (n, b) in image[16 * 4096..18 * 4096].iter_mut().enumerate() {
        *b = (n * 73 + 11) as u8;
    }
    let log = (2 * 64 + 12) * 4096;
    let h = &mut image[log..log + 512];
    for (o, v) in [
        (0, 0xfeedbabeu32),
        (4, 1),
        (8, 2),
        (12, 512),
        (16, 1),
        (24, 1),
        (36, u32::MAX),
        (40, 1),
        (44, 0xb0c0d0d0),
        (300, 1),
        (320, 32768),
    ] {
        d(h, o, v);
    }
    h[304..320].copy_from_slice(&UUID);
    let data = &mut image[log + 512..log + 1024];
    d(data, 0, 1);
    d(data, 4, 8);
    data[8] = 0xaa;
    data[9] = 0x20;
    data[12..14].copy_from_slice(&0x556eu16.to_le_bytes());
    image
}
