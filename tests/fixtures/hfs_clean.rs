// Independent Inside Macintosh: Files byte constructor; no production codecs.
pub const BASE: usize = 4 * 512;
pub const BLOCK: usize = 512;
pub const BLOCKS: usize = 128;
pub fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_be_bytes());
}
pub fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_be_bytes());
}
pub fn extent(b: &mut [u8], at: usize, ext: &[(u16, u16)]) {
    for (i, (start, count)) in ext.iter().take(3).enumerate() {
        p16(b, at + i * 4, *start);
        p16(b, at + i * 4 + 2, *count);
    }
}
pub fn catalog_key(parent: u32, name: &[u8], index: bool) -> Vec<u8> {
    let length = if index { 38 } else { (7 + name.len() + 1) & !1 };
    let mut b = vec![0; length];
    b[0] = (length - 1) as u8;
    p32(&mut b, 2, parent);
    b[6] = name.len() as u8;
    b[7..7 + name.len()].copy_from_slice(name);
    b
}
pub fn object(id: u32, dir: bool, valence: u16) -> Vec<u8> {
    let mut b = vec![0; if dir { 70 } else { 102 }];
    b[0] = if dir { 1 } else { 2 };
    if dir {
        p16(&mut b, 2, 0x10);
        p16(&mut b, 4, valence);
        p32(&mut b, 6, id);
    } else {
        b[2] = 2;
        p32(&mut b, 20, id);
        b[4..12].copy_from_slice(b"TEXTPMGR");
    }
    let at = if dir { 10 } else { 44 };
    p32(&mut b, at, 0xabcdef01);
    p32(&mut b, at + 4, 0xabcdef02);
    p32(&mut b, at + 8, 0xabcdef03);
    b
}
pub fn thread(parent: u32, name: &[u8], dir: bool) -> Vec<u8> {
    let mut b = vec![0; 46];
    b[0] = if dir { 3 } else { 4 };
    p32(&mut b, 10, parent);
    b[14] = name.len() as u8;
    b[15..15 + name.len()].copy_from_slice(name);
    b
}
pub fn node(kind: u8, height: u8, forward: u32, backward: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 512];
    b[8] = kind;
    b[9] = height;
    p32(&mut b, 0, forward);
    p32(&mut b, 4, backward);
    p16(&mut b, 10, records.len() as u16);
    let mut at = 14;
    for (i, r) in records.iter().enumerate() {
        p16(&mut b, 510 - i * 2, at as u16);
        b[at..at + r.len()].copy_from_slice(r);
        at += r.len();
    }
    assert!(at <= 510 - records.len() * 2);
    p16(&mut b, 510 - records.len() * 2, at as u16);
    b
}
#[allow(clippy::too_many_arguments)]
pub fn header(
    total: u32,
    free: u32,
    root: u32,
    depth: u16,
    records: u32,
    first: u32,
    last: u32,
    catalog: bool,
    map: u8,
) -> Vec<u8> {
    let mut h = vec![0; 106];
    p16(&mut h, 0, depth);
    p32(&mut h, 2, root);
    p32(&mut h, 6, records);
    p32(&mut h, 10, first);
    p32(&mut h, 14, last);
    p16(&mut h, 18, 512);
    p16(&mut h, 20, if catalog { 37 } else { 7 });
    p32(&mut h, 22, total);
    p32(&mut h, 26, free);
    let mut bitmap = vec![0; 256];
    bitmap[0] = map;
    node(1, 0, 0, 0, &[h, vec![0; 128], bitmap])
}
pub fn hfs_seed() -> Vec<u8> {
    let mut image = vec![0; BASE + BLOCKS * BLOCK + 1024];
    let mut data = object(16, false, 0);
    p32(&mut data, 26, 4 * 512 - 7);
    p32(&mut data, 30, 4 * 512);
    extent(&mut data, 74, &[(12, 1), (14, 1), (16, 1)]);
    p32(&mut data, 36, 5);
    p32(&mut data, 40, 512);
    extent(&mut data, 86, &[(20, 1)]);
    let mut child = object(18, false, 0);
    p32(&mut child, 26, 7);
    p32(&mut child, 30, 512);
    extent(&mut child, 74, &[(22, 1)]);
    let records = vec![
        (1, b"Volume".as_slice(), object(2, true, 2)),
        (2, b"", thread(1, b"Volume", true)),
        (2, b"Box", object(17, true, 1)),
        (2, b"Data", data),
        (16, b"", thread(2, b"Data", false)),
        (17, b"", thread(2, b"Box", true)),
        (17, b"Child", child),
        (18, b"", thread(17, b"Child", false)),
    ];
    let records: Vec<_> = records
        .into_iter()
        .map(|(p, n, b)| {
            let mut k = catalog_key(p, n, false);
            k.extend(b);
            k
        })
        .collect();
    let mut index = Vec::new();
    for (p, n, id) in [(1, b"Volume".as_slice(), 2u32), (16, b"".as_slice(), 3u32)] {
        let mut k = catalog_key(p, n, true);
        k.extend(id.to_be_bytes());
        index.push(k);
    }
    for (i, b) in [
        header(4, 0, 1, 2, 8, 2, 3, true, 0xf0),
        node(0, 2, 0, 0, &index),
        node(255, 1, 3, 0, &records[..4]),
        node(255, 1, 0, 2, &records[4..]),
    ]
    .iter()
    .enumerate()
    {
        image[BASE + (4 + i) * 512..BASE + (5 + i) * 512].copy_from_slice(b);
    }
    let mut overflow = vec![0; 20];
    overflow[0] = 7;
    p32(&mut overflow, 2, 16);
    p16(&mut overflow, 6, 3);
    extent(&mut overflow, 8, &[(18, 1)]);
    image[BASE..BASE + 512].copy_from_slice(&header(2, 0, 1, 1, 1, 1, 1, false, 0xc0));
    image[BASE + 512..BASE + 1024].copy_from_slice(&node(255, 1, 0, 0, &[overflow]));
    let allocated = [0, 1, 4, 5, 6, 7, 12, 14, 16, 18, 20, 22];
    for n in allocated {
        image[1536 + n / 8] |= 0x80 >> (n % 8);
    }
    for (i, n) in [12, 14, 16, 18].iter().enumerate() {
        for j in 0..512 {
            image[BASE + n * 512 + j] = ((i * 512 + j) * 17 % 251) as u8;
        }
    }
    image[BASE + 20 * 512..BASE + 20 * 512 + 5].copy_from_slice(b"RSRC!");
    image[BASE + 22 * 512..BASE + 22 * 512 + 7].copy_from_slice(b"nested!");
    let mut mdb = vec![0; 512];
    p16(&mut mdb, 0, 0x4244);
    p16(&mut mdb, 10, 0x100);
    p16(&mut mdb, 12, 1);
    p16(&mut mdb, 14, 3);
    p16(&mut mdb, 18, BLOCKS as u16);
    p32(&mut mdb, 20, 512);
    p16(&mut mdb, 28, 4);
    p32(&mut mdb, 30, 19);
    p16(&mut mdb, 34, (BLOCKS - allocated.len()) as u16);
    mdb[36] = 6;
    mdb[37..43].copy_from_slice(b"Volume");
    p16(&mut mdb, 82, 1);
    p32(&mut mdb, 84, 2);
    p32(&mut mdb, 88, 1);
    p32(&mut mdb, 130, 1024);
    extent(&mut mdb, 134, &[(0, 2)]);
    p32(&mut mdb, 146, 2048);
    extent(&mut mdb, 150, &[(4, 4)]);
    image[1024..1536].copy_from_slice(&mdb);
    let len = image.len();
    image[len - 1024..len - 512].copy_from_slice(&mdb);
    image
}
/// Independent raw insertion over a native formatter/copy fixture, retaining original allocations.
/// Catalog and extents system forks must be contiguous in this test-only profile.
#[allow(dead_code)] // Shared ordinary facade fixtures do not invoke the enabled native gate.
pub fn fragment_native_data(image: &mut [u8]) -> (u32, usize) {
    let h = image[1024..1536].to_vec();
    let base = u16::from_be_bytes(h[28..30].try_into().unwrap()) as usize * 512;
    let size = u32::from_be_bytes(h[20..24].try_into().unwrap()) as usize;
    assert_eq!(size, 512);
    let count = u16::from_be_bytes(h[18..20].try_into().unwrap()) as usize;
    let bitmap = u16::from_be_bytes(h[14..16].try_into().unwrap()) as usize * 512;
    let catalog = base + u16::from_be_bytes(h[150..152].try_into().unwrap()) as usize * size;
    let catalog_nodes =
        u32::from_be_bytes(image[catalog + 36..catalog + 40].try_into().unwrap()) as usize;
    let mut found = None;
    for n in 1..catalog_nodes {
        let start = catalog + n * 512;
        if image[start + 8] != 255 {
            continue;
        }
        let records =
            u16::from_be_bytes(image[start + 10..start + 12].try_into().unwrap()) as usize;
        for i in 0..records {
            let at = start
                + u16::from_be_bytes(
                    image[start + 510 - i * 2..start + 512 - i * 2]
                        .try_into()
                        .unwrap(),
                ) as usize;
            if image[at + 6] == 4 && &image[at + 7..at + 11] == b"Data" {
                found = Some(at + ((image[at] as usize + 2) & !1));
            }
        }
    }
    let at = found.expect("native Data catalog record");
    assert_eq!(image[at], 2);
    let id = u32::from_be_bytes(image[at + 20..at + 24].try_into().unwrap());
    let physical = u32::from_be_bytes(image[at + 30..at + 34].try_into().unwrap()) as usize;
    let blocks = physical / size;
    assert!(blocks >= 4);
    let old = u16::from_be_bytes(image[at + 74..at + 76].try_into().unwrap()) as usize;
    assert_eq!(
        u16::from_be_bytes(image[at + 76..at + 78].try_into().unwrap()) as usize,
        blocks
    );
    let payload = image[base + old * size..base + (old + blocks) * size].to_vec();
    let mut selected = Vec::new();
    for n in (1024..count).step_by(2) {
        if image[bitmap + n / 8] & (0x80 >> (n % 8)) == 0 {
            selected.push(n);
            if selected.len() == blocks {
                break;
            }
        }
    }
    assert_eq!(selected.len(), blocks);
    for n in old..old + blocks {
        image[bitmap + n / 8] &= !(0x80 >> (n % 8));
    }
    for (i, n) in selected.iter().enumerate() {
        image[bitmap + n / 8] |= 0x80 >> (n % 8);
        image[base + n * size..base + (n + 1) * size]
            .copy_from_slice(&payload[i * size..(i + 1) * size]);
    }
    image[at + 74..at + 86].fill(0);
    extent(
        image,
        at + 74,
        &selected[..3]
            .iter()
            .map(|n| (*n as u16, 1))
            .collect::<Vec<_>>(),
    );
    let ext = base + u16::from_be_bytes(h[134..136].try_into().unwrap()) as usize * size;
    assert_eq!(
        u32::from_be_bytes(image[ext + 20..ext + 24].try_into().unwrap()),
        0
    );
    let total = u32::from_be_bytes(image[ext + 36..ext + 40].try_into().unwrap());
    let mut records = Vec::new();
    for (chunk, more) in selected[3..].chunks(3).enumerate() {
        let mut r = vec![0; 20];
        r[0] = 7;
        p32(&mut r, 2, id);
        p16(&mut r, 6, (3 + chunk * 3) as u16);
        extent(
            &mut r,
            8,
            &more.iter().map(|n| (*n as u16, 1)).collect::<Vec<_>>(),
        );
        records.push(r);
    }
    assert!(records.len() < 24);
    let root = node(255, 1, 0, 0, &records);
    image[ext + 512..ext + 1024].copy_from_slice(&root);
    p16(image, ext + 14, 1);
    p32(image, ext + 16, 1);
    p32(image, ext + 20, records.len() as u32);
    p32(image, ext + 24, 1);
    p32(image, ext + 28, 1);
    p32(image, ext + 40, total - 2);
    image[ext + 248] |= 0x40;
    (id, blocks)
}
