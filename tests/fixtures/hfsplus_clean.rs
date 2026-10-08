// Independent TN1150 big-endian byte constructor; never calls partmgr codecs/builders.
pub fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_be_bytes());
}
pub fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_be_bytes());
}
pub fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_be_bytes());
}
pub fn fork(length: u64, extents: &[(u32, u32)]) -> Vec<u8> {
    let mut b = vec![0; 80];
    p64(&mut b, 0, length);
    p32(&mut b, 12, extents.iter().map(|e| e.1).sum());
    for (i, (start, count)) in extents.iter().take(8).enumerate() {
        p32(&mut b, 16 + i * 8, *start);
        p32(&mut b, 20 + i * 8, *count);
    }
    b
}
pub fn catalog_key(parent: u32, name: &[u16]) -> Vec<u8> {
    let mut b = vec![0; 8 + name.len() * 2];
    p16(&mut b, 0, (6 + name.len() * 2) as u16);
    p32(&mut b, 2, parent);
    p16(&mut b, 6, name.len() as u16);
    for (i, u) in name.iter().enumerate() {
        p16(&mut b, 8 + i * 2, *u);
    }
    b
}
pub fn thread(parent: u32, name: &[u16], directory: bool) -> Vec<u8> {
    let mut b = vec![0; 10 + name.len() * 2];
    p16(&mut b, 0, if directory { 3 } else { 4 });
    p32(&mut b, 4, parent);
    p16(&mut b, 8, name.len() as u16);
    for (i, u) in name.iter().enumerate() {
        p16(&mut b, 10 + i * 2, *u);
    }
    b
}
pub fn object(id: u32, directory: bool, valence: u32, data: &[u8], resource: &[u8]) -> Vec<u8> {
    let mut b = vec![0; if directory { 88 } else { 248 }];
    p16(&mut b, 0, if directory { 1 } else { 2 });
    p16(&mut b, 2, if directory { 0 } else { 2 });
    p32(&mut b, 4, valence);
    p32(&mut b, 8, id);
    p32(&mut b, 12, 0xabcdef01);
    p32(&mut b, 16, 0xabcdef02);
    p32(&mut b, 20, 0xabcdef03);
    p32(&mut b, 24, 0xabcdef04);
    p32(&mut b, 28, 0xabcdef05);
    p32(&mut b, 32, 501);
    p32(&mut b, 36, 20);
    p16(&mut b, 42, if directory { 0x41ed } else { 0x81a4 });
    if !directory {
        b[88..168].copy_from_slice(data);
        b[168..248].copy_from_slice(resource);
    }
    b
}
pub fn node(
    size: usize,
    kind: u8,
    height: u8,
    forward: u32,
    backward: u32,
    records: &[Vec<u8>],
) -> Vec<u8> {
    let mut b = vec![0; size];
    p32(&mut b, 0, forward);
    p32(&mut b, 4, backward);
    b[8] = kind;
    b[9] = height;
    p16(&mut b, 10, records.len() as u16);
    let mut at = 14;
    for (i, record) in records.iter().enumerate() {
        p16(&mut b, size - 2 * (i + 1), at as u16);
        b[at..at + record.len()].copy_from_slice(record);
        at += record.len();
    }
    assert!(at <= size - 2 * (records.len() + 1));
    p16(&mut b, size - 2 * (records.len() + 1), at as u16);
    b
}
#[allow(clippy::too_many_arguments)]
pub fn header(
    size: usize,
    total: u32,
    free: u32,
    root: u32,
    depth: u16,
    records: u32,
    first: u32,
    last: u32,
    catalog: bool,
    binary: bool,
    map: u8,
) -> Vec<u8> {
    let mut h = vec![0; 106];
    p16(&mut h, 0, depth);
    p32(&mut h, 2, root);
    p32(&mut h, 6, records);
    p32(&mut h, 10, first);
    p32(&mut h, 14, last);
    p16(&mut h, 18, size as u16);
    p16(&mut h, 20, if catalog { 516 } else { 10 });
    p32(&mut h, 22, total);
    p32(&mut h, 26, free);
    h[37] = if binary { 0xbc } else { 0xcf };
    p32(&mut h, 38, if catalog { 6 } else { 2 });
    let mut bitmap = vec![0; size - 256];
    bitmap[0] = map;
    node(size, 1, 0, 0, 0, &[h, vec![0; 128], bitmap])
}
pub fn native_name(binary: bool) -> Vec<u16> {
    if binary {
        vec![0x03a9, 0xd800, 0x58]
    } else {
        "Data".encode_utf16().collect()
    }
}
pub fn hfsplus_seed(binary: bool) -> Vec<u8> {
    seed_profile(binary, false)
}
#[allow(dead_code)]
pub fn hfsplus_directory_seed(binary: bool) -> Vec<u8> {
    seed_profile(binary, true)
}
fn seed_profile(binary: bool, destination: bool) -> Vec<u8> {
    let block = 4096;
    let total = 256;
    let mut image = vec![0; total * block];
    let name = if destination {
        "Data".encode_utf16().collect()
    } else {
        native_name(binary)
    };
    let root: Vec<_> = "Volume".encode_utf16().collect();
    let dir: Vec<_> = "Dir".encode_utf16().collect();
    let child: Vec<_> = "child".encode_utf16().collect();
    let empty = fork(0, &[]);
    let mut data = fork(
        9 * block as u64 - 7,
        &[
            (12, 1),
            (14, 1),
            (16, 1),
            (18, 1),
            (20, 1),
            (22, 1),
            (24, 1),
            (26, 1),
        ],
    );
    p32(&mut data, 12, 9);
    let resource = fork(5, &[(32, 1)]);
    let child_fork = fork(7, &[(34, 1)]);
    let mut records = vec![
        (
            1,
            root.clone(),
            object(2, true, if destination { 3 } else { 2 }, &empty, &empty),
        ),
        (2, vec![], thread(1, &root, true)),
        (2, name.clone(), object(16, false, 0, &data, &resource)),
        (2, dir.clone(), object(17, true, 1, &empty, &empty)),
        (16, vec![], thread(2, &name, false)),
        (17, vec![], thread(2, &dir, true)),
        (17, child.clone(), object(18, false, 0, &child_fork, &empty)),
        (18, vec![], thread(17, &child, false)),
    ];
    if destination {
        let name: Vec<u16> = "Target".encode_utf16().collect();
        records.push((2, name.clone(), object(19, true, 0, &empty, &empty)));
        records.push((19, vec![], thread(2, &name, true)));
    }
    if binary {
        for (_, _, body) in &mut records {
            if u16::from_be_bytes(body[..2].try_into().unwrap()) == 1 {
                p16(body, 2, 0x10);
                let id = u32::from_be_bytes(body[8..12].try_into().unwrap());
                p32(
                    body,
                    84,
                    if id == 2 {
                        if destination { 2 } else { 1 }
                    } else {
                        0
                    },
                );
            }
        }
    }
    records.sort_by_key(|(p, n, _)| {
        (
            *p,
            n.iter()
                .map(|u| {
                    if !binary && (65..=90).contains(u) {
                        u + 32
                    } else {
                        *u
                    }
                })
                .collect::<Vec<_>>(),
        )
    });
    let records: Vec<_> = records
        .into_iter()
        .map(|(p, n, b)| {
            let mut r = catalog_key(p, &n);
            r.extend_from_slice(&b);
            r
        })
        .collect();
    let mut index = Vec::new();
    for (first, id) in [(0, 2u32), (4, 3)] {
        let length = 2 + u16::from_be_bytes(records[first][..2].try_into().unwrap()) as usize;
        let mut key = records[first][..length].to_vec();
        key.extend_from_slice(&id.to_be_bytes());
        index.push(key);
    }
    let catalog_header = header(
        block,
        4,
        0,
        1,
        2,
        if destination { 10 } else { 8 },
        2,
        3,
        true,
        binary,
        0xf0,
    );
    let catalog_root = node(block, 0, 2, 0, 0, &index);
    let left = node(block, 255, 1, 3, 0, &records[..4]);
    let right = node(block, 255, 1, 0, 2, &records[4..]);
    for (i, node) in [catalog_header, catalog_root, left, right]
        .iter()
        .enumerate()
    {
        image[(4 + i) * block..(5 + i) * block].copy_from_slice(node);
    }
    let mut overflow = vec![0; 12 + 64];
    p16(&mut overflow, 0, 10);
    p32(&mut overflow, 4, 16);
    p32(&mut overflow, 8, 8);
    p32(&mut overflow, 12, 28);
    p32(&mut overflow, 16, 1);
    image[2 * block..2 * block + 1024]
        .copy_from_slice(&header(1024, 4, 2, 1, 1, 1, 1, 1, false, false, 0xc0));
    image[2 * block + 1024..2 * block + 2048].copy_from_slice(&node(
        1024,
        255,
        1,
        0,
        0,
        &[overflow],
    ));
    let allocated = [
        0, 1, 2, 4, 5, 6, 7, 12, 14, 16, 18, 20, 22, 24, 26, 28, 32, 34, 255,
    ];
    for &n in &allocated {
        image[block + n / 8] |= 0x80 >> (n % 8);
    }
    for (i, n) in [12, 14, 16, 18, 20, 22, 24, 26, 28].iter().enumerate() {
        for j in 0..block {
            image[n * block + j] = ((i * block + j) * 17 % 251) as u8;
        }
    }
    image[32 * block..32 * block + 5].copy_from_slice(b"RSRC!");
    image[34 * block..34 * block + 7].copy_from_slice(b"nested!");
    let mut vh = vec![0; 512];
    p16(&mut vh, 0, if binary { 0x4858 } else { 0x482b });
    p16(&mut vh, 2, if binary { 5 } else { 4 });
    p32(&mut vh, 4, 0x100);
    p32(&mut vh, 32, 2);
    p32(&mut vh, 36, if destination { 2 } else { 1 });
    p32(&mut vh, 40, block as u32);
    p32(&mut vh, 44, total as u32);
    p32(&mut vh, 48, total as u32 - allocated.len() as u32);
    if destination {
        p32(&mut vh, 56, 16384);
        p32(&mut vh, 60, 16384);
    }
    p32(&mut vh, 64, if destination { 20 } else { 19 });
    vh[112..192].copy_from_slice(&fork(32, &[(1, 1)]));
    vh[192..272].copy_from_slice(&fork(block as u64, &[(2, 1)]));
    vh[272..352].copy_from_slice(&fork(4 * block as u64, &[(4, 4)]));
    image[1024..1536].copy_from_slice(&vh);
    let len = image.len();
    image[len - 1024..len - 512].copy_from_slice(&vh);
    image
}
