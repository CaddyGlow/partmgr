//! Independently authored native APFS byte fixture; no production decoder helpers.
pub const BLOCK: usize = 4096;
pub type Records = Vec<(Vec<u8>, Vec<u8>)>;
pub fn p16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn p32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn p64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn seal(b: &mut [u8]) {
    // Independent reduction via u128 accumulators and end-around carry per complete word.
    let modulus = u128::from(u32::MAX);
    let mut sum = 0u128;
    let mut weighted = 0u128;
    for word in b[8..].as_chunks::<4>().0 {
        sum = (sum + u128::from(u32::from_le_bytes(*word))) % modulus;
        weighted = (weighted + sum) % modulus;
    }
    let first = modulus - ((sum + weighted) % modulus);
    let second = modulus - ((sum + first) % modulus);
    p64(b, 0, first as u64 | (second as u64) << 32);
}
pub fn object(oid: u64, xid: u64, kind: u32, sub: u32) -> Vec<u8> {
    let mut b = vec![0; BLOCK];
    p64(&mut b, 8, oid);
    p64(&mut b, 16, xid);
    p32(&mut b, 24, kind);
    p32(&mut b, 28, sub);
    b
}
pub fn leaf(
    oid: u64,
    xid: u64,
    storage: u32,
    sub: u32,
    records: &[(Vec<u8>, Vec<u8>)],
    fixed: bool,
) -> Vec<u8> {
    let mut b = object(oid, xid, storage | 2, sub);
    p16(&mut b, 32, 3 + 4 * u16::from(fixed));
    p32(&mut b, 36, records.len() as u32);
    let table = if fixed {
        if sub == 9 { 576 } else { 448 }
    } else {
        records.len().max(16) * 8
    };
    p16(&mut b, 42, table as u16);
    let base = 56 + table;
    let end = BLOCK - 40;
    let mut key_position = 0;
    let mut val_position = 0;
    for (i, (k, v)) in records.iter().enumerate() {
        let t = 56 + i * if fixed { 4 } else { 8 };
        p16(&mut b, t, key_position as u16);
        val_position += v.len();
        if fixed {
            p16(&mut b, t + 2, val_position as u16);
        } else {
            p16(&mut b, t + 2, k.len() as u16);
            p16(&mut b, t + 4, val_position as u16);
            p16(&mut b, t + 6, v.len() as u16);
        }
        b[base + key_position..base + key_position + k.len()].copy_from_slice(k);
        b[end - val_position..end - val_position + v.len()].copy_from_slice(v);
        key_position += k.len();
    }
    p16(&mut b, 44, key_position as u16);
    p16(
        &mut b,
        46,
        (end - val_position - base - key_position) as u16,
    );
    p16(&mut b, 48, 65535);
    p16(&mut b, 52, 65535);
    p32(
        &mut b,
        end,
        if storage == 0x40000000 {
            if fixed { 0x10 } else { 0x50 }
        } else if storage == 0x80000000 {
            0xc
        } else {
            0x40
        },
    );
    p32(&mut b, end + 4, 4096);
    if fixed {
        p32(&mut b, end + 8, 16);
        p32(&mut b, end + 12, if sub == 9 { 8 } else { 16 });
    }
    p32(
        &mut b,
        end + 16,
        records.iter().map(|r| r.0.len()).max().unwrap_or(0) as u32,
    );
    p32(
        &mut b,
        end + 20,
        records.iter().map(|r| r.1.len()).max().unwrap_or(0) as u32,
    );
    p64(&mut b, end + 24, records.len() as u64);
    p64(&mut b, end + 32, 1);
    seal(&mut b);
    b
}
pub fn key(id: u64, kind: u64) -> Vec<u8> {
    ((kind << 60) | id).to_le_bytes().to_vec()
}
fn inode(
    parent: u64,
    id: u64,
    name: &[u8],
    directory: bool,
    children: u32,
    data: Option<(u64, u64)>,
) -> Vec<u8> {
    let mut b = vec![0; 92];
    p64(&mut b, 0, parent);
    p64(&mut b, 8, id);
    for p in [16, 24, 32, 40] {
        p64(&mut b, p, 1_500_000_000_123_456_789);
    }
    p32(&mut b, 56, children);
    p32(&mut b, 72, 501);
    p32(&mut b, 76, 20);
    p16(&mut b, 80, if directory { 0x41ed } else { 0x81a4 });
    let mut n = name.to_vec();
    n.push(0);
    let mut fields = vec![(4u8, n)];
    if let Some((size, allocated)) = data {
        let mut ds = vec![0; 40];
        p64(&mut ds, 0, size);
        p64(&mut ds, 8, allocated);
        fields.push((8, ds));
        if id == 16 {
            fields.push((13, 8192u64.to_le_bytes().to_vec()));
        }
    }
    let count = fields.len();
    let used = fields
        .iter()
        .map(|(_, v)| v.len().next_multiple_of(8))
        .sum::<usize>();
    let start = b.len();
    b.resize(start + 4 + count * 4 + used, 0);
    p16(&mut b, start, count as u16);
    p16(&mut b, start + 2, used as u16);
    let mut at = start + 4 + count * 4;
    for (i, (kind, value)) in fields.into_iter().enumerate() {
        b[start + 4 + i * 4] = kind;
        b[start + 5 + i * 4] = match kind {
            8 => 32,
            13 => 40,
            _ => 2,
        };
        p16(&mut b, start + 6 + i * 4, value.len() as u16);
        b[at..at + value.len()].copy_from_slice(&value);
        at += value.len().next_multiple_of(8);
    }
    b
}
fn drec(parent: u64, id: u64, name: &[u8], dir: bool) -> (Vec<u8>, Vec<u8>) {
    let mut k = key(parent, 9);
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name);
    k.push(0);
    let mut v = vec![0; 18];
    p64(&mut v, 0, id);
    p64(&mut v, 8, 1_500_000_000_123_456_789);
    p16(&mut v, 16, if dir { 4 } else { 8 });
    (k, v)
}
pub fn fs_records() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut file = inode(
        2,
        16,
        b"A\xc3\xa9-file",
        false,
        1,
        Some((4 * 4096 + 13, 5 * 4096)),
    );
    p64(&mut file, 48, 0x4200);
    let mut records = vec![
        drec(1, 3, b"private-dir", true),
        drec(1, 2, b"root", true),
        (key(2, 3), inode(1, 2, b"root", true, 2, None)),
        drec(2, 16, b"A\xc3\xa9-file", false),
        drec(2, 17, b"Box", true),
        (key(3, 3), inode(1, 3, b"private-dir", true, 0, None)),
        (key(16, 3), file),
    ];
    let mut xkey = key(16, 4);
    let name = b"com.apple.ResourceFork";
    xkey.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    xkey.extend_from_slice(name);
    xkey.push(0);
    let mut xv = vec![0; 4];
    p16(&mut xv, 0, 2);
    p16(&mut xv, 2, 8);
    xv.extend_from_slice(b"resource");
    records.push((xkey, xv));
    records.push((key(16, 6), 1u32.to_le_bytes().to_vec()));
    for (logical, physical) in [(0, 100), (4096, 0), (8192, 102), (12288, 0), (16384, 110)] {
        let mut k = key(16, 8);
        k.extend_from_slice(&(logical as u64).to_le_bytes());
        let mut v = vec![0; 24];
        p64(&mut v, 0, 4096);
        p64(&mut v, 8, physical);
        records.push((k, v));
    }
    records.push((key(17, 3), inode(2, 17, b"Box", true, 1, None)));
    records.push(drec(17, 18, b"Child", false));
    records.push((
        key(18, 3),
        inode(17, 18, b"Child", false, 1, Some((7, 4096))),
    ));
    records.push((key(18, 6), 1u32.to_le_bytes().to_vec()));
    let mut k = key(18, 8);
    k.extend_from_slice(&0u64.to_le_bytes());
    let mut v = vec![0; 24];
    p64(&mut v, 0, 4096);
    p64(&mut v, 8, 112);
    records.push((k, v));
    records
}
pub fn extent_records() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut records = Vec::new();
    for (start, id) in [(100, 16), (102, 16), (110, 16), (112, 18)] {
        let mut v = vec![0; 20];
        p64(&mut v, 0, (1u64 << 60) | 1);
        p64(&mut v, 8, id);
        p32(&mut v, 16, 1);
        records.push((key(start, 2), v));
    }
    records
}
fn omap(oid: u64, root: u64) -> Vec<u8> {
    let mut b = object(oid, 1, 0x4000000b, 0);
    p32(&mut b, 40, 0x40000002);
    p32(&mut b, 44, 0x40000002);
    p64(&mut b, 48, root);
    seal(&mut b);
    b
}
fn omap_records(oid: u64, address: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut k = oid.to_le_bytes().to_vec();
    k.extend_from_slice(&1u64.to_le_bytes());
    let mut v = vec![0; 16];
    p32(&mut v, 4, 4096);
    p64(&mut v, 8, address);
    vec![(k, v)]
}
/// Bare 2MiB container with one complete checkpoint, two files, nested directory,
/// resource fork, sparse data and physical allocation beyond EOF.
pub fn apfs_seed() -> Vec<u8> {
    let mut image = vec![0; 512 * BLOCK];
    let mut nx = object(1, 1, 0x80000001, 0);
    nx[32..36].copy_from_slice(b"NXSB");
    p32(&mut nx, 36, 4096);
    p64(&mut nx, 40, 512);
    p64(&mut nx, 64, 2);
    nx[72..88].fill(0x51);
    p64(&mut nx, 88, 1100);
    p64(&mut nx, 96, 2);
    p32(&mut nx, 104, 8);
    p32(&mut nx, 108, 8);
    p64(&mut nx, 112, 1);
    p64(&mut nx, 120, 9);
    p32(&mut nx, 128, 2);
    p32(&mut nx, 132, 4);
    p32(&mut nx, 140, 2);
    p32(&mut nx, 148, 4);
    p64(&mut nx, 152, 1024);
    p64(&mut nx, 160, 17);
    p64(&mut nx, 168, 1025);
    p32(&mut nx, 180, 1);
    p64(&mut nx, 184, 1026);
    seal(&mut nx);
    for block in [0, 2] {
        image[block * BLOCK..(block + 1) * BLOCK].copy_from_slice(&nx);
    }
    let mut cp = object(1, 1, 0x4000000c, 0);
    p32(&mut cp, 32, 1);
    p32(&mut cp, 36, 4);
    for (i, (kind, sub, id, at)) in [
        (0x80000011, 0, 1025, 9),
        (0x80000005, 0, 1024, 10),
        (0x80000002, 9, 1028, 11),
        (0x80000002, 9, 1029, 12),
    ]
    .into_iter()
    .enumerate()
    {
        let p = 40 + i * 40;
        p32(&mut cp, p, kind);
        p32(&mut cp, p + 4, sub);
        p32(&mut cp, p + 8, 4096);
        p64(&mut cp, p + 24, id);
        p64(&mut cp, p + 32, at);
    }
    seal(&mut cp);
    image[BLOCK..2 * BLOCK].copy_from_slice(&cp);
    let mut reaper = object(1025, 1, 0x80000011, 0);
    p64(&mut reaper, 32, 1);
    p32(&mut reaper, 64, 1);
    seal(&mut reaper);
    image[9 * BLOCK..10 * BLOCK].copy_from_slice(&reaper);
    let mut sm = object(1024, 1, 0x80000005, 0);
    p32(&mut sm, 32, 4096);
    p32(&mut sm, 36, 32768);
    p32(&mut sm, 40, 126);
    p32(&mut sm, 44, 507);
    p64(&mut sm, 48, 512);
    p64(&mut sm, 56, 1);
    p32(&mut sm, 64, 1);
    p64(&mut sm, 72, 461);
    p32(&mut sm, 80, 384);
    p32(&mut sm, 148, 16);
    p64(&mut sm, 152, 6);
    p32(&mut sm, 160, 1);
    p32(&mut sm, 164, 16);
    p64(&mut sm, 168, 25);
    p64(&mut sm, 176, 41);
    p64(&mut sm, 208, 1028);
    p64(&mut sm, 248, 1029);
    p16(&mut sm, 224, 1);
    p16(&mut sm, 264, 4);
    p16(&mut sm, 320, 1);
    p16(&mut sm, 322, 15);
    p32(&mut sm, 324, 336);
    p32(&mut sm, 328, 344);
    p32(&mut sm, 332, 352);
    p64(&mut sm, 336, 1);
    for i in 0..16 {
        p16(
            &mut sm,
            352 + i * 2,
            if i == 0 || i == 15 {
                65535
            } else {
                (i + 1) as u16
            },
        );
    }
    p64(&mut sm, 384, 42);
    seal(&mut sm);
    image[10 * BLOCK..11 * BLOCK].copy_from_slice(&sm);
    for (block, id) in [(11, 1028), (12, 1029)] {
        image[block * BLOCK..(block + 1) * BLOCK].copy_from_slice(&leaf(
            id,
            1,
            0x80000000,
            9,
            &[],
            true,
        ));
    }
    for (block, b) in [
        (17, omap(17, 18)),
        (
            18,
            leaf(18, 1, 0x40000000, 11, &omap_records(1026, 19), true),
        ),
        (20, omap(20, 21)),
        (
            21,
            leaf(21, 1, 0x40000000, 11, &omap_records(1027, 22), true),
        ),
        (22, leaf(1027, 1, 0, 14, &fs_records(), false)),
        (23, leaf(23, 1, 0x40000000, 15, &extent_records(), false)),
        (24, leaf(24, 1, 0x40000000, 16, &[], false)),
    ] {
        image[block * BLOCK..(block + 1) * BLOCK].copy_from_slice(&b);
    }
    let mut vol = object(1026, 1, 13, 0);
    vol[32..36].copy_from_slice(b"APSB");
    p64(&mut vol, 40, 2);
    p64(&mut vol, 88, 9);
    p32(&mut vol, 116, 2);
    p32(&mut vol, 120, 0x40000002);
    p32(&mut vol, 124, 0x40000002);
    p64(&mut vol, 128, 20);
    p64(&mut vol, 136, 1027);
    p64(&mut vol, 144, 23);
    p64(&mut vol, 152, 24);
    p64(&mut vol, 176, 19);
    p64(&mut vol, 184, 2);
    p64(&mut vol, 192, 1);
    p64(&mut vol, 264, 1);
    vol[704..712].copy_from_slice(b"fixture\0");
    seal(&mut vol);
    image[19 * BLOCK..20 * BLOCK].copy_from_slice(&vol);
    image[25 * BLOCK] = 3;
    let mut cib = object(42, 1, 0x40000007, 0);
    p32(&mut cib, 36, 1);
    p64(&mut cib, 40, 1);
    p32(&mut cib, 56, 512);
    p32(&mut cib, 60, 461);
    p64(&mut cib, 64, 41);
    seal(&mut cib);
    image[42 * BLOCK..43 * BLOCK].copy_from_slice(&cib);
    for bit in (0..47).chain([100, 102, 110, 112]) {
        image[41 * BLOCK + bit / 8] |= 1 << (bit % 8);
    }
    for block in [100, 102, 110] {
        for i in 0..BLOCK {
            image[block * BLOCK + i] = (i * 17 % 251) as u8;
        }
    }
    image[112 * BLOCK..112 * BLOCK + 7].copy_from_slice(b"nested!");
    image
}
/// Raw insertion into apfsprogs' independent single-volume format. System geometry is retained.
pub fn insert_native(image: &mut [u8]) {
    let q = |b: &[u8], p| u64::from_le_bytes(b[p..p + 8].try_into().unwrap());
    let u = |b: &[u8], p| u32::from_le_bytes(b[p..p + 4].try_into().unwrap());
    assert_eq!(&image[32..36], b"NXSB");
    assert_eq!(q(image, 16), 1);
    // Tool fixture addresses are independently checked against native object headers.
    for (at, kind) in [(171, 13), (174, 2), (175, 0x40000002), (196, 0x40000007)] {
        assert_eq!(u(image, at * BLOCK + 24), kind);
    }
    let mut fs = fs_records();
    for (key, value) in &mut fs {
        if q(key, 0) >> 60 == 8 {
            let physical = q(value, 8);
            if physical != 0 {
                p64(value, 8, physical + 200);
            }
        }
    }
    let mut ext = extent_records();
    for (key, _) in &mut ext {
        let physical = q(key, 0) & 0x0fffffffffffffff;
        p64(key, 0, (2u64 << 60) | (physical + 200));
    }
    image[174 * BLOCK..175 * BLOCK].copy_from_slice(&leaf(1027, 1, 0, 14, &fs, false));
    image[175 * BLOCK..176 * BLOCK].copy_from_slice(&leaf(175, 1, 0x40000000, 15, &ext, false));
    let vol = &mut image[171 * BLOCK..172 * BLOCK];
    p64(vol, 88, 9);
    p64(vol, 176, 19);
    p64(vol, 184, 2);
    p64(vol, 192, 1);
    p64(vol, 224, 9);
    seal(vol);
    for block in [300, 302, 310, 312] {
        for i in 0..BLOCK {
            image[block * BLOCK + i] = (i * 17 % 251) as u8;
        }
        let bit = block % 32768;
        let bitmap = 195 * BLOCK;
        assert_eq!(image[bitmap + bit / 8] & (1 << (bit % 8)), 0);
        image[bitmap + bit / 8] |= 1 << (bit % 8);
    }
    image[312 * BLOCK..312 * BLOCK + 7].copy_from_slice(b"nested!");
    let cib = &mut image[196 * BLOCK..197 * BLOCK];
    let free = u(cib, 60);
    p32(cib, 60, free - 4);
    seal(cib);
    let sm = &mut image[10 * BLOCK..11 * BLOCK];
    let free = q(sm, 72);
    p64(sm, 72, free - 4);
    seal(sm);
}
/// Second ring checkpoint; caller can tear one ephemeral checksum to exercise fallback.
pub fn next_checkpoint(image: &mut [u8]) {
    let mut nx = image[2 * BLOCK..3 * BLOCK].to_vec();
    p64(&mut nx, 16, 2);
    p64(&mut nx, 96, 3);
    p32(&mut nx, 128, 4);
    let data_count = u32::from_le_bytes(nx[108..112].try_into().unwrap());
    p32(&mut nx, 132, 8 % data_count);
    p32(&mut nx, 136, 2);
    p32(&mut nx, 144, 4);
    seal(&mut nx);
    image[4 * BLOCK..5 * BLOCK].copy_from_slice(&nx);
    let mut map = image[BLOCK..2 * BLOCK].to_vec();
    p64(&mut map, 8, 3);
    p64(&mut map, 16, 2);
    for i in 0..4 {
        let p = 40 + i * 40;
        let at = u64::from_le_bytes(map[p + 32..p + 40].try_into().unwrap()) + 4;
        p64(&mut map, p + 32, at);
    }
    seal(&mut map);
    image[3 * BLOCK..4 * BLOCK].copy_from_slice(&map);
    let data_base = u64::from_le_bytes(nx[120..128].try_into().unwrap()) as usize;
    for source in data_base..data_base + 4 {
        let mut b = image[source * BLOCK..(source + 1) * BLOCK].to_vec();
        p64(&mut b, 16, 2);
        if source == data_base + 1 {
            p64(&mut b, 336, 2);
        }
        seal(&mut b);
        image[(source + 4) * BLOCK..(source + 5) * BLOCK].copy_from_slice(&b);
    }
}
/// Recompute bitmap count summaries after an independently requested bit mutation.
pub fn bitmap_counts(image: &mut [u8]) {
    let allocated = (0..512)
        .filter(|n| image[41 * BLOCK + n / 8] & (1 << (n % 8)) != 0)
        .count();
    p64(image, 10 * BLOCK + 72, (512 - allocated) as u64);
    seal(&mut image[10 * BLOCK..11 * BLOCK]);
    p32(image, 42 * BLOCK + 60, (512 - allocated) as u32);
    seal(&mut image[42 * BLOCK..43 * BLOCK]);
}

/// Independently add an empty second volume with disjoint virtual/physical metadata.
pub fn second_volume(image: &mut [u8]) {
    for at in [0, 2] {
        let nx = &mut image[at * BLOCK..(at + 1) * BLOCK];
        p32(nx, 180, 2);
        p64(nx, 192, 1100);
        p64(nx, 88, 1102);
        seal(nx);
    }
    let mut records = omap_records(1026, 19);
    records.extend(omap_records(1100, 50));
    let root = leaf(18, 1, 0x40000000, 11, &records, true);
    image[18 * BLOCK..19 * BLOCK].copy_from_slice(&root);
    let mut vol = image[19 * BLOCK..20 * BLOCK].to_vec();
    p64(&mut vol, 8, 1100);
    p32(&mut vol, 36, 1);
    p64(&mut vol, 128, 51);
    p64(&mut vol, 136, 1101);
    p64(&mut vol, 144, 54);
    p64(&mut vol, 152, 55);
    p64(&mut vol, 176, 16);
    p64(&mut vol, 184, 0);
    p64(&mut vol, 192, 0);
    p64(&mut vol, 88, 5);
    vol[240..256].fill(0x62);
    seal(&mut vol);
    image[50 * BLOCK..51 * BLOCK].copy_from_slice(&vol);
    image[51 * BLOCK..52 * BLOCK].copy_from_slice(&omap(51, 52));
    image[52 * BLOCK..53 * BLOCK].copy_from_slice(&leaf(
        52,
        1,
        0x40000000,
        11,
        &omap_records(1101, 53),
        true,
    ));
    let records = vec![
        drec(1, 3, b"private-dir", true),
        drec(1, 2, b"root", true),
        (key(2, 3), inode(1, 2, b"root", true, 0, None)),
        (key(3, 3), inode(1, 3, b"private-dir", true, 0, None)),
    ];
    image[53 * BLOCK..54 * BLOCK].copy_from_slice(&leaf(1101, 1, 0, 14, &records, false));
    image[54 * BLOCK..55 * BLOCK].copy_from_slice(&leaf(54, 1, 0x40000000, 15, &[], false));
    image[55 * BLOCK..56 * BLOCK].copy_from_slice(&leaf(55, 1, 0x40000000, 16, &[], false));
    for block in 50..56 {
        image[41 * BLOCK + block / 8] |= 1 << (block % 8);
    }
    bitmap_counts(image);
    multivolume_geometry(image);
}
/// New checkpoint owns new volume/object-map pages while old checkpoint pages remain pinned.
pub fn relocated_checkpoint(image: &mut [u8]) {
    next_checkpoint(image);
    let mut vol = image[19 * BLOCK..20 * BLOCK].to_vec();
    p64(&mut vol, 16, 2);
    p64(&mut vol, 128, 61);
    p64(&mut vol, 144, 64);
    p64(&mut vol, 152, 65);
    seal(&mut vol);
    image[60 * BLOCK..61 * BLOCK].copy_from_slice(&vol);
    for (at, b) in [
        (61, omap(61, 62)),
        (
            62,
            leaf(62, 2, 0x40000000, 11, &omap_records(1027, 63), true),
        ),
        (63, leaf(1027, 2, 0, 14, &fs_records(), false)),
        (64, leaf(64, 2, 0x40000000, 15, &extent_records(), false)),
        (65, leaf(65, 2, 0x40000000, 16, &[], false)),
        (66, omap(66, 67)),
        (
            67,
            leaf(67, 2, 0x40000000, 11, &omap_records(1026, 60), true),
        ),
    ] {
        image[at * BLOCK..(at + 1) * BLOCK].copy_from_slice(&b);
    }
    let old_bitmap = image[41 * BLOCK..42 * BLOCK].to_vec();
    image[43 * BLOCK..44 * BLOCK].copy_from_slice(&old_bitmap);
    for at in 60..68 {
        image[43 * BLOCK + at / 8] |= 1 << (at % 8);
    }
    let mut cib = image[42 * BLOCK..43 * BLOCK].to_vec();
    p64(&mut cib, 8, 44);
    p64(&mut cib, 16, 2);
    p64(&mut cib, 40, 2);
    p32(&mut cib, 60, 453);
    p64(&mut cib, 64, 43);
    seal(&mut cib);
    image[44 * BLOCK..45 * BLOCK].copy_from_slice(&cib);
    image[26 * BLOCK] = 0x0f;
    let sm = &mut image[14 * BLOCK..15 * BLOCK];
    p64(sm, 72, 453);
    p16(sm, 344, 1);
    p16(sm, 320, 0);
    p16(sm, 352, 2);
    p16(sm, 354, 65535);
    p64(sm, 384, 44);
    seal(sm);
    let nx = &mut image[4 * BLOCK..5 * BLOCK];
    p64(nx, 160, 66);
    seal(nx);
}

/// Second independent volume inserted into the pinned 64 MiB experimental formatter layout.
pub fn insert_native_second_volume(image: &mut [u8]) {
    let q = |b: &[u8], p| u64::from_le_bytes(b[p..p + 8].try_into().unwrap());
    let cmap = q(image, 160) as usize;
    let vol_at = cmap + 2;
    let sm_at = q(image, 120) as usize + 1;
    let cib_at = q(image, sm_at * BLOCK + 384) as usize;
    let bitmap_at = q(image, cib_at * BLOCK + 64) as usize;
    assert_eq!(&image[vol_at * BLOCK + 32..vol_at * BLOCK + 36], b"APSB");
    assert_eq!(u32::from_le_bytes(image[180..184].try_into().unwrap()), 2);
    for at in [0, 2] {
        let nx = &mut image[at * BLOCK..(at + 1) * BLOCK];
        p64(nx, 192, 1100);
        p64(nx, 88, 1102);
        seal(nx);
    }
    let mut records = omap_records(1026, vol_at as u64);
    records.extend(omap_records(1100, 600));
    image[(cmap + 1) * BLOCK..(cmap + 2) * BLOCK].copy_from_slice(&leaf(
        cmap as u64 + 1,
        1,
        0x40000000,
        11,
        &records,
        true,
    ));
    let mut vol = image[vol_at * BLOCK..(vol_at + 1) * BLOCK].to_vec();
    p64(&mut vol, 8, 1100);
    p32(&mut vol, 36, 1);
    p64(&mut vol, 128, 601);
    p64(&mut vol, 136, 1101);
    p64(&mut vol, 144, 604);
    p64(&mut vol, 152, 605);
    p64(&mut vol, 176, 16);
    p64(&mut vol, 184, 0);
    p64(&mut vol, 192, 0);
    p64(&mut vol, 88, 5);
    p64(&mut vol, 224, 5);
    vol[240..256].fill(0x62);
    seal(&mut vol);
    image[600 * BLOCK..601 * BLOCK].copy_from_slice(&vol);
    let fs = vec![
        drec(1, 3, b"private-dir", true),
        drec(1, 2, b"root", true),
        (key(2, 3), inode(1, 2, b"root", true, 0, None)),
        (key(3, 3), inode(1, 3, b"private-dir", true, 0, None)),
    ];
    for (at, b) in [
        (601, omap(601, 602)),
        (
            602,
            leaf(602, 1, 0x40000000, 11, &omap_records(1101, 603), true),
        ),
        (603, leaf(1101, 1, 0, 14, &fs, false)),
        (604, leaf(604, 1, 0x40000000, 15, &[], false)),
        (605, leaf(605, 1, 0x40000000, 16, &[], false)),
    ] {
        image[at * BLOCK..(at + 1) * BLOCK].copy_from_slice(&b);
    }
    for block in 600..606 {
        assert_eq!(image[bitmap_at * BLOCK + block / 8] & (1 << (block % 8)), 0);
        image[bitmap_at * BLOCK + block / 8] |= 1 << (block % 8);
    }
    let free = u32::from_le_bytes(
        image[cib_at * BLOCK + 60..cib_at * BLOCK + 64]
            .try_into()
            .unwrap(),
    );
    p32(image, cib_at * BLOCK + 60, free - 6);
    seal(&mut image[cib_at * BLOCK..(cib_at + 1) * BLOCK]);
    let free = q(image, sm_at * BLOCK + 72);
    p64(image, sm_at * BLOCK + 72, free - 6);
    seal(&mut image[sm_at * BLOCK..(sm_at + 1) * BLOCK]);
}
/// Native multi-volume minimum geometry represented by a small stored prefix and zero tail.
pub const MULTIVOLUME_LENGTH: u64 = 512 * 1024 * 1024 + 4096;
pub fn multivolume_geometry(image: &mut [u8]) {
    let blocks = MULTIVOLUME_LENGTH / 4096;
    for at in [0, 2] {
        p64(image, at * BLOCK + 40, blocks);
        seal(&mut image[at * BLOCK..(at + 1) * BLOCK]);
    }
    // Five chunks + one CIB require exactly18 internal-pool blocks. Relocate
    // the pool so it does not overlap the independent second volume at50..55.
    let old_bitmap = image[41 * BLOCK..42 * BLOCK].to_vec();
    let mut bitmap = old_bitmap;
    for n in 41..47 {
        bitmap[n / 8] &= !(1 << (n % 8));
    }
    for n in 400..418 {
        bitmap[n / 8] |= 1 << (n % 8);
    }
    image[400 * BLOCK..401 * BLOCK].copy_from_slice(&bitmap);
    let mut cib = image[42 * BLOCK..43 * BLOCK].to_vec();
    p64(&mut cib, 8, 401);
    p64(&mut cib, 64, 400);
    image[401 * BLOCK..402 * BLOCK].copy_from_slice(&cib);
    p64(image, 10 * BLOCK + 152, 18);
    p64(image, 10 * BLOCK + 176, 400);
    p64(image, 10 * BLOCK + 384, 401);
    let allocated = bitmap
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum::<u64>();
    p64(image, 10 * BLOCK + 48, blocks);
    p64(image, 10 * BLOCK + 56, 5);
    p64(image, 10 * BLOCK + 72, blocks - allocated);
    seal(&mut image[10 * BLOCK..11 * BLOCK]);
    p32(image, 401 * BLOCK + 36, 5);
    for i in 0..5 {
        let p = 401 * BLOCK + 40 + i * 32;
        let start = i as u64 * 32768;
        let count = (blocks - start).min(32768);
        p64(image, p, 1);
        p64(image, p + 8, start);
        p32(image, p + 16, count as u32);
        p32(
            image,
            p + 20,
            (count - if i == 0 { allocated } else { 0 }) as u32,
        );
        if i != 0 {
            p64(image, p + 24, 0);
        }
    }
    seal(&mut image[401 * BLOCK..402 * BLOCK]);
}

fn sibling_field(value: &mut Vec<u8>, id: u64) {
    let mut field = vec![0; 16];
    p16(&mut field, 0, 1);
    p16(&mut field, 2, 8);
    field[4] = 1;
    field[5] = 2;
    p16(&mut field, 6, 8);
    p64(&mut field, 8, id);
    value.extend(field);
}
/// Regular hardlinks with exact dentry sibling IDs and bidirectional sibling records.
pub fn hardlink_records() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut records = fs_records();
    for (key, value) in &mut records {
        let raw = u64::from_le_bytes(key[..8].try_into().unwrap());
        if raw == (9u64 << 60) | 2 && key[10..] == *b"A\xc3\xa9-file\0" {
            sibling_field(value, 19);
        }
        if raw == (3u64 << 60) | 16 {
            p32(value, 56, 2);
        }
        if raw == (3u64 << 60) | 17 {
            p32(value, 56, 2);
        }
    }
    let mut alias = drec(17, 16, b"Alias", false);
    sibling_field(&mut alias.1, 20);
    records.push(alias);
    for (sibling, parent, name) in [
        (19u64, 2u64, b"A\xc3\xa9-file".as_slice()),
        (20, 17, b"Alias".as_slice()),
    ] {
        let mut k = key(16, 5);
        k.extend_from_slice(&sibling.to_le_bytes());
        let mut v = parent.to_le_bytes().to_vec();
        v.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
        v.extend_from_slice(name);
        v.push(0);
        records.push((k, v));
        records.push((key(sibling, 12), 16u64.to_le_bytes().to_vec()));
    }
    sort_records(&mut records);
    records
}
/// A clone either shares its original private dstream, or has a distinct dstream sharing blocks.
pub fn shared_records(distinct: bool) -> (Records, Records) {
    let mut records = hardlink_records();
    let mut clone = inode(2, 16, b"Clone", false, 1, Some((4 * 4096 + 13, 5 * 4096)));
    p64(&mut clone, 48, 0x4610);
    if distinct {
        p64(&mut clone, 8, 21);
    }
    records.push((key(21, 3), clone));
    records.push(drec(2, 21, b"Clone", false));
    let resource = records
        .iter()
        .find(|(k, _)| u64::from_le_bytes(k[..8].try_into().unwrap()) == ((4u64 << 60) | 16))
        .unwrap()
        .clone();
    let mut k = resource.0;
    p64(&mut k, 0, (4u64 << 60) | 21);
    records.push((k, resource.1));
    let copied: Vec<_> = records
        .iter()
        .filter(|(k, _)| u64::from_le_bytes(k[..8].try_into().unwrap()) == ((8u64 << 60) | 16))
        .cloned()
        .collect();
    for (k, v) in &mut records {
        let raw = u64::from_le_bytes(k[..8].try_into().unwrap());
        if raw == ((3u64 << 60) | 16) {
            p64(v, 48, 0x4600);
        }
        if raw == ((3u64 << 60) | 2) {
            p32(v, 56, 3);
        }
        if !distinct && raw == ((6u64 << 60) | 16) {
            p32(v, 0, 2);
        }
    }
    if distinct {
        records.push((key(21, 6), 1u32.to_le_bytes().to_vec()));
        for (mut k, v) in copied {
            p64(&mut k, 0, (8u64 << 60) | 21);
            records.push((k, v));
        }
    }
    sort_records(&mut records);
    let mut ext = extent_records();
    if distinct {
        for (k, v) in &mut ext {
            if u64::from_le_bytes(k[..8].try_into().unwrap()) & 0x0fff_ffff_ffff_ffff != 112 {
                p32(v, 16, 2);
            }
        }
    }
    (records, ext)
}
/// Fully framed independent shared-object seed; no writer or decoder is invoked.
pub fn shared_seed(distinct: bool) -> Vec<u8> {
    let mut image = apfs_seed();
    let (fs, ext) = shared_records(distinct);
    image[22 * BLOCK..23 * BLOCK].copy_from_slice(&leaf(1027, 1, 0, 14, &fs, false));
    image[23 * BLOCK..24 * BLOCK].copy_from_slice(&leaf(23, 1, 0x40000000, 15, &ext, false));
    let vol = &mut image[19 * BLOCK..20 * BLOCK];
    p64(vol, 176, 22);
    p64(vol, 184, 3);
    seal(vol);
    image
}

fn sort_records(records: &mut [(Vec<u8>, Vec<u8>)]) {
    records.sort_by(|a, b| {
        let x = u64::from_le_bytes(a.0[..8].try_into().unwrap());
        let y = u64::from_le_bytes(b.0[..8].try_into().unwrap());
        (x & 0x0fff_ffff_ffff_ffff)
            .cmp(&(y & 0x0fff_ffff_ffff_ffff))
            .then((x >> 60).cmp(&(y >> 60)))
            .then_with(|| match x >> 60 {
                4 | 9 => a.0[10..].cmp(&b.0[10..]),
                5 | 8 => u64::from_le_bytes(a.0[8..16].try_into().unwrap())
                    .cmp(&u64::from_le_bytes(b.0[8..16].try_into().unwrap())),
                _ => a.0[8..].cmp(&b.0[8..]),
            })
    });
}

/// Independent shared native object insertion into the pinned populated 64 MiB formatter image.
pub fn insert_native_shared(image: &mut [u8], distinct: bool) {
    let (mut fs, mut ext) = shared_records(distinct);
    for (k, v) in &mut fs {
        if u64::from_le_bytes(k[..8].try_into().unwrap()) >> 60 == 8 {
            let at = u64::from_le_bytes(v[8..16].try_into().unwrap());
            if at != 0 {
                p64(v, 8, at + 200);
            }
        }
    }
    for (k, _) in &mut ext {
        let at = u64::from_le_bytes(k[..8].try_into().unwrap()) & 0x0fff_ffff_ffff_ffff;
        p64(k, 0, (2u64 << 60) | (at + 200));
    }
    image[174 * BLOCK..175 * BLOCK].copy_from_slice(&leaf(1027, 1, 0, 14, &fs, false));
    image[175 * BLOCK..176 * BLOCK].copy_from_slice(&leaf(175, 1, 0x40000000, 15, &ext, false));
    let vol = &mut image[171 * BLOCK..172 * BLOCK];
    p64(vol, 176, 22);
    p64(vol, 184, 3);
    seal(vol);
}

pub fn shared_history_seed(distinct: bool) -> Vec<u8> {
    let mut image = apfs_seed();
    relocated_checkpoint(&mut image);
    let (fs, ext) = shared_records(distinct);
    image[63 * BLOCK..64 * BLOCK].copy_from_slice(&leaf(1027, 2, 0, 14, &fs, false));
    image[64 * BLOCK..65 * BLOCK].copy_from_slice(&leaf(64, 2, 0x40000000, 15, &ext, false));
    let vol = &mut image[60 * BLOCK..61 * BLOCK];
    p64(vol, 176, 22);
    p64(vol, 184, 3);
    seal(vol);
    image
}
