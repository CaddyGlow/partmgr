// Independent Linux JFS little-endian fixture; no production codec.
pub const BLOCK: usize = 4096;
pub fn p16(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
pub fn p32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
pub fn p64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
pub fn pxd(b: &mut [u8], p: usize, start: u64, count: u32) {
    p32(b, p, count | ((start >> 32) as u32) << 24);
    p32(b, p + 4, start as u32);
}
pub fn xt(runs: &[(u64, u64, u32, u8)], index: bool, page: Option<u64>) -> Vec<u8> {
    let mut b = vec![0; if page.is_some() { 4096 } else { 288 }];
    b[16] = 0x80 | if index { 4 } else { 2 } | if page.is_none() { 1 } else { 0 };
    p16(&mut b, 18, (runs.len() + 2) as u16);
    p16(&mut b, 20, if page.is_some() { 256 } else { 18 });
    if let Some(p) = page {
        pxd(&mut b, 24, p, 1);
    }
    for (i, (logical, physical, count, flag)) in runs.iter().enumerate() {
        let p = (i + 2) * 16;
        b[p] = *flag;
        b[p + 3] = (logical >> 32) as u8;
        p32(&mut b, p + 4, *logical as u32);
        pxd(&mut b, p + 8, *physical, *count);
    }
    b
}
pub fn inode(
    id: u32,
    set: u32,
    extent: u64,
    dir: bool,
    size: u64,
    blocks: u64,
    links: u32,
) -> Vec<u8> {
    let mut b = vec![0; 512];
    p32(&mut b, 0, 0x11223344);
    p32(&mut b, 4, set);
    p32(&mut b, 8, id);
    p32(&mut b, 12, 7);
    pxd(&mut b, 16, extent, 4);
    p64(&mut b, 24, size);
    p64(&mut b, 32, blocks);
    p32(&mut b, 40, links);
    p32(&mut b, 44, 501);
    p32(&mut b, 48, 20);
    p32(&mut b, 52, if dir { 0x141ed } else { 0x280a4 });
    for p in [56, 64, 72, 80] {
        p32(&mut b, p, 0xabcdef01);
        p32(&mut b, p + 4, 123456789);
    }
    p32(&mut b, 120, 2);
    b
}
pub fn imap(extent: u64, allocated: &[u32]) -> Vec<u8> {
    let mut b = vec![0; 8192];
    p32(&mut b, 0, u32::MAX);
    p32(&mut b, 4, 1);
    p32(&mut b, 8, 32);
    p32(&mut b, 12, 32 - allocated.len() as u32);
    p32(&mut b, 16, 4);
    p32(&mut b, 20, 2);
    for ag in 0..128 {
        p32(&mut b, 2048 + ag * 16, u32::MAX);
        p32(&mut b, 2052 + ag * 16, u32::MAX);
    }
    p32(&mut b, 2048, 0);
    p32(&mut b, 2052, 0);
    p32(&mut b, 2056, 32);
    p32(&mut b, 2060, 32 - allocated.len() as u32);
    for p in [12, 16, 20, 24, 28] {
        p32(&mut b, 4096 + p, u32::MAX);
    }
    for i in 0..4 {
        p32(
            &mut b,
            4096 + 32 + i * 4,
            if i == 0 { 0x7fffffff } else { u32::MAX },
        );
        p32(
            &mut b,
            4096 + 48 + i * 4,
            if i == 0 { 0x80000000 } else { 0 },
        );
    }
    p32(&mut b, 4096 + 64, 32 - allocated.len() as u32);
    p32(&mut b, 4096 + 68, 127);
    let word = allocated.iter().fold(0, |w, n| w | (0x80000000 >> n));
    p32(&mut b, 4096 + 2048, word);
    p32(&mut b, 4096 + 2560, word);
    pxd(&mut b, 4096 + 3072, extent, 4);
    b
}
pub fn name() -> Vec<u16> {
    vec![0x03a9, 0xd800, 0x78]
}
pub fn dt(names: &[(Vec<u16>, u32, u32)], parent: u32) -> (Vec<u8>, Vec<u8>) {
    let mut b = vec![0; 288];
    b[16] = 0x83;
    b[17] = names.len() as u8;
    b[18] = (8 - names.len()) as u8;
    b[19] = (names.len() + 1) as u8;
    p32(&mut b, 20, parent);
    let mut indexes = vec![0; 96];
    for (i, (name, ino, index)) in names.iter().enumerate() {
        assert!(name.len() <= 11);
        let slot = i + 1;
        let p = slot * 32;
        b[24 + i] = slot as u8;
        p32(&mut b, p, *ino);
        b[p + 4] = 255;
        b[p + 5] = name.len() as u8;
        for (j, u) in name.iter().enumerate() {
            p16(&mut b, p + 6 + j * 2, *u);
        }
        p32(&mut b, p + 28, *index);
        let p = (*index as usize - 2) * 8;
        indexes[p + 1] = 1;
        indexes[p + 2] = i as u8;
    }
    for slot in names.len() + 1..9 {
        b[slot * 32] = if slot < 8 { (slot + 1) as u8 } else { 255 };
        b[slot * 32 + 1] = 1;
    }
    (b, indexes)
}
fn summary(b: &mut [u8], p: usize, mut leaves: Vec<i8>, min: i8) -> i8 {
    let count = leaves.len();
    for power in 1..=count.ilog2() {
        let width = 1 << power;
        for start in (0..count).step_by(width) {
            if leaves[start] == min + power as i8 - 1 && leaves[start + width / 2] == leaves[start]
            {
                leaves[start] += 1;
                leaves[start + width / 2] = -1;
            }
        }
    }
    let total = (4 * count - 1) / 3;
    let first = total - count;
    let mut tree = vec![-1; total];
    tree[first..].copy_from_slice(&leaves);
    for i in (0..first).rev() {
        tree[i] = *tree[i * 4 + 1..i * 4 + 5].iter().max().unwrap();
    }
    p32(b, p, count as u32);
    p32(b, p + 4, count.ilog2());
    p32(b, p + 8, first as u32);
    p32(b, p + 12, count.ilog2() / 2);
    b[p + 16] = min as u8;
    for (i, v) in tree.iter().enumerate() {
        b[p + 17 + i] = *v as u8;
    }
    tree[0]
}
pub fn rebuild_map(image: &mut [u8], used: &[usize]) {
    let mut words = [u32::MAX; 256];
    for n in 0..480 {
        if !used.contains(&n) {
            words[n / 32] &= !(0x80000000 >> (n % 32));
        }
    }
    let free = 480 - used.len();
    let page = &mut image[20 * BLOCK..21 * BLOCK];
    page.fill(0);
    p32(page, 0, 480);
    p32(page, 4, free as u32);
    let mut leaves = Vec::new();
    for (i, word) in words.iter().enumerate() {
        p32(page, 2048 + i * 4, *word);
        p32(page, 3072 + i * 4, *word);
        let mut best = -1;
        for power in 0..=5 {
            for start in (0..32).step_by(1 << power) {
                let mask = if power == 5 {
                    u32::MAX
                } else {
                    ((1u32 << (1 << power)) - 1) << (32 - start - (1 << power))
                };
                if word & mask == 0 {
                    best = best.max(power as i8);
                }
            }
        }
        leaves.push(best);
    }
    let root = summary(page, 16, leaves, 5);
    let mut leaves = vec![-1; 1024];
    leaves[0] = root;
    let root = summary(&mut image[19 * BLOCK..20 * BLOCK], 0, leaves, 13);
    let control = &mut image[16 * BLOCK..17 * BLOCK];
    p64(control, 0, 480);
    p64(control, 8, free as u64);
    p32(control, 20, 1);
    p32(control, 44, 1);
    p32(control, 48, 341);
    p32(control, 52, 13);
    p64(control, 56, free as u64);
    p64(control, 1080, 8192);
    control[1088] = root as u8;
}
pub fn jfs_seed() -> Vec<u8> {
    let mut image = vec![0; 512 * BLOCK];
    let mut h = vec![0; BLOCK];
    h[..4].copy_from_slice(b"JFS1");
    p32(&mut h, 4, 2);
    p64(&mut h, 8, 480 * 8);
    p32(&mut h, 16, 4096);
    p16(&mut h, 20, 12);
    p16(&mut h, 22, 3);
    p32(&mut h, 24, 512);
    p16(&mut h, 28, 9);
    p32(&mut h, 32, 8192);
    p32(&mut h, 36, 0x10200900);
    pxd(&mut h, 48, 25, 4);
    pxd(&mut h, 56, 23, 2);
    pxd(&mut h, 72, 482, 30);
    pxd(&mut h, 80, 480, 2);
    image[32768..36864].copy_from_slice(&h);
    image[61440..65536].copy_from_slice(&h);
    let mut table = vec![0; 16384];
    for id in [0, 1, 2, 3, 4, 16] {
        let runs = match id {
            1 => vec![(0, 9, 2, 0)],
            2 => vec![(0, 16, 6, 0)],
            16 => vec![(0, 33, 2, 0)],
            _ => vec![],
        };
        let length = if id == 1 || id == 16 {
            8192
        } else if id == 2 {
            24576
        } else {
            0
        };
        let mut raw = inode(
            id,
            1,
            11,
            false,
            length,
            runs.iter().map(|r| u64::from(r.2)).sum(),
            1,
        );
        raw[44..52].fill(0);
        p32(&mut raw, 52, 0x18000);
        raw[224..].copy_from_slice(&xt(&runs, false, None));
        if id == 0 {
            raw[224..].fill(0);
        }
        table[id as usize * 512..(id as usize + 1) * 512].copy_from_slice(&raw);
    }
    image[45056..61440].copy_from_slice(&table);
    let mut secondary = table.clone();
    for id in [0, 1, 2, 3, 4, 16] {
        pxd(&mut secondary, id * 512 + 16, 25, 4);
    }
    secondary[512 + 224..1024].copy_from_slice(&xt(&[(0, 23, 2, 0)], false, None));
    image[25 * BLOCK..29 * BLOCK].copy_from_slice(&secondary);
    image[9 * BLOCK..11 * BLOCK].copy_from_slice(&imap(11, &[0, 1, 2, 3, 4, 16]));
    image[23 * BLOCK..25 * BLOCK].copy_from_slice(&imap(25, &[0, 1, 2, 3, 4, 16]));
    image[33 * BLOCK..35 * BLOCK].copy_from_slice(&imap(29, &[0, 1, 2, 3, 4, 5, 6]));
    let names = [
        ("Alias".encode_utf16().collect(), 4, 2),
        ("Box".encode_utf16().collect(), 5, 3),
        (name(), 4, 4),
    ];
    let (d, i) = dt(&names, 2);
    let mut raw = inode(2, 16, 29, true, 256, 0, 3);
    p32(&mut raw, 120, 5);
    raw[128..224].copy_from_slice(&i);
    raw[224..].copy_from_slice(&d);
    image[29 * BLOCK + 1024..29 * BLOCK + 1536].copy_from_slice(&raw);
    for id in [0, 1, 3] {
        let raw = inode(id, 16, 29, false, 0, 0, 1);
        image[29 * BLOCK + id as usize * 512..29 * BLOCK + (id as usize + 1) * 512]
            .copy_from_slice(&raw);
    }
    let mut raw = inode(4, 16, 29, false, 4 * 4096 + 7, 4, 2);
    raw[224..].copy_from_slice(&xt(&[(0, 90, 1, 0)], true, None));
    image[29 * BLOCK + 2048..29 * BLOCK + 2560].copy_from_slice(&raw);
    image[90 * BLOCK..91 * BLOCK].copy_from_slice(&xt(
        &[(0, 100, 1, 0), (2, 102, 1, 0), (4, 110, 1, 8)],
        false,
        Some(90),
    ));
    let mut raw = inode(5, 16, 29, true, 256, 0, 2);
    p32(&mut raw, 120, 3);
    let (d, i) = dt(&[("Child".encode_utf16().collect(), 6, 2)], 2);
    raw[128..224].copy_from_slice(&i);
    raw[224..].copy_from_slice(&d);
    image[29 * BLOCK + 2560..29 * BLOCK + 3072].copy_from_slice(&raw);
    let mut raw = inode(6, 16, 29, false, 7, 1, 1);
    raw[224..].copy_from_slice(&xt(&[(0, 112, 1, 0)], false, None));
    image[29 * BLOCK + 3072..29 * BLOCK + 3584].copy_from_slice(&raw);
    image[112 * BLOCK..112 * BLOCK + 7].copy_from_slice(b"nested!");
    for n in [100, 102] {
        for j in 0..BLOCK {
            image[n * BLOCK + j] = (j * 17 % 251) as u8;
        }
    }
    image[110 * BLOCK..111 * BLOCK].fill(0xaa);
    let mut log = vec![0; BLOCK];
    p32(&mut log, 0, 0x87654321);
    p32(&mut log, 4, 1);
    p32(&mut log, 12, 30);
    p32(&mut log, 16, 4096);
    p32(&mut log, 20, 12);
    p32(&mut log, 24, 0x10200900);
    p32(&mut log, 28, 1);
    image[483 * BLOCK..484 * BLOCK].copy_from_slice(&log);
    let mut used: Vec<_> = (0..22).chain(23..35).collect();
    used.extend([90, 100, 102, 110, 112]);
    rebuild_map(&mut image, &used);
    image
}
/// Independent test-only native fixture insertion, leaving formatter geometry/system files intact.
pub fn insert_native(image: &mut [u8]) {
    let le32 = |b: &[u8], p: usize| u32::from_le_bytes(b[p..p + 4].try_into().unwrap());
    let le64 = |b: &[u8], p: usize| u64::from_le_bytes(b[p..p + 8].try_into().unwrap());
    let address =
        |b: &[u8], p: usize| ((u64::from(le32(b, p) >> 24)) << 32) | u64::from(le32(b, p + 4));
    let inode_map = address(image, 45056 + 16 * 512 + 224 + 40) as usize * BLOCK;
    let inode_extent = address(image, inode_map + 4096 + 3072) as usize * BLOCK;
    let block_map = address(image, 45056 + 2 * 512 + 224 + 40) as usize * BLOCK;
    let root = inode_extent + 2 * 512;
    let stamp = le32(image, root);
    let extent = image[root + 16..root + 24].to_vec();
    let mut donor = jfs_seed();
    external_directory(&mut donor);
    image[root + 128..root + 512]
        .copy_from_slice(&donor[29 * BLOCK + 2 * 512 + 128..29 * BLOCK + 3 * 512]);
    p64(image, root + 32, 1);
    p32(image, root + 40, 3);
    p32(image, root + 120, 5);
    for ino in [4, 5, 6] {
        let mut raw = donor[29 * BLOCK + ino * 512..29 * BLOCK + (ino + 1) * 512].to_vec();
        p32(&mut raw, 0, stamp);
        raw[16..24].copy_from_slice(&extent);
        image[inode_extent + ino * 512..inode_extent + (ino + 1) * 512].copy_from_slice(&raw);
    }
    p32(image, inode_map + 12, 25);
    p32(image, inode_map + 2060, 25);
    p32(image, inode_map + 4096 + 64, 25);
    p32(image, inode_map + 4096 + 2048, 0xfe000000);
    p32(image, inode_map + 4096 + 2560, 0xfe000000);
    let additions = [90, 91, 100, 102, 110, 112];
    for block in additions {
        let at = block_map + (4 + block / 8192) * BLOCK;
        let word = (block % 8192) / 32;
        let bit = 0x80000000 >> (block % 32);
        assert_eq!(le32(image, at + 3072 + word * 4) & bit, 0);
        for map in [2048, 3072] {
            let value = le32(image, at + map + word * 4) | bit;
            p32(image, at + map + word * 4, value);
        }
        image[block * BLOCK..(block + 1) * BLOCK]
            .copy_from_slice(&donor[block * BLOCK..(block + 1) * BLOCK]);
    }
    let mapped = le64(image, block_map) as usize;
    let agsize = le64(image, block_map + 1080) as usize;
    let mut roots = vec![-1; 1024];
    let mut totalfree = 0;
    let mut agfree = [0u64; 128];
    for (number, root) in roots.iter_mut().enumerate().take(mapped.div_ceil(8192)) {
        let at = block_map + (4 + number) * BLOCK;
        let covered = le32(image, at) as usize;
        let mut free = 0;
        let mut leaves = Vec::new();
        for word in 0..256 {
            let value = le32(image, at + 3072 + word * 4);
            let mut best = -1;
            for power in 0..=5 {
                for start in (0..32).step_by(1 << power) {
                    let mask = if power == 5 {
                        u32::MAX
                    } else {
                        ((1u32 << (1 << power)) - 1) << (32 - start - (1 << power))
                    };
                    if value & mask == 0 {
                        best = best.max(power as i8);
                    }
                }
            }
            leaves.push(best);
            for bit in 0..32 {
                let relative = word * 32 + bit;
                if relative < covered && value & (0x80000000 >> bit) == 0 {
                    free += 1;
                    agfree[(number * 8192 + relative) / agsize] += 1;
                }
            }
        }
        p32(image, at + 4, free);
        totalfree += u64::from(free);
        *root = summary(&mut image[at..at + BLOCK], 16, leaves, 5);
    }
    let root = summary(
        &mut image[block_map + 3 * BLOCK..block_map + 4 * BLOCK],
        0,
        roots,
        13,
    );
    p64(image, block_map + 8, totalfree);
    for (ag, free) in agfree.iter().enumerate() {
        p64(image, block_map + 56 + ag * 8, *free);
    }
    image[block_map + 1088] = root as u8;
}
/// Independent external directory-leaf/index fixture with native persistent table references.
pub fn external_directory(image: &mut [u8]) {
    let root = 29 * BLOCK + 2 * 512;
    let old = image[root + 224..root + 512].to_vec();
    let mut page = vec![0; BLOCK];
    page[16] = 0x82;
    page[17] = 3;
    page[18] = 120;
    page[19] = 4;
    page[20] = 128;
    page[21] = 124;
    pxd(&mut page, 24, 91, 1);
    page[32..128].copy_from_slice(&old[32..128]);
    page[124 * 32..124 * 32 + 3].copy_from_slice(&[1, 2, 3]);
    for slot in 4..124 {
        page[slot * 32] = if slot < 123 { (slot + 1) as u8 } else { 255 };
        page[slot * 32 + 1] = 1;
    }
    image[91 * BLOCK..92 * BLOCK].copy_from_slice(&page);
    let mut index = vec![0; 288];
    index[16] = 0x85;
    index[17] = 1;
    index[18] = 7;
    index[19] = 2;
    p32(&mut index, 20, 2);
    index[24] = 1;
    pxd(&mut index, 32, 91, 1);
    index[40] = 255;
    for slot in 2..9 {
        index[slot * 32] = if slot < 8 { (slot + 1) as u8 } else { 255 };
        index[slot * 32 + 1] = 1;
    }
    image[root + 224..root + 512].copy_from_slice(&index);
    p64(image, root + 32, 1);
    for slot in 0..3 {
        p32(image, root + 128 + slot * 8 + 4, 91);
    }
    let mut used: Vec<_> = (0..22).chain(23..35).collect();
    used.extend([90, 91, 100, 102, 110, 112]);
    rebuild_map(image, &used);
}
