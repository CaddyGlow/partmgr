// Independent hand-authored NTFS allocation/index fixture; no production encoder.
#![allow(dead_code)]
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
fn base_fixture() -> Vec<u8> {
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
pub(crate) fn name_value(name: &str, parent: u64) -> Vec<u8> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let mut v = vec![0; 66 + 2 * units.len()];
    q(&mut v, 0, parent | (7 << 48));
    v[64] = units.len() as u8;
    v[65] = 1;
    for (i, c) in units.into_iter().enumerate() {
        w(&mut v, 66 + 2 * i, c);
    }
    v
}
pub(crate) fn index_entry(number: u64, name: &str, child: Option<u64>) -> Vec<u8> {
    let v = name_value(name, 5);
    let n = (16 + v.len() + usize::from(child.is_some()) * 8).next_multiple_of(8);
    let mut b = vec![0; n];
    q(&mut b, 0, number | (7 << 48));
    w(&mut b, 8, n as u16);
    w(&mut b, 10, v.len() as u16);
    w(&mut b, 12, u16::from(child.is_some()));
    b[16..16 + v.len()].copy_from_slice(&v);
    if let Some(c) = child {
        q(&mut b, n - 8, c);
    }
    b
}
pub(crate) fn terminal(child: Option<u64>) -> Vec<u8> {
    let n = if child.is_some() { 24 } else { 16 };
    let mut b = vec![0; n];
    w(&mut b, 8, n as u16);
    w(&mut b, 12, 2 | u16::from(child.is_some()));
    if let Some(c) = child {
        q(&mut b, 16, c);
    }
    b
}
pub(crate) fn root_attribute(entries: &[Vec<u8>], large: bool) -> Vec<u8> {
    let n = 32 + entries.iter().map(Vec::len).sum::<usize>();
    let mut v = vec![0; n];
    d(&mut v, 0, 0x30);
    d(&mut v, 4, 1);
    d(&mut v, 8, 1024);
    v[12] = 2;
    d(&mut v, 16, 16);
    d(&mut v, 20, (n - 16) as u32);
    d(&mut v, 24, (n - 16) as u32);
    d(&mut v, 28, u32::from(large));
    let mut at = 32;
    for e in entries {
        v[at..at + e.len()].copy_from_slice(e);
        at += e.len();
    }
    named_resident(0x90, &v, 1)
}
pub(crate) fn named_resident(kind: u32, value: &[u8], id: u16) -> Vec<u8> {
    let mut a = resident(kind, &[vec![0; 8], value.to_vec()].concat(), id);
    a[9] = 4;
    w(&mut a, 10, 24);
    d(&mut a, 16, value.len() as u32);
    w(&mut a, 20, 32);
    a[24..32].copy_from_slice(&[36, 0, 73, 0, 51, 0, 48, 0]);
    a
}
fn fixture() -> Vec<u8> {
    let mut b = base_fixture();
    b.resize(512 * 1024, 0);
    q(&mut b, 40, 1024);
    let up = nonresident(&[0x22, 0, 1, 0x80, 0, 0], 256, 131072, 131072, false);
    let p = 2048 + 10 * 1024;
    b[p..p + 1024].copy_from_slice(&record(10, &[up]));
    for c in 0..65536u32 {
        let upper = if (97..=122).contains(&c) { c - 32 } else { c };
        w(&mut b, 128 * 512 + c as usize * 2, upper as u16);
    }
    let p = 2048 + 5 * 1024;
    let mut root = record(
        5,
        &[root_attribute(
            &[
                index_entry(24, "alpha", None),
                index_entry(24, "beta", None),
                terminal(None),
            ],
            false,
        )],
    );
    w(&mut root, 22, 3);
    b[p..p + 1024].copy_from_slice(&root);
    let attrs = [
        resident(0x30, &name_value("alpha", 5), 1),
        resident(0x30, &name_value("beta", 5), 2),
        resident(0x80, b"hello", 3),
    ];
    let p = 2048 + 24 * 1024;
    b[p..p + 1024].copy_from_slice(&record(24, &attrs));
    b
}
pub(crate) fn named_allocation(mut a: Vec<u8>, kind: u32, name: &str, id: u16) -> Vec<u8> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let h = if u16::from_le_bytes([a[12], a[13]]) & 0x8000 != 0 {
        72
    } else {
        64
    };
    let old = a[h..].to_vec();
    a.truncate(h);
    for u in &units {
        a.extend_from_slice(&u.to_le_bytes());
    }
    let offset = a.len().next_multiple_of(8);
    a.resize(offset, 0);
    a.extend_from_slice(&old);
    a.resize(a.len().next_multiple_of(8), 0);
    let n = a.len();
    d(&mut a, 0, kind);
    d(&mut a, 4, n as u32);
    a[9] = units.len() as u8;
    w(&mut a, 10, h as u16);
    w(&mut a, 14, id);
    w(&mut a, 32, offset as u16);
    a
}
pub(crate) fn put(b: &mut [u8], n: usize, attrs: &[Vec<u8>], dir: bool, links: u16) {
    let mut rec = record(n as u32, attrs);
    w(&mut rec, 22, if dir { 3 } else { 1 });
    w(&mut rec, 18, links);
    let p = 2048 + n * 1024;
    b[p..p + 1024].copy_from_slice(&rec);
}
pub fn ntfs_audit_seed() -> Vec<u8> {
    let mut b = fixture();
    b.resize(1024 * 512 + 512, 0);
    q(&mut b, 56, 500);
    b[68] = (-11i8) as u8;
    let names = [
        "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot", "$BadClus",
        "$Secure", "$UpCase", "$Extend",
    ];
    let mut entries = Vec::new();
    for (n, name) in names.iter().enumerate() {
        let mut entry = index_entry(n as u64, name, None);
        if n == 5 || n == 11 {
            d(&mut entry, 16 + 56, 0x10000000);
        }
        entries.push(entry);
    }
    for name in ["alpha", "beta"] {
        entries.push(index_entry(24, name, None));
    }
    entries.push(index_entry(25, "gamma", None));
    entries.sort_by_key(|e| {
        let length = e[16 + 64] as usize;
        let mut units = Vec::new();
        for i in 0..length {
            let u = u16::from_le_bytes([e[16 + 66 + i * 2], e[16 + 67 + i * 2]]);
            units.push(if (97..=122).contains(&u) { u - 32 } else { u });
        }
        units
    });
    entries.push(terminal(None));
    let mut bits = vec![0; 128];
    for cluster in [0usize]
        .into_iter()
        .chain(4..68)
        .chain(128..384)
        .chain(400..404)
        .chain(500..508)
        .chain(90..92)
    {
        bits[cluster / 8] |= 1 << (cluster % 8);
    }
    for (n, name) in names.iter().enumerate() {
        let name = resident(0x30, &name_value(name, 5), 2);
        let mut attrs = vec![name];
        match n {
            0 => {
                attrs.push(nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false));
                attrs.push(resident(0xb0, &(0x0300ffffu64).to_le_bytes(), 4));
            }
            1 => attrs.push(nonresident(&[0x21, 8, 0xf4, 1, 0], 8, 4096, 4096, false)),
            3 => {
                let mut volume = vec![0; 12];
                volume[8] = 3;
                volume[9] = 1;
                attrs.push(resident(0x70, &volume, 3));
            }
            5 => {
                let mut root = root_attribute(&[terminal(Some(0))], true);
                d(&mut root, 32 + 8, 2048);
                root[32 + 12] = 4;
                attrs.push(root);
                let allocation = named_allocation(
                    nonresident(&[0x21, 4, 0x90, 1, 0], 4, 2048, 2048, false),
                    0xa0,
                    "$I30",
                    5,
                );
                attrs.push(allocation);
                attrs.push(named_resident(0xb0, &[1, 0, 0, 0, 0, 0, 0, 0], 6));
            }
            6 => attrs.push(resident(0x80, &bits, 3)),
            7 => attrs.push(nonresident(&[0x11, 1, 0, 0], 1, 512, 512, false)),
            8 => {
                attrs.push(resident(0x80, &[], 3));
                let bad = nonresident(&[0x02, 0, 4, 0], 1024, 1024 * 512, 0, false);
                attrs.push(named_allocation(bad, 0x80, "$Bad", 4));
            }
            10 => attrs.push(nonresident(
                &[0x22, 0, 1, 0x80, 0, 0],
                256,
                131072,
                131072,
                false,
            )),
            11 => {
                let mut root = root_attribute(&[terminal(None)], false);
                d(&mut root, 32 + 8, 2048);
                root[32 + 12] = 4;
                attrs.push(root);
            }
            _ => attrs.push(resident(0x80, &[], 3)),
        }
        put(&mut b, n, &attrs, n == 5 || n == 11, 1);
    }
    for n in 12..16 {
        put(&mut b, n, &[], false, 0);
    }
    put(
        &mut b,
        24,
        &[
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x30, &name_value("beta", 5), 2),
            resident(0x80, b"hello", 3),
        ],
        false,
        2,
    );
    put(
        &mut b,
        25,
        &[
            resident(0x30, &name_value("gamma", 5), 2),
            nonresident(&[0x11, 1, 90, 0x01, 1, 0x11, 1, 1, 0], 3, 1000, 256, true),
        ],
        false,
        1,
    );
    let mut index = vec![0; 2048];
    index[..4].copy_from_slice(b"INDX");
    w(&mut index, 4, 40);
    w(&mut index, 6, 5);
    d(&mut index, 24, 32);
    d(&mut index, 32, 2024);
    let mut at = 56;
    for e in entries {
        index[at..at + e.len()].copy_from_slice(&e);
        at += e.len();
    }
    d(&mut index, 28, (at - 24) as u32);
    w(&mut index, 40, 0xa55a);
    for i in 1..=4 {
        let p = i * 512 - 2;
        let old = u16::from_le_bytes([index[p], index[p + 1]]);
        w(&mut index, 40 + i * 2, old);
        w(&mut index, p, 0xa55a);
    }
    b[400 * 512..404 * 512].copy_from_slice(&index);
    let mirror = b[2048..2048 + 4096].to_vec();
    b[500 * 512..508 * 512].copy_from_slice(&mirror);
    let boot = b[..512].to_vec();
    b[1024 * 512..1024 * 512 + 512].copy_from_slice(&boot);
    b
}
