// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! A small NTFS volume built in memory, for the unit tests and the fuzz seeds.
//!
//! 1024-byte clusters, 1024-byte records, 2048-byte index blocks, 256
//! clusters. The root folder's index has a root node with one key and two
//! `INDX` blocks below it; `frag.bin` has an attribute list and an extension
//! record; `big.bin` has a hole; `init.bin` has an initialized size below its
//! size. The layout (logical clusters):
//!
//! | clusters | what |
//! |---|---|
//! | 0 | boot sector |
//! | 4 to 31 | `$MFT`, 28 records |
//! | 32 to 35 | `$MFTMirr`, a copy of records 0 to 3 |
//! | 36 | `$Bitmap` |
//! | 38 to 41 | the root's `INDX` blocks (VCN 0 and 2) |
//! | 44, 45, 55 | `big.bin` (a hole between) |
//! | 60, 61 | `init.bin` |
//! | 70, 71 and 80, 81 | the two extents of `frag.bin` |

pub const CLUSTER: usize = 1024;
pub const RECORD: usize = 1024;
pub const BLOCK: usize = 2048;
pub const CLUSTERS: usize = 256;
pub const MFT_LCN: usize = 4;
pub const MIRROR_LCN: usize = 32;
/// Clusters 0 to this (exclusive) are marked used in `$Bitmap`.
pub const USED_CLUSTERS: usize = 91;
pub const HELLO: &[u8] = b"hello from the NTFS builder\n";
/// Unix seconds of every `$STANDARD_INFORMATION` modification time.
pub const UNIX_SECONDS: u64 = 1_700_000_000;

/// Record numbers.
pub const R_HELLO: u64 = 16;
pub const R_DOCS: u64 = 17;
pub const R_BIG: u64 = 18;
pub const R_ZED: u64 = 19;
pub const R_ALPHA: u64 = 20;
pub const R_FRAG: u64 = 21;
pub const R_INIT: u64 = 24;
pub const R_SECRET: u64 = 25;

/// The bytes the disk holds for logical byte `i` of a patterned run.
pub fn pattern(i: usize) -> u8 {
    u8::try_from((i * 7 + 3) % 251).unwrap_or(0)
}

/// What `big.bin` reads as: patterned, a 3-cluster hole, patterned.
pub fn big_expected() -> Vec<u8> {
    let mut v = vec![0u8; 6000];
    for (i, b) in v.iter_mut().enumerate() {
        let in_hole = (2 * CLUSTER..5 * CLUSTER).contains(&i);
        if !in_hole {
            *b = pattern(i);
        }
    }
    v
}

/// What `frag.bin` reads as.
pub fn frag_expected() -> Vec<u8> {
    (0..4000).map(pattern).collect()
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn align8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

fn filetime(unix: u64) -> u64 {
    unix * 10_000_000 + 116_444_736_000_000_000
}

fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A resident attribute.
fn resident(ty: u32, name: &str, value: &[u8], id: u16) -> Vec<u8> {
    let name_bytes = utf16(name);
    let value_off = align8(0x18 + name_bytes.len());
    let total = align8(value_off + value.len());
    let mut a = vec![0u8; total];
    put(&mut a, 0, &ty.to_le_bytes());
    put(&mut a, 4, &u32::try_from(total).unwrap().to_le_bytes());
    a[9] = u8::try_from(name_bytes.len() / 2).unwrap();
    put(&mut a, 0x0A, &0x18u16.to_le_bytes());
    put(&mut a, 0x0E, &id.to_le_bytes());
    put(
        &mut a,
        0x10,
        &u32::try_from(value.len()).unwrap().to_le_bytes(),
    );
    put(
        &mut a,
        0x14,
        &u16::try_from(value_off).unwrap().to_le_bytes(),
    );
    put(&mut a, 0x18, &name_bytes);
    put(&mut a, value_off, value);
    a
}

/// What a non-resident attribute header holds besides its run list.
#[derive(Clone, Copy)]
pub struct NonRes {
    pub start_vcn: u64,
    pub last_vcn: u64,
    pub allocated: u64,
    pub real: u64,
    pub init: u64,
    pub flags: u16,
}

fn nonresident(ty: u32, name: &str, h: NonRes, runs: &[u8], id: u16) -> Vec<u8> {
    let name_bytes = utf16(name);
    let runs_off = align8(0x40 + name_bytes.len());
    let total = align8(runs_off + runs.len() + 1);
    let mut a = vec![0u8; total];
    put(&mut a, 0, &ty.to_le_bytes());
    put(&mut a, 4, &u32::try_from(total).unwrap().to_le_bytes());
    a[8] = 1;
    a[9] = u8::try_from(name_bytes.len() / 2).unwrap();
    put(&mut a, 0x0A, &0x40u16.to_le_bytes());
    put(&mut a, 0x0C, &h.flags.to_le_bytes());
    put(&mut a, 0x0E, &id.to_le_bytes());
    put(&mut a, 0x10, &h.start_vcn.to_le_bytes());
    put(&mut a, 0x18, &h.last_vcn.to_le_bytes());
    put(
        &mut a,
        0x20,
        &u16::try_from(runs_off).unwrap().to_le_bytes(),
    );
    if h.flags & 1 != 0 {
        // Compressed: units of 2^4 clusters.
        a[0x22] = 4;
    }
    put(&mut a, 0x28, &h.allocated.to_le_bytes());
    put(&mut a, 0x30, &h.real.to_le_bytes());
    put(&mut a, 0x38, &h.init.to_le_bytes());
    put(&mut a, 0x40, &name_bytes);
    put(&mut a, runs_off, runs);
    a
}

/// Mapping pairs for `(length, Some(lcn) | None for a hole)` runs.
pub fn mapping_pairs(runs: &[(u64, Option<i64>)]) -> Vec<u8> {
    fn signed(v: i64) -> Vec<u8> {
        let b = v.to_le_bytes();
        for n in 1..=8usize {
            let ext = if b[n - 1] & 0x80 != 0 { 0xFF } else { 0 };
            if b[n..].iter().all(|&x| x == ext) {
                return b[..n].to_vec();
            }
        }
        b.to_vec()
    }
    let mut out = Vec::new();
    let mut prev = 0i64;
    for &(len, lcn) in runs {
        let lb = len.to_le_bytes();
        let n = 8 - lb.iter().rev().take_while(|&&x| x == 0).count();
        let len_bytes = &lb[..n.max(1)];
        match lcn {
            Some(l) => {
                let off = signed(l - prev);
                prev = l;
                out.push(
                    u8::try_from(off.len()).unwrap() << 4 | u8::try_from(len_bytes.len()).unwrap(),
                );
                out.extend_from_slice(len_bytes);
                out.extend_from_slice(&off);
            }
            None => {
                out.push(u8::try_from(len_bytes.len()).unwrap());
                out.extend_from_slice(len_bytes);
            }
        }
    }
    out.push(0);
    out
}

fn std_info(attrs: u32) -> Vec<u8> {
    let mut v = vec![0u8; 0x30];
    let t = filetime(UNIX_SECONDS);
    put(&mut v, 0, &(t - 20_000_000).to_le_bytes());
    put(&mut v, 8, &t.to_le_bytes());
    put(&mut v, 0x10, &t.to_le_bytes());
    put(&mut v, 0x18, &(t + 10_000_000).to_le_bytes());
    put(&mut v, 0x20, &attrs.to_le_bytes());
    resident(0x10, "", &v, 0)
}

fn file_name(parent: u64, name: &str, ns: u8, size: u64, attrs: u32) -> Vec<u8> {
    let n = utf16(name);
    let mut v = vec![0u8; 0x42 + n.len()];
    put(&mut v, 0, &(parent | 1 << 48).to_le_bytes());
    put(&mut v, 8, &filetime(UNIX_SECONDS).to_le_bytes());
    put(&mut v, 0x10, &filetime(UNIX_SECONDS).to_le_bytes());
    put(&mut v, 0x30, &size.to_le_bytes());
    put(&mut v, 0x38, &attrs.to_le_bytes());
    v[0x40] = u8::try_from(n.len() / 2).unwrap();
    v[0x41] = ns;
    put(&mut v, 0x42, &n);
    v
}

/// An MFT record with its fixups applied.
fn record(number: u32, flags: u16, base: u64, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut r = vec![0u8; RECORD];
    put(&mut r, 0, b"FILE");
    put(&mut r, 4, &0x30u16.to_le_bytes());
    put(&mut r, 6, &3u16.to_le_bytes());
    put(&mut r, 0x10, &1u16.to_le_bytes());
    put(&mut r, 0x12, &1u16.to_le_bytes());
    put(&mut r, 0x14, &0x38u16.to_le_bytes());
    put(&mut r, 0x16, &flags.to_le_bytes());
    put(&mut r, 0x1C, &u32::try_from(RECORD).unwrap().to_le_bytes());
    put(&mut r, 0x20, &base.to_le_bytes());
    put(&mut r, 0x2C, &number.to_le_bytes());
    let mut pos = 0x38;
    for a in attrs {
        put(&mut r, pos, a);
        pos += a.len();
    }
    put(&mut r, pos, &0xFFFF_FFFFu32.to_le_bytes());
    pos += 8;
    assert!(pos <= RECORD - 2, "record {number} overflows");
    put(&mut r, 0x18, &u32::try_from(pos).unwrap().to_le_bytes());
    fixups_in(&mut r, 0x30, 0x4321);
    r
}

/// Moves the last two bytes of every stride into the array at `array`.
fn fixups_in(buf: &mut [u8], array: usize, usn: u16) {
    put(buf, array, &usn.to_le_bytes());
    for i in 1..=buf.len() / 512 {
        let at = i * 512 - 2;
        let saved = [buf[at], buf[at + 1]];
        put(buf, array + 2 * i, &saved);
        put(buf, at, &usn.to_le_bytes());
    }
}

/// An index entry. `key` is `None` for the last entry.
fn entry(file: u64, key: Option<&[u8]>, sub: Option<u64>) -> Vec<u8> {
    let key_len = key.map_or(0, <[u8]>::len);
    let body = if key.is_some() {
        align8(16 + key_len)
    } else {
        16
    };
    let len = body + if sub.is_some() { 8 } else { 0 };
    let mut e = vec![0u8; len];
    put(&mut e, 0, &(file | 1 << 48).to_le_bytes());
    put(&mut e, 8, &u16::try_from(len).unwrap().to_le_bytes());
    put(&mut e, 10, &u16::try_from(key_len).unwrap().to_le_bytes());
    let flags = u16::from(sub.is_some()) | if key.is_none() { 2 } else { 0 };
    put(&mut e, 12, &flags.to_le_bytes());
    if let Some(k) = key {
        put(&mut e, 16, k);
    }
    if let Some(s) = sub {
        put(&mut e, len - 8, &s.to_le_bytes());
    }
    e
}

fn index_root(entries: &[Vec<u8>], has_sub: bool) -> Vec<u8> {
    let body: Vec<u8> = entries.concat();
    let mut v = vec![0u8; 0x20];
    put(&mut v, 0, &0x30u32.to_le_bytes());
    put(&mut v, 4, &1u32.to_le_bytes());
    put(&mut v, 8, &u32::try_from(BLOCK).unwrap().to_le_bytes());
    v[0x0C] = 2;
    put(&mut v, 0x10, &16u32.to_le_bytes());
    put(
        &mut v,
        0x14,
        &u32::try_from(16 + body.len()).unwrap().to_le_bytes(),
    );
    put(
        &mut v,
        0x18,
        &u32::try_from(16 + body.len()).unwrap().to_le_bytes(),
    );
    v[0x1C] = u8::from(has_sub);
    v.extend_from_slice(&body);
    v
}

fn indx_block(vcn: u64, entries: &[Vec<u8>], has_sub: bool) -> Vec<u8> {
    let body: Vec<u8> = entries.concat();
    let mut b = vec![0u8; BLOCK];
    put(&mut b, 0, b"INDX");
    put(&mut b, 4, &0x28u16.to_le_bytes());
    put(&mut b, 6, &5u16.to_le_bytes());
    put(&mut b, 0x10, &vcn.to_le_bytes());
    // The node header is at 0x18; the entries start at 0x40.
    put(&mut b, 0x18, &0x28u32.to_le_bytes());
    put(
        &mut b,
        0x1C,
        &u32::try_from(0x28 + body.len()).unwrap().to_le_bytes(),
    );
    put(
        &mut b,
        0x20,
        &u32::try_from(BLOCK - 0x18).unwrap().to_le_bytes(),
    );
    b[0x24] = u8::from(has_sub);
    put(&mut b, 0x40, &body);
    fixups_in(&mut b, 0x28, 0x7777);
    b
}

/// The in-memory volume.
pub struct Built {
    /// The whole volume, `CLUSTERS * CLUSTER` bytes.
    pub image: Vec<u8>,
}

impl Built {
    /// The image up to the last cluster in use.
    pub fn trimmed(&self) -> Vec<u8> {
        self.image[..USED_CLUSTERS * CLUSTER].to_vec()
    }
}

fn boot_sector() -> Vec<u8> {
    let mut s = vec![0u8; 512];
    put(&mut s, 3, b"NTFS    ");
    put(&mut s, 0x0B, &512u16.to_le_bytes());
    s[0x0D] = 2;
    put(
        &mut s,
        0x28,
        &u64::try_from(CLUSTERS * 2).unwrap().to_le_bytes(),
    );
    put(&mut s, 0x30, &u64::try_from(MFT_LCN).unwrap().to_le_bytes());
    put(
        &mut s,
        0x38,
        &u64::try_from(MIRROR_LCN).unwrap().to_le_bytes(),
    );
    s[0x40] = 1; // one cluster per record
    s[0x44] = 2; // two per index block
    put(&mut s, 0x48, &0x1122_3344_5566_7788u64.to_le_bytes());
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

/// The standard volume; `cyclic` makes the last `INDX` block point at itself.
fn build(cyclic: bool) -> Built {
    let mut img = vec![0u8; CLUSTERS * CLUSTER];
    put(&mut img, 0, &boot_sector());
    let dir_attrs = 0x1000_0000;
    let key = |name: &str, ns: u8, size: u64, attrs: u32| file_name(5, name, ns, size, attrs);

    // Index blocks and the root node.
    let b0 = [
        entry(0, Some(&key("$MFT", 3, 0, 0x6)), None),
        entry(5, Some(&key(".", 1, 0, dir_attrs)), None),
        entry(R_ALPHA, Some(&key("alpha.txt", 3, 0, 0x20)), None),
        entry(R_BIG, Some(&key("big.bin", 1, 6000, 0x20)), None),
        entry(R_BIG, Some(&key("BIG~1.BIN", 2, 6000, 0x20)), None),
        entry(R_DOCS, Some(&key("docs", 3, 0, dir_attrs)), None),
        entry(0, None, None),
    ];
    let b1 = [
        entry(
            R_HELLO,
            Some(&key("hello.txt", 3, HELLO.len() as u64, 0x20)),
            None,
        ),
        entry(R_INIT, Some(&key("init.bin", 3, 2000, 0x20)), None),
        entry(R_SECRET, Some(&key("secret.sys", 3, 1, 0x26)), None),
        entry(R_ZED, Some(&key("zed.txt", 3, 1, 0x20)), None),
        entry(0, None, cyclic.then_some(2)),
    ];
    let root_entries = [
        entry(R_FRAG, Some(&key("frag.bin", 3, 4000, 0x20)), Some(0)),
        entry(0, None, Some(2)),
    ];
    put(&mut img, 38 * CLUSTER, &indx_block(0, &b0, false));
    put(&mut img, 40 * CLUSTER, &indx_block(2, &b1, cyclic));

    // Content clusters.
    for (lcn, first) in [(44usize, 0usize), (55, 5 * CLUSTER)] {
        let n = if lcn == 44 { 2 * CLUSTER } else { CLUSTER };
        for i in 0..n {
            img[lcn * CLUSTER + i] = pattern(first + i);
        }
    }
    img[60 * CLUSTER..62 * CLUSTER].fill(0xAB);
    for i in 0..2 * CLUSTER {
        img[70 * CLUSTER + i] = pattern(i);
        img[80 * CLUSTER + i] = pattern(2 * CLUSTER + i);
    }
    // $Bitmap: clusters 0 to USED_CLUSTERS - 1 in use.
    for c in 0..USED_CLUSTERS {
        img[36 * CLUSTER + c / 8] |= 1 << (c % 8);
    }

    let nr = |real: u64, allocated: u64, last: u64| NonRes {
        start_vcn: 0,
        last_vcn: last,
        allocated,
        real,
        init: real,
        flags: 0,
    };
    let mft_size = u64::try_from(28 * RECORD).unwrap();
    let mut records: Vec<Option<Vec<u8>>> = vec![None; 28];
    let plain = |n: u32, attrs: &[Vec<u8>]| Some(record(n, 1, 0, attrs));
    records[0] = plain(
        0,
        &[
            std_info(0x6),
            nonresident(
                0x80,
                "",
                nr(mft_size, mft_size, 27),
                &mapping_pairs(&[(28, Some(4))]),
                2,
            ),
        ],
    );
    records[1] = plain(1, &[std_info(0x6)]);
    records[2] = plain(2, &[std_info(0x6)]);
    records[3] = plain(3, &[std_info(0x6), resident(0x60, "", &utf16("ATLAS"), 1)]);
    records[4] = plain(4, &[std_info(0x6)]);
    let root_value = index_root(&root_entries, true);
    let alloc_h = nr(4096, 4096, 3);
    records[5] = Some(record(
        5,
        3,
        0,
        &[
            std_info(0x6),
            resident(0x90, "$I30", &root_value, 3),
            nonresident(0xA0, "$I30", alloc_h, &mapping_pairs(&[(4, Some(38))]), 4),
        ],
    ));
    records[6] = plain(
        6,
        &[
            std_info(0x6),
            nonresident(
                0x80,
                "",
                nr(32, 1024, 0),
                &mapping_pairs(&[(1, Some(36))]),
                2,
            ),
        ],
    );
    records[usize::try_from(R_HELLO).unwrap()] =
        plain(16, &[std_info(0x20), resident(0x80, "", HELLO, 1)]);
    let docs_root = index_root(
        &[
            entry(23, Some(&file_name(R_DOCS, "inner.txt", 3, 5, 0x20)), None),
            entry(0, None, None),
        ],
        false,
    );
    records[17] = Some(record(
        17,
        3,
        0,
        &[std_info(0x10), resident(0x90, "$I30", &docs_root, 1)],
    ));
    let big_h = NonRes {
        start_vcn: 0,
        last_vcn: 5,
        allocated: 6144,
        real: 6000,
        init: 6000,
        flags: 0x8000,
    };
    records[18] = plain(
        18,
        &[
            std_info(0x220),
            nonresident(
                0x80,
                "",
                big_h,
                &mapping_pairs(&[(2, Some(44)), (3, None), (1, Some(55))]),
                1,
            ),
        ],
    );
    records[19] = plain(19, &[std_info(0x20), resident(0x80, "", b"z", 1)]);
    records[20] = plain(20, &[std_info(0x20), resident(0x80, "", b"", 1)]);
    // frag.bin: base record 21 with an attribute list, extension record 22.
    let mut list = Vec::new();
    for (start, seg) in [(0u64, 21u64), (2, 22)] {
        let mut e = vec![0u8; 0x20];
        put(&mut e, 0, &0x80u32.to_le_bytes());
        put(&mut e, 4, &0x20u16.to_le_bytes());
        put(&mut e, 8, &start.to_le_bytes());
        put(&mut e, 0x10, &(seg | 1 << 48).to_le_bytes());
        list.extend_from_slice(&e);
    }
    let first = NonRes {
        start_vcn: 0,
        last_vcn: 1,
        allocated: 4096,
        real: 4000,
        init: 4000,
        flags: 0,
    };
    records[21] = plain(
        21,
        &[
            std_info(0x20),
            resident(0x20, "", &list, 1),
            nonresident(0x80, "", first, &mapping_pairs(&[(2, Some(70))]), 2),
        ],
    );
    let second = NonRes {
        start_vcn: 2,
        last_vcn: 3,
        allocated: 0,
        real: 0,
        init: 0,
        flags: 0,
    };
    records[22] = Some(record(
        22,
        1,
        21 | 1 << 48,
        &[nonresident(
            0x80,
            "",
            second,
            &mapping_pairs(&[(2, Some(80))]),
            3,
        )],
    ));
    records[23] = plain(23, &[std_info(0x20), resident(0x80, "", b"inner", 1)]);
    let init_h = NonRes {
        start_vcn: 0,
        last_vcn: 1,
        allocated: 2048,
        real: 2000,
        init: 1200,
        flags: 0,
    };
    records[24] = plain(
        24,
        &[
            std_info(0x20),
            nonresident(0x80, "", init_h, &mapping_pairs(&[(2, Some(60))]), 1),
        ],
    );
    records[25] = plain(25, &[std_info(0x26), resident(0x80, "", b"s", 1)]);

    for (n, rec) in records.iter().enumerate() {
        if let Some(r) = rec {
            put(&mut img, MFT_LCN * CLUSTER + n * RECORD, r);
            if n < 4 {
                put(&mut img, MIRROR_LCN * CLUSTER + n * RECORD, r);
            }
        }
    }
    Built { image: img }
}

/// What the compressed `alpha.txt` of `compressed()` reads as: a raw chunk
/// of patterned bytes and three chunks of `A` (one unit of 16 clusters), a
/// unit that is a hole, and 2000 bytes of a unit stored as it is.
pub fn compressed_expected() -> Vec<u8> {
    let mut v: Vec<u8> = (0..4096).map(pattern).collect();
    v.resize(16 * CLUSTER, b'A');
    v.resize(32 * CLUSTER, 0);
    v.extend((0..2000).map(|i| pattern(i + 1)));
    v
}

/// The standard volume with `alpha.txt` replaced by a compressed file (flag
/// 0x0001, units of 16 clusters): unit 0 is LZNT1 in clusters 100 to 104 and
/// a hole after, unit 1 is a hole, unit 2 is 16 clusters stored as they are
/// at 110. See `compressed_expected` for the content.
pub fn compressed() -> Built {
    use super::lznt1::tests::{Tok, compressed_chunk, raw_chunk};
    let mut img = build(false).image;
    let mut stream = raw_chunk(&(0..4096).map(pattern).collect::<Vec<_>>());
    for _ in 0..3 {
        stream.extend(compressed_chunk(&[
            Tok::Lit(b'A'),
            Tok::Ref { disp: 1, len: 4095 },
        ]));
    }
    put(&mut img, 100 * CLUSTER, &stream);
    for i in 0..16 * CLUSTER {
        img[110 * CLUSTER + i] = pattern(i + 1);
    }
    let h = NonRes {
        start_vcn: 0,
        last_vcn: 47,
        allocated: 21 * CLUSTER as u64,
        real: 34_768,
        init: 34_768,
        flags: 1,
    };
    let attr = nonresident(
        0x80,
        "",
        h,
        &mapping_pairs(&[(5, Some(100)), (27, None), (16, Some(110))]),
        1,
    );
    let rec = record(20, 1, 0, &[std_info(0x20), attr]);
    put(&mut img, MFT_LCN * CLUSTER + 20 * RECORD, &rec);
    Built { image: img }
}

/// What `alpha.txt` holds in [`streams_and_links`], and its named stream.
pub const ALPHA_TEXT: &[u8] = b"alpha";
pub const ZONE_TEXT: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

/// The standard volume with `alpha.txt` given a `Zone.Identifier` stream and
/// `zed.txt` turned into a symbolic link to `C:\data` (reparse bit set in
/// its record; its index entry still says a plain file, as a listing lags).
pub fn streams_and_links() -> Built {
    let mut img = build(false).image;
    let alpha = record(
        20,
        1,
        0,
        &[
            std_info(0x20),
            resident(0x80, "", ALPHA_TEXT, 1),
            resident(0x80, "Zone.Identifier", ZONE_TEXT, 2),
            resident(0x80, "x", b"", 3),
        ],
    );
    put(&mut img, MFT_LCN * CLUSTER + 20 * RECORD, &alpha);
    let link = super::reparse::tests::symlink("\\??\\C:\\data", "C:\\data");
    let zed = record(19, 1, 0, &[std_info(0x420), resident(0xC0, "", &link, 1)]);
    put(&mut img, MFT_LCN * CLUSTER + 19 * RECORD, &zed);
    Built { image: img }
}

/// The standard volume.
pub fn standard() -> Built {
    build(false)
}

/// The standard volume with an index block that points at itself.
pub fn cyclic() -> Built {
    build(true)
}
