// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Directory indexes: the `$INDEX_ROOT` node and the `INDX` blocks of
//! `$INDEX_ALLOCATION` that hang below it.
//!
//! An index is a B-tree whose interior entries are real entries too: the
//! entries of a node are in order, an entry with a sub-node has the sub-node
//! on its smaller side, and the last entry has no key (only perhaps a
//! sub-node for everything larger). Every walk here is bounded: a node is
//! loaded at most once, the depth is capped, and so are the entries seen.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

use super::attr::FileName;
use super::le::{self, invalid, limit, other, u16_at, u32_at, u64_at};
use super::record::{REF_MASK, apply_fixups};
use super::runs::FileData;
use super::upcase::Upcase;
use super::{MAX_DIR_BLOCKS, MAX_DIR_ENTRIES, MAX_INDEX_BLOCK, MAX_INDEX_DEPTH};
use atlas_fs_core::error::{CorruptKind, Corruption, Location, Result};
use atlas_fs_core::io::block::BlockSource;

const ROOT: &str = "NTFS index root";
const BLOCK: &str = "NTFS index block";
/// `INDX`.
const INDX_MAGIC: u32 = u32::from_le_bytes(*b"INDX");
/// The collation rule for file name indexes.
pub const COLLATION_FILE_NAME: u32 = 1;
/// Entry flag: a sub-node VCN follows the key.
const HAS_SUB: u16 = 1;
/// Entry flag: the last entry of its node.
const LAST: u16 = 2;
/// Bytes of an entry before its key.
const ENTRY_HEADER: usize = 16;

/// One index entry, borrowing its node.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// The file the entry names.
    pub file_ref: u64,
    /// Bytes the entry takes in its node.
    pub len: usize,
    /// The last entry of the node (no key).
    pub last: bool,
    /// VCN of the sub-node of smaller keys.
    pub sub: Option<u64>,
    /// The key: a `$FILE_NAME` value.
    pub key: &'a [u8],
}

/// Reads the entry at `pos` of a node whose entries end at `end`.
pub fn parse_entry<'a>(
    buf: &'a [u8],
    pos: usize,
    end: usize,
    structure: &'static str,
    loc: Location,
) -> Result<Entry<'a>> {
    let fixed = pos
        .checked_add(ENTRY_HEADER)
        .filter(|&e| e <= end && e <= buf.len())
        .ok_or_else(|| other(structure, loc, "entry runs past the node"))?;
    let len = usize::from(u16_at(buf, pos.saturating_add(8))?);
    let key_len = usize::from(u16_at(buf, pos.saturating_add(10))?);
    let flags = u16_at(buf, pos.saturating_add(12))?;
    let entry_end = pos
        .checked_add(len)
        .filter(|&e| len >= ENTRY_HEADER && e <= end)
        .ok_or_else(|| other(structure, loc, "entry length is outside the node"))?;
    let has_sub = flags & HAS_SUB != 0;
    let body_end = if has_sub {
        entry_end
            .checked_sub(8)
            .filter(|&b| b >= fixed)
            .ok_or_else(|| {
                other(
                    structure,
                    loc,
                    "entry is too short for its sub-node pointer",
                )
            })?
    } else {
        entry_end
    };
    let key_end = fixed
        .checked_add(key_len)
        .filter(|&k| k <= body_end)
        .ok_or_else(|| other(structure, loc, "entry key is longer than the entry"))?;
    Ok(Entry {
        file_ref: u64_at(buf, pos)?,
        len,
        last: flags & LAST != 0,
        sub: if has_sub {
            Some(u64_at(buf, entry_end.saturating_sub(8))?)
        } else {
            None
        },
        key: le::bytes(buf, fixed, key_end.saturating_sub(fixed))?,
    })
}

/// A directory's index: the root node and the way to its blocks.
#[derive(Clone)]
pub struct Tree {
    root: Vec<u8>,
    range: (usize, usize),
    block_size: usize,
    collation: u32,
    alloc: Option<Arc<FileData>>,
    unit: u64,
    max_blocks: u64,
    record: u64,
}

impl Tree {
    /// Parses an `$INDEX_ROOT` value of record `record`.
    pub fn new(root: Vec<u8>, alloc: Option<Arc<FileData>>, record: u64) -> Result<Self> {
        let loc = Location::Object(record);
        let collation = u32_at(&root, 4)?;
        let block_size = le::to_usize(u64::from(u32_at(&root, 8)?), ROOT, "index block size")?;
        if !(512..=MAX_INDEX_BLOCK as usize).contains(&block_size)
            || !block_size.is_multiple_of(512)
        {
            return Err(invalid(ROOT, loc, "index block size", block_size as u64));
        }
        let entries = le::to_usize(u64::from(u32_at(&root, 0x10)?), ROOT, "entries offset")?;
        let length = le::to_usize(u64::from(u32_at(&root, 0x14)?), ROOT, "index length")?;
        let start = 0x10usize
            .checked_add(entries)
            .filter(|&s| entries >= 16 && s <= root.len())
            .ok_or_else(|| invalid(ROOT, loc, "entries offset", entries as u64))?;
        let end = 0x10usize
            .checked_add(length)
            .filter(|&e| e <= root.len() && e >= start)
            .ok_or_else(|| invalid(ROOT, loc, "index length", length as u64))?;
        let (unit, max_blocks) = match &alloc {
            Some(a) => {
                let cluster = a.cluster_size();
                let unit = if block_size as u64 >= cluster {
                    cluster
                } else {
                    512
                };
                let blocks = a.len().checked_div(block_size as u64).unwrap_or(0);
                (unit, blocks.min(MAX_DIR_BLOCKS))
            }
            None => (512, 0),
        };
        Ok(Self {
            root,
            range: (start, end),
            block_size,
            collation,
            alloc,
            unit,
            max_blocks,
            record,
        })
    }

    /// True when the root says the names are ordered as file names.
    pub fn is_file_name_collation(&self) -> bool {
        self.collation == COLLATION_FILE_NAME
    }

    /// Reads and validates the block at `vcn` into `buf`; returns where its
    /// entries start and end.
    fn load(&self, vcn: u64, buf: &mut Vec<u8>) -> Result<(usize, usize)> {
        let loc = Location::Object(self.record);
        let alloc = self.alloc.as_ref().ok_or_else(|| {
            other(
                BLOCK,
                loc,
                "an entry points to a block but there is no $INDEX_ALLOCATION",
            )
        })?;
        let offset = vcn
            .checked_mul(self.unit)
            .ok_or_else(|| invalid(BLOCK, loc, "sub-node VCN", vcn))?;
        buf.clear();
        buf.resize(self.block_size, 0);
        alloc.read_at(offset, buf)?;
        let magic = u32_at(buf, 0)?;
        if magic != INDX_MAGIC {
            return Err(Corruption::new(
                BLOCK,
                Location::Byte(offset),
                CorruptKind::BadSignature {
                    expected: u64::from(INDX_MAGIC),
                    found: u64::from(magic),
                },
            )
            .into());
        }
        apply_fixups(buf, 0x28, BLOCK, Location::Byte(offset))?;
        if u64_at(buf, 0x10)? != vcn {
            return Err(invalid(BLOCK, Location::Byte(offset), "block VCN", vcn));
        }
        let entries = le::to_usize(u64::from(u32_at(buf, 0x18)?), BLOCK, "entries offset")?;
        let length = le::to_usize(u64::from(u32_at(buf, 0x1C)?), BLOCK, "index length")?;
        let start = 0x18usize
            .checked_add(entries)
            .filter(|&s| entries >= 16 && s <= buf.len())
            .ok_or_else(|| {
                invalid(
                    BLOCK,
                    Location::Byte(offset),
                    "entries offset",
                    entries as u64,
                )
            })?;
        let end = 0x18usize
            .checked_add(length)
            .filter(|&e| e <= buf.len() && e >= start)
            .ok_or_else(|| invalid(BLOCK, Location::Byte(offset), "index length", length as u64))?;
        Ok((start, end))
    }
}

/// An entry the walk found, with its name decoded into [`Walker::name`].
#[derive(Debug, Clone, Copy)]
pub struct Found {
    /// File reference (record number in the low 48 bits).
    pub file_ref: u64,
    /// Real size as recorded in the entry's key.
    pub size: u64,
    /// File attribute flags of the key.
    pub attrs: u32,
    /// Reparse tag of the key; meaningful when `attrs` has the reparse bit.
    pub reparse_tag: u32,
    /// Modification time of the key, as a FILETIME.
    pub modified: u64,
    /// Name space of the key.
    pub namespace: u8,
}

struct Frame {
    buf: Vec<u8>,
    pos: usize,
    end: usize,
    descended: bool,
}

/// An in-order walk of one directory's index that can pause between entries.
pub struct Walker {
    tree: Tree,
    frames: Vec<Frame>,
    pool: Vec<Vec<u8>>,
    visited: HashSet<u64>,
    seen: u64,
    started: bool,
    /// The name of the entry [`Self::next_entry`] last returned.
    pub name: String,
}

impl Walker {
    /// A walk over `tree`.
    pub fn new(tree: Tree) -> Self {
        Self {
            tree,
            frames: Vec::new(),
            pool: Vec::new(),
            visited: HashSet::new(),
            seen: 0,
            started: false,
            name: String::new(),
        }
    }

    fn descend(&mut self, vcn: u64) -> Result<()> {
        let loc = Location::Object(self.tree.record);
        if self.frames.len() >= MAX_INDEX_DEPTH {
            return Err(limit(BLOCK, loc, "index depth", MAX_INDEX_DEPTH as u64));
        }
        if !self.visited.insert(vcn) {
            return Err(Corruption::new(
                BLOCK,
                loc,
                CorruptKind::Loop {
                    what: "index blocks point back at a block already visited",
                },
            )
            .into());
        }
        if self.visited.len() as u64 > self.tree.max_blocks {
            return Err(limit(
                BLOCK,
                loc,
                "index blocks visited",
                self.tree.max_blocks,
            ));
        }
        let mut buf = self.pool.pop().unwrap_or_default();
        let (pos, end) = self.tree.load(vcn, &mut buf)?;
        self.frames.push(Frame {
            buf,
            pos,
            end,
            descended: false,
        });
        Ok(())
    }

    /// The next entry in index order, or `None` at the end.
    pub fn next_entry(&mut self) -> Result<Option<Found>> {
        let loc = Location::Object(self.tree.record);
        if !self.started {
            self.started = true;
            self.frames.push(Frame {
                buf: self.tree.root.clone(),
                pos: self.tree.range.0,
                end: self.tree.range.1,
                descended: false,
            });
        }
        loop {
            let Some(frame) = self.frames.last_mut() else {
                return Ok(None);
            };
            if frame.pos >= frame.end {
                if let Some(done) = self.frames.pop() {
                    self.pool.push(done.buf);
                }
                continue;
            }
            let entry = parse_entry(&frame.buf, frame.pos, frame.end, BLOCK, loc)?;
            let (len, last, sub) = (entry.len, entry.last, entry.sub);
            if let Some(vcn) = sub
                && !frame.descended
            {
                frame.descended = true;
                self.descend(vcn)?;
                continue;
            }
            frame.descended = false;
            frame.pos = frame.pos.saturating_add(len);
            if last {
                frame.pos = frame.end;
                continue;
            }
            self.seen = self.seen.saturating_add(1);
            if self.seen > MAX_DIR_ENTRIES {
                return Err(limit(BLOCK, loc, "entries in one folder", MAX_DIR_ENTRIES));
            }
            let name = FileName::parse(entry.key)?;
            self.name.clear();
            le::decode_name(name.name, &mut self.name);
            return Ok(Some(Found {
                file_ref: entry.file_ref,
                size: name.size,
                attrs: name.attrs,
                reparse_tag: name.reparse_tag,
                modified: name.modified,
                namespace: name.namespace,
            }));
        }
    }
}

/// Finds `want` (UTF-16 units) in the index by descending the B-tree.
/// Needs the file name collation; the caller scans otherwise.
pub fn lookup(tree: &Tree, up: &Upcase, want: &[u16]) -> Result<Option<u64>> {
    let loc = Location::Object(tree.record);
    let mut buf = tree.root.clone();
    let (mut pos, mut end) = tree.range;
    for _ in 0..=MAX_INDEX_DEPTH {
        let mut next = None;
        let mut at = pos;
        while at < end {
            let entry = parse_entry(&buf, at, end, BLOCK, loc)?;
            at = at.saturating_add(entry.len);
            if entry.last {
                next = entry.sub;
                break;
            }
            let name = FileName::parse(entry.key)?;
            match up.compare(want.iter().copied(), le::units(name.name)) {
                Ordering::Equal => return Ok(Some(entry.file_ref & REF_MASK)),
                Ordering::Less => {
                    next = entry.sub;
                    break;
                }
                Ordering::Greater => {}
            }
        }
        let Some(vcn) = next else {
            return Ok(None);
        };
        (pos, end) = tree.load(vcn, &mut buf)?;
    }
    Err(limit(BLOCK, loc, "index depth", MAX_INDEX_DEPTH as u64))
}

/// Finds `want` by walking every entry; for any collation, and for a
/// volume without a usable `$UpCase`.
pub fn lookup_scan(tree: &Tree, up: &Upcase, want: &[u16]) -> Result<Option<u64>> {
    let mut walker = Walker::new(tree.clone());
    while let Some(found) = walker.next_entry()? {
        if up.compare(want.iter().copied(), walker.name.encode_utf16()) == Ordering::Equal {
            return Ok(Some(found.file_ref & REF_MASK));
        }
    }
    Ok(None)
}
