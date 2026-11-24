// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! NTFS, read-only.
//!
//! [`mount`] parses the boot sector ([`boot`]), finds the `$MFT` record
//! ([`record`]) and builds the stream of the MFT's own data ([`runs`]); every
//! other record is then read from that stream. A file is a [`node::Node`]:
//! the attributes of its record and of the extension records its attribute
//! list names ([`attr`]). Folders are `$I30` indexes ([`index`]): a root node
//! in the record and `INDX` blocks in `$INDEX_ALLOCATION`.
//!
//! Node ids are MFT record numbers; the root is record 5. A listing hides
//! the first 16 records (the metadata files) and the DOS (8.3) names of
//! files that also have a long name. Sizes and dates in a listing come from
//! the folder's index entry, like Windows' own listings, and can lag the
//! file; `metadata` reads the file's record.
//!
//! Compressed files (LZNT1) read through `compressed::Compressed`.
//!
//! Alternate data streams are the node's extended attributes (`xattrs`,
//! `read_xattr`), named as on Windows (`Zone.Identifier`). A symbolic link
//! or junction is a `Symlink` with its stored target and is never followed;
//! other reparse points leave the file as it is. Hard links are several
//! index entries naming one record, so they are one node.
//!
//! Not handled here: EFS encryption (`open` fails with `Unsupported`),
//! the content of files Windows keeps outside the volume (cloud
//! placeholders, WOF), and writing.
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use atlas_fs_core::fs::{DirBatch, DirProgress, FileSystem};
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source = Arc::new(FileSource::open(Path::new("volume.img"))?);
//! let volume = atlas_ntfs::mount(source)?;
//! println!("{}", volume.info().name);
//!
//! let mut stream = volume.read_dir(volume.root())?;
//! let mut batch = DirBatch::new();
//! while stream.next_batch(&mut batch, 256)? == DirProgress::More {}
//! for entry in batch.iter() {
//!     println!("{}", entry.name);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::fs::{
    AllocationMap, DirBatch, DirEntry, DirProgress, DirStream, EntryFlags, Extent, FileSystem,
    MAX_ALLOCATION_BUCKETS, Metadata, NodeId, NodeKind, Stream, VolumeInfo, XattrInfo,
};
use atlas_fs_core::io::block::BlockSource;

use boot::Geometry;
use index::{Tree, Walker};
use node::{Ctx, Data, Node};
use record::{IS_DIR, REF_MASK};
use runs::{FileData, Resident};
use upcase::Upcase;

pub mod attr;
pub mod boot;
pub mod compressed;
#[cfg(test)]
mod fuzz_seeds;
pub mod index;
pub mod le;
pub mod lznt1;
pub mod node;
pub mod record;
pub mod reparse;
pub mod runs;
#[cfg(test)]
pub mod test_volume;
pub mod upcase;

/// Largest MFT record, in bytes.
pub const MAX_RECORD: u32 = 64 * 1024;
/// Largest index block, in bytes.
pub const MAX_INDEX_BLOCK: u32 = 64 * 1024;
/// Largest cluster, in bytes (Windows' own limit).
pub const MAX_CLUSTER_BYTES: u32 = 2 * 1024 * 1024;
/// Most runs one attribute may hold.
pub const MAX_RUNS: usize = 1 << 20;
/// Largest `$ATTRIBUTE_LIST` read, in bytes.
pub const MAX_LIST_BYTES: u64 = 1 << 20;
/// Most entries read from one attribute list.
pub const MAX_LIST_ENTRIES: usize = 1 << 16;
/// Most extension records one file may name (records visited per file).
pub const MAX_EXT_RECORDS: usize = 1024;
/// Most `INDX` blocks one folder walk may load.
pub const MAX_DIR_BLOCKS: u64 = 1 << 24;
/// Most entries one folder walk may see.
pub const MAX_DIR_ENTRIES: u64 = 1 << 26;
/// Deepest index tree followed.
pub const MAX_INDEX_DEPTH: usize = 32;
/// Index entries one `next_batch` call may look at before it hands back.
pub const MAX_ENTRIES_PER_PASS: usize = 1 << 16;
/// The free space is counted at mount only for a bitmap up to this size.
const FREE_COUNT_LIMIT: u64 = 1 << 20;
/// Bytes of the bitmap read at once.
const BITMAP_PIECE: usize = 1 << 16;

/// The root folder's record.
const ROOT_RECORD: u64 = 5;
/// Records below this number are the volume's metadata files.
const FIRST_USER_RECORD: u64 = 16;
/// `$Volume`, `$Bitmap` and `$UpCase`.
const VOLUME_RECORD: u64 = 3;
const BITMAP_RECORD: u64 = 6;
const UPCASE_RECORD: u64 = 10;
/// The file attribute bit EFS sets.
const ATTR_ENCRYPTED: u32 = 0x4000;

/// A mounted NTFS volume.
pub struct Ntfs {
    source: Arc<dyn BlockSource>,
    geo: Geometry,
    mft: Arc<FileData>,
    upcase: Arc<Upcase>,
    info: VolumeInfo,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Ntfs>();
};

/// Reads the `$MFT` record at cluster `lcn` and builds the stream of the
/// MFT's data from it.
fn try_mft(source: &Arc<dyn BlockSource>, geo: &Geometry, lcn: u64) -> Result<Arc<FileData>> {
    let loc = Location::Block(lcn);
    let at = lcn
        .checked_mul(u64::from(geo.cluster_size))
        .ok_or_else(|| le::other("NTFS $MFT", loc, "start cluster overflows"))?;
    let mut buf = vec![0u8; le::to_usize(u64::from(geo.record_size), "NTFS $MFT", "record size")?];
    source.read_at(at, &mut buf)?;
    let hdr = record::parse(&mut buf, 0)?;
    if hdr.flags & record::IN_USE == 0 || hdr.flags & IS_DIR != 0 || !hdr.is_base() {
        return Err(le::other("NTFS $MFT", loc, "record 0 is not the MFT file"));
    }
    let partial = node::bootstrap_mft(source, geo, &buf, &hdr)?;
    let ctx = Ctx {
        source,
        geo,
        mft: &partial,
    };
    let node = ctx.load_from(0, &buf, &hdr)?;
    match node.data {
        Some(Data::NonResident { file, .. }) if file.len() >= u64::from(geo.record_size) => {
            Ok(file)
        }
        _ => Err(le::other("NTFS $MFT", loc, "the MFT has no usable $DATA")),
    }
}

/// Mounts the NTFS volume in `source`.
///
/// Fails when the boot sector is not a valid NTFS boot sector or neither
/// `$MFT` nor its mirror's copy of record 0 is usable.
pub fn mount(source: Arc<dyn BlockSource>) -> Result<Ntfs> {
    let mut sector = [0u8; boot::BOOT_LEN];
    let have = usize::try_from(source.len()).map_or(sector.len(), |l| l.min(sector.len()));
    if let Some(dst) = sector.get_mut(..have) {
        source.read_at(0, dst)?;
    }
    let geo = boot::parse(sector.get(..have).unwrap_or(&[]))?;
    let mut candidates = vec![geo.mft_lcn];
    if geo.mirror_lcn < geo.cluster_count && geo.mirror_lcn != geo.mft_lcn {
        candidates.push(geo.mirror_lcn);
    }
    let mut first_error = None;
    let mut mft = None;
    for lcn in candidates {
        match try_mft(&source, &geo, lcn) {
            Ok(file) => {
                mft = Some(file);
                break;
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    let Some(mft) = mft else {
        return Err(
            first_error.unwrap_or_else(|| le::other("NTFS $MFT", Location::Unspecified, "no MFT"))
        );
    };
    let mut fs = Ntfs {
        source,
        geo,
        mft,
        upcase: Arc::new(Upcase::fallback()),
        info: VolumeInfo::new(""),
    };
    fs.upcase = Arc::new(fs.load_upcase());
    fs.info = fs.volume_info();
    Ok(fs)
}

fn corrupt_dir(what: &'static str, dir: u64) -> Error {
    le::other("NTFS folder", Location::Object(dir), what)
}

impl Ntfs {
    /// The geometry the boot sector gave.
    pub fn geometry(&self) -> &Geometry {
        &self.geo
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            source: &self.source,
            geo: &self.geo,
            mft: &self.mft,
        }
    }

    fn load_upcase(&self) -> Upcase {
        let table = self.ctx().load(UPCASE_RECORD).ok().and_then(|n| {
            let data = n.data?;
            if data.len() != upcase::TABLE_BYTES as u64 {
                return None;
            }
            let mut bytes = vec![0u8; upcase::TABLE_BYTES];
            data.source().read_at(0, &mut bytes).ok()?;
            Upcase::from_table(&bytes)
        });
        table.unwrap_or_else(Upcase::fallback)
    }

    fn volume_info(&self) -> VolumeInfo {
        let label = self
            .ctx()
            .load(VOLUME_RECORD)
            .ok()
            .and_then(|n| n.volume_name)
            .map(|bytes| {
                let mut s = String::new();
                le::decode_name(&bytes, &mut s);
                s.trim_end().to_owned()
            })
            .unwrap_or_default();
        let mut info = VolumeInfo::new(if label.is_empty() {
            "NTFS volume".to_owned()
        } else {
            label
        });
        info.format = Some("NTFS");
        info.total_bytes = Some(self.geo.volume_bytes);
        info.free_bytes = self.free_bytes();
        info.local_times = false;
        info
    }

    /// The `$Bitmap` stream, when it covers every cluster.
    fn bitmap(&self) -> Result<Arc<dyn BlockSource>> {
        let node = self.ctx().load(BITMAP_RECORD)?;
        let data = node
            .data
            .ok_or_else(|| le::other("NTFS $Bitmap", Location::Unspecified, "no $DATA"))?;
        let need = self.geo.cluster_count.div_ceil(8);
        if data.len() < need {
            return Err(Corruption::new(
                "NTFS $Bitmap",
                Location::Object(BITMAP_RECORD),
                CorruptKind::Truncated {
                    needed: need,
                    available: data.len(),
                },
            )
            .into());
        }
        Ok(data.source())
    }

    /// Free bytes from a small bitmap; `None` for a large or damaged one.
    fn free_bytes(&self) -> Option<u64> {
        if self.geo.cluster_count.div_ceil(8) > FREE_COUNT_LIMIT {
            return None;
        }
        let bitmap = self.bitmap().ok()?;
        let total = self.geo.cluster_count;
        let used = count_set(&*bitmap, 0, total, &mut Vec::new()).ok()?;
        Some(
            total
                .saturating_sub(used)
                .saturating_mul(u64::from(self.geo.cluster_size)),
        )
    }

    /// A folder's index tree.
    fn tree_of(&self, dir: NodeId) -> Result<Tree> {
        let n = self.ctx().load(dir.0)?;
        // A junction or symbolic link to a folder is not followed: its
        // target is a path on the machine that made it.
        if !n.is_dir || is_link(&n) {
            return Err(Error::NotADirectory { node: dir.0 });
        }
        let root = n
            .root
            .ok_or_else(|| corrupt_dir("folder has no $INDEX_ROOT", dir.0))?;
        Tree::new(root, n.alloc, dir.0)
    }

    /// A file's node, refusing folders.
    fn file_node(&self, node: NodeId) -> Result<Node> {
        let n = self.ctx().load(node.0)?;
        if n.is_dir && !is_link(&n) {
            return Err(Error::IsADirectory { node: node.0 });
        }
        Ok(n)
    }
}

/// True for a symbolic link or junction. Files with another kind of reparse
/// point are not links.
fn is_link(n: &Node) -> bool {
    n.reparse_value
        .as_deref()
        .is_some_and(|v| le::u32_at(v, 0).is_ok_and(reparse::is_link))
}

/// The target a symbolic link or junction stores; `None` for every other
/// node and for a link that stores no name.
fn link_target(n: &Node, number: u64) -> Result<Option<String>> {
    match &n.reparse_value {
        Some(value) => reparse::target(value, number),
        None => Ok(None),
    }
}

/// A stream's bytes: the decompressed content for a compressed one.
fn data_source(data: Data) -> Result<Arc<dyn BlockSource>> {
    if data.flags() & attr::FLAG_ENCRYPTED != 0 {
        return Err(Error::Unsupported("NTFS encryption (EFS)".into()));
    }
    if let Some((file, unit_shift)) = data.compressed() {
        return Ok(Arc::new(compressed::Compressed::new(file, unit_shift)?));
    }
    Ok(data.source())
}

/// Counts the set bits of `bitmap` for clusters `lo..hi`.
fn count_set(bitmap: &dyn BlockSource, lo: u64, hi: u64, piece: &mut Vec<u8>) -> Result<u64> {
    if hi <= lo {
        return Ok(0);
    }
    let last_bit = hi.saturating_sub(1);
    let first = lo / 8;
    let last = last_bit / 8;
    let mut count = 0u64;
    let mut at = first;
    piece.resize(BITMAP_PIECE, 0);
    while at <= last {
        let left = last.saturating_sub(at).saturating_add(1);
        let take = usize::try_from(left).map_or(BITMAP_PIECE, |n| n.min(BITMAP_PIECE));
        let Some(dst) = piece.get_mut(..take) else {
            break;
        };
        bitmap.read_at(at, dst)?;
        for (i, &byte) in dst.iter().enumerate() {
            let abs = at.saturating_add(u64::try_from(i).unwrap_or(0));
            let mut byte = byte;
            if abs == first {
                byte &= 0xFFu8.wrapping_shl(u32::try_from(lo % 8).unwrap_or(0));
            }
            if abs == last {
                let bits = u32::try_from(last_bit % 8).unwrap_or(7).saturating_add(1);
                byte &= 0xFFu8.wrapping_shr(8u32.saturating_sub(bits));
            }
            count = count.saturating_add(u64::from(byte.count_ones()));
        }
        at = at.saturating_add(u64::try_from(take).unwrap_or(1));
    }
    Ok(count)
}

/// What a listing says about a file: hidden or system entries are hidden.
fn entry_flags(attrs: u32) -> EntryFlags {
    if attrs & (attr::ATTR_HIDDEN | attr::ATTR_SYSTEM) != 0 {
        EntryFlags::HIDDEN
    } else {
        EntryFlags::EMPTY
    }
}

struct NtDir {
    walker: Walker,
    done: bool,
}

impl DirStream for NtDir {
    fn next_batch(&mut self, out: &mut DirBatch, max: usize) -> Result<DirProgress> {
        if self.done {
            return Ok(DirProgress::Done);
        }
        let mut added = 0usize;
        let mut looked = 0usize;
        // Bounded: `max` entries added, or `MAX_ENTRIES_PER_PASS` looked at.
        while added < max {
            if looked >= MAX_ENTRIES_PER_PASS {
                return Ok(DirProgress::More);
            }
            looked = looked.saturating_add(1);
            let found = match self.walker.next_entry() {
                Ok(Some(found)) => found,
                Ok(None) => {
                    self.done = true;
                    return Ok(DirProgress::Done);
                }
                Err(e) => {
                    self.done = true;
                    return Err(e);
                }
            };
            let number = found.file_ref & REF_MASK;
            // DOS names repeat a file listed under its long name; records
            // below 16 are the volume's own files (and the root's `.`).
            if found.namespace == 2 || number < FIRST_USER_RECORD || self.walker.name.is_empty() {
                continue;
            }
            let has_index = found.attrs & attr::ATTR_DIRECTORY_INDEX != 0;
            let is_link =
                found.attrs & attr::ATTR_REPARSE != 0 && reparse::is_link(found.reparse_tag);
            let mut flags = entry_flags(found.attrs);
            if is_link && has_index {
                flags = flags.with(EntryFlags::LINKS_TO_DIRECTORY);
            }
            out.push(DirEntry {
                node: NodeId(number),
                name: &self.walker.name,
                kind: if is_link {
                    NodeKind::Symlink
                } else if has_index {
                    NodeKind::Directory
                } else {
                    NodeKind::File
                },
                size: (!is_link && !has_index).then_some(found.size),
                resource_size: None,
                modified: attr::filetime(found.modified),
                flags,
            });
            added = added.saturating_add(1);
        }
        Ok(DirProgress::More)
    }
}

impl FileSystem for Ntfs {
    fn info(&self) -> VolumeInfo {
        self.info.clone()
    }

    fn root(&self) -> NodeId {
        NodeId(ROOT_RECORD)
    }

    fn metadata(&self, node: NodeId) -> Result<Metadata> {
        let n = self.ctx().load(node.0)?;
        // A damaged link value is shown as a link with no target.
        let link = link_target(&n, node.0).unwrap_or(None);
        let is_link = is_link(&n);
        let is_dir = n.is_dir && !is_link;
        let std = n.std;
        let mut flags = std.map_or(EntryFlags::EMPTY, |s| entry_flags(s.attrs));
        if is_link && n.is_dir {
            flags = flags.with(EntryFlags::LINKS_TO_DIRECTORY);
        }
        Ok(Metadata {
            node,
            kind: if is_link {
                NodeKind::Symlink
            } else if is_dir {
                NodeKind::Directory
            } else {
                NodeKind::File
            },
            size: (!is_dir && !is_link).then(|| n.data.as_ref().map_or(0, Data::len)),
            resource_size: None,
            created: std.and_then(|s| attr::filetime(s.created)),
            modified: std.and_then(|s| attr::filetime(s.modified)),
            accessed: std.and_then(|s| attr::filetime(s.accessed)),
            flags,
            link_target: link,
            finder_codes: None,
            owner: None,
            attributes: u32::try_from(n.streams.len()).ok().filter(|&c| c > 0),
            finder_info: None,
        })
    }

    fn lookup(&self, dir: NodeId, name: &str) -> Result<Option<NodeId>> {
        let tree = self.tree_of(dir)?;
        let want: Vec<u16> = name.encode_utf16().collect();
        if want.is_empty() || want.len() > attr::MAX_NAME_UNITS {
            return Ok(None);
        }
        let found = if tree.is_file_name_collation() {
            match index::lookup(&tree, &self.upcase, &want)? {
                // Without the volume's own table the order may differ from
                // the one the index was sorted in: look again by scanning.
                None if !self.upcase.is_volume_table() => {
                    index::lookup_scan(&tree, &self.upcase, &want)?
                }
                found => found,
            }
        } else {
            index::lookup_scan(&tree, &self.upcase, &want)?
        };
        Ok(found.map(NodeId))
    }

    fn read_dir(&self, dir: NodeId) -> Result<Box<dyn DirStream>> {
        Ok(Box::new(NtDir {
            walker: Walker::new(self.tree_of(dir)?),
            done: false,
        }))
    }

    fn extents(&self, node: NodeId, stream: Stream) -> Result<Vec<Extent>> {
        let n = self.file_node(node)?;
        if stream == Stream::Resource {
            return Ok(Vec::new());
        }
        let Some(Data::NonResident { file, .. }) = n.data else {
            return Ok(Vec::new());
        };
        let cs = file.cluster_size();
        let mut out: Vec<Extent> = Vec::new();
        for run in file.runs().runs() {
            let Some(lcn) = run.lcn else { continue };
            let offset = lcn.saturating_mul(cs);
            let len = run.len.saturating_mul(cs);
            match out.last_mut() {
                Some(last) if last.offset.saturating_add(last.len) == offset => {
                    last.len = last.len.saturating_add(len);
                }
                _ => out.push(Extent { offset, len }),
            }
        }
        Ok(out)
    }

    fn allocation_map(&self, buckets: usize) -> Result<AllocationMap> {
        let bitmap = self.bitmap()?;
        let total = self.geo.cluster_count;
        let n = buckets
            .clamp(1, MAX_ALLOCATION_BUCKETS)
            .min(usize::try_from(total).unwrap_or(usize::MAX))
            .max(1);
        let n64 = u64::try_from(n).unwrap_or(1);
        // Bucket `i` covers clusters `[i * total / n, (i + 1) * total / n)`.
        let edge = |i: u64| {
            u128::from(i)
                .saturating_mul(u128::from(total))
                .checked_div(u128::from(n64))
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(total)
        };
        let mut piece = Vec::new();
        let mut density = Vec::with_capacity(n);
        for i in 0..n64 {
            let (lo, hi) = (edge(i), edge(i.saturating_add(1)));
            let used = count_set(&*bitmap, lo, hi, &mut piece)?;
            let size = hi.saturating_sub(lo).max(1);
            let d = used.saturating_mul(255).div_ceil(size);
            density.push(u8::try_from(d).unwrap_or(255));
        }
        Ok(AllocationMap::new(
            0,
            total.saturating_mul(u64::from(self.geo.cluster_size)),
            density,
        ))
    }

    fn open(&self, node: NodeId, stream: Stream) -> Result<Arc<dyn BlockSource>> {
        let n = self.file_node(node)?;
        if stream == Stream::Resource {
            return Err(Error::NoSuchStream { node: node.0 });
        }
        if n.std.is_some_and(|s| s.attrs & ATTR_ENCRYPTED != 0) {
            return Err(Error::Unsupported("NTFS encryption (EFS)".into()));
        }
        // A link gives the stored target path.
        if is_link(&n) {
            let target = link_target(&n, node.0)?.unwrap_or_default();
            return Ok(Arc::new(Resident(target.into_bytes())));
        }
        let Some(data) = n.data else {
            return Ok(Arc::new(Resident(Vec::new())));
        };
        data_source(data)
    }

    fn xattrs(&self, node: NodeId) -> Result<Vec<XattrInfo>> {
        let n = self.ctx().load(node.0)?;
        Ok(n.streams
            .iter()
            .map(|(name, data)| XattrInfo {
                name: name.clone(),
                size: data.len(),
            })
            .collect())
    }

    fn read_xattr(&self, node: NodeId, name: &str, max: usize) -> Result<Option<Vec<u8>>> {
        let n = self.ctx().load(node.0)?;
        // Stream names compare like file names.
        let want: Vec<u16> = name.encode_utf16().collect();
        let Some((_, data)) = n.streams.into_iter().find(|(have, _)| {
            self.upcase
                .compare(have.encode_utf16(), want.iter().copied())
                .is_eq()
        }) else {
            return Ok(None);
        };
        let len = data.len();
        let size = usize::try_from(len)
            .ok()
            .filter(|&s| s <= max)
            .ok_or_else(|| Error::Unsupported("stream is larger than the limit".into()))?;
        let source = data_source(data)?;
        let mut value = vec![0u8; size];
        source.read_at(0, &mut value)?;
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use sha2::{Digest, Sha256};

    use super::test_volume as tv;
    use super::*;
    use atlas_fs_core::io::block::MemSource;
    use atlas_fs_core::io::file::FileSource;

    fn mounted(image: Vec<u8>) -> Result<Ntfs> {
        mount(Arc::new(MemSource::new(image)))
    }

    type Row = (String, NodeId, NodeKind, Option<u64>, EntryFlags);

    fn list(fs: &Ntfs, dir: NodeId) -> Result<Vec<Row>> {
        let mut stream = fs.read_dir(dir)?;
        let mut batch = DirBatch::default();
        let mut out = Vec::new();
        loop {
            batch.clear();
            let progress = stream.next_batch(&mut batch, 7)?;
            out.extend(
                batch
                    .iter()
                    .map(|e| (e.name.to_owned(), e.node, e.kind, e.size, e.flags)),
            );
            if progress == DirProgress::Done {
                return Ok(out);
            }
        }
    }

    fn read_all(source: &dyn BlockSource) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; usize::try_from(source.len()).unwrap()];
        source.read_at(0, &mut buf)?;
        Ok(buf)
    }

    fn node_of(fs: &Ntfs, dir: NodeId, name: &str) -> NodeId {
        fs.lookup(dir, name)
            .unwrap()
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    fn content(fs: &Ntfs, name: &str) -> Vec<u8> {
        let node = node_of(fs, fs.root(), name);
        read_all(&*fs.open(node, Stream::Data).unwrap()).unwrap()
    }

    #[test]
    fn the_standard_volume_lists_reads_and_looks_up() {
        let fs = mounted(tv::standard().image).unwrap();
        let info = fs.info();
        assert_eq!(info.name, "ATLAS");
        assert_eq!(info.format, Some("NTFS"));
        assert_eq!(
            info.free_bytes,
            Some(((tv::CLUSTERS - tv::USED_CLUSTERS) * tv::CLUSTER) as u64)
        );
        // The listing hides metadata files and the DOS name, and every
        // other name is there once.
        let root = list(&fs, fs.root()).unwrap();
        let names: BTreeSet<_> = root.iter().map(|e| e.0.as_str()).collect();
        let want: BTreeSet<_> = [
            "alpha.txt",
            "big.bin",
            "docs",
            "frag.bin",
            "hello.txt",
            "init.bin",
            "secret.sys",
            "zed.txt",
        ]
        .into();
        assert_eq!(names, want);
        assert_eq!(root.len(), want.len());
        let docs = root.iter().find(|e| e.0 == "docs").unwrap();
        assert_eq!(docs.2, NodeKind::Directory);
        let secret = root.iter().find(|e| e.0 == "secret.sys").unwrap();
        assert!(secret.4.contains(EntryFlags::HIDDEN));
        let inner = list(&fs, docs.1).unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(
            read_all(&*fs.open(inner[0].1, Stream::Data).unwrap()).unwrap(),
            b"inner"
        );
        // Lookup ignores case, finds names on both sides of the root key, the
        // DOS name, and says no to a missing one.
        for (name, record) in [
            ("HELLO.TXT", tv::R_HELLO),
            ("Frag.Bin", tv::R_FRAG),
            ("ALPHA.txt", tv::R_ALPHA),
            ("zed.TXT", tv::R_ZED),
            ("big~1.bin", tv::R_BIG),
            ("DOCS", tv::R_DOCS),
        ] {
            assert_eq!(
                fs.lookup(fs.root(), name).unwrap(),
                Some(NodeId(record)),
                "{name}"
            );
        }
        assert_eq!(fs.lookup(fs.root(), "nope.txt").unwrap(), None);
        assert_eq!(fs.lookup(fs.root(), "aaa").unwrap(), None);
        assert_eq!(fs.lookup(fs.root(), "zzz").unwrap(), None);
        assert!(matches!(
            fs.lookup(NodeId(tv::R_HELLO), "x"),
            Err(Error::NotADirectory { .. })
        ));
        // Contents: resident, a hole, an attribute list with an extension
        // record, an initialized size below the size.
        assert_eq!(content(&fs, "hello.txt"), tv::HELLO);
        assert_eq!(content(&fs, "big.bin"), tv::big_expected());
        assert_eq!(content(&fs, "frag.bin"), tv::frag_expected());
        let init = content(&fs, "init.bin");
        assert_eq!(init.len(), 2000);
        assert!(init[..1200].iter().all(|&b| b == 0xAB));
        assert!(init[1200..].iter().all(|&b| b == 0));
        assert!(content(&fs, "alpha.txt").is_empty());
        // Metadata and extents.
        let meta = fs.metadata(NodeId(tv::R_HELLO)).unwrap();
        assert_eq!(meta.size, Some(tv::HELLO.len() as u64));
        let secs = i64::try_from(tv::UNIX_SECONDS).unwrap();
        assert_eq!(meta.modified.unwrap().unix_seconds(), secs);
        assert_eq!(meta.created.unwrap().unix_seconds(), secs - 2);
        assert_eq!(meta.accessed.unwrap().unix_seconds(), secs + 1);
        assert_eq!(
            fs.metadata(NodeId(tv::R_DOCS)).unwrap().kind,
            NodeKind::Directory
        );
        assert!(
            fs.metadata(NodeId(tv::R_SECRET))
                .unwrap()
                .flags
                .contains(EntryFlags::HIDDEN)
        );
        let k = tv::CLUSTER as u64;
        assert_eq!(
            fs.extents(NodeId(tv::R_BIG), Stream::Data).unwrap(),
            vec![
                Extent {
                    offset: 44 * k,
                    len: 2 * k
                },
                Extent {
                    offset: 55 * k,
                    len: k
                }
            ]
        );
        assert_eq!(
            fs.extents(NodeId(tv::R_FRAG), Stream::Data).unwrap().len(),
            2
        );
        assert!(
            fs.extents(NodeId(tv::R_HELLO), Stream::Data)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            fs.extents(NodeId(tv::R_DOCS), Stream::Data),
            Err(Error::IsADirectory { .. })
        ));
        assert!(matches!(
            fs.open(NodeId(tv::R_HELLO), Stream::Resource),
            Err(Error::NoSuchStream { .. })
        ));
        // A record that was never written, and one past the MFT.
        assert!(matches!(
            fs.metadata(NodeId(27)),
            Err(Error::NotFound { .. })
        ));
        assert!(matches!(
            fs.metadata(NodeId(9999)),
            Err(Error::NotFound { .. })
        ));
        // The allocation map covers the used front of the volume.
        let map = fs.allocation_map(8).unwrap();
        assert_eq!(
            (map.density.len(), map.len),
            (8, (tv::CLUSTERS * tv::CLUSTER) as u64)
        );
        assert_eq!(map.density[0], 255);
        assert_eq!(map.density[7], 0);
    }

    #[test]
    fn damage_is_an_error_or_a_fallback_never_a_panic() {
        let k = tv::CLUSTER;
        // A bad first record: the mirror's copy of record 0 carries the mount.
        let mut image = tv::standard().image;
        image[tv::MFT_LCN * k] = b'X';
        let fs = mounted(image).unwrap();
        assert_eq!(list(&fs, fs.root()).unwrap().len(), 8);
        // Both copies bad: no mount.
        let mut image = tv::standard().image;
        image[tv::MFT_LCN * k] = b'X';
        image[tv::MIRROR_LCN * k] = b'X';
        assert!(mounted(image).is_err());
        // A torn root record (fixup mismatch) fails its folder, not the volume.
        let mut image = tv::standard().image;
        image[tv::MFT_LCN * k + 5 * tv::RECORD + 510] ^= 0xFF;
        let fs = mounted(image).unwrap();
        assert!(fs.read_dir(fs.root()).is_err());
        assert!(fs.lookup(fs.root(), "hello.txt").is_err());
        assert_eq!(content_of(&fs, tv::R_HELLO), tv::HELLO);
        // A run list that reaches past the volume: opening fails.
        let mut image = tv::standard().image;
        let runs = [0x11u8, 2, 44, 0x01, 3, 0x11, 1, 11, 0];
        let at = image
            .windows(runs.len())
            .position(|w| w == runs)
            .expect("big.bin's run list");
        image[at..at + 3].copy_from_slice(&[0x11, 0xF0, 0x7F]);
        let fs = mounted(image).unwrap();
        assert!(fs.open(NodeId(tv::R_BIG), Stream::Data).is_err());
        assert!(fs.extents(NodeId(tv::R_BIG), Stream::Data).is_err());
        // Cut short: a source that ends inside the MFT.
        let image = tv::standard().image[..(tv::MFT_LCN + 6) * k].to_vec();
        if let Ok(fs) = mounted(image) {
            let _ = fs.read_dir(fs.root()).map(|_| ());
            let _ = fs.open(NodeId(tv::R_BIG), Stream::Data);
        }
    }

    fn content_of(fs: &Ntfs, record: u64) -> Vec<u8> {
        read_all(&*fs.open(NodeId(record), Stream::Data).unwrap()).unwrap()
    }

    #[test]
    fn an_index_that_points_at_itself_terminates() {
        let fs = mounted(tv::cyclic().image).unwrap();
        // The listing yields the entries before the loop and then fails.
        let err = list(&fs, fs.root()).unwrap_err();
        assert!(err.to_string().contains("visited"), "{err}");
        // A name before the bad pointer is still found; one past it is not
        // found but the lookup ends in an error, not a hang.
        assert!(fs.lookup(fs.root(), "zed.txt").unwrap().is_some());
        assert!(fs.lookup(fs.root(), "zzz").is_err());
    }

    /// Mounts `image` and walks and reads what it finds, within bounds.
    fn exercise(image: Vec<u8>) {
        let Ok(fs) = mounted(image) else { return };
        let _ = fs.info();
        let _ = fs.allocation_map(5);
        let mut budget = 300usize;
        let mut dirs = vec![(fs.root(), 0usize)];
        while let Some((dir, depth)) = dirs.pop() {
            let Ok(mut stream) = fs.read_dir(dir) else {
                continue;
            };
            let mut batch = DirBatch::new();
            loop {
                batch.clear();
                let progress = stream.next_batch(&mut batch, 16);
                for e in batch.iter() {
                    budget = budget.saturating_sub(1);
                    if budget == 0 {
                        return;
                    }
                    let _ = fs.lookup(dir, e.name);
                    let _ = fs.metadata(e.node);
                    let _ = fs.extents(e.node, Stream::Data);
                    if let Ok(src) = fs.open(e.node, Stream::Data) {
                        let mut buf = vec![0u8; usize::try_from(src.len().min(70_000)).unwrap()];
                        let _ = src.read_at(0, &mut buf);
                    }
                    if e.is_browsable() && depth < 4 {
                        dirs.push((e.node, depth + 1));
                    }
                }
                if !matches!(progress, Ok(DirProgress::More)) {
                    break;
                }
            }
        }
    }

    #[test]
    fn flipping_every_byte_of_the_key_structures_never_panics() {
        let base = tv::standard().image;
        let k = tv::CLUSTER;
        let ranges = [
            0..0x50,
            tv::MFT_LCN * k..tv::MFT_LCN * k + tv::RECORD,
            tv::MFT_LCN * k + 5 * tv::RECORD..tv::MFT_LCN * k + 6 * tv::RECORD,
            38 * k..38 * k + 0x80,
            40 * k..40 * k + 0x80,
        ];
        for range in ranges {
            for at in range {
                for mask in [0xFFu8, 0x01, 0x80] {
                    let mut image = base.clone();
                    image[at] ^= mask;
                    exercise(image);
                }
            }
        }
    }

    // ---- real images made by tools/test-images/make-ntfs-images.sh ----

    fn sha_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn walk_path(fs: &Ntfs, path: &str) -> NodeId {
        path.split('/')
            .fold(fs.root(), |dir, part| node_of(fs, dir, part))
    }

    #[allow(clippy::print_stderr)]
    fn check_image(path: &Path) {
        let source = Arc::new(FileSource::open(path).unwrap());
        let fs = mount(source).unwrap();
        let info = fs.info();
        assert_eq!(info.name, "AtlasTest");
        assert_eq!(info.format, Some("NTFS"));
        assert!(
            info.free_bytes
                .is_some_and(|f| f > 0 && f < info.total_bytes.unwrap())
        );
        let root: BTreeMap<String, NodeKind> = list(&fs, fs.root())
            .unwrap()
            .into_iter()
            .map(|e| (e.0, e.2))
            .collect();
        for name in [
            "hello.txt",
            "café-ünïcode.txt",
            "empty.txt",
            "docs",
            "many",
            "long",
        ] {
            assert!(root.contains_key(name), "{name} in {root:?}");
        }
        assert!(root.keys().all(|n| !n.starts_with('$')), "{root:?}");
        // 3000 files: the folder's index has INDX blocks.
        let many = node_of(&fs, fs.root(), "many");
        let listed = list(&fs, many).unwrap();
        assert_eq!(listed.len(), 3000);
        let names: BTreeSet<_> = listed.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names.len(), 3000);
        let f100 = fs.lookup(many, "F0100.TXT").unwrap().unwrap();
        assert_eq!(listed.iter().find(|e| e.0 == "f0100.txt").unwrap().1, f100);
        assert!(fs.lookup(NodeId(f100.0), "x").is_err());
        assert_eq!(
            read_all(&*fs.open(f100, Stream::Data).unwrap()).unwrap(),
            b"f0100\n"
        );
        let by_path = fs
            .lookup(fs.lookup(fs.root(), "MANY").unwrap().unwrap(), "F2999.TXT")
            .unwrap();
        assert!(by_path.is_some());
        assert_eq!(fs.lookup(many, "f3000.txt").unwrap(), None);
        // A 254-unit name.
        let long = list(&fs, node_of(&fs, fs.root(), "long")).unwrap();
        assert_eq!(long.len(), 1);
        assert_eq!(long[0].0.encode_utf16().count(), 254);
        // Content against the manifest.
        let manifest = std::fs::read_to_string(format!("{}.sha256", path.display())).unwrap();
        let mut hashed = 0;
        for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
            let (hash, file) = line.split_once("  ").unwrap();
            let node = walk_path(&fs, file);
            let data = read_all(&*fs.open(node, Stream::Data).unwrap()).unwrap();
            assert_eq!(sha_hex(&data), hash, "{file}");
            assert_eq!(
                fs.metadata(node).unwrap().size,
                Some(data.len() as u64),
                "{file}"
            );
            hashed += 1;
        }
        assert_eq!(hashed, 7);
        // The sparse file: 2100000 bytes, zeros except the marker.
        let sparse = walk_path(&fs, "docs/sparse.bin");
        let data = read_all(&*fs.open(sparse, Stream::Data).unwrap()).unwrap();
        assert_eq!(data.len(), 2_100_000);
        let marker = b"sparse-data-marker";
        assert_eq!(&data[1_048_576..1_048_576 + marker.len()], marker);
        assert!(data[..1_048_576].iter().all(|&b| b == 0));
        assert!(data[1_048_576 + marker.len()..].iter().all(|&b| b == 0));
        let sparse_extents = fs.extents(sparse, Stream::Data).unwrap();
        assert!(!sparse_extents.is_empty());
        let frag = fs
            .extents(walk_path(&fs, "docs/frag.bin"), Stream::Data)
            .unwrap();
        // ntfs-3g allocates frag.bin in one run on every image, however the
        // script writes it (it allocates from a last-position hint, not into
        // holes), so the multi-extent paths are covered by the built volume's
        // frag.bin and by sparse.bin.
        assert!(!frag.is_empty(), "frag.bin extents: {frag:?}");
        assert!(
            fs.allocation_map(64)
                .unwrap()
                .density
                .iter()
                .any(|&d| d > 0)
        );
        assert_eq!(
            read_all(&*fs.open(walk_path(&fs, "hello.txt"), Stream::Data).unwrap()).unwrap(),
            b"hello from disk atlas\n"
        );
        eprintln!(
            "{}: {hashed} files hashed, frag.bin in {} runs, {} entries in many/",
            path.display(),
            frag.len(),
            listed.len()
        );
    }

    #[test]
    #[allow(clippy::print_stderr)]
    fn real_images_match_their_manifests() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/test-images/out");
        let mut checked = 0;
        for name in ["ntfs-4k.img", "ntfs-512c.img", "ntfs-4kn.img"] {
            let path = dir.join(name);
            if !path.exists() {
                eprintln!("skipping {name}: {} is missing", path.display());
                continue;
            }
            check_image(&path);
            checked += 1;
        }
        eprintln!("{checked} real NTFS images checked");
    }

    #[test]
    #[allow(clippy::print_stderr)]
    fn a_real_compressed_image_matches_its_manifest() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/test-images/out");
        let path = dir.join("ntfs-compressed.img");
        if !path.exists() {
            eprintln!("skipping: {} is missing", path.display());
            return;
        }
        let fs = mount(Arc::new(FileSource::open(&path).unwrap())).unwrap();
        let manifest = std::fs::read_to_string(dir.join("ntfs-compressed.img.sha256")).unwrap();
        let mut compressed = 0;
        for line in manifest.lines() {
            let (hash, name) = line.split_once("  ").unwrap();
            let node = walk_path(&fs, name);
            let bytes = read_all(&*fs.open(node, Stream::Data).unwrap()).unwrap();
            let digest: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(digest, hash, "{name}");
            // The runs on disk hold fewer bytes than the file: it is compressed.
            let on_disk: u64 = fs
                .extents(node, Stream::Data)
                .unwrap()
                .iter()
                .map(|e| e.len)
                .sum();
            if on_disk < bytes.len() as u64 {
                compressed += 1;
            }
            eprintln!("{name}: {} bytes, {on_disk} on disk", bytes.len());
        }
        assert!(compressed >= 2, "ntfs-3g stored no compressed file");
    }
}
