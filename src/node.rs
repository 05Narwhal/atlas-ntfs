// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! One file as the reader sees it: the attributes of its base record and of
//! the extension records an `$ATTRIBUTE_LIST` names, gathered into a
//! [`Node`].

use std::collections::BTreeSet;
use std::sync::Arc;

use super::attr::{self, Attr, Attrs, Body, NonRes, StdInfo};
use super::boot::Geometry;
use super::le::{self, invalid, limit, other, u16_at, u32_at, u64_at};
use super::record::{self, Header, IN_USE, IS_DIR, REF_MASK};
use super::runs::{FileData, Resident, RunList};
use super::{MAX_EXT_RECORDS, MAX_LIST_BYTES, MAX_LIST_ENTRIES};
use atlas_fs_core::error::{Error, Location, Result};
use atlas_fs_core::io::block::BlockSource;

const STRUCTURE: &str = "NTFS file";
const LIST: &str = "NTFS attribute list";

/// The content of an unnamed `$DATA` attribute.
pub enum Data {
    /// Inside the record.
    Resident(Vec<u8>),
    /// In clusters.
    NonResident {
        /// The stream.
        file: Arc<FileData>,
        /// The attribute flags (compressed, encrypted, sparse).
        flags: u16,
        /// Compression unit size exponent of the first extent.
        unit_shift: u8,
    },
}

impl Data {
    /// Real size in bytes.
    pub fn len(&self) -> u64 {
        match self {
            Self::Resident(v) => u64::try_from(v.len()).unwrap_or(u64::MAX),
            Self::NonResident { file, .. } => file.len(),
        }
    }

    /// True when the stream has no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The content as a source.
    pub fn source(&self) -> Arc<dyn BlockSource> {
        match self {
            Self::Resident(v) => Arc::new(Resident(v.clone())),
            Self::NonResident { file, .. } => file.clone(),
        }
    }

    /// The stream and compression unit exponent when the data is
    /// non-resident and flagged compressed.
    pub fn compressed(&self) -> Option<(Arc<FileData>, u8)> {
        match self {
            Self::NonResident {
                file,
                flags,
                unit_shift,
            } if flags & attr::FLAG_COMPRESSED != 0 => Some((file.clone(), *unit_shift)),
            _ => None,
        }
    }

    /// The attribute flags; 0 for resident data.
    pub fn flags(&self) -> u16 {
        match self {
            Self::Resident(_) => 0,
            Self::NonResident { flags, .. } => *flags,
        }
    }
}

/// What the reader needs to know about one file.
pub struct Node {
    /// The MFT record number.
    pub number: u64,
    /// The record is a directory.
    pub is_dir: bool,
    /// `$STANDARD_INFORMATION`.
    pub std: Option<StdInfo>,
    /// `$VOLUME_NAME` as UTF-16LE bytes.
    pub volume_name: Option<Vec<u8>>,
    /// The unnamed `$DATA`.
    pub data: Option<Data>,
    /// The value of the `$I30` `$INDEX_ROOT`.
    pub root: Option<Vec<u8>>,
    /// The `$I30` `$INDEX_ALLOCATION`.
    pub alloc: Option<Arc<FileData>>,
    /// The file has a `$REPARSE_POINT` attribute.
    pub reparse: bool,
    /// The value of the `$REPARSE_POINT` (always resident on a real volume).
    pub reparse_value: Option<Vec<u8>>,
    /// The named `$DATA` attributes (alternate data streams), by name, in
    /// the order the record lists them. At most [`MAX_STREAMS`].
    pub streams: Vec<(String, Data)>,
}

/// Most alternate data streams read from one file; the rest are ignored.
pub const MAX_STREAMS: usize = 128;

/// Named `$DATA` attributes (and extents of them) collected from one file.
const MAX_NAMED_PIECES: usize = 1024;

/// A named `$DATA` attribute, or one extent of it.
struct NamedPiece {
    name: Vec<u8>,
    body: NamedBody,
}

enum NamedBody {
    Resident(Vec<u8>),
    Piece(Piece),
}

/// One extent's worth of a non-resident attribute, copied out of its record.
#[derive(Clone)]
struct Piece {
    start_vcn: u64,
    last_vcn: u64,
    allocated: u64,
    real: u64,
    init: u64,
    flags: u16,
    unit_shift: u8,
    runs: Vec<u8>,
}

impl Piece {
    fn new(n: &NonRes<'_>, flags: u16) -> Self {
        Self {
            start_vcn: n.start_vcn,
            last_vcn: n.last_vcn,
            allocated: n.allocated,
            real: n.real,
            init: n.init,
            flags,
            unit_shift: n.unit_shift,
            runs: n.runs.to_vec(),
        }
    }
}

enum ListSrc {
    Resident(Vec<u8>),
    Piece(Piece),
}

/// Attributes collected from a record and its extensions.
#[derive(Default)]
struct Collected {
    std: Option<StdInfo>,
    volume_name: Option<Vec<u8>>,
    list: Option<ListSrc>,
    data_res: Option<Vec<u8>>,
    data_pieces: Vec<Piece>,
    root: Option<Vec<u8>>,
    alloc_pieces: Vec<Piece>,
    reparse: bool,
    reparse_value: Option<Vec<u8>>,
    named: Vec<NamedPiece>,
}

impl Collected {
    fn scan(&mut self, buf: &[u8], hdr: &Header, number: u64, is_base: bool) -> Result<()> {
        for item in Attrs::new(buf, hdr.first_attr, hdr.used, number) {
            let a: Attr<'_> = item?;
            match (a.ty, a.body) {
                (attr::STANDARD_INFORMATION, Body::Resident(v)) if self.std.is_none() => {
                    self.std = Some(StdInfo::parse(v)?);
                }
                (attr::ATTRIBUTE_LIST, body) if is_base && self.list.is_none() => {
                    self.list = Some(match body {
                        Body::Resident(v) => ListSrc::Resident(v.to_vec()),
                        Body::NonResident(n) => ListSrc::Piece(Piece::new(&n, a.flags)),
                    });
                }
                (attr::VOLUME_NAME, Body::Resident(v)) => {
                    self.volume_name.get_or_insert_with(|| v.to_vec());
                }
                (attr::DATA, Body::Resident(v)) if a.unnamed() => {
                    self.data_res.get_or_insert_with(|| v.to_vec());
                }
                (attr::DATA, Body::NonResident(n)) if a.unnamed() => {
                    self.data_pieces.push(Piece::new(&n, a.flags));
                }
                (attr::INDEX_ROOT, Body::Resident(v)) if a.name_is("$I30") => {
                    self.root.get_or_insert_with(|| v.to_vec());
                }
                (attr::INDEX_ALLOCATION, Body::NonResident(n)) if a.name_is("$I30") => {
                    self.alloc_pieces.push(Piece::new(&n, a.flags));
                }
                (attr::DATA, body) if self.named.len() < MAX_NAMED_PIECES => {
                    let body = match body {
                        Body::Resident(v) => NamedBody::Resident(v.to_vec()),
                        Body::NonResident(n) => NamedBody::Piece(Piece::new(&n, a.flags)),
                    };
                    self.named.push(NamedPiece {
                        name: a.name.to_vec(),
                        body,
                    });
                }
                (attr::REPARSE_POINT, body) => {
                    self.reparse = true;
                    if let Body::Resident(v) = body
                        && v.len() <= super::reparse::MAX_VALUE
                    {
                        self.reparse_value.get_or_insert_with(|| v.to_vec());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Reads records through an MFT stream.
pub struct Ctx<'a> {
    /// The volume.
    pub source: &'a Arc<dyn BlockSource>,
    /// Its geometry.
    pub geo: &'a Geometry,
    /// The MFT's own `$DATA` (partial while the volume is being mounted).
    pub mft: &'a FileData,
}

impl Ctx<'_> {
    /// Record `n` with its fixups applied.
    pub fn record(&self, n: u64) -> Result<(Vec<u8>, Header)> {
        let size = u64::from(self.geo.record_size);
        let at = n
            .checked_mul(size)
            .filter(|&o| o.checked_add(size).is_some_and(|e| e <= self.mft.len()))
            .ok_or(Error::NotFound { node: n })?;
        let mut buf = vec![0u8; le::to_usize(size, STRUCTURE, "record size")?];
        self.mft.read_at(at, &mut buf)?;
        // A record that was never written is all zeros: not a damaged one.
        if u32_at(&buf, 0)? == 0 {
            return Err(Error::NotFound { node: n });
        }
        let hdr = record::parse(&mut buf, n)?;
        Ok((buf, hdr))
    }

    /// Joins the pieces of one attribute into a stream. `partial` accepts a
    /// run list that does not cover the attribute's size (the first extent
    /// of `$MFT`, before its other extents are known).
    fn assemble(
        &self,
        mut pieces: Vec<Piece>,
        number: u64,
        partial: bool,
    ) -> Result<Option<(FileData, u16, u8)>> {
        pieces.sort_by_key(|p| p.start_vcn);
        let Some(first) = pieces.first() else {
            return Ok(None);
        };
        let loc = Location::Object(number);
        if first.start_vcn != 0 {
            return Err(invalid(
                STRUCTURE,
                loc,
                "first extent starts at VCN",
                first.start_vcn,
            ));
        }
        let cs = u64::from(self.geo.cluster_size);
        let mut runs = RunList::new();
        for p in &pieces {
            runs.extend(p.start_vcn, &p.runs, self.geo.cluster_count, cs, number)?;
            if runs.clusters() != p.last_vcn.wrapping_add(1) {
                return Err(invalid(STRUCTURE, loc, "last VCN of an extent", p.last_vcn));
            }
        }
        let (real, init, flags) = (first.real, first.init, first.flags);
        let mapped = runs.clusters().saturating_mul(cs);
        let compressed = flags & attr::FLAG_COMPRESSED != 0;
        if init > real || (!partial && real > mapped) || (!compressed && real > first.allocated) {
            return Err(invalid(STRUCTURE, loc, "attribute sizes", real));
        }
        Ok(Some((
            FileData::new(self.source.clone(), runs, cs, real, init),
            flags,
            first.unit_shift,
        )))
    }

    fn read_list(&self, src: ListSrc, number: u64) -> Result<Vec<u8>> {
        match src {
            ListSrc::Resident(v) => Ok(v),
            ListSrc::Piece(p) => {
                let Some((fd, ..)) = self.assemble(vec![p], number, false)? else {
                    return Ok(Vec::new());
                };
                if fd.len() > MAX_LIST_BYTES {
                    return Err(limit(
                        LIST,
                        Location::Object(number),
                        "attribute list bytes",
                        MAX_LIST_BYTES,
                    ));
                }
                let mut v = vec![0u8; le::to_usize(fd.len(), LIST, "list size")?];
                fd.read_at(0, &mut v)?;
                Ok(v)
            }
        }
    }

    /// The extension records `list` names for attributes this reader uses.
    fn extension_records(list: &[u8], number: u64) -> Result<BTreeSet<u64>> {
        let loc = Location::Object(number);
        let mut out = BTreeSet::new();
        let mut pos = 0usize;
        let mut entries = 0usize;
        while pos.saturating_add(0x1A) <= list.len() {
            entries = entries.saturating_add(1);
            if entries > MAX_LIST_ENTRIES {
                return Err(limit(
                    LIST,
                    loc,
                    "attribute list entries",
                    MAX_LIST_ENTRIES as u64,
                ));
            }
            let ty = u32_at(list, pos)?;
            let len = usize::from(u16_at(list, pos.saturating_add(4))?);
            if len < 0x1A || pos.saturating_add(len) > list.len() {
                return Err(other(LIST, loc, "entry length is outside the list"));
            }
            let wanted = matches!(
                ty,
                attr::STANDARD_INFORMATION
                    | attr::VOLUME_NAME
                    | attr::REPARSE_POINT
                    | attr::DATA
                    | attr::INDEX_ROOT
                    | attr::INDEX_ALLOCATION
            );
            let rec = u64_at(list, pos.saturating_add(0x10))? & REF_MASK;
            if wanted && rec != number {
                out.insert(rec);
                if out.len() > MAX_EXT_RECORDS {
                    return Err(limit(
                        LIST,
                        loc,
                        "extension records",
                        MAX_EXT_RECORDS as u64,
                    ));
                }
            }
            pos = pos.saturating_add(len);
        }
        Ok(out)
    }

    /// Reads record `n` and everything an attribute list adds to it.
    pub fn load(&self, n: u64) -> Result<Node> {
        let (buf, hdr) = self.record(n)?;
        self.load_from(n, &buf, &hdr)
    }

    /// As [`Self::load`] for a record already read.
    pub fn load_from(&self, n: u64, buf: &[u8], hdr: &Header) -> Result<Node> {
        if hdr.flags & IN_USE == 0 || !hdr.is_base() {
            return Err(Error::NotFound { node: n });
        }
        let mut c = Collected::default();
        c.scan(buf, hdr, n, true)?;
        if let Some(src) = c.list.take() {
            let list = self.read_list(src, n)?;
            for rec in Self::extension_records(&list, n)? {
                let (b, h) = self.record(rec)?;
                if h.flags & IN_USE == 0 || h.base & REF_MASK != n {
                    return Err(other(
                        STRUCTURE,
                        Location::Object(n),
                        "extension record does not belong to this file",
                    ));
                }
                c.scan(&b, &h, rec, false)?;
            }
        }
        let data = match c.data_res.take() {
            Some(v) => Some(Data::Resident(v)),
            None => self
                .assemble(std::mem::take(&mut c.data_pieces), n, false)?
                .map(|(fd, flags, unit_shift)| Data::NonResident {
                    file: Arc::new(fd),
                    flags,
                    unit_shift,
                }),
        };
        let alloc = self
            .assemble(std::mem::take(&mut c.alloc_pieces), n, false)?
            .map(|(fd, ..)| Arc::new(fd));
        let streams = self.streams(std::mem::take(&mut c.named), n);
        Ok(Node {
            number: n,
            is_dir: hdr.flags & IS_DIR != 0,
            std: c.std,
            volume_name: c.volume_name,
            data,
            root: c.root,
            alloc,
            reparse: c.reparse,
            reparse_value: c.reparse_value,
            streams,
        })
    }

    /// Joins the extents of each named `$DATA` into a stream. A stream whose
    /// run list is damaged is left out: it must not hide the file.
    fn streams(&self, named: Vec<NamedPiece>, number: u64) -> Vec<(String, Data)> {
        let mut order: Vec<Vec<u8>> = Vec::new();
        for p in &named {
            if !order.contains(&p.name) {
                if order.len() >= MAX_STREAMS {
                    break;
                }
                order.push(p.name.clone());
            }
        }
        let mut out = Vec::with_capacity(order.len());
        for name in order {
            let mut resident = None;
            let mut pieces = Vec::new();
            for p in named.iter().filter(|p| p.name == name) {
                match &p.body {
                    NamedBody::Resident(v) => {
                        resident.get_or_insert_with(|| v.clone());
                    }
                    NamedBody::Piece(piece) => pieces.push(piece.clone()),
                }
            }
            let data = match resident {
                Some(v) => Some(Data::Resident(v)),
                None => match self.assemble(pieces, number, false) {
                    Ok(found) => found.map(|(fd, flags, unit_shift)| Data::NonResident {
                        unit_shift,
                        file: Arc::new(fd),
                        flags,
                    }),
                    Err(_) => None,
                },
            };
            if let Some(data) = data {
                let mut text = String::new();
                le::decode_name(&name, &mut text);
                out.push((text, data));
            }
        }
        out
    }
}

/// The bootstrap stream of `$MFT` from its first record: the first extent
/// only, so that extension records in the early part of the MFT can be read.
pub fn bootstrap_mft(
    source: &Arc<dyn BlockSource>,
    geo: &Geometry,
    buf: &[u8],
    hdr: &Header,
) -> Result<FileData> {
    let mut c = Collected::default();
    c.scan(buf, hdr, 0, true)?;
    let mut first: Vec<Piece> = c
        .data_pieces
        .into_iter()
        .filter(|p| p.start_vcn == 0)
        .collect();
    first.truncate(1);
    // `assemble` never reads the disk, so any stream will do for the context.
    let probe = FileData::new(
        source.clone(),
        RunList::new(),
        u64::from(geo.cluster_size),
        0,
        0,
    );
    let ctx = Ctx {
        source,
        geo,
        mft: &probe,
    };
    ctx.assemble(first, 0, true)?
        .map(|(fd, ..)| fd)
        .ok_or_else(|| {
            other(
                STRUCTURE,
                Location::Object(0),
                "$MFT has no non-resident $DATA",
            )
        })
}
