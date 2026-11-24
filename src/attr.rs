// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Attributes of an MFT record: the iterator over a record's attributes and
//! readers for the few attribute bodies the reader needs.

use super::le::{self, invalid, other, u8_at, u16_at, u32_at, u64_at};
use atlas_fs_core::error::{Location, Result};
use atlas_fs_core::fs::Timestamp;

/// `$STANDARD_INFORMATION`.
pub const STANDARD_INFORMATION: u32 = 0x10;
/// `$ATTRIBUTE_LIST`.
pub const ATTRIBUTE_LIST: u32 = 0x20;
/// `$FILE_NAME`.
pub const FILE_NAME: u32 = 0x30;
/// `$VOLUME_NAME`.
pub const VOLUME_NAME: u32 = 0x60;
/// `$DATA`.
pub const DATA: u32 = 0x80;
/// `$INDEX_ROOT`.
pub const INDEX_ROOT: u32 = 0x90;
/// `$INDEX_ALLOCATION`.
pub const INDEX_ALLOCATION: u32 = 0xA0;
/// `$REPARSE_POINT`.
pub const REPARSE_POINT: u32 = 0xC0;
/// The end-of-attributes marker.
pub const END: u32 = 0xFFFF_FFFF;

/// Attribute flag: compressed.
pub const FLAG_COMPRESSED: u16 = 0x0001;
/// Attribute flag: encrypted (EFS).
pub const FLAG_ENCRYPTED: u16 = 0x4000;

/// File attribute: read only.
pub const ATTR_READONLY: u32 = 0x1;
/// File attribute: hidden.
pub const ATTR_HIDDEN: u32 = 0x2;
/// File attribute: system.
pub const ATTR_SYSTEM: u32 = 0x4;
/// File attribute: reparse point.
pub const ATTR_REPARSE: u32 = 0x400;
/// `$FILE_NAME` flag: the file is a directory (an index is present).
pub const ATTR_DIRECTORY_INDEX: u32 = 0x1000_0000;

const STRUCTURE: &str = "NTFS attribute";

/// The body of the non-resident attribute header.
#[derive(Debug, Clone, Copy)]
pub struct NonRes<'a> {
    /// First VCN this record's run list covers.
    pub start_vcn: u64,
    /// Last VCN it covers, as stored (-1 for none).
    pub last_vcn: u64,
    /// Allocated bytes (first extent only).
    pub allocated: u64,
    /// Real size in bytes (first extent only).
    pub real: u64,
    /// Initialized size in bytes (first extent only).
    pub init: u64,
    /// Compression unit size: a unit is `2^unit_shift` clusters (0 when the
    /// attribute has no compression unit; first extent only).
    pub unit_shift: u8,
    /// The mapping pairs.
    pub runs: &'a [u8],
}

/// Where an attribute's content is.
#[derive(Debug, Clone, Copy)]
pub enum Body<'a> {
    /// In the record.
    Resident(&'a [u8]),
    /// In clusters.
    NonResident(NonRes<'a>),
}

/// One attribute of a record, borrowing the record's bytes.
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    /// The type code.
    pub ty: u32,
    /// The attribute flags (compressed, encrypted, sparse).
    pub flags: u16,
    /// The name as UTF-16LE bytes; empty when unnamed.
    pub name: &'a [u8],
    /// The content.
    pub body: Body<'a>,
}

impl Attr<'_> {
    /// True when the attribute is unnamed.
    pub fn unnamed(&self) -> bool {
        self.name.is_empty()
    }

    /// True when the (ASCII) `text` is the attribute's name.
    pub fn name_is(&self, text: &str) -> bool {
        le::units(self.name).eq(text.encode_utf16())
    }
}

/// Iterates the attributes of a record's used bytes.
pub struct Attrs<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
    number: u64,
}

impl<'a> Attrs<'a> {
    /// The attributes in `buf[first..used]` of record `number`.
    pub fn new(buf: &'a [u8], first: usize, used: usize, number: u64) -> Self {
        Self {
            buf,
            pos: first,
            end: used.min(buf.len()),
            number,
        }
    }

    fn parse(&self, at: usize, len: usize) -> Result<Attr<'a>> {
        let loc = Location::Object(self.number);
        let a = le::bytes(self.buf, at, len)?;
        let ty = u32_at(a, 0)?;
        let non_resident = u8_at(a, 8)? != 0;
        let name_len = usize::from(u8_at(a, 9)?);
        let name_off = usize::from(u16_at(a, 0x0A)?);
        let flags = u16_at(a, 0x0C)?;
        let name = if name_len == 0 {
            &[][..]
        } else {
            le::bytes(a, name_off, name_len.saturating_mul(2))?
        };
        let body = if non_resident {
            if len < 0x40 {
                return Err(other(STRUCTURE, loc, "non-resident header is truncated"));
            }
            let runs_off = usize::from(u16_at(a, 0x20)?);
            if runs_off < 0x40 || runs_off > len {
                return Err(other(
                    STRUCTURE,
                    loc,
                    "run list offset is outside the attribute",
                ));
            }
            let unit_shift = u8_at(a, 0x22)?;
            if unit_shift > 16 {
                return Err(invalid(
                    STRUCTURE,
                    loc,
                    "compression unit size exponent",
                    u64::from(unit_shift),
                ));
            }
            Body::NonResident(NonRes {
                start_vcn: u64_at(a, 0x10)?,
                last_vcn: u64_at(a, 0x18)?,
                allocated: u64_at(a, 0x28)?,
                real: u64_at(a, 0x30)?,
                init: u64_at(a, 0x38)?,
                unit_shift,
                runs: a.get(runs_off..).unwrap_or(&[]),
            })
        } else {
            if len < 0x18 {
                return Err(other(STRUCTURE, loc, "resident header is truncated"));
            }
            let value_len = le::to_usize(u64::from(u32_at(a, 0x10)?), STRUCTURE, "value length")?;
            let value_off = usize::from(u16_at(a, 0x14)?);
            Body::Resident(le::bytes(a, value_off, value_len)?)
        };
        Ok(Attr {
            ty,
            flags,
            name,
            body,
        })
    }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Result<Attr<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let at = self.pos;
        if at.checked_add(8)? > self.end {
            return None;
        }
        let ty = u32_at(self.buf, at).ok()?;
        if ty == END {
            self.pos = self.end;
            return None;
        }
        let len = match u32_at(self.buf, at.saturating_add(4))
            .and_then(|l| le::to_usize(u64::from(l), STRUCTURE, "attribute length"))
        {
            Ok(l) if l >= 0x10 && at.checked_add(l).is_some_and(|e| e <= self.end) => l,
            Ok(_) => {
                self.pos = self.end;
                return Some(Err(other(
                    STRUCTURE,
                    Location::Object(self.number),
                    "attribute length is outside the record",
                )));
            }
            Err(e) => {
                self.pos = self.end;
                return Some(Err(e));
            }
        };
        // `len >= 0x10`, so the walk always advances.
        self.pos = at.saturating_add(len);
        let parsed = self.parse(at, len);
        if parsed.is_err() {
            self.pos = self.end;
        }
        Some(parsed)
    }
}

/// Converts a FILETIME (100 ns ticks since 1601-01-01) to a timestamp.
/// 0 is "not set"; values outside the timestamp range saturate.
pub fn filetime(ticks: u64) -> Option<Timestamp> {
    const UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;
    if ticks == 0 {
        return None;
    }
    let nanos = i128::from(ticks)
        .saturating_sub(UNIX_EPOCH_TICKS)
        .saturating_mul(100);
    let clamped = i64::try_from(nanos).unwrap_or(if nanos < 0 { i64::MIN } else { i64::MAX });
    Some(Timestamp::from_unix_nanos(clamped))
}

/// `$STANDARD_INFORMATION`.
#[derive(Debug, Clone, Copy)]
pub struct StdInfo {
    /// Creation time.
    pub created: u64,
    /// Content modification time.
    pub modified: u64,
    /// Last access time.
    pub accessed: u64,
    /// File attribute flags.
    pub attrs: u32,
}

impl StdInfo {
    /// Parses the value of a `$STANDARD_INFORMATION` attribute.
    pub fn parse(value: &[u8]) -> Result<Self> {
        Ok(Self {
            created: u64_at(value, 0)?,
            modified: u64_at(value, 8)?,
            accessed: u64_at(value, 0x18)?,
            attrs: u32_at(value, 0x20)?,
        })
    }
}

/// A `$FILE_NAME` value, borrowing its name.
#[derive(Debug, Clone, Copy)]
pub struct FileName<'a> {
    /// Content modification time.
    pub modified: u64,
    /// Real size as last recorded in the index.
    pub size: u64,
    /// File attribute flags.
    pub attrs: u32,
    /// The reparse tag, meaningful only when `attrs` has the reparse bit.
    pub reparse_tag: u32,
    /// 0 POSIX, 1 Win32, 2 DOS, 3 Win32 and DOS.
    pub namespace: u8,
    /// The name as UTF-16LE bytes.
    pub name: &'a [u8],
}

/// Longest name, in UTF-16 units.
pub const MAX_NAME_UNITS: usize = 255;

impl<'a> FileName<'a> {
    /// Parses a `$FILE_NAME` value (also an index key).
    pub fn parse(value: &'a [u8]) -> Result<Self> {
        let units = usize::from(u8_at(value, 0x40)?);
        Ok(Self {
            modified: u64_at(value, 0x10)?,
            size: u64_at(value, 0x30)?,
            attrs: u32_at(value, 0x38)?,
            reparse_tag: u32_at(value, 0x3C)?,
            namespace: u8_at(value, 0x41)?,
            name: le::bytes(value, 0x42, units.saturating_mul(2))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_edges() {
        assert!(filetime(0).is_none());
        // 1970-01-01 and one second later.
        assert_eq!(filetime(116_444_736_000_000_000).unwrap().unix_nanos(), 0);
        assert_eq!(filetime(116_444_736_010_000_000).unwrap().unix_seconds(), 1);
        // Before 1677 and after 2262 saturate instead of overflowing.
        assert_eq!(filetime(1).unwrap().unix_nanos(), i64::MIN);
        assert_eq!(filetime(u64::MAX).unwrap().unix_nanos(), i64::MAX);
    }

    #[test]
    fn attribute_lengths_are_checked() {
        let mut rec = vec![0u8; 64];
        rec[0..4].copy_from_slice(&DATA.to_le_bytes());
        rec[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        let mut it = Attrs::new(&rec, 0, 64, 1);
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }
}
