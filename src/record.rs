// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! MFT records and the update sequence fixups every multi-sector NTFS
//! structure carries.
//!
//! The last two bytes of every 512-byte stride of a record or index block
//! are replaced on disk by the update sequence number; the real bytes are in
//! the update sequence array in the header. A stride whose last two bytes
//! are not the number was torn or damaged.

use super::le::{self, invalid, other, u16_at, u32_at, u64_at};
use atlas_fs_core::error::{CorruptKind, Corruption, Location, Result};

/// Bytes of one fixup stride. Always 512, whatever the sector size.
pub const STRIDE: usize = 512;
/// `FILE`.
pub const FILE_MAGIC: u32 = u32::from_le_bytes(*b"FILE");
/// Record flag: the record is in use.
pub const IN_USE: u16 = 1;
/// Record flag: the record is a directory.
pub const IS_DIR: u16 = 2;
/// Low 48 bits of a file reference are the record number.
pub const REF_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

const STRUCTURE: &str = "NTFS record";

/// Checks the update sequence array of `buf` and restores the bytes it
/// replaced. The header's array offset must be at least `header_min`.
pub fn apply_fixups(
    buf: &mut [u8],
    header_min: usize,
    structure: &'static str,
    location: Location,
) -> Result<()> {
    if buf.len() < STRIDE || !buf.len().is_multiple_of(STRIDE) {
        return Err(other(structure, location, "size is not a multiple of 512"));
    }
    let offset = usize::from(u16_at(buf, 4)?);
    let count = usize::from(u16_at(buf, 6)?);
    let strides = buf.len() / STRIDE;
    let array_end = count
        .checked_mul(2)
        .and_then(|n| n.checked_add(offset))
        .ok_or_else(|| other(structure, location, "update sequence array overflows"))?;
    // The array holds the number and one entry per stride, and lies inside the first stride.
    if count != strides.saturating_add(1) || offset < header_min || array_end > STRIDE - 2 {
        return Err(invalid(
            structure,
            location,
            "update sequence array",
            u64::try_from(count).unwrap_or(u64::MAX),
        ));
    }
    let usn = u16_at(buf, offset)?;
    for i in 1..count {
        let saved = u16_at(buf, offset.saturating_add(i.saturating_mul(2)))?;
        let at = i.saturating_mul(STRIDE).saturating_sub(2);
        if u16_at(buf, at)? != usn {
            return Err(Corruption::new(
                structure,
                location,
                CorruptKind::InvalidValue {
                    field: "update sequence number at the end of a sector",
                    value: u64::try_from(at).unwrap_or(u64::MAX),
                },
            )
            .into());
        }
        if let Some(dst) = buf.get_mut(at..at.saturating_add(2)) {
            dst.copy_from_slice(&saved.to_le_bytes());
        }
    }
    Ok(())
}

/// What the record header says.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// `IN_USE` and `IS_DIR`.
    pub flags: u16,
    /// Offset of the first attribute.
    pub first_attr: usize,
    /// End of the used part of the record.
    pub used: usize,
    /// File reference of the base record; 0 for a base record.
    pub base: u64,
}

impl Header {
    /// True for a base record (not an extension record of another file).
    pub fn is_base(&self) -> bool {
        self.base & REF_MASK == 0
    }
}

/// Checks the `FILE` signature, applies the fixups and validates the
/// offsets the header gives. `number` is for messages only.
pub fn parse(buf: &mut [u8], number: u64) -> Result<Header> {
    let at = Location::Object(number);
    let magic = u32_at(buf, 0)?;
    if magic != FILE_MAGIC {
        return Err(Corruption::new(
            STRUCTURE,
            at,
            CorruptKind::BadSignature {
                expected: u64::from(FILE_MAGIC),
                found: u64::from(magic),
            },
        )
        .into());
    }
    apply_fixups(buf, 0x2A, STRUCTURE, at)?;
    let first_attr = usize::from(u16_at(buf, 0x14)?);
    let flags = u16_at(buf, 0x16)?;
    let used = le::to_usize(u64::from(u32_at(buf, 0x18)?), STRUCTURE, "bytes in use")?;
    if used > buf.len() || first_attr < 0x18 || first_attr.saturating_add(4) > used {
        return Err(invalid(
            STRUCTURE,
            at,
            "bytes in use",
            u64::try_from(used).unwrap_or(u64::MAX),
        ));
    }
    Ok(Header {
        flags,
        first_attr,
        used,
        base: u64_at(buf, 0x20)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        let count = u16::try_from(len / STRIDE + 1).unwrap();
        b[6..8].copy_from_slice(&count.to_le_bytes());
        b[0x30] = 0x77;
        b[0x31] = 0x01;
        for i in 1..=len / STRIDE {
            b[0x30 + 2 * i] = i as u8;
            b[i * STRIDE - 2] = 0x77;
            b[i * STRIDE - 1] = 0x01;
        }
        b
    }

    #[test]
    fn fixups_restore_and_reject() {
        let mut b = block(1024);
        apply_fixups(&mut b, 0x2A, "t", Location::Unspecified).unwrap();
        assert_eq!((b[510], b[511], b[1022], b[1023]), (1, 0, 2, 0));
        let mut b = block(1024);
        b[1022] = 0;
        assert!(apply_fixups(&mut b, 0x2A, "t", Location::Unspecified).is_err());
        let mut b = block(1024);
        b[6] = 9; // wrong count
        assert!(apply_fixups(&mut b, 0x2A, "t", Location::Unspecified).is_err());
        let mut b = block(1024);
        b[4] = 0xFF; // array offset past the first stride
        assert!(apply_fixups(&mut b, 0x2A, "t", Location::Unspecified).is_err());
    }
}
