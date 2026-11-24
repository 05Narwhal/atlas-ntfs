// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Bounds-checked little-endian field reads and error constructors.
//!
//! Every NTFS structure is little-endian and every offset in it comes from
//! the disk, so no field is read except through these.

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};

/// A `Corruption` as an `Error`.
pub fn corrupt(structure: &'static str, location: Location, kind: CorruptKind) -> Error {
    Corruption::new(structure, location, kind).into()
}

/// Damage described by a fixed text.
pub fn other(structure: &'static str, location: Location, what: &'static str) -> Error {
    corrupt(structure, location, CorruptKind::Other(what))
}

/// A field with a value the format does not allow.
pub fn invalid(
    structure: &'static str,
    location: Location,
    field: &'static str,
    value: u64,
) -> Error {
    corrupt(
        structure,
        location,
        CorruptKind::InvalidValue { field, value },
    )
}

/// A traversal that went past its bound.
pub fn limit(structure: &'static str, location: Location, what: &'static str, limit: u64) -> Error {
    corrupt(
        structure,
        location,
        CorruptKind::LimitExceeded { what, limit },
    )
}

/// `value` as a `usize`, or an overflow error naming `field`.
pub fn to_usize(value: u64, structure: &'static str, field: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| {
        corrupt(
            structure,
            Location::Unspecified,
            CorruptKind::Overflow { field },
        )
    })
}

fn truncated(offset: usize, wanted: usize, have: usize) -> Error {
    corrupt(
        "NTFS structure",
        Location::Unspecified,
        CorruptKind::Truncated {
            needed: u64::try_from(offset.saturating_add(wanted)).unwrap_or(u64::MAX),
            available: u64::try_from(have).unwrap_or(u64::MAX),
        },
    )
}

/// `len` bytes at `offset`, or a truncation error.
pub fn bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    offset
        .checked_add(len)
        .and_then(|end| buf.get(offset..end))
        .ok_or_else(|| truncated(offset, len, buf.len()))
}

/// The byte at `offset`.
pub fn u8_at(buf: &[u8], offset: usize) -> Result<u8> {
    buf.get(offset)
        .copied()
        .ok_or_else(|| truncated(offset, 1, buf.len()))
}

/// The `u16` at `offset`.
pub fn u16_at(buf: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes(buf, offset, 2)?
        .try_into()
        .map_err(|_| truncated(offset, 2, buf.len()))?;
    Ok(u16::from_le_bytes(raw))
}

/// The `u32` at `offset`.
pub fn u32_at(buf: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes(buf, offset, 4)?
        .try_into()
        .map_err(|_| truncated(offset, 4, buf.len()))?;
    Ok(u32::from_le_bytes(raw))
}

/// The `u64` at `offset`.
pub fn u64_at(buf: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes(buf, offset, 8)?
        .try_into()
        .map_err(|_| truncated(offset, 8, buf.len()))?;
    Ok(u64::from_le_bytes(raw))
}

/// The little-endian unsigned integer in the first 8 (at most) of `bytes`.
pub fn uint(bytes: &[u8]) -> u64 {
    let mut raw = [0u8; 8];
    for (dst, src) in raw.iter_mut().zip(bytes) {
        *dst = *src;
    }
    u64::from_le_bytes(raw)
}

/// The little-endian two's complement integer in the first 8 (at most) of `bytes`.
pub fn int(bytes: &[u8]) -> i64 {
    let fill = if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        0xFF
    } else {
        0
    };
    let mut raw = [fill; 8];
    for (dst, src) in raw.iter_mut().zip(bytes) {
        *dst = *src;
    }
    i64::from_le_bytes(raw)
}

/// The UTF-16 code units of little-endian `bytes` (a trailing odd byte is dropped).
pub fn units(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
}

/// Appends the text of the UTF-16LE `bytes` to `out`; a lone surrogate
/// becomes U+FFFD.
pub fn decode_name(bytes: &[u8], out: &mut String) {
    out.extend(char::decode_utf16(units(bytes)).map(|r| r.unwrap_or('\u{FFFD}')));
}
