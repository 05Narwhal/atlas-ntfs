// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! `$REPARSE_POINT` values: the two tags that are links.
//!
//! A symbolic link (`IO_REPARSE_TAG_SYMLINK`) and a junction
//! (`IO_REPARSE_TAG_MOUNT_POINT`) are shown as links and never followed: their
//! target is a path on the machine that made them. Every other tag (cloud
//! placeholders, deduplication, WSL special files) leaves the file as it is.

use super::le::{self, u16_at, u32_at};
use atlas_fs_core::error::{Location, Result};

/// A symbolic link.
pub const TAG_SYMLINK: u32 = 0xA000_000C;
/// A junction (mount point).
pub const TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// The most a reparse value holds (the format's own limit is 16 KiB).
pub const MAX_VALUE: usize = 16 * 1024;

const STRUCTURE: &str = "NTFS reparse point";

/// True for the tags shown as links.
pub const fn is_link(tag: u32) -> bool {
    tag == TAG_SYMLINK || tag == TAG_MOUNT_POINT
}

/// The target a link's reparse `value` stores, or `None` for any other tag.
///
/// The print name is preferred; the substitute name has its NT prefix
/// (`\??\`) removed. A malformed value is an error, not a panic.
pub fn target(value: &[u8], record: u64) -> Result<Option<String>> {
    let tag = u32_at(value, 0)?;
    if !is_link(tag) {
        return Ok(None);
    }
    // Header: tag, data length, reserved. Then four u16 offsets and lengths
    // (substitute, print), a u32 of flags for a symbolic link only, and the
    // names' buffer.
    let buffer: usize = if tag == TAG_SYMLINK { 20 } else { 16 };
    let part = |at: usize| -> Result<Option<String>> {
        let off = usize::from(u16_at(value, at)?);
        let len = usize::from(u16_at(value, at.saturating_add(2))?);
        if len == 0 {
            return Ok(None);
        }
        let start = buffer.saturating_add(off);
        let bytes = le::bytes(value, start, len)
            .map_err(|_| le::other(STRUCTURE, Location::Object(record), "name is outside"))?;
        let mut text = String::new();
        le::decode_name(bytes, &mut text);
        Ok(Some(text))
    };
    let print = part(12)?;
    let target = match print {
        Some(p) => p,
        None => match part(8)? {
            Some(s) => s.strip_prefix("\\??\\").map_or(s.clone(), str::to_owned),
            None => return Ok(None),
        },
    };
    Ok(Some(target))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A symbolic link reparse value.
    pub fn symlink(subst: &str, print: &str) -> Vec<u8> {
        let units = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let (s, p) = (units(subst), units(print));
        let mut v = Vec::new();
        v.extend_from_slice(&TAG_SYMLINK.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&u16::try_from(s.len()).unwrap().to_le_bytes());
        v.extend_from_slice(&u16::try_from(s.len()).unwrap().to_le_bytes());
        v.extend_from_slice(&u16::try_from(p.len()).unwrap().to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&s);
        v.extend_from_slice(&p);
        v
    }

    #[test]
    fn a_symlink_gives_its_print_name_or_the_substitute_name() {
        let v = symlink("\\??\\C:\\data", "C:\\data");
        assert_eq!(target(&v, 40).unwrap().as_deref(), Some("C:\\data"));
        let mut only_subst = symlink("\\??\\C:\\data", "");
        only_subst[14..16].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            target(&only_subst, 40).unwrap().as_deref(),
            Some("C:\\data")
        );
    }

    #[test]
    fn other_tags_are_not_links_and_damage_is_an_error() {
        let mut cloud = symlink("a", "a");
        cloud[0..4].copy_from_slice(&0x9000_001Au32.to_le_bytes());
        assert_eq!(target(&cloud, 40).unwrap(), None);
        let mut bad = symlink("abc", "abc");
        bad[14..16].copy_from_slice(&0xFFF0u16.to_le_bytes());
        assert!(target(&bad, 40).is_err());
        assert!(target(&[1, 2], 40).is_err());
    }
}
