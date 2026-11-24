// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Case folding for file names, from the volume's `$UpCase` table.

use std::cmp::Ordering;

use super::le::units;

/// Bytes of a `$UpCase` file: one `u16` for each of the 65536 UTF-16 units.
pub const TABLE_BYTES: usize = 65536 * 2;

/// The folding NTFS indexes names by. Without a usable `$UpCase` file it
/// falls back to the simple Unicode uppercase mapping.
pub struct Upcase {
    table: Option<Box<[u16]>>,
}

impl Upcase {
    /// The built-in folding.
    pub fn fallback() -> Self {
        Self { table: None }
    }

    /// The volume's table, or `None` when `bytes` is not 128 KiB.
    pub fn from_table(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == TABLE_BYTES).then(|| Self {
            table: Some(units(bytes).collect()),
        })
    }

    /// True when the folding is the volume's own table.
    pub fn is_volume_table(&self) -> bool {
        self.table.is_some()
    }

    /// The folded form of one UTF-16 unit.
    pub fn fold(&self, unit: u16) -> u16 {
        match &self.table {
            Some(table) => table.get(usize::from(unit)).copied().unwrap_or(unit),
            None => simple_fold(unit),
        }
    }

    /// Orders two names the way the file name index does: unit by unit
    /// after folding, a prefix before the longer name.
    pub fn compare(&self, a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>) -> Ordering {
        a.map(|u| self.fold(u)).cmp(b.map(|u| self.fold(u)))
    }
}

fn simple_fold(unit: u16) -> u16 {
    if (0x61..=0x7A).contains(&unit) {
        return unit.saturating_sub(0x20);
    }
    if unit < 0x80 {
        return unit;
    }
    let Some(c) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u16::try_from(u32::from(u)).unwrap_or(unit),
        _ => unit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_folds_ascii_and_latin() {
        let up = Upcase::fallback();
        let utf = |s: &str| s.encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            up.compare(utf("abc").into_iter(), utf("ABC").into_iter()),
            Ordering::Equal
        );
        assert_eq!(
            up.compare(utf("caf\u{e9}").into_iter(), utf("CAF\u{c9}").into_iter()),
            Ordering::Equal
        );
        assert_eq!(
            up.compare(utf("ab").into_iter(), utf("abc").into_iter()),
            Ordering::Less
        );
        assert!(Upcase::from_table(&[0u8; 10]).is_none());
    }
}
