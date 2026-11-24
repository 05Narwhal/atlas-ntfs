// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The NTFS boot sector and the geometry it gives.
//!
//! Every field is checked before any byte offset is made from it, with
//! checked arithmetic throughout.

use super::le::{self, invalid, other, u8_at, u16_at, u64_at};
use super::{MAX_CLUSTER_BYTES, MAX_INDEX_BLOCK, MAX_RECORD};
use atlas_fs_core::error::{CorruptKind, Corruption, Location, Result};

/// Bytes of the boot sector this module reads.
pub const BOOT_LEN: usize = 512;

const STRUCTURE: &str = "NTFS boot sector";

/// What the boot sector says, in bytes and clusters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    /// Bytes per sector (512 to 4096).
    pub bytes_per_sector: u32,
    /// Bytes per cluster.
    pub cluster_size: u32,
    /// Clusters on the volume (whole clusters of the sector count).
    pub cluster_count: u64,
    /// Bytes of the volume as the boot sector counts them.
    pub volume_bytes: u64,
    /// Cluster where `$MFT` starts.
    pub mft_lcn: u64,
    /// Cluster where the `$MFTMirr` copy of the first records starts.
    pub mirror_lcn: u64,
    /// Bytes per MFT record.
    pub record_size: u32,
    /// Bytes per index block the boot sector announces (the index root's own
    /// value is what a walk uses).
    pub index_block_size: u32,
    /// Volume serial number.
    pub serial: u64,
}

/// Bytes of a size given as a count of clusters (positive) or as a power
/// of two exponent (negative), as the record and index size fields are.
fn size_field(raw: u8, cluster_size: u32, field: &'static str, max: u32) -> Result<u32> {
    let signed = i8::from_le_bytes([raw]);
    let bytes = if signed > 0 {
        u32::try_from(signed)
            .ok()
            .and_then(|n| n.checked_mul(cluster_size))
    } else {
        let exp = u32::from(signed.unsigned_abs());
        1u32.checked_shl(exp).filter(|_| exp < 32)
    };
    match bytes {
        Some(b) if (512..=max).contains(&b) && b.is_power_of_two() => Ok(b),
        _ => Err(invalid(
            STRUCTURE,
            Location::Unspecified,
            field,
            u64::from(raw),
        )),
    }
}

/// Parses the boot sector (at least [`BOOT_LEN`] bytes).
pub fn parse(sector: &[u8]) -> Result<Geometry> {
    if sector.len() < BOOT_LEN {
        return Err(Corruption::new(
            STRUCTURE,
            Location::Byte(0),
            CorruptKind::Truncated {
                needed: BOOT_LEN as u64,
                available: u64::try_from(sector.len()).unwrap_or(u64::MAX),
            },
        )
        .into());
    }
    let oem = le::bytes(sector, 3, 8)?;
    if oem != b"NTFS    " {
        return Err(Corruption::new(
            STRUCTURE,
            Location::Byte(3),
            CorruptKind::BadSignature {
                expected: u64::from_le_bytes(*b"NTFS    "),
                found: oem.try_into().map_or(0, u64::from_le_bytes),
            },
        )
        .into());
    }
    let sig = u16_at(sector, 510)?;
    if sig != 0xAA55 {
        return Err(Corruption::new(
            STRUCTURE,
            Location::Byte(510),
            CorruptKind::BadSignature {
                expected: 0xAA55,
                found: u64::from(sig),
            },
        )
        .into());
    }
    let bps = u32::from(u16_at(sector, 0x0B)?);
    if !(512..=4096).contains(&bps) || !bps.is_power_of_two() {
        return Err(invalid(
            STRUCTURE,
            Location::Byte(0x0B),
            "bytes per sector",
            u64::from(bps),
        ));
    }
    let raw_spc = u8_at(sector, 0x0D)?;
    let spc: u64 = match raw_spc {
        0 => 0,
        1..=0x80 => u64::from(raw_spc),
        // 0x81..=0xFF: 2^(256 - n) sectors.
        n => 1u64
            .checked_shl(256u32.saturating_sub(u32::from(n)))
            .unwrap_or(0),
    };
    if spc == 0 || !spc.is_power_of_two() {
        return Err(invalid(
            STRUCTURE,
            Location::Byte(0x0D),
            "sectors per cluster",
            u64::from(raw_spc),
        ));
    }
    let cluster_size = u64::from(bps)
        .checked_mul(spc)
        .filter(|&c| c <= u64::from(MAX_CLUSTER_BYTES))
        .and_then(|c| u32::try_from(c).ok())
        .ok_or_else(|| {
            invalid(
                STRUCTURE,
                Location::Byte(0x0D),
                "sectors per cluster",
                u64::from(raw_spc),
            )
        })?;
    let total_sectors = u64_at(sector, 0x28)?;
    let cluster_count = total_sectors.checked_div(spc).unwrap_or(0);
    let volume_bytes = total_sectors.checked_mul(u64::from(bps));
    let Some(volume_bytes) = volume_bytes.filter(|_| cluster_count > 0) else {
        return Err(invalid(
            STRUCTURE,
            Location::Byte(0x28),
            "total sectors",
            total_sectors,
        ));
    };
    let mft_lcn = u64_at(sector, 0x30)?;
    if mft_lcn >= cluster_count {
        return Err(other(
            STRUCTURE,
            Location::Byte(0x30),
            "$MFT start cluster is outside the volume",
        ));
    }
    // A mirror outside the volume is just not usable.
    let mirror_lcn = u64_at(sector, 0x38)?;
    let record_size = size_field(
        u8_at(sector, 0x40)?,
        cluster_size,
        "clusters per file record",
        MAX_RECORD,
    )?;
    let index_block_size = size_field(
        u8_at(sector, 0x44)?,
        cluster_size,
        "clusters per index block",
        MAX_INDEX_BLOCK,
    )?;
    Ok(Geometry {
        bytes_per_sector: bps,
        cluster_size,
        cluster_count,
        volume_bytes,
        mft_lcn,
        mirror_lcn,
        record_size,
        index_block_size,
        serial: u64_at(sector, 0x48)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sector() -> Vec<u8> {
        let mut s = vec![0u8; BOOT_LEN];
        s[3..11].copy_from_slice(b"NTFS    ");
        s[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        s[0x0D] = 8;
        s[0x28..0x30].copy_from_slice(&1000u64.to_le_bytes());
        s[0x30..0x38].copy_from_slice(&4u64.to_le_bytes());
        s[0x38..0x40].copy_from_slice(&50u64.to_le_bytes());
        s[0x40] = 0xF6; // 2^10 = 1024
        s[0x44] = 1;
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn parses_and_rejects() {
        let g = parse(&sector()).unwrap();
        assert_eq!(g.cluster_size, 4096);
        assert_eq!(g.record_size, 1024);
        assert_eq!(g.index_block_size, 4096);
        assert_eq!(g.cluster_count, 125);
        let mut s = sector();
        s[0x0D] = 0xF9; // 2^7 sectors = 64 KiB clusters
        assert_eq!(parse(&s).unwrap().cluster_size, 65536);
        for (at, value) in [
            (0x0D, 3u8),
            (0x0D, 0),
            (0x40, 0),
            (0x40, 0xE0),
            (0x44, 0x7F),
        ] {
            let mut s = sector();
            s[at] = value;
            assert!(parse(&s).is_err(), "{at:#x}={value}");
        }
        let mut s = sector();
        s[0x30..0x38].copy_from_slice(&125u64.to_le_bytes());
        assert!(parse(&s).is_err());
        assert!(parse(&sector()[..100]).is_err());
    }
}
