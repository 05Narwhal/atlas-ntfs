// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The reader for LZNT1-compressed files.
//!
//! The stream is cut into compression units of `2^n` clusters (the exponent
//! is in the attribute header, normally 4). For each unit the run list says
//! how it is stored: all holes is zeros; every cluster allocated is the
//! unit's bytes as they are; an allocated prefix followed by holes is LZNT1
//! chunks that decompress to the unit (zero-padded). One decompressed unit is
//! cached, so a sequential read decompresses each unit once.

use std::sync::{Arc, Mutex, PoisonError};

use super::le::{invalid, limit, other};
use super::lznt1::decompress_chunks;
use super::runs::FileData;
use atlas_fs_core::error::{Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};

const STRUCTURE: &str = "NTFS compressed file";

/// Largest compression unit accepted, in bytes.
pub const MAX_UNIT_BYTES: u64 = 1 << 20;

/// The last unit read: its number, its bytes and a scratch buffer for the
/// compressed form.
struct Cache {
    unit: Option<u64>,
    data: Vec<u8>,
    raw: Vec<u8>,
}

/// A compressed non-resident stream as a source of its real bytes.
pub struct Compressed {
    file: Arc<FileData>,
    cluster_size: u64,
    unit_clusters: u64,
    unit_bytes: usize,
    cache: Mutex<Cache>,
}

impl Compressed {
    /// Wraps `file`, whose compression units are `2^unit_shift` clusters.
    /// Fails for an exponent of 0 or one that makes a unit larger than 1 MiB.
    pub fn new(file: Arc<FileData>, unit_shift: u8) -> Result<Self> {
        let cluster_size = file.cluster_size();
        if unit_shift == 0 || unit_shift > 16 {
            return Err(invalid(
                STRUCTURE,
                Location::Unspecified,
                "compression unit size exponent",
                u64::from(unit_shift),
            ));
        }
        let unit_clusters = 1u64 << unit_shift;
        let unit_bytes = unit_clusters
            .checked_mul(cluster_size)
            .filter(|&b| b > 0 && b <= MAX_UNIT_BYTES)
            .ok_or_else(|| {
                limit(
                    STRUCTURE,
                    Location::Unspecified,
                    "compression unit bytes",
                    MAX_UNIT_BYTES,
                )
            })?;
        let unit_bytes = usize::try_from(unit_bytes).map_err(|_| {
            limit(
                STRUCTURE,
                Location::Unspecified,
                "compression unit bytes",
                MAX_UNIT_BYTES,
            )
        })?;
        Ok(Self {
            file,
            cluster_size,
            unit_clusters,
            unit_bytes,
            cache: Mutex::new(Cache {
                unit: None,
                data: Vec::new(),
                raw: Vec::new(),
            }),
        })
    }

    /// Fills `cache.data` with the bytes of `unit`.
    fn load(&self, cache: &mut Cache, unit: u64) -> Result<()> {
        if cache.unit == Some(unit) && cache.data.len() == self.unit_bytes {
            return Ok(());
        }
        cache.unit = None;
        cache.data.clear();
        cache.data.resize(self.unit_bytes, 0);
        let at = unit.saturating_mul(u64::try_from(self.unit_bytes).unwrap_or(u64::MAX));
        let damaged = |what: &'static str| other(STRUCTURE, Location::Byte(at), what);

        let runs = self.file.runs();
        let first = unit.saturating_mul(self.unit_clusters);
        let want_end = first.saturating_add(self.unit_clusters);
        let end = want_end.min(runs.clusters());
        // Clusters past the mapped part count as holes.
        let mut hole = end < want_end;
        let mut allocated = 0u64;
        let mut vcn = first;
        while vcn < end {
            let run = runs
                .find(vcn)
                .ok_or_else(|| damaged("no run covers part of a compression unit"))?;
            let run_end = run.vcn.saturating_add(run.len).min(end);
            let seg = run_end.saturating_sub(vcn);
            if seg == 0 {
                return Err(damaged("empty run in a compression unit"));
            }
            if run.lcn.is_some() {
                if hole {
                    return Err(damaged("allocated clusters follow a hole in a unit"));
                }
                allocated = allocated.saturating_add(seg);
            } else {
                hole = true;
            }
            vcn = run_end;
        }

        let from = first.saturating_mul(self.cluster_size);
        if allocated == 0 {
            // All zeros.
        } else if allocated == self.unit_clusters {
            self.file.read_mapped(from, &mut cache.data)?;
        } else {
            let bytes = usize::try_from(allocated.saturating_mul(self.cluster_size))
                .map_err(|_| damaged("compressed unit is too large"))?;
            cache.raw.clear();
            cache.raw.resize(bytes, 0);
            self.file.read_mapped(from, &mut cache.raw)?;
            decompress_chunks(&cache.raw, &mut cache.data).map_err(damaged)?;
        }
        cache.unit = Some(unit);
        Ok(())
    }
}

impl BlockSource for Compressed {
    fn len(&self) -> u64 {
        self.file.len()
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len())?;
        let unit_bytes = u64::try_from(self.unit_bytes).unwrap_or(u64::MAX);
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            let unit = pos.checked_div(unit_bytes).unwrap_or(0);
            let within = usize::try_from(pos.checked_rem(unit_bytes).unwrap_or(0)).unwrap_or(0);
            self.load(&mut cache, unit)?;
            let (_, rest) = buf.split_at_mut(done);
            let n = self.unit_bytes.saturating_sub(within).min(rest.len());
            let src = cache
                .data
                .get(within..within.saturating_add(n))
                .filter(|s| !s.is_empty())
                .ok_or_else(|| other(STRUCTURE, Location::Byte(pos), "read past the unit"))?;
            let (dst, _) = rest.split_at_mut(n);
            dst.copy_from_slice(src);
            done = done.saturating_add(n);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lznt1::tests::{Tok, compressed_chunk};
    use crate::mount;
    use crate::runs::RunList;
    use crate::test_volume as tv;
    use atlas_fs_core::fs::{FileSystem, NodeId, Stream};
    use atlas_fs_core::io::block::MemSource;

    const CS: usize = 512;

    /// A stream of 3 units of 4 clusters (512-byte clusters): unit 0 is
    /// compressed into 2 clusters (at cluster 1), unit 1 is a hole, unit 2 is
    /// stored raw (at cluster 8). The file is 2 * 2048 + 1000 bytes.
    fn stream(damage: bool) -> (Compressed, Vec<u8>) {
        let mut disk = vec![0u8; 16 * CS];
        // One chunk of 2048 bytes: a literal and a long reference.
        let chunk = compressed_chunk(&[Tok::Lit(b'q'), Tok::Ref { disp: 1, len: 2047 }]);
        let mut expected = vec![b'q'; 2048];
        disk[CS..CS + chunk.len()].copy_from_slice(&chunk);
        if damage {
            // A reference before the start of the chunk.
            disk[CS + 2] = 0x01;
        }
        for i in 0..2048usize {
            disk[8 * CS + i] = u8::try_from(i % 241).unwrap();
        }
        expected.extend(vec![0u8; 2048]);
        expected.extend((0..1000usize).map(|i| u8::try_from(i % 241).unwrap()));
        let pairs = tv::mapping_pairs(&[(2, Some(1)), (6, None), (4, Some(8))]);
        let mut list = RunList::new();
        list.extend(0, &pairs, 16, CS as u64, 1).unwrap();
        let file = FileData::new(Arc::new(MemSource::new(disk)), list, CS as u64, 5096, 5096);
        (Compressed::new(Arc::new(file), 2).unwrap(), expected)
    }

    #[test]
    fn reads_compressed_hole_and_raw_units_in_any_piece_size() {
        let (c, expected) = stream(false);
        assert_eq!(c.len(), 5096);
        let mut all = vec![0u8; 5096];
        c.read_at(0, &mut all).unwrap();
        assert_eq!(all, expected);
        // Small reads across unit edges, and the empty read at the end.
        for step in [1usize, 7, 333, 2048] {
            let mut got = Vec::new();
            let mut at = 0usize;
            while at < expected.len() {
                let n = step.min(expected.len() - at);
                let mut piece = vec![0u8; n];
                c.read_at(at as u64, &mut piece).unwrap();
                got.extend_from_slice(&piece);
                at += n;
            }
            assert_eq!(got, expected, "step {step}");
        }
        c.read_at(5096, &mut []).unwrap();
        assert!(c.read_at(5090, &mut [0u8; 7]).is_err());
    }

    #[test]
    fn a_damaged_unit_fails_the_read_and_a_huge_unit_fails_the_open() {
        let (c, _) = stream(true);
        let mut buf = [0u8; 16];
        let err = c.read_at(0, &mut buf).unwrap_err().to_string();
        assert!(err.contains("NTFS compressed file"), "{err}");
        // Other units still read.
        c.read_at(2048, &mut buf).unwrap();
        // 2^16 clusters of 512 bytes is 32 MiB.
        let (ok, _) = stream(false);
        assert!(Compressed::new(ok.file.clone(), 16).is_err());
        assert!(Compressed::new(ok.file.clone(), 0).is_err());
        assert!(Compressed::new(ok.file.clone(), 17).is_err());
    }

    #[test]
    fn a_compressed_file_reads_through_a_mounted_volume() {
        let fs = mount(Arc::new(MemSource::new(tv::compressed().image))).unwrap();
        let node = fs.lookup(fs.root(), "alpha.txt").unwrap().unwrap();
        assert_eq!(node, NodeId(tv::R_ALPHA));
        let src = fs.open(node, Stream::Data).unwrap();
        let expected = tv::compressed_expected();
        assert_eq!(src.len(), u64::try_from(expected.len()).unwrap());
        let mut got = vec![0u8; expected.len()];
        src.read_at(0, &mut got).unwrap();
        assert!(got == expected, "compressed content differs");
        // A read in the middle of the hole and across the last two units.
        let mut mid = vec![0u8; 5000];
        src.read_at(20_000, &mut mid).unwrap();
        assert!(mid == expected[20_000..25_000]);
    }
}
