// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Data runs (mapping pairs) and the reader that follows them.

use std::sync::Arc;

use super::MAX_RUNS;
use super::le::{self, invalid, limit, other};
use atlas_fs_core::error::{CorruptKind, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};

const STRUCTURE: &str = "NTFS data runs";

/// A run of clusters: `len` clusters starting at virtual cluster `vcn`, at
/// logical cluster `lcn`, or a hole of zeros when `lcn` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// First virtual cluster of the run.
    pub vcn: u64,
    /// Clusters in the run; never 0.
    pub len: u64,
    /// First logical cluster; `None` for a sparse run.
    pub lcn: Option<u64>,
}

/// The decoded run list of one attribute: contiguous, in VCN order.
#[derive(Debug, Clone, Default)]
pub struct RunList {
    runs: Vec<Run>,
    clusters: u64,
}

impl RunList {
    /// An empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clusters the runs cover.
    pub fn clusters(&self) -> u64 {
        self.clusters
    }

    /// The runs in VCN order.
    pub fn runs(&self) -> &[Run] {
        &self.runs
    }

    /// The run holding `vcn`.
    pub fn find(&self, vcn: u64) -> Option<&Run> {
        let i = self
            .runs
            .partition_point(|r| r.vcn.saturating_add(r.len) <= vcn);
        self.runs.get(i).filter(|r| r.vcn <= vcn)
    }

    /// Decodes `pairs` and appends the runs. `start_vcn` must continue the
    /// list exactly; every real run must lie inside the volume
    /// (`volume_clusters`), and the whole list must fit `u64` bytes.
    pub fn extend(
        &mut self,
        start_vcn: u64,
        pairs: &[u8],
        volume_clusters: u64,
        cluster_size: u64,
        record: u64,
    ) -> Result<()> {
        let loc = Location::Object(record);
        if start_vcn != self.clusters {
            return Err(invalid(
                STRUCTURE,
                loc,
                "starting VCN does not continue the previous extent",
                start_vcn,
            ));
        }
        let mut pos = 0usize;
        let mut lcn = 0u64;
        loop {
            let header = le::u8_at(pairs, pos).unwrap_or(0);
            if header == 0 {
                break;
            }
            pos = pos.saturating_add(1);
            let len_bytes = usize::from(header & 0x0F);
            let off_bytes = usize::from(header >> 4);
            if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 {
                return Err(invalid(STRUCTURE, loc, "run header", u64::from(header)));
            }
            let len = le::uint(le::bytes(pairs, pos, len_bytes)?);
            pos = pos.saturating_add(len_bytes);
            let lcn_field = if off_bytes == 0 {
                None
            } else {
                let delta = le::int(le::bytes(pairs, pos, off_bytes)?);
                pos = pos.saturating_add(off_bytes);
                lcn = lcn
                    .checked_add_signed(delta)
                    .ok_or_else(|| other(STRUCTURE, loc, "run starts before the first cluster"))?;
                Some(lcn)
            };
            if len == 0 {
                return Err(invalid(STRUCTURE, loc, "run length", 0));
            }
            if let Some(first) = lcn_field
                && first
                    .checked_add(len)
                    .is_none_or(|end| end > volume_clusters)
            {
                return Err(le::corrupt(
                    STRUCTURE,
                    loc,
                    CorruptKind::OutOfRange {
                        field: "run end cluster",
                        value: first.saturating_add(len),
                        limit_name: "volume clusters",
                        limit: volume_clusters,
                    },
                ));
            }
            if self.runs.len() >= MAX_RUNS {
                return Err(limit(
                    STRUCTURE,
                    loc,
                    "runs in one attribute",
                    MAX_RUNS as u64,
                ));
            }
            let vcn = self.clusters;
            self.clusters = vcn
                .checked_add(len)
                .filter(|c| c.checked_mul(cluster_size).is_some())
                .ok_or_else(|| {
                    le::corrupt(
                        STRUCTURE,
                        loc,
                        CorruptKind::Overflow {
                            field: "clusters in the attribute",
                        },
                    )
                })?;
            self.runs.push(Run {
                vcn,
                len,
                lcn: lcn_field,
            });
        }
        Ok(())
    }
}

/// A non-resident stream: its run list, the cluster size and the sizes.
/// Bytes at and after `init` read as zeros; holes read as zeros.
pub struct FileData {
    source: Arc<dyn BlockSource>,
    runs: RunList,
    cluster_size: u64,
    size: u64,
    init: u64,
}

impl FileData {
    /// A stream of `size` bytes whose first `init` bytes are on disk.
    pub fn new(
        source: Arc<dyn BlockSource>,
        runs: RunList,
        cluster_size: u64,
        size: u64,
        init: u64,
    ) -> Self {
        Self {
            source,
            runs,
            cluster_size,
            size,
            init: init.min(size),
        }
    }

    /// The run list.
    pub fn runs(&self) -> &RunList {
        &self.runs
    }

    /// The cluster size the run list counts in.
    pub fn cluster_size(&self) -> u64 {
        self.cluster_size
    }
}

impl FileData {
    /// Fills `buf` from the clusters the run list maps, ignoring the
    /// initialized size (a compressed stream's units are read this way).
    pub fn read_mapped(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mapped = self.runs.clusters().saturating_mul(self.cluster_size);
        check_range(offset, buf.len(), mapped)?;
        self.read_inner(offset, buf, u64::MAX)
    }

    /// Reads `buf` at `offset`; bytes at and after `init` are zeros.
    fn read_inner(&self, offset: u64, buf: &mut [u8], init: u64) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let (_, rest) = buf.split_at_mut(done);
            let pos = offset.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            if pos >= init {
                rest.fill(0);
                return Ok(());
            }
            let want = u64::try_from(rest.len()).unwrap_or(u64::MAX);
            let limit = init.saturating_sub(pos).min(want);
            let vcn = pos.checked_div(self.cluster_size).unwrap_or(0);
            let run = self.runs.find(vcn).ok_or_else(|| {
                other(
                    STRUCTURE,
                    Location::Byte(pos),
                    "no run covers this part of the stream",
                )
            })?;
            // Both products were checked when the list was built.
            let run_start = run.vcn.saturating_mul(self.cluster_size);
            let into = pos.saturating_sub(run_start);
            let avail = run
                .len
                .saturating_mul(self.cluster_size)
                .saturating_sub(into);
            let n = limit.min(avail);
            let n_usize = usize::try_from(n).unwrap_or(0);
            if n_usize == 0 {
                return Err(other(STRUCTURE, Location::Byte(pos), "empty run"));
            }
            let (chunk, _) = rest.split_at_mut(n_usize);
            match run.lcn {
                None => chunk.fill(0),
                Some(lcn) => {
                    let at = lcn.saturating_mul(self.cluster_size).saturating_add(into);
                    self.source.read_at(at, chunk)?;
                }
            }
            done = done.saturating_add(n_usize);
        }
        Ok(())
    }
}

impl BlockSource for FileData {
    fn len(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        self.read_inner(offset, buf, self.init)
    }
}

/// A resident stream held in memory.
pub struct Resident(pub Vec<u8>);

impl BlockSource for Resident {
    fn len(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len())?;
        let start = le::to_usize(offset, STRUCTURE, "offset")?;
        let src = le::bytes(&self.0, start, buf.len())?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    #[test]
    fn decodes_signed_offsets_and_holes() {
        // 3 clusters at 0x10, a 2-cluster hole, 1 cluster back at 0x0E (offset -2).
        let pairs = [0x11, 3, 0x10, 0x01, 2, 0x11, 1, 0xFE, 0];
        let mut list = RunList::new();
        list.extend(0, &pairs, 100, 512, 1).unwrap();
        assert_eq!(
            list.runs(),
            &[
                Run {
                    vcn: 0,
                    len: 3,
                    lcn: Some(0x10)
                },
                Run {
                    vcn: 3,
                    len: 2,
                    lcn: None
                },
                Run {
                    vcn: 5,
                    len: 1,
                    lcn: Some(0x0E)
                },
            ]
        );
        assert_eq!(list.clusters(), 6);
        assert_eq!(list.find(4).unwrap().lcn, None);
        assert!(list.find(6).is_none());
    }

    #[test]
    fn hostile_run_lists_fail() {
        let cases: [&[u8]; 5] = [
            &[0x11, 3, 0x7F, 0], // past the volume (100 clusters)
            &[0x11, 0, 0x10, 0], // zero length
            &[0x91, 1, 0, 0],    // offset field wider than 8
            &[0x21, 3, 0x10],    // truncated offset field
            &[0x11, 3, 0xF0, 0], // negative first LCN
        ];
        for (i, pairs) in cases.iter().enumerate() {
            let mut list = RunList::new();
            assert!(list.extend(0, pairs, 100, 512, 1).is_err(), "case {i}");
        }
        // A start VCN that skips clusters.
        let mut list = RunList::new();
        assert!(list.extend(5, &[0x11, 1, 1, 0], 100, 512, 1).is_err());
    }

    #[test]
    fn reads_follow_runs_holes_and_the_initialized_size() {
        let mut disk = vec![0u8; 20 * 512];
        for (i, b) in disk.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        let mut list = RunList::new();
        // vcn 0..2 -> lcn 4, vcn 2..4 hole, vcn 4..5 -> lcn 10
        list.extend(0, &[0x11, 2, 4, 0x01, 2, 0x11, 1, 6, 0], 20, 512, 1)
            .unwrap();
        let src: Arc<dyn BlockSource> = Arc::new(MemSource::new(disk.clone()));
        // size 5 clusters minus 10 bytes, initialized only through vcn 4's first 100 bytes.
        let fd = FileData::new(src, list, 512, 5 * 512 - 10, 4 * 512 + 100);
        let mut all = vec![0xEEu8; 5 * 512 - 10];
        fd.read_at(0, &mut all).unwrap();
        assert_eq!(all[..1024], disk[4 * 512..6 * 512]);
        assert!(all[1024..2048].iter().all(|&b| b == 0));
        assert_eq!(all[2048..2148], disk[10 * 512..10 * 512 + 100]);
        assert!(all[2148..].iter().all(|&b| b == 0));
        // A read starting mid-run and crossing into the hole.
        let mut buf = [0u8; 40];
        fd.read_at(1010, &mut buf).unwrap();
        assert_eq!(buf[..14], disk[4 * 512 + 1010..4 * 512 + 1024]);
        assert!(buf[14..].iter().all(|&b| b == 0));
        assert!(fd.read_at(5 * 512 - 20, &mut [0u8; 11]).is_err());
    }
}
