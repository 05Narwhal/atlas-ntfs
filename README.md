# atlas-ntfs

A read-only NTFS reader. It implements `atlas_fs_core::fs::FileSystem`, so a mounted volume lists folders, looks up names, reads
file content and reports its allocation through the same trait as the other `atlas-*` readers.

- MFT records with fixups, attribute lists and extension records, resident and non-resident attributes (run lists with holes).
- Folders as `$I30` indexes (root node and `INDX` blocks), the `$UpCase` table, DOS names hidden from listings.
- LZNT1 compressed files, alternate data streams as extended attributes, symbolic links and junctions as stored targets.
- Read-only: EFS-encrypted files report `Unsupported`; there is no writer.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

```rust,no_run
use std::sync::Arc;
use atlas_fs_core::fs::FileSystem;
use atlas_fs_core::io::block::BlockSource;
use atlas_fs_core::io::file::FileSource;

let source: Arc<dyn BlockSource> = Arc::new(FileSource::open("volume.img".as_ref())?);
let volume = atlas_ntfs::mount(source)?;
let mut dir = volume.read_dir(volume.root())?;
# Ok::<(), atlas_fs_core::error::Error>(())
```

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
