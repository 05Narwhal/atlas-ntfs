// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! LZNT1, the compression of NTFS files: a stream of chunks, each of which
//! decompresses to at most 4096 bytes.
//!
//! A chunk starts with a 16-bit header: bits 0 to 11 hold the size of the
//! chunk's data minus one (the header itself is not counted), bits 12 to 14
//! the signature 3, and bit 15 says the data is compressed. A header of 0, or
//! fewer than two bytes left, ends the stream. Uncompressed chunk data is the
//! bytes themselves. Compressed chunk data is groups of one flag byte and up
//! to eight tokens, low bit first: a 0 bit is a literal byte, a 1 bit a
//! 16-bit back-reference. How the 16 bits split into displacement and length
//! depends on how much of the chunk is already produced: the displacement
//! gets as many bits as `position - 1` needs (at least 4), the length the
//! rest, and the length is stored minus 3, the displacement minus 1.

use super::le::u16_at;

/// Largest chunk output.
const CHUNK: usize = 4096;

/// Decompresses the chunks in `input` into `out`, which is the most the
/// caller accepts (a compression unit). Returns the bytes produced; the
/// caller owns the rest of `out`. A chunk that does not fit, a reference
/// outside the chunk's own output, a bad signature and a chunk running past
/// `input` are errors.
pub fn decompress_chunks(input: &[u8], out: &mut [u8]) -> Result<usize, &'static str> {
    let mut pos = 0usize;
    let mut produced = 0usize;
    // Every pass consumes at least three bytes of `input`.
    while let Ok(head) = u16_at(input, pos) {
        if head == 0 {
            break;
        }
        if (head >> 12) & 7 != 3 {
            return Err("LZNT1 chunk signature is not 3");
        }
        let size = usize::from(head & 0x0FFF).saturating_add(1);
        let start = pos.saturating_add(2);
        let data = start
            .checked_add(size)
            .and_then(|end| input.get(start..end))
            .ok_or("LZNT1 chunk runs past the end of the data")?;
        let room = out.get_mut(produced..).unwrap_or_default();
        if room.is_empty() {
            return Err("LZNT1 data is larger than the compression unit");
        }
        let n = if head & 0x8000 == 0 {
            let dst = room
                .get_mut(..size)
                .ok_or("LZNT1 data is larger than the compression unit")?;
            dst.copy_from_slice(data);
            size
        } else {
            let cap = room.len().min(CHUNK);
            let dst = room.get_mut(..cap).unwrap_or_default();
            decompress_chunk(data, dst)?
        };
        produced = produced.saturating_add(n);
        pos = start.saturating_add(size);
    }
    Ok(produced)
}

/// One compressed chunk's data into `dst` (at most 4096 bytes).
fn decompress_chunk(data: &[u8], dst: &mut [u8]) -> Result<usize, &'static str> {
    let mut i = 0usize;
    let mut o = 0usize;
    while let Some(&flags) = data.get(i) {
        i = i.saturating_add(1);
        for bit in 0..8u32 {
            let Some(&first) = data.get(i) else {
                return Ok(o);
            };
            if (flags >> bit) & 1 == 0 {
                let slot = dst
                    .get_mut(o)
                    .ok_or("LZNT1 chunk expands past 4096 bytes")?;
                *slot = first;
                o = o.saturating_add(1);
                i = i.saturating_add(1);
                continue;
            }
            let token = u16_at(data, i).map_err(|_| "LZNT1 back-reference is cut off")?;
            i = i.saturating_add(2);
            if o == 0 {
                return Err("LZNT1 back-reference at the start of a chunk");
            }
            // Bits needed for the largest displacement now possible.
            let need = usize::BITS.saturating_sub(o.saturating_sub(1).leading_zeros());
            let disp_bits = need.clamp(4, 12);
            let len_bits = 16u32.saturating_sub(disp_bits);
            let mask = (1u16 << len_bits).saturating_sub(1);
            let len = usize::from(token & mask).saturating_add(3);
            let disp = usize::from(token >> len_bits).saturating_add(1);
            if disp > o {
                return Err("LZNT1 back-reference points before the chunk");
            }
            if o.checked_add(len).is_none_or(|end| end > dst.len()) {
                return Err("LZNT1 chunk expands past 4096 bytes");
            }
            // The ranges may overlap: copy forward one byte at a time.
            for k in 0..len {
                let from = o.saturating_sub(disp).saturating_add(k);
                let b = dst.get(from).copied().ok_or("LZNT1 copy source")?;
                if let Some(slot) = dst.get_mut(o.saturating_add(k)) {
                    *slot = b;
                }
            }
            o = o.saturating_add(len);
        }
    }
    Ok(o)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A token of the test encoder.
    pub enum Tok {
        Lit(u8),
        Ref { disp: usize, len: usize },
    }

    /// An LZNT1 compressed chunk (header included) for `toks`.
    pub fn compressed_chunk(toks: &[Tok]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut produced = 0usize;
        for group in toks.chunks(8) {
            let at = data.len();
            data.push(0u8);
            for (bit, t) in group.iter().enumerate() {
                match *t {
                    Tok::Lit(b) => {
                        data.push(b);
                        produced += 1;
                    }
                    Tok::Ref { disp, len } => {
                        data[at] |= 1 << bit;
                        let need = usize::BITS - (produced - 1).leading_zeros();
                        let disp_bits = need.clamp(4, 12);
                        let len_bits = 16 - disp_bits;
                        let token = (u16::try_from(disp - 1).unwrap() << len_bits)
                            | u16::try_from(len - 3).unwrap();
                        data.extend_from_slice(&token.to_le_bytes());
                        produced += len;
                    }
                }
            }
        }
        let head = 0xB000u16 | u16::try_from(data.len() - 1).unwrap();
        let mut chunk = head.to_le_bytes().to_vec();
        chunk.extend_from_slice(&data);
        chunk
    }

    /// An uncompressed chunk of exactly 4096 bytes.
    pub fn raw_chunk(bytes: &[u8]) -> Vec<u8> {
        assert_eq!(bytes.len(), 4096);
        let mut chunk = (0x3000u16 | 0x0FFF).to_le_bytes().to_vec();
        chunk.extend_from_slice(bytes);
        chunk
    }

    #[test]
    fn decodes_literals_references_and_raw_chunks() {
        // Literals only, then a stream end.
        let mut input =
            compressed_chunk(&b"hello".iter().map(|&b| Tok::Lit(b)).collect::<Vec<_>>());
        input.extend_from_slice(&[0, 0]);
        let mut out = [0u8; 64];
        assert_eq!(decompress_chunks(&input, &mut out), Ok(5));
        assert_eq!(&out[..5], b"hello");

        // A reference with 4 displacement bits that overlaps itself, and one
        // after 20 bytes (5 displacement bits).
        let mut toks: Vec<Tok> = b"abc".iter().map(|&b| Tok::Lit(b)).collect();
        toks.push(Tok::Ref { disp: 3, len: 9 });
        toks.extend((0..8u8).map(Tok::Lit));
        toks.push(Tok::Ref { disp: 20, len: 5 });
        let mut expected = b"abcabcabcabc".to_vec();
        expected.extend(0..8u8);
        for _ in 0..5 {
            let b = expected[expected.len() - 20];
            expected.push(b);
        }
        let mut input = compressed_chunk(&toks);
        // Then an uncompressed chunk, then zero padding.
        let raw: Vec<u8> = (0..4096usize)
            .map(|i| u8::try_from(i % 253).unwrap())
            .collect();
        input.extend_from_slice(&raw_chunk(&raw));
        input.extend_from_slice(&[0; 8]);
        let mut out = vec![0u8; 8192];
        let n = decompress_chunks(&input, &mut out).unwrap();
        assert_eq!(n, expected.len() + 4096);
        assert_eq!(&out[..expected.len()], &expected[..]);
        assert_eq!(&out[expected.len()..n], &raw[..]);
    }

    #[test]
    fn hostile_input_is_an_error() {
        let ok = compressed_chunk(&[Tok::Lit(1), Tok::Lit(2), Tok::Ref { disp: 2, len: 4 }]);
        let mut out = [0u8; 4096];
        assert_eq!(decompress_chunks(&ok, &mut out), Ok(6));
        // Truncated chunk, and a size beyond the input.
        assert!(decompress_chunks(&ok[..ok.len() - 1], &mut out).is_err());
        assert!(decompress_chunks(&[0xFF, 0xBF, 1, 2, 3], &mut out).is_err());
        // Bad signature.
        assert!(decompress_chunks(&[0x02, 0x80, 0x00, b'a', b'b'], &mut out).is_err());
        // A reference at the start, and one reaching before the chunk.
        assert!(decompress_chunks(&[0x03, 0xB0, 0x01, 0, 0, 0], &mut out).is_err());
        assert!(
            decompress_chunks(&[0x03, 0xB0, 0x02, b'a', 0x00, 0x10], &mut out).is_err(),
            "displacement 2 after one byte"
        );
        // A token cut in half.
        assert!(decompress_chunks(&[0x02, 0xB0, 0x02, b'a', 0x10], &mut out).is_err());
        // Output beyond the room given.
        let mut small = [0u8; 4];
        assert!(decompress_chunks(&ok, &mut small).is_err());
        let mut small = [0u8; 100];
        assert!(decompress_chunks(&raw_chunk(&[7; 4096]), &mut small).is_err());
        // A reference that would run past 4096 bytes in one chunk.
        let full = compressed_chunk(&[Tok::Lit(9), Tok::Ref { disp: 1, len: 4095 }]);
        assert_eq!(decompress_chunks(&full, &mut [0u8; 8192]), Ok(4096));
        let over = compressed_chunk(&[
            Tok::Lit(9),
            Tok::Ref { disp: 1, len: 4095 },
            Tok::Ref { disp: 1, len: 3 },
        ]);
        assert!(decompress_chunks(&over, &mut [0u8; 8192]).is_err());
        // No input, a lone byte and a bare terminator are empty streams.
        for input in [&[][..], &[5], &[0, 0]] {
            assert_eq!(decompress_chunks(input, &mut out), Ok(0));
        }
    }
}
