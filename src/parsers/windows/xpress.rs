//! LZXPRESS Huffman decompression (MS-XCA section 2.2.4), the scheme Windows 8+ uses for
//! compressed Prefetch files (`MAM\x04` header) and for pages of hiberfil.sys.
//!
//! The stream is a sequence of blocks. Each block starts with a 256-byte table of 4-bit code
//! lengths for 512 symbols (0-255 literals, 256-511 matches), followed by the Huffman-coded
//! data read as 16-bit little-endian words, most significant bit first. A block ends when
//! 65536 bytes have been produced; the next table follows at the current input position.

const BLOCK_OUTPUT: usize = 65536;
const TABLE_BITS: u32 = 15;

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    next: u32,
    extra: i32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        let mut b = Bits { data, pos, next: 0, extra: 16 };
        let hi = b.word() as u32;
        let lo = b.word() as u32;
        b.next = (hi << 16) | lo;
        b
    }

    /// Next 16-bit word of the byte stream; zero past the end (the encoder pads with zeros).
    fn word(&mut self) -> u16 {
        let v = if self.pos + 2 <= self.data.len() {
            u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]])
        } else {
            0
        };
        self.pos += 2;
        v
    }

    fn peek(&self) -> usize {
        (self.next >> (32 - TABLE_BITS)) as usize
    }

    fn consume(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.next <<= n;
        self.extra -= n as i32;
        if self.extra < 0 {
            let w = self.word() as u32;
            self.next |= w << (-self.extra);
            self.extra += 16;
        }
    }

    fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = self.next >> (32 - n);
        self.consume(n);
        v
    }

    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.data.get(self.pos).ok_or("compressed stream ends inside a match length")?;
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, String> {
        if self.pos + 2 > self.data.len() {
            return Err("compressed stream ends inside a match length".into());
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.data.len() {
            return Err("compressed stream ends inside a match length".into());
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
}

/// Canonical Huffman decoding table: index by the next 15 bits, get (symbol, code length).
fn build_table(lengths: &[u8; 512]) -> Result<Vec<(u16, u8)>, String> {
    let mut bl_count = [0u32; 16];
    for &l in lengths.iter() {
        bl_count[l as usize] += 1;
    }
    bl_count[0] = 0;
    let mut next_code = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..16 {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    let mut table = vec![(0u16, 0u8); 1 << TABLE_BITS];
    for (sym, &l) in lengths.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let l = l as u32;
        let c = next_code[l as usize];
        next_code[l as usize] += 1;
        if c >= 1 << l {
            return Err("over-subscribed Huffman code lengths".into());
        }
        let span = 1usize << (TABLE_BITS - l);
        let start = (c as usize) << (TABLE_BITS - l);
        for e in &mut table[start..start + span] {
            *e = (sym as u16, l as u8);
        }
    }
    Ok(table)
}

/// Decompresses an LZXPRESS Huffman stream into exactly `expected_len` bytes.
pub fn decompress(input: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    if expected_len > 256 << 20 {
        return Err(format!("implausible decompressed size {}", expected_len));
    }
    let mut out: Vec<u8> = Vec::with_capacity(expected_len);
    let mut pos = 0usize;
    while out.len() < expected_len {
        if pos + 256 > input.len() {
            return Err(format!("stream ends before the Huffman table of the block at output {}", out.len()));
        }
        let mut lengths = [0u8; 512];
        for i in 0..256 {
            lengths[2 * i] = input[pos + i] & 0x0F;
            lengths[2 * i + 1] = input[pos + i] >> 4;
        }
        pos += 256;
        let table = build_table(&lengths)?;
        let mut br = Bits::new(input, pos);
        let block_end = (out.len() + BLOCK_OUTPUT).min(expected_len);
        while out.len() < block_end {
            let (sym, len) = table[br.peek()];
            if len == 0 {
                return Err(format!("invalid Huffman code at output {}", out.len()));
            }
            br.consume(len as u32);
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            if sym == 256 && out.len() >= expected_len {
                break;
            }
            let m = (sym - 256) as u32;
            let mut length = (m & 0x0F) as usize;
            let offset_bits = m >> 4;
            // The extended length bytes come from the byte stream *before* the offset bits
            // are taken from the bit buffer: taking the offset first could refill the bit
            // buffer with the length byte.
            if length == 15 {
                let b = br.byte()? as usize;
                if b == 255 {
                    let w = br.u16()? as usize;
                    length = if w == 0 { br.u32()? as usize } else { w };
                    if length < 15 {
                        return Err("invalid extended match length".into());
                    }
                    length -= 15;
                } else {
                    length = b;
                }
                length += 15;
            }
            length += 3;
            let offset = (1usize << offset_bits) + br.read_bits(offset_bits) as usize;
            if offset > out.len() || offset == 0 {
                return Err(format!("match offset {} beyond the {} bytes produced", offset, out.len()));
            }
            let start = out.len() - offset;
            for i in 0..length {
                let b = out[start + i];
                out.push(b);
            }
        }
        pos = br.pos;
        if out.len() >= expected_len {
            break;
        }
    }
    out.truncate(expected_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes `data` with a flat 9-bit code for every symbol (0..=511), the simplest valid
    /// table, using literals only, so the decoder's bit reader and table builder are
    /// exercised independently of a real encoder.
    fn encode_literals(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x99u8; 256]; // every nibble = 9 → all 512 symbols have length 9
        // canonical: symbol s gets code s (9 bits)
        let mut acc: u64 = 0;
        let mut nbits = 0u32;
        let mut words: Vec<u16> = Vec::new();
        for &b in data {
            acc = (acc << 9) | b as u64;
            nbits += 9;
            while nbits >= 16 {
                words.push(((acc >> (nbits - 16)) & 0xFFFF) as u16);
                nbits -= 16;
            }
        }
        // end-of-stream symbol 256 then flush
        acc = (acc << 9) | 256;
        nbits += 9;
        while nbits >= 16 {
            words.push(((acc >> (nbits - 16)) & 0xFFFF) as u16);
            nbits -= 16;
        }
        if nbits > 0 {
            words.push(((acc << (16 - nbits)) & 0xFFFF) as u16);
        }
        words.push(0);
        words.push(0);
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    #[test]
    fn literal_only_stream_round_trips() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
        let enc = encode_literals(&data);
        let dec = decompress(&enc, data.len()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn match_copies_overlapping_history() {
        // table: symbol 'a' (0x61) length 1 code 0, symbol 256+? we want a match with length 3, offset 1:
        // match symbol = 256 + (length_code 0 | offset_bits 0 << 4) = 256 -> but 256 is EOF only when done.
        // Use length code 1 (length 4) offset bits 0: symbol 257. Give 'a' code 0 (len 1), 257 code 10 (len 2), 256 code 11 (len 2).
        let mut table = [0u8; 256];
        table[0x30] |= 0x10; // symbol 0x61 'a' (odd: high nibble of byte 0x30): length 1
        table[256 / 2] |= 2; // 256 length 2 (low nibble of byte 128)
        table[257 / 2] |= 2 << 4; // 257 length 2 (high nibble of byte 128)
        // canonical: 'a' = 0 ; 256 = 10 ; 257 = 11
        // stream: 'a' (0), 257 (11) -> copies 4 bytes from offset 1 => "aaaaa", then 256 (10) EOF
        // bits: 0 11 10 -> 01110 followed by zero padding, MSB first in a 16-bit word
        let word: u16 = 0b0111_0000_0000_0000;
        let mut enc = table.to_vec();
        enc.extend_from_slice(&word.to_le_bytes());
        enc.extend_from_slice(&[0, 0, 0, 0]);
        let dec = decompress(&enc, 5).unwrap();
        assert_eq!(dec, b"aaaaa");
    }

    #[test]
    fn rejects_truncated_table() {
        assert!(decompress(&[0u8; 100], 10).is_err());
    }
}
