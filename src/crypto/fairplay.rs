//! FairPlay DRM handshake (fp-setup M1/M2) for AirPlay authentication.
//!
//! The iPhone sends two fp-setup requests:
//! - **M1** (16 bytes): mode selection → server replies with 142-byte pre-computed response
//! - **M2** (164 bytes): key message → server replies with 32-byte header + echo
//!
//! After M2, the server can decrypt the 72-byte AES session key using the
//! playfair algorithm (ported from the C reference implementation).

use crate::crypto::fairplay_tables::*;
use crate::error::CryptoError;

// Reply messages from fairplay_playfair.c (4 modes x 142 bytes)
const REPLY_MESSAGE: [[u8; 142]; 4] = [
    [0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x00,0x0f,0x9f,
     0x3f,0x9e,0x0a,0x25,0x21,0xdb,0xdf,0x31,0x2a,0xb2,0xbf,0xb2,0x9e,0x8d,0x23,0x2b,
     0x63,0x76,0xa8,0xc8,0x18,0x70,0x1d,0x22,0xae,0x93,0xd8,0x27,0x37,0xfe,0xaf,0x9d,
     0xb4,0xfd,0xf4,0x1c,0x2d,0xba,0x9d,0x1f,0x49,0xca,0xaa,0xbf,0x65,0x91,0xac,0x1f,
     0x7b,0xc6,0xf7,0xe0,0x66,0x3d,0x21,0xaf,0xe0,0x15,0x65,0x95,0x3e,0xab,0x81,0xf4,
     0x18,0xce,0xed,0x09,0x5a,0xdb,0x7c,0x3d,0x0e,0x25,0x49,0x09,0xa7,0x98,0x31,0xd4,
     0x9c,0x39,0x82,0x97,0x34,0x34,0xfa,0xcb,0x42,0xc6,0x3a,0x1c,0xd9,0x11,0xa6,0xfe,
     0x94,0x1a,0x8a,0x6d,0x4a,0x74,0x3b,0x46,0xc3,0xa7,0x64,0x9e,0x44,0xc7,0x89,0x55,
     0xe4,0x9d,0x81,0x55,0x00,0x95,0x49,0xc4,0xe2,0xf7,0xa3,0xf6,0xd5,0xba],
    [0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x01,0xcf,0x32,
     0xa2,0x57,0x14,0xb2,0x52,0x4f,0x8a,0xa0,0xad,0x7a,0xf1,0x64,0xe3,0x7b,0xcf,0x44,
     0x24,0xe2,0x00,0x04,0x7e,0xfc,0x0a,0xd6,0x7a,0xfc,0xd9,0x5d,0xed,0x1c,0x27,0x30,
     0xbb,0x59,0x1b,0x96,0x2e,0xd6,0x3a,0x9c,0x4d,0xed,0x88,0xba,0x8f,0xc7,0x8d,0xe6,
     0x4d,0x91,0xcc,0xfd,0x5c,0x7b,0x56,0xda,0x88,0xe3,0x1f,0x5c,0xce,0xaf,0xc7,0x43,
     0x19,0x95,0xa0,0x16,0x65,0xa5,0x4e,0x19,0x39,0xd2,0x5b,0x94,0xdb,0x64,0xb9,0xe4,
     0x5d,0x8d,0x06,0x3e,0x1e,0x6a,0xf0,0x7e,0x96,0x56,0x16,0x2b,0x0e,0xfa,0x40,0x42,
     0x75,0xea,0x5a,0x44,0xd9,0x59,0x1c,0x72,0x56,0xb9,0xfb,0xe6,0x51,0x38,0x98,0xb8,
     0x02,0x27,0x72,0x19,0x88,0x57,0x16,0x50,0x94,0x2a,0xd9,0x46,0x68,0x8a],
    [0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x02,0xc1,0x69,
     0xa3,0x52,0xee,0xed,0x35,0xb1,0x8c,0xdd,0x9c,0x58,0xd6,0x4f,0x16,0xc1,0x51,0x9a,
     0x89,0xeb,0x53,0x17,0xbd,0x0d,0x43,0x36,0xcd,0x68,0xf6,0x38,0xff,0x9d,0x01,0x6a,
     0x5b,0x52,0xb7,0xfa,0x92,0x16,0xb2,0xb6,0x54,0x82,0xc7,0x84,0x44,0x11,0x81,0x21,
     0xa2,0xc7,0xfe,0xd8,0x3d,0xb7,0x11,0x9e,0x91,0x82,0xaa,0xd7,0xd1,0x8c,0x70,0x63,
     0xe2,0xa4,0x57,0x55,0x59,0x10,0xaf,0x9e,0x0e,0xfc,0x76,0x34,0x7d,0x16,0x40,0x43,
     0x80,0x7f,0x58,0x1e,0xe4,0xfb,0xe4,0x2c,0xa9,0xde,0xdc,0x1b,0x5e,0xb2,0xa3,0xaa,
     0x3d,0x2e,0xcd,0x59,0xe7,0xee,0xe7,0x0b,0x36,0x29,0xf2,0x2a,0xfd,0x16,0x1d,0x87,
     0x73,0x53,0xdd,0xb9,0x9a,0xdc,0x8e,0x07,0x00,0x6e,0x56,0xf8,0x50,0xce],
    [0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x03,0x90,0x01,
     0xe1,0x72,0x7e,0x0f,0x57,0xf9,0xf5,0x88,0x0d,0xb1,0x04,0xa6,0x25,0x7a,0x23,0xf5,
     0xcf,0xff,0x1a,0xbb,0xe1,0xe9,0x30,0x45,0x25,0x1a,0xfb,0x97,0xeb,0x9f,0xc0,0x01,
     0x1e,0xbe,0x0f,0x3a,0x81,0xdf,0x5b,0x69,0x1d,0x76,0xac,0xb2,0xf7,0xa5,0xc7,0x08,
     0xe3,0xd3,0x28,0xf5,0x6b,0xb3,0x9d,0xbd,0xe5,0xf2,0x9c,0x8a,0x17,0xf4,0x81,0x48,
     0x7e,0x3a,0xe8,0x63,0xc6,0x78,0x32,0x54,0x22,0xe6,0xf7,0x8e,0x16,0x6d,0x18,0xaa,
     0x7f,0xd6,0x36,0x25,0x8b,0xce,0x28,0x72,0x6f,0x66,0x1f,0x73,0x88,0x93,0xce,0x44,
     0x31,0x1e,0x4b,0xe6,0xc0,0x53,0x51,0x93,0xe5,0xef,0x72,0xe8,0x68,0x62,0x33,0x72,
     0x9c,0x22,0x7d,0x82,0x0c,0x99,0x94,0x45,0xd8,0x92,0x46,0xc8,0xc3,0x59],
];

const FP_HEADER: [u8; 12] = [0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14];

/// FairPlay handshake state machine.
///
/// Holds the 164-byte key message from M2, used to decrypt the AES session key.
pub struct FairPlay {
    keymsg: [u8; 164],
    keymsglen: usize,
}

impl Default for FairPlay {
    fn default() -> Self {
        Self::new()
    }
}

impl FairPlay {
    /// Create a new FairPlay handshake state.
    pub fn new() -> Self {
        Self { keymsg: [0u8; 164], keymsglen: 0 }
    }

    /// Process M1 (mode selection). Returns the 142-byte pre-computed reply.
    pub fn setup(&mut self, request: &[u8; 16]) -> Result<[u8; 142], CryptoError> {
        if request[4] != 0x03 {
            return Err(CryptoError::FairPlay("unsupported version".into()));
        }
        let mode = request[14] as usize;
        if mode >= 4 {
            return Err(CryptoError::FairPlay("invalid mode".into()));
        }
        self.keymsglen = 0;
        Ok(REPLY_MESSAGE[mode])
    }

    /// Process M2 (key message). Stores the key message and returns the 32-byte reply.
    pub fn handshake(&mut self, request: &[u8; 164]) -> Result<[u8; 32], CryptoError> {
        if request[4] != 0x03 {
            return Err(CryptoError::FairPlay("unsupported version".into()));
        }
        self.keymsg.copy_from_slice(request);
        self.keymsglen = 164;
        let mut res = [0u8; 32];
        res[..12].copy_from_slice(&FP_HEADER);
        res[12..].copy_from_slice(&request[144..164]);
        Ok(res)
    }

    /// Decrypt the 72-byte AES session key. Must be called after handshake().
    pub fn decrypt(&self, input: &[u8; 72]) -> Result<[u8; 16], CryptoError> {
        if self.keymsglen != 164 {
            return Err(CryptoError::FairPlay("handshake not complete".into()));
        }
        Ok(playfair_decrypt(&self.keymsg, input))
    }

    /// Returns the 164-byte key message from M2, or None if handshake not complete.
    pub fn keymsg(&self) -> Option<&[u8; 164]> {
        if self.keymsglen == 164 { Some(&self.keymsg) } else { None }
    }
}

// --- playfair.c port ---

fn playfair_decrypt(message3: &[u8; 164], cipher_text: &[u8; 72]) -> [u8; 16] {
    let chunk1 = &cipher_text[16..32];
    let chunk2 = &cipher_text[56..72];
    let mut block_in = [0u8; 16];
    let mut sap_key = [0u8; 16];
    let mut key_schedule = [[0u32; 4]; 11];

    generate_session_key(&DEFAULT_SAP, message3, &mut sap_key);
    generate_key_schedule(&sap_key, &mut key_schedule);
    z_xor_block(chunk2, &mut block_in);
    cycle(&mut block_in, &key_schedule);

    let mut key_out = [0u8; 16];
    key_out.iter_mut().zip(block_in.iter().zip(chunk1)).for_each(|(o, (&a, &b))| *o = a ^ b);
    x_xor_inplace(&mut key_out);
    z_xor_inplace(&mut key_out);
    key_out
}

// --- omg_hax.c port ---

/// XOR a 16-byte block with the Z key.
fn z_xor_block(input: &[u8], out: &mut [u8; 16]) {
    out.iter_mut().zip(input.iter().zip(&Z_KEY)).for_each(|(o, (&a, &b))| *o = a ^ b);
}

/// XOR a block in-place with the Z key.
fn z_xor_inplace(block: &mut [u8; 16]) {
    block.iter_mut().zip(&Z_KEY).for_each(|(b, &k)| *b ^= k);
}

/// XOR a block in-place with the X key.
fn x_xor_inplace(block: &mut [u8; 16]) {
    block.iter_mut().zip(&X_KEY).for_each(|(b, &k)| *b ^= k);
}

/// XOR a 16-byte block with the T key.
fn t_xor(input: &[u8], out: &mut [u8; 16]) {
    out.iter_mut().zip(input.iter().zip(&T_KEY)).for_each(|(o, (&a, &b))| *o = a ^ b);
}

fn table_index(i: usize) -> &'static [u8] {
    let offset = ((31 * i) % 0x28) << 8;
    &TABLE_S1[offset..offset + 256]
}

fn message_table_index(i: usize) -> &'static [u8] {
    let offset = ((97 * i) % 144) << 8;
    &TABLE_S2[offset..offset + 256]
}

fn permute_table_2(i: usize) -> &'static [u8] {
    let offset = ((71 * i) % 144) << 8;
    &TABLE_S4[offset..offset + 256]
}

fn permute_block_1(block: &mut [u8; 16]) {
    block[0] = TABLE_S3[block[0] as usize];
    block[4] = TABLE_S3[0x400 + block[4] as usize];
    block[8] = TABLE_S3[0x800 + block[8] as usize];
    block[12] = TABLE_S3[0xc00 + block[12] as usize];

    let tmp = block[13];
    block[13] = TABLE_S3[0x100 + block[9] as usize];
    block[9] = TABLE_S3[0xd00 + block[5] as usize];
    block[5] = TABLE_S3[0x900 + block[1] as usize];
    block[1] = TABLE_S3[0x500 + tmp as usize];

    let tmp = block[2];
    block[2] = TABLE_S3[0xa00 + block[10] as usize];
    block[10] = TABLE_S3[0x200 + tmp as usize];
    let tmp = block[6];
    block[6] = TABLE_S3[0xe00 + block[14] as usize];
    block[14] = TABLE_S3[0x600 + tmp as usize];

    let tmp = block[3];
    block[3] = TABLE_S3[0xf00 + block[7] as usize];
    block[7] = TABLE_S3[0x300 + block[11] as usize];
    block[11] = TABLE_S3[0x700 + block[15] as usize];
    block[15] = TABLE_S3[0xb00 + tmp as usize];
}

fn permute_block_2(block: &mut [u8; 16], round: usize) {
    let r = round * 16;
    block[0] = permute_table_2(r)[block[0] as usize];
    block[4] = permute_table_2(r + 4)[block[4] as usize];
    block[8] = permute_table_2(r + 8)[block[8] as usize];
    block[12] = permute_table_2(r + 12)[block[12] as usize];

    let tmp = block[13];
    block[13] = permute_table_2(r + 13)[block[9] as usize];
    block[9] = permute_table_2(r + 9)[block[5] as usize];
    block[5] = permute_table_2(r + 5)[block[1] as usize];
    block[1] = permute_table_2(r + 1)[tmp as usize];

    let tmp = block[2];
    block[2] = permute_table_2(r + 2)[block[10] as usize];
    block[10] = permute_table_2(r + 10)[tmp as usize];
    let tmp = block[6];
    block[6] = permute_table_2(r + 6)[block[14] as usize];
    block[14] = permute_table_2(r + 14)[tmp as usize];

    let tmp = block[3];
    block[3] = permute_table_2(r + 3)[block[7] as usize];
    block[7] = permute_table_2(r + 7)[block[11] as usize];
    block[11] = permute_table_2(r + 11)[block[15] as usize];
    block[15] = permute_table_2(r + 15)[tmp as usize];
}

fn read_u32_le(block: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([block[offset], block[offset+1], block[offset+2], block[offset+3]])
}

fn write_u32_le(block: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    block[offset..offset+4].copy_from_slice(&bytes);
}

fn generate_key_schedule(key_material: &[u8; 16], key_schedule: &mut [[u32; 4]; 11]) {
    let mut buffer = [0u8; 16];
    t_xor(key_material, &mut buffer);
    let mut ti = 0usize;

    for round in 0..11 {
        let key_data_0 = read_u32_le(&buffer, 0);
        key_schedule[round][0] = key_data_0;
        key_schedule[round][1] = read_u32_le(&buffer, 4);
        key_schedule[round][2] = read_u32_le(&buffer, 8);
        key_schedule[round][3] = read_u32_le(&buffer, 12);

        let t1 = table_index(ti);
        let t2 = table_index(ti + 1);
        let t3 = table_index(ti + 2);
        let t4 = table_index(ti + 3);
        ti += 4;

        buffer[0] ^= t1[buffer[0x0d] as usize] ^ INDEX_MANGLE[round];
        buffer[1] ^= t2[buffer[0x0e] as usize];
        buffer[2] ^= t3[buffer[0x0f] as usize];
        buffer[3] ^= t4[buffer[0x0c] as usize];

        // J operations
        let w0 = read_u32_le(&buffer, 0);
        let w1 = read_u32_le(&buffer, 4) ^ w0;
        write_u32_le(&mut buffer, 4, w1);
        let w2 = read_u32_le(&buffer, 8) ^ w1;
        write_u32_le(&mut buffer, 8, w2);
        let w3 = read_u32_le(&buffer, 12) ^ w2;
        write_u32_le(&mut buffer, 12, w3);
    }
}

fn cycle(block: &mut [u8; 16], key_schedule: &[[u32; 4]; 11]) {
    // XOR with last round key
    for (i, &k) in key_schedule[10].iter().enumerate() {
        let v = read_u32_le(block, i * 4) ^ k;
        write_u32_le(block, i * 4, v);
    }
    permute_block_1(block);

    for round in 0..9 {
        let ks = &key_schedule[9 - round];
        let key0 = ks[0].to_le_bytes();
        let ptr1 = TABLE_S5[(block[3] ^ key0[3]) as usize];
        let ptr2 = TABLE_S6[(block[2] ^ key0[2]) as usize];
        let ptr3 = TABLE_S8[(block[0] ^ key0[0]) as usize];
        let ptr4 = TABLE_S7[(block[1] ^ key0[1]) as usize];
        let ab = ptr1 ^ ptr2 ^ ptr3 ^ ptr4;
        write_u32_le(block, 0, ab);

        let key1 = ks[1].to_le_bytes();
        let ptr2 = TABLE_S5[(block[7] ^ key1[3]) as usize];
        let ptr1 = TABLE_S6[(block[6] ^ key1[2]) as usize];
        let ptr4 = TABLE_S7[(block[5] ^ key1[1]) as usize];
        let ptr3 = TABLE_S8[(block[4] ^ key1[0]) as usize];
        let ab = ptr1 ^ ptr2 ^ ptr3 ^ ptr4;
        write_u32_le(block, 4, ab);

        let key2 = ks[2].to_le_bytes();
        let v2 = TABLE_S5[(block[11] ^ key2[3]) as usize]
               ^ TABLE_S6[(block[10] ^ key2[2]) as usize]
               ^ TABLE_S7[(block[9] ^ key2[1]) as usize]
               ^ TABLE_S8[(block[8] ^ key2[0]) as usize];
        write_u32_le(block, 8, v2);

        let key3 = ks[3].to_le_bytes();
        let v3 = TABLE_S5[(block[15] ^ key3[3]) as usize]
               ^ TABLE_S6[(block[14] ^ key3[2]) as usize]
               ^ TABLE_S7[(block[13] ^ key3[1]) as usize]
               ^ TABLE_S8[(block[12] ^ key3[0]) as usize];
        write_u32_le(block, 12, v3);

        permute_block_2(block, 8 - round);
    }

    // Final XOR with first round key
    for (i, &k) in key_schedule[0].iter().enumerate() {
        let v = read_u32_le(block, i * 4) ^ k;
        write_u32_le(block, i * 4, v);
    }
}

// --- modified_md5.c port ---

fn modified_md5(original_block_in: &[u8], key_in: &[u8; 16], key_out: &mut [u8; 16]) {
    let mut block_in = [0u8; 64];
    block_in[..64.min(original_block_in.len())].copy_from_slice(&original_block_in[..64.min(original_block_in.len())]);

    let key_words: [u32; 4] = [
        u32::from_le_bytes([key_in[0], key_in[1], key_in[2], key_in[3]]),
        u32::from_le_bytes([key_in[4], key_in[5], key_in[6], key_in[7]]),
        u32::from_le_bytes([key_in[8], key_in[9], key_in[10], key_in[11]]),
        u32::from_le_bytes([key_in[12], key_in[13], key_in[14], key_in[15]]),
    ];

    let (mut a, mut b, mut c, mut d) = (key_words[0], key_words[1], key_words[2], key_words[3]);

    for i in 0..64u32 {
        let j = match i {
            0..=15 => i as usize,
            16..=31 => ((5 * i + 1) % 16) as usize,
            32..=47 => ((3 * i + 5) % 16) as usize,
            _ => ((7 * i) % 16) as usize,
        };

        let input = (block_in[4*j] as u32) << 24
                  | (block_in[4*j+1] as u32) << 16
                  | (block_in[4*j+2] as u32) << 8
                  | block_in[4*j+3] as u32;

        let k = ((1u64 << 32) as f64 * ((i + 1) as f64).sin().abs()) as u32;
        let mut z = a.wrapping_add(input).wrapping_add(k);

        z = match i {
            0..=15 => z.wrapping_add((b & c) | (!b & d)),
            16..=31 => z.wrapping_add((b & d) | (c & !d)),
            32..=47 => z.wrapping_add(b ^ c ^ d),
            _ => z.wrapping_add(c ^ (b | !d)),
        };

        let s = MD5_SHIFT[i as usize];
        z = z.rotate_left(s);

        z = z.wrapping_add(b);
        let tmp = d;
        d = c;
        c = b;
        b = z;
        a = tmp;

        if i == 31 {
            let mut bw = [0u32; 16];
            for idx in 0..16 {
                bw[idx] = u32::from_le_bytes([
                    block_in[idx*4], block_in[idx*4+1], block_in[idx*4+2], block_in[idx*4+3]
                ]);
            }
            bw.swap((a & 15) as usize, (b & 15) as usize);
            bw.swap((c & 15) as usize, (d & 15) as usize);
            bw.swap(((a >> 4) & 15) as usize, ((b >> 4) & 15) as usize);
            bw.swap(((a >> 8) & 15) as usize, ((b >> 8) & 15) as usize);
            bw.swap(((a >> 12) & 15) as usize, ((b >> 12) & 15) as usize);
            for idx in 0..16 {
                let bytes = bw[idx].to_le_bytes();
                block_in[idx*4..idx*4+4].copy_from_slice(&bytes);
            }
        }
    }

    let out_words = [
        key_words[0].wrapping_add(a),
        key_words[1].wrapping_add(b),
        key_words[2].wrapping_add(c),
        key_words[3].wrapping_add(d),
    ];
    for (i, w) in out_words.iter().enumerate() {
        let bytes = w.to_le_bytes();
        key_out[i*4..i*4+4].copy_from_slice(&bytes);
    }
}

// --- sap_hash.c port ---

fn rol8(x: u8, y: u32) -> u8 {
    ((x as u16) << (y & 7) | (x as u16) >> (8 - (y & 7))) as u8
}


fn sap_hash(block_in: &[u8], key_out: &mut [u8; 16]) {
    let block_words: Vec<u32> = (0..16).map(|i| {
        u32::from_le_bytes([block_in[i*4], block_in[i*4+1], block_in[i*4+2], block_in[i*4+3]])
    }).collect();

    let mut buffer0: [u8; 20] = [0x96,0x5F,0xC6,0x53,0xF8,0x46,0xCC,0x18,0xDF,0xBE,0xB2,0xF8,0x38,0xD7,0xEC,0x22,0x03,0xD1,0x20,0x8F];
    let mut buffer1 = [0u8; 210];
    let mut buffer2: [u8; 35] = [0x43,0x54,0x62,0x7A,0x18,0xC3,0xD6,0xB3,0x9A,0x56,0xF6,0x1C,0x14,0x3F,0x0C,0x1D,0x3B,0x36,0x83,0xB1,0x39,0x51,0x4A,0xAA,0x09,0x3E,0xFE,0x44,0xAF,0xDE,0xC3,0x20,0x9D,0x42,0x3A];
    let mut buffer3 = [0u8; 132];
    let buffer4: [u8; 21] = [0xED,0x25,0xD1,0xBB,0xBC,0x27,0x9F,0x02,0xA2,0xA9,0x11,0x00,0x0C,0xB3,0x52,0xC0,0xBD,0xE3,0x1B,0x49,0xC7];
    let i0_index: [usize; 11] = [18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30];

    // Load input into buffer1
    for i in 0..210 {
        let in_word = block_words[(i % 64) >> 2];
        let in_byte = (in_word >> ((3 - (i % 4)) << 3)) & 0xff;
        buffer1[i] = in_byte as u8;
    }

    // Scrambling
    for i in 0..840u32 {
        let xi = ((i.wrapping_sub(155)) as usize) % 210;
        let yi = ((i.wrapping_sub(57)) as usize) % 210;
        let zi = ((i.wrapping_sub(13)) as usize) % 210;
        let wi = (i as usize) % 210;
        let x = buffer1[xi];
        let y = buffer1[yi];
        let z = buffer1[zi];
        let w = buffer1[wi];
        buffer1[i as usize % 210] = rol8(y, 5).wrapping_add(rol8(z, 3) ^ w).wrapping_sub(rol8(x, 7));
    }

    // Garble
    garble(&mut buffer0, &mut buffer1, &mut buffer2, &mut buffer3, &buffer4);

    // Fill output with 0xE1
    for b in key_out.iter_mut() { *b = 0xE1; }

    // Apply buffer3
    for i in 0..11 {
        if i == 3 {
            key_out[i] = 0x3d;
        } else {
            key_out[i] = key_out[i].wrapping_add(buffer3[i0_index[i] * 4]);
        }
    }

    // Apply buffer0
    for i in 0..20 { key_out[i % 16] ^= buffer0[i]; }
    // Apply buffer2
    for i in 0..35 { key_out[i % 16] ^= buffer2[i]; }
    // Apply buffer1
    for i in 0..210 { key_out[i % 16] ^= buffer1[i]; }

    // Reverse scramble
    for _ in 0..16 {
        for i in 0..16u32 {
            let x = key_out[((i.wrapping_sub(7)) as usize) % 16];
            let y = key_out[i as usize % 16];
            let z = key_out[((i.wrapping_sub(37)) as usize) % 16];
            let w = key_out[((i.wrapping_sub(177)) as usize) % 16];
            key_out[i as usize] = rol8(x, 1) ^ y ^ rol8(z, 6) ^ rol8(w, 5);
        }
    }
}

// --- hand_garble.c port (full mechanical translation in fairplay_garble.rs) ---

fn garble(buffer0: &mut [u8; 20], buffer1: &mut [u8; 210], buffer2: &mut [u8; 35], buffer3: &mut [u8; 132], buffer4: &[u8; 21]) {
    super::fairplay_garble::garble(buffer0, buffer1, buffer2, buffer3, buffer4);
}

// --- omg_hax.c: generate_session_key ---

fn decrypt_message(message_in: &[u8], decrypted_message: &mut [u8; 128]) {
    let mode = message_in[12] as usize;
    let mut buffer = [0u8; 16];

    for i in 0..8 {
        // Copy block
        for j in 0..16 {
            buffer[j] = if mode == 3 {
                message_in[(0x80 - 0x10 * i) + j]
            } else {
                message_in[(0x10 * (i + 1)) + j]
            };
        }

        // 9 rounds of permutation
        for j_round in 0..9 {
            let base = 0x80 - 0x10 * j_round;
            let mk = &MESSAGE_KEY[mode];

            buffer[0x0] = message_table_index(base)[buffer[0x0] as usize] ^ mk[base];
            buffer[0x4] = message_table_index(base + 0x4)[buffer[0x4] as usize] ^ mk[base + 0x4];
            buffer[0x8] = message_table_index(base + 0x8)[buffer[0x8] as usize] ^ mk[base + 0x8];
            buffer[0xc] = message_table_index(base + 0xc)[buffer[0xc] as usize] ^ mk[base + 0xc];

            let tmp = buffer[0x0d];
            buffer[0xd] = message_table_index(base + 0xd)[buffer[0x9] as usize] ^ mk[base + 0xd];
            buffer[0x9] = message_table_index(base + 0x9)[buffer[0x5] as usize] ^ mk[base + 0x9];
            buffer[0x5] = message_table_index(base + 0x5)[buffer[0x1] as usize] ^ mk[base + 0x5];
            buffer[0x1] = message_table_index(base + 0x1)[tmp as usize] ^ mk[base + 0x1];

            let tmp = buffer[0x02];
            buffer[0x2] = message_table_index(base + 0x2)[buffer[0xa] as usize] ^ mk[base + 0x2];
            buffer[0xa] = message_table_index(base + 0xa)[tmp as usize] ^ mk[base + 0xa];
            let tmp = buffer[0x06];
            buffer[0x6] = message_table_index(base + 0x6)[buffer[0xe] as usize] ^ mk[base + 0x6];
            buffer[0xe] = message_table_index(base + 0xe)[tmp as usize] ^ mk[base + 0xe];

            let tmp = buffer[0x3];
            buffer[0x3] = message_table_index(base + 0x3)[buffer[0x7] as usize] ^ mk[base + 0x3];
            buffer[0x7] = message_table_index(base + 0x7)[buffer[0xb] as usize] ^ mk[base + 0x7];
            buffer[0xb] = message_table_index(base + 0xb)[buffer[0xf] as usize] ^ mk[base + 0xb];
            buffer[0xf] = message_table_index(base + 0xf)[tmp as usize] ^ mk[base + 0xf];

            // T-table mixing
            let b0 = TABLE_S9[buffer[0x0] as usize] ^ TABLE_S9[0x100 + buffer[0x1] as usize] ^ TABLE_S9[0x200 + buffer[0x2] as usize] ^ TABLE_S9[0x300 + buffer[0x3] as usize];
            let b1 = TABLE_S9[buffer[0x4] as usize] ^ TABLE_S9[0x100 + buffer[0x5] as usize] ^ TABLE_S9[0x200 + buffer[0x6] as usize] ^ TABLE_S9[0x300 + buffer[0x7] as usize];
            let b2 = TABLE_S9[buffer[0x8] as usize] ^ TABLE_S9[0x100 + buffer[0x9] as usize] ^ TABLE_S9[0x200 + buffer[0xa] as usize] ^ TABLE_S9[0x300 + buffer[0xb] as usize];
            let b3 = TABLE_S9[buffer[0xc] as usize] ^ TABLE_S9[0x100 + buffer[0xd] as usize] ^ TABLE_S9[0x200 + buffer[0xe] as usize] ^ TABLE_S9[0x300 + buffer[0xf] as usize];
            write_u32_le(&mut buffer, 0, b0);
            write_u32_le(&mut buffer, 4, b1);
            write_u32_le(&mut buffer, 8, b2);
            write_u32_le(&mut buffer, 12, b3);
        }

        // Final permutation with TABLE_S10
        let b = &mut buffer;
        b[0x0] = TABLE_S10[b[0x0] as usize];
        b[0x4] = TABLE_S10[(0x4 << 8) + b[0x4] as usize];
        b[0x8] = TABLE_S10[(0x8 << 8) + b[0x8] as usize];
        b[0xc] = TABLE_S10[(0xc << 8) + b[0xc] as usize];
        let tmp = b[0x0d];
        b[0xd] = TABLE_S10[(0xd << 8) + b[0x9] as usize];
        b[0x9] = TABLE_S10[(0x9 << 8) + b[0x5] as usize];
        b[0x5] = TABLE_S10[(0x5 << 8) + b[0x1] as usize];
        b[0x1] = TABLE_S10[(0x1 << 8) + tmp as usize];
        let tmp = b[0x02];
        b[0x2] = TABLE_S10[(0x2 << 8) + b[0xa] as usize];
        b[0xa] = TABLE_S10[(0xa << 8) + tmp as usize];
        let tmp = b[0x06];
        b[0x6] = TABLE_S10[(0x6 << 8) + b[0xe] as usize];
        b[0xe] = TABLE_S10[(0xe << 8) + tmp as usize];
        let tmp = b[0x3];
        b[0x3] = TABLE_S10[(0x3 << 8) + b[0x7] as usize];
        b[0x7] = TABLE_S10[(0x7 << 8) + b[0xb] as usize];
        b[0xb] = TABLE_S10[(0xb << 8) + b[0xf] as usize];
        b[0xf] = TABLE_S10[(0xf << 8) + tmp as usize];

        // XOR with previous block or IV
        if mode == 2 || mode == 1 || mode == 0 {
            let iv = if i > 0 { &message_in[0x10 * i..0x10 * i + 16] } else { &MESSAGE_IV[mode] };
            for j in 0..16 {
                decrypted_message[0x10 * i + j] = buffer[j] ^ iv[j];
            }
        } else {
            let iv = if i < 7 { &message_in[0x70 - 0x10 * i..0x70 - 0x10 * i + 16] } else { &MESSAGE_IV[mode] };
            for j in 0..16 {
                decrypted_message[0x70 - 0x10 * i + j] = buffer[j] ^ iv[j];
            }
        }
    }
}


fn generate_session_key(old_sap: &[u8], message_in: &[u8], session_key: &mut [u8; 16]) {
    let mut decrypted_message = [0u8; 128];
    decrypt_message(message_in, &mut decrypted_message);

    let mut new_sap = [0u8; 320];
    new_sap[0x000..0x011].copy_from_slice(&STATIC_SOURCE_1);
    new_sap[0x011..0x091].copy_from_slice(&decrypted_message);
    new_sap[0x091..0x111].copy_from_slice(&old_sap[0x80..0x100]);
    new_sap[0x111..0x140].copy_from_slice(&STATIC_SOURCE_2);

    session_key.copy_from_slice(&INITIAL_SESSION_KEY);

    for round in 0..5 {
        let base = &new_sap[round * 64..(round + 1) * 64];
        let mut md5_out = [0u8; 16];
        modified_md5(base, session_key, &mut md5_out);
        sap_hash(base, session_key);

        let sk_words: [u32; 4] = [
            u32::from_le_bytes([session_key[0], session_key[1], session_key[2], session_key[3]]),
            u32::from_le_bytes([session_key[4], session_key[5], session_key[6], session_key[7]]),
            u32::from_le_bytes([session_key[8], session_key[9], session_key[10], session_key[11]]),
            u32::from_le_bytes([session_key[12], session_key[13], session_key[14], session_key[15]]),
        ];
        let md5_words: [u32; 4] = [
            u32::from_le_bytes([md5_out[0], md5_out[1], md5_out[2], md5_out[3]]),
            u32::from_le_bytes([md5_out[4], md5_out[5], md5_out[6], md5_out[7]]),
            u32::from_le_bytes([md5_out[8], md5_out[9], md5_out[10], md5_out[11]]),
            u32::from_le_bytes([md5_out[12], md5_out[13], md5_out[14], md5_out[15]]),
        ];
        for i in 0..4 {
            let v = sk_words[i].wrapping_add(md5_words[i]);
            session_key[i*4..i*4+4].copy_from_slice(&v.to_le_bytes());
        }
    }

    // Byte swap within each 4-byte word
    for i in (0..16).step_by(4) {
        session_key.swap(i, i + 3);
        session_key.swap(i + 1, i + 2);
    }

    // XOR with 121
    for b in session_key.iter_mut() {
        *b ^= 121;
    }
}

#[cfg(test)]
mod playfair_tests {
    use super::*;

    fn to_hex(d: &[u8]) -> String { d.iter().map(|b| format!("{:02x}", b)).collect() }

    #[test]
    fn md5_zeros() {
        let mut out = [0u8; 16];
        modified_md5(&[0u8; 64], &[0u8; 16], &mut out);
        assert_eq!(to_hex(&out), "971ccdf7813648a532d8682b39a60cf9");
    }

    #[test]
    fn md5_all_0x41() {
        let mut out = [0u8; 16];
        modified_md5(&[0x41u8; 64], &[0x41u8; 16], &mut out);
        assert_eq!(to_hex(&out), "695b0c3715d9d4ceb4bfee317c92de79");
    }

    #[test]
    fn md5_real_block() {
        let block: [u8; 64] = [
            0xfa,0x9c,0xad,0x4d,0x4b,0x68,0x26,0x8c,0x7f,0xf3,0x88,0x99,0xde,0x92,0x2e,0x95,
            0x1e,0xef,0xbf,0x61,0x64,0x43,0xab,0x48,0x6b,0x70,0x0a,0x3f,0x74,0x3d,0xf2,0x0d,
            0xdd,0x71,0x85,0x35,0x46,0xf2,0xef,0x51,0x5d,0x63,0xe2,0x7a,0x37,0xc5,0x10,0xde,
            0x09,0x71,0x85,0x35,0x46,0xf2,0xef,0x51,0x5d,0x63,0xe2,0x7a,0x37,0xc5,0x10,0xde,
        ];
        let key: [u8; 16] = [0xdc,0xdc,0xf3,0xb9,0x0b,0x74,0xdc,0xfb,0x86,0x7f,0xf7,0x60,0x16,0x72,0x90,0x51];
        let mut out = [0u8; 16];
        modified_md5(&block, &key, &mut out);
        assert_eq!(to_hex(&out), "47da73bfb135d7aaf2934e953f6372ed");
    }

    #[test]
    fn md5_incrementing() {
        let mut block = [0u8; 64];
        let mut key = [0u8; 16];
        for i in 0..64 { block[i] = i as u8; }
        for i in 0..16 { key[i] = (i + 64) as u8; }
        let mut out = [0u8; 16];
        modified_md5(&block, &key, &mut out);
        assert_eq!(to_hex(&out), "086862637e36ec8ccfeed2d71d459bf0");
    }

    #[test]
    fn sap_hash_real_block() {
        let block: [u8; 64] = [
            0xfa,0x9c,0xad,0x4d,0x4b,0x68,0x26,0x8c,0x7f,0xf3,0x88,0x99,0xde,0x92,0x2e,0x95,
            0x1e,0xef,0xbf,0x61,0x64,0x43,0xab,0x48,0x6b,0x70,0x0a,0x3f,0x74,0x3d,0xf2,0x0d,
            0xdd,0x71,0x85,0x35,0x46,0xf2,0xef,0x51,0x5d,0x63,0xe2,0x7a,0x37,0xc5,0x10,0xde,
            0x09,0x71,0x85,0x35,0x46,0xf2,0xef,0x51,0x5d,0x63,0xe2,0x7a,0x37,0xc5,0x10,0xde,
        ];
        let mut key: [u8; 16] = [0xdc,0xdc,0xf3,0xb9,0x0b,0x74,0xdc,0xfb,0x86,0x7f,0xf7,0x60,0x16,0x72,0x90,0x51];
        sap_hash(&block, &mut key);
        assert_eq!(to_hex(&key), "b638c90d9db20392b91613624eb07ba4");
    }

    #[test]
    fn playfair_full() {
        let mut keymsg = [0x41u8; 164];
        keymsg[0] = 0x46; keymsg[1] = 0x50; keymsg[2] = 0x4c; keymsg[3] = 0x59;
        keymsg[4] = 0x03; keymsg[12] = 0x01;
        let mut ekey = [0x42u8; 72];
        ekey[0] = 0x46; ekey[1] = 0x50; ekey[2] = 0x4c; ekey[3] = 0x59;
        let result = playfair_decrypt(&keymsg, &ekey);
        assert_eq!(to_hex(&result), "51e601d65942f9bd660b57bf98800cdf");
    }

    #[test]
    fn generate_session_key_full() {
        let mut msg = [0x41u8; 164];
        msg[0] = 0x46; msg[1] = 0x50; msg[2] = 0x4c; msg[3] = 0x59;
        msg[4] = 0x03; msg[12] = 0x01;
        let mut sk = [0u8; 16];
        generate_session_key(&DEFAULT_SAP, &msg, &mut sk);
        assert_eq!(to_hex(&sk), "4c8323c42e6b9b50fa961f0039cc90f3");
    }

    #[test]
    fn decrypt_message_vector() {
        let mut msg = [0x41u8; 164];
        msg[0] = 0x46; msg[1] = 0x50; msg[2] = 0x4c; msg[3] = 0x59;
        msg[4] = 0x03; msg[12] = 0x01;
        let mut dec = [0u8; 128];
        decrypt_message(&msg, &mut dec);
        assert_eq!(to_hex(&dec[..16]), "efbf616443ab486b700a3f743df20ddd");
        assert_eq!(to_hex(&dec[112..128]), "71853546f2ef515d63e27a37c510de09");
    }

    #[test]
    fn cycle_zero_key_schedule() {
        let mut block: [u8; 16] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
        let ks = [[0u32; 4]; 11];
        cycle(&mut block, &ks);
        assert_eq!(to_hex(&block), "d8dfd3c32f1de7b4d16e65e92e6d3f27");
    }

    #[test]
    fn garble_vector() {
        use crate::crypto::fairplay_garble::garble;
        let mut b0 = [0u8; 20];
        let mut b1 = [0u8; 210];
        let mut b2 = [0u8; 35];
        let mut b3 = [0u8; 132];
        let b4 = [0u8; 21];
        for i in 0..20 { b0[i] = i as u8; }
        for i in 0..210 { b1[i] = (i & 0xff) as u8; }
        for i in 0..35 { b2[i] = (i + 100) as u8; }
        for i in 0..132 { b3[i] = (i + 50) as u8; }
        let mut b4m = [0u8; 21];
        for i in 0..21 { b4m[i] = (i + 200) as u8; }
        garble(&mut b0, &mut b1, &mut b2, &mut b3, &b4m);
        assert_eq!(to_hex(&b0), "000102fb04059ef508090c0b513e73550073129e");
        assert_eq!(to_hex(&b1[..16]), "0001c203d231060708090a0b0c0d0e6b");
        assert_eq!(to_hex(&b2), "643da6672b996a6b536d6e6fbdbf4273e2752e777879077b7cb97e7f08a22d83849eb8");
        assert_eq!(to_hex(&b3[..16]), "d8333435113738394c3b3c3d823f4041");
    }
}
