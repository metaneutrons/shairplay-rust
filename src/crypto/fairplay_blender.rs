//! The FairPlay blender: a fixed sequence of byte and word operations that mixes five
//! working buffers into the key material.
//!
//! The sequence of operations is dictated by protocol compatibility. Any receiver
//! must produce exactly the same buffers as the sender's implementation, so there is
//! no freedom in how the steps are chosen or ordered, and this routine is written
//! out as straight-line code with register-style names and explicit wrapping
//! arithmetic. The lint exceptions below are scoped to this module.

#![allow(
    unused_parens,
    unused_assignments,
    reason = "explicit expression grouping mirrors the fixed transformation"
)]

fn ror8_or_zero(input: u8, amount: u32) -> u32 {
    if amount == 0 {
        return 0;
    }
    let c = amount & 7;
    ((input as u32 >> c) & 0xff) | ((input as u32 & 0xff) << (8u32.wrapping_sub(c)))
}

fn rol8_or_zero(input: u8, amount: u32) -> u32 {
    if amount == 0 {
        return 0;
    }
    let c = amount & 7;
    (((input as u32) << c) & 0xff) | ((input as u32) >> (8u32.wrapping_sub(c)))
}

fn shl_shr_xor(input: u8, amount: u32) -> u32 {
    if amount == 0 {
        return 0;
    }
    ((input as u32) << amount) ^ ((input as u32) >> (8u32.wrapping_sub(amount)))
}

fn rotl8(x: u8, y: u32) -> u8 {
    (((x as u16) << (y & 7)) | ((x as u16) >> (8 - (y & 7)))) as u8
}

fn rotl8_wide(x: u8, y: u32) -> u32 {
    ((x as u32) << (y & 7)) | ((x as u32) >> (8u32.wrapping_sub(y & 7)))
}

#[rustfmt::skip]
pub(crate) fn blend(
    lane0: &mut [u8; 20],
    lane1: &mut [u8; 210],
    lane2: &mut [u8; 35],
    lane3: &mut [u8; 132],
    lane4: &[u8; 21],
) {
    // Working registers are zero-initialised and then assigned in sequence. The
    // initial stores are why this module allows `unused_assignments`.
    #[rustfmt::skip]
    let (mut hold, mut hold2, mut hold3): (u32, u32, u32) = (0, 0, 0);
    #[rustfmt::skip]
    let (mut ra, mut rb, mut rc, mut rd, mut re, mut rf, mut rg, mut rh, mut rj, mut rk, mut rm):
        (u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    #[rustfmt::skip]
    let (mut rr, mut rs, mut rt, mut ru, mut rv, mut rw, mut rx, mut ry, mut rz):
        (u32, u32, u32, u32, u32, u32, u32, u32, u32) = (0, 0, 0, 0, 0, 0, 0, 0, 0);

    lane2[12] = (0x14u32.wrapping_add(
        (((lane1[64] as u32) & 92) | (((lane1[99] as u32) / 3) & 35))
            & (lane4[(rotl8_wide(lane4[(lane1[206] as usize) % 21], 4) as usize) % 21] as u32),
    )) as u8;

    lane1[4] = (((lane1[99] as u32) / 5)
        .wrapping_mul((lane1[99] as u32) / 5)
        .wrapping_mul(2)) as u8;

    lane2[34] = (0xb8u32) as u8;

    lane1[153] ^= ((lane2[(lane1[203] as usize) % 35] as u32)
        .wrapping_mul(lane2[(lane1[203] as usize) % 35] as u32)
        .wrapping_mul(lane1[190] as u32)) as u8;

    lane0[3] =
        lane0[3].wrapping_sub(((((lane4[(lane1[205] as usize) % 21] as u32) >> 1) & 80) | 0xe6440u32) as u8);

    lane0[16] = (0x93u32) as u8;

    lane0[13] = (0x62u32) as u8;

    lane1[33] = lane1[33].wrapping_sub(((lane4[(lane1[36] as usize) % 21] as u32) & 0xf6u32) as u8);

    hold2 = (lane2[(lane1[67] as usize) % 35] as u32);

    lane2[12] = (0x07u32) as u8;

    hold = (lane0[(lane1[181] as usize) % 20] as u32);

    lane1[2] = lane1[2].wrapping_sub((3136u32 & 0xff) as u8);

    lane0[19] = (lane4[(lane1[58] as usize) % 21] as u32) as u8;

    lane3[0] = (92u32.wrapping_sub(lane2[(lane1[32] as usize) % 35] as u32)) as u8;

    lane3[4] = ((lane2[(lane1[15] as usize) % 35] as u32).wrapping_add(0x9eu32)) as u8;

    lane1[34] = lane1[34].wrapping_add(
        (lane4[(((lane2[(lane1[15] as usize) % 35] as u32).wrapping_add(0x9eu32)) & 0xffu32) as usize % 21] / 5),
    );

    lane0[19] = lane0[19]
        .wrapping_add((0xfffffee6u32.wrapping_sub(((lane0[(lane3[4] as usize) % 20] as u32) >> 1) & 102)) as u8);

    lane1[15] = (3u32.wrapping_mul(
        (((lane1[72] as u32) >> ((lane4[(lane1[190] as usize) % 21] as u32) & 7))
            ^ ((lane1[72] as u32)
                << ((7u32.wrapping_sub((lane4[(lane1[190] as usize) % 21] as u32).wrapping_sub(1))) & 7)))
            .wrapping_sub(3u32.wrapping_mul(lane4[(lane1[126] as usize) % 21] as u32)),
    ) ^ (lane1[15] as u32)) as u8;

    lane0[15] ^= ((lane2[(lane1[181] as usize) % 35] as u32)
        .wrapping_mul(lane2[(lane1[181] as usize) % 35] as u32)
        .wrapping_mul(lane2[(lane1[181] as usize) % 35] as u32)) as u8;

    lane2[4] ^= ((lane1[202] as u32) / 3) as u8;

    ra = 92u32.wrapping_sub(lane0[(lane3[0] as usize) % 20] as u32);

    re = (ra & 0xc6u32) | (!(lane1[105] as u32) & 0xc6u32) | (ra & (!(lane1[105] as u32)));

    lane2[1] = lane2[1].wrapping_add((re.wrapping_mul(re).wrapping_mul(re)) as u8);

    lane0[19] ^= (((224 | ((lane4[(lane1[92] as usize) % 21] as u32) & 27))
        .wrapping_mul(lane2[(lane1[41] as usize) % 35] as u32))
        / 3) as u8;

    lane1[140] = lane1[140].wrapping_add((ror8_or_zero(92, (lane1[5] as u32) & 7)) as u8);

    lane2[12] = lane2[12].wrapping_add(
        (((((!(lane1[4] as u32)) ^ (lane2[(lane1[12] as usize) % 35] as u32)) | (lane1[182] as u32)) & 192)
            | (((!(lane1[4] as u32)) ^ (lane2[(lane1[12] as usize) % 35] as u32)) & (lane1[182] as u32)))
            as u8,
    );

    lane1[36] = lane1[36].wrapping_add(125_u8);

    lane1[124] = (rotl8_wide(
        ((((74u32 & (lane1[138] as u32)) | ((74u32 | (lane1[138] as u32)) & (lane0[15] as u32)))
            & (lane0[(lane1[43] as usize) % 20] as u32))
            | (((74u32 & (lane1[138] as u32))
                | ((74u32 | (lane1[138] as u32)) & (lane0[15] as u32))
                | (lane0[(lane1[43] as usize) % 20] as u32))
                & 95)) as u8,
        4,
    )) as u8;

    lane3[8] = (((((lane0[(lane3[4] as usize) % 20] as u32) & 95)
        & (((lane4[(lane1[68] as usize) % 21] as u32) & 46) << 1))
        | 16)
        ^ 92) as u8;

    ra = (lane1[177] as u32).wrapping_add(lane4[(lane1[79] as usize) % 21] as u32);

    rd = (((ra >> 1) | ((3u32.wrapping_mul(lane1[148] as u32)) / 5)) & (lane2[1] as u32))
        | ((ra >> 1) & ((3u32.wrapping_mul(lane1[148] as u32)) / 5));

    lane3[12] = (0u32.wrapping_sub(34).wrapping_sub(rd)) as u8;

    ra = 8u32.wrapping_sub((lane2[22] as u32) & 7); // NOTE: (lane2[22] as u32) = 74, so ra is always 6 and rb^rc is just ror8((lane1[33] as u32), 6);

    rb = ((lane1[33] as u32) >> (ra & 7));

    rc = (lane1[33] as u32) << ((lane2[22] as u32) & 7);

    lane2[16] = lane2[16].wrapping_add(
        ((((lane2[(lane3[0] as usize) % 35] as u32) & 159) | (lane0[(lane3[4] as usize) % 20] as u32) | 8)
            .wrapping_sub((rb ^ rc) | 128)) as u8,
    );

    lane0[14] ^= (lane2[(lane3[12] as usize) % 35] as u32) as u8;

    ra = rol8_or_zero(
        lane4[(lane0[(lane1[201] as usize) % 20] as usize) % 21],
        (((lane2[(lane1[112] as usize) % 35] as u32) << 1) & 7),
    );

    rd = ((lane0[(lane1[208] as usize) % 20] as u32) & 131) | ((lane0[(lane1[164] as usize) % 20] as u32) & 124);

    lane1[19] = lane1[19].wrapping_add(((ra & (rd / 5)) | ((ra | (rd / 5)) & 37)) as u8);

    lane2[8] = (ror8_or_zero(
        140,
        (((lane4[(lane1[45] as usize) % 21] as u32).wrapping_add(92))
            .wrapping_mul((lane4[(lane1[45] as usize) % 21] as u32).wrapping_add(92)))
            & 7,
    )) as u8;

    lane1[190] = 56_u8;

    lane2[8] ^= (lane3[0] as u32) as u8;

    lane1[53] = (!(((lane0[(lane1[83] as usize) % 20] as u32) | 204) / 5)) as u8;

    lane0[13] = lane0[13].wrapping_add((lane0[(lane1[41] as usize) % 20] as u32) as u8);

    lane0[10] = ((((lane2[(lane3[0] as usize) % 35] as u32) & (lane1[2] as u32))
        | (((lane2[(lane3[0] as usize) % 35] as u32) | (lane1[2] as u32)) & (lane3[12] as u32)))
        / 15) as u8;

    ra = (((56 | ((lane4[(lane1[2] as usize) % 21] as u32) & 68)) | (lane2[(lane3[8] as usize) % 35] as u32))
        & 42)
        | ((((lane4[(lane1[2] as usize) % 21] as u32) & 68) | 56) & (lane2[(lane3[8] as usize) % 35] as u32));

    lane3[16] = (ra.wrapping_mul(ra).wrapping_add(110)) as u8;

    lane3[20] = (202u32.wrapping_sub(lane3[16] as u32)) as u8;

    lane3[24] = (lane1[151] as u32) as u8;

    lane2[13] ^= (lane4[(lane3[0] as usize) % 21] as u32) as u8;

    rb = (((lane2[(lane1[179] as usize) % 35] as u32).wrapping_sub(38)) & 177) | ((lane3[12] as u32) & 177);

    rc = ((lane2[(lane1[179] as usize) % 35] as u32).wrapping_sub(38)) & (lane3[12] as u32);

    lane3[28] = (30u32.wrapping_add((rb | rc).wrapping_mul(rb | rc))) as u8;

    lane3[32] = ((lane3[28] as u32).wrapping_add(62)) as u8;

    ra = (((lane3[20] as u32).wrapping_add((lane3[0] as u32) & 74)) | !(lane4[(lane3[0] as usize) % 21] as u32))
        & 121;

    rb = (((lane3[20] as u32).wrapping_add((lane3[0] as u32) & 74)) & !(lane4[(lane3[0] as usize) % 21] as u32));

    hold3 = (ra | rb);

    rc = ((((ra | rb) ^ 0xffffffa6u32) | (lane3[0] as u32)) & 4) | (((ra | rb) ^ 0xffffffa6u32) & (lane3[0] as u32));

    lane1[47] = (((lane2[(lane1[89] as usize) % 35] as u32).wrapping_add(rc)) ^ (lane1[47] as u32)) as u8;

    lane3[36] = ((((rotl8(((hold & 179).wrapping_add(68)) as u8, 2) as u32) & (lane0[3] as u32))
        | (hold2 & !(lane0[3] as u32)))
        .wrapping_sub(15)) as u8;

    lane1[123] ^= 221_u8;

    ra = ((lane4[(lane3[0] as usize) % 21] as u32) / 3).wrapping_sub(lane2[(lane3[4] as usize) % 35] as u32);

    rc = ((((lane3[0] as u32) & 163).wrapping_add(92)) & 246) | ((lane3[0] as u32) & 92);

    re = ((rc | (lane3[24] as u32)) & 54) | (rc & (lane3[24] as u32));

    lane3[40] = (ra.wrapping_sub(re)) as u8;

    lane3[44] = (hold3 ^ 81 ^ ((((lane3[0] as u32) >> 1) & 101).wrapping_add(26))) as u8;

    lane3[48] = ((lane2[(lane3[4] as usize) % 35] as u32) & 27) as u8;

    lane3[52] = 27_u8;

    lane3[56] = 199_u8;

    lane3[64] = ((lane3[4] as u32).wrapping_add(
        ((((((((lane3[40] as u32) | (lane3[24] as u32)) & 177) | ((lane3[40] as u32) & (lane3[24] as u32)))
            & ((((lane4[(lane3[0] as usize) % 20] as u32) & 177) | 176)
                | ((lane4[(lane3[0] as usize) % 21] as u32) & !3u32)))
            | (((((lane3[40] as u32) & (lane3[24] as u32))
                | (((lane3[40] as u32) | (lane3[24] as u32)) & 177))
                & 199)
                | (((((lane4[(lane3[0] as usize) % 21] as u32) & 1).wrapping_add(176))
                    | ((lane4[(lane3[0] as usize) % 21] as u32) & !3u32))
                    & (lane3[56] as u32))))
            & (!(lane3[52] as u32)))
            | (lane3[48] as u32)),
    )) as u8;

    lane2[33] ^= (lane1[26] as u32) as u8;

    lane1[106] ^= ((lane3[20] as u32) ^ 133) as u8;

    lane2[30] = ((((lane3[64] as u32) / 3).wrapping_sub(275 | ((lane3[0] as u32) & 247)))
        ^ (lane0[(lane1[122] as usize) % 20] as u32)) as u8;

    lane1[22] = (((lane2[(lane1[90] as usize) % 35] as u32) & 95) | 68) as u8;

    ra = ((lane4[(lane3[36] as usize) % 21] as u32) & 184)
        | ((lane2[(lane3[44] as usize) % 35] as u32) & !184u32);

    lane2[18] = lane2[18].wrapping_add(((ra.wrapping_mul(ra).wrapping_mul(ra)) >> 1) as u8);

    lane2[5] = lane2[5].wrapping_sub((lane4[(lane1[92] as usize) % 21] as u32) as u8);

    ra = ((((lane1[41] as u32) & !24u32) | ((lane2[(lane1[183] as usize) % 35] as u32) & 24))
        & ((lane3[16] as u32).wrapping_add(53)))
        | ((lane3[20] as u32) & (lane2[(lane3[20] as usize) % 35] as u32));

    rb = ((lane1[17] as u32) & (!(lane3[44] as u32)))
        | ((lane0[(lane1[59] as usize) % 20] as u32) & (lane3[44] as u32));

    lane2[18] ^= (ra.wrapping_mul(rb)) as u8;

    ra = ror8_or_zero(lane1[11], (lane2[(lane1[28] as usize) % 35] as u32) & 7) & 7;

    rb = ((((lane0[(lane1[93] as usize) % 20] as u32) & !(lane0[14] as u32)) | ((lane0[14] as u32) & 150))
        & !28u32)
        | ((lane1[7] as u32) & 28);

    lane2[22] = (((((rb | rol8_or_zero(((lane2[(lane3[0] as usize) % 35] as u32) as u8), ra))
        & (lane2[33] as u32))
        | (rb & rol8_or_zero(((lane2[(lane3[0] as usize) % 35] as u32) as u8), ra)))
    .wrapping_add(74))
        & 0xffu32) as u8;

    ra = (lane4[(((lane0[(lane1[39] as usize) % 20] as u32) ^ 217) as usize) % 21] as u32); // X5;

    lane0[15] = lane0[15].wrapping_sub(
        ((((((lane3[20] as u32) | (lane3[0] as u32)) & 214) | ((lane3[20] as u32) & (lane3[0] as u32))) & ra)
            | (((((lane3[20] as u32) | (lane3[0] as u32)) & 214)
                | ((lane3[20] as u32) & (lane3[0] as u32))
                | ra)
                & (lane3[32] as u32))) as u8,
    );

    rb = ((((lane2[(lane1[57] as usize) % 35] as u32) & (lane0[(lane3[64] as usize) % 20] as u32))
        | (((lane0[(lane3[64] as usize) % 20] as u32) | (lane2[(lane1[57] as usize) % 35] as u32)) & 95)
        | ((lane3[64] as u32) & 45)
        | 82)
        & 32);

    rc = (((lane2[(lane1[57] as usize) % 35] as u32) & (lane0[(lane3[64] as usize) % 20] as u32))
        | (((lane2[(lane1[57] as usize) % 35] as u32) | (lane0[(lane3[64] as usize) % 20] as u32)) & 95))
        & (((lane3[64] as u32) & 45) | 82);

    rd = ((((lane3[0] as u32) / 3).wrapping_sub((lane3[64] as u32) | (lane1[22] as u32)))
        ^ ((lane3[28] as u32).wrapping_add(62))
        ^ (rb | rc));

    rt = lane0[((rd & 0xffu32) as usize) % 20] as u32;

    lane3[68] = ((lane0[(lane1[99] as usize) % 20] as u32)
        .wrapping_mul(lane0[(lane1[99] as usize) % 20] as u32)
        .wrapping_mul(lane0[(lane1[99] as usize) % 20] as u32)
        .wrapping_mul(lane0[(lane1[99] as usize) % 20] as u32)
        | (lane2[(lane3[64] as usize) % 35] as u32)) as u8;

    ru = (lane0[(lane1[50] as usize) % 20] as u32); // this is also v100;

    rw = (lane2[(lane1[138] as usize) % 35] as u32);

    rx = (lane4[(lane1[39] as usize) % 21] as u32);

    ry = (lane0[(lane1[4] as usize) % 20] as u32); // this is also v120;

    rz = (lane4[(lane1[202] as usize) % 21] as u32); // also v124;

    rv = (lane0[(lane1[151] as usize) % 20] as u32);

    rs = (lane2[(lane1[14] as usize) % 35] as u32);

    rr = (lane0[(lane1[145] as usize) % 20] as u32);

    ra = ((lane2[(lane3[68] as usize) % 35] as u32) & (lane0[(lane1[209] as usize) % 20] as u32))
        | (((lane2[(lane3[68] as usize) % 35] as u32) | (lane0[(lane1[209] as usize) % 20] as u32)) & 24);

    rb = rol8_or_zero(
        ((lane4[(lane1[127] as usize) % 21] as u32) as u8),
        (lane2[(lane3[68] as usize) % 35] as u32) & 7,
    );

    rc = (ra & (lane0[10] as u32)) | (rb & !(lane0[10] as u32));

    rd = 7 ^ ((lane4[(lane2[(lane3[36] as usize) % 35] as usize) % 21] as u32) << 1);

    lane3[72] = ((rc & 71) | (rd & !71u32)) as u8;

    lane2[2] = lane2[2].wrapping_add(
        (((((lane0[(lane3[20] as usize) % 20] as u32) << 1) & 159)
            | ((lane4[(lane1[190] as usize) % 21] as u32) & !159u32))
            & (((((lane4[(lane3[64] as usize) % 21] as u32) & 110)
                | ((lane0[(lane1[25] as usize) % 20] as u32) & !110u32))
                & !150u32)
                | ((lane1[25] as u32) & 150))) as u8,
    );

    lane2[14] = lane2[14].wrapping_sub(
        ((((lane2[(lane3[20] as usize) % 35] as u32)
            & ((lane3[72] as u32) ^ (lane2[(lane1[100] as usize) % 35] as u32)))
            & !34u32)
            | ((lane1[97] as u32) & 34)) as u8,
    );

    lane0[17] = 115_u8;

    lane1[23] ^= ((((((lane4[(lane1[17] as usize) % 21] as u32 | lane0[(lane3[20] as usize) % 20] as u32)
        & lane3[72] as u32)
        | (lane4[(lane1[17] as usize) % 21] as u32 & lane0[(lane3[20] as usize) % 20] as u32))
        & (lane1[50] as u32 / 3))
        | ((((lane4[(lane1[17] as usize) % 21] as u32 | lane0[(lane3[20] as usize) % 20] as u32)
            & lane3[72] as u32)
            | (lane4[(lane1[17] as usize) % 21] as u32 & lane0[(lane3[20] as usize) % 20] as u32)
            | (lane1[50] as u32 / 3))
            & 246))
        << 1) as u8;

    lane0[13] = ((((((lane0[(lane3[40] as usize) % 20] as u32 | lane1[10] as u32) & 82)
        | (lane0[(lane3[40] as usize) % 20] as u32 & lane1[10] as u32))
        & 209)
        | ((lane0[(lane1[39] as usize) % 20] as u32) << 1) & 46)
        >> 1) as u8;

    lane2[33] = lane2[33].wrapping_sub(((lane1[113] as u32) & 9) as u8);

    lane2[28] = lane2[28]
        .wrapping_sub(((((2 | ((lane1[110] as u32) & 222)) >> 1) & !223u32) | ((lane3[20] as u32) & 223)) as u8);

    rj = rol8_or_zero((rv | rz) as u8, (ru & 7)); // OK;

    ra = ((lane2[16] as u32) & rt) | (rw & (!(lane2[16] as u32)));

    rb = ((lane1[33] as u32) & 17) | (rx & !17u32);

    re = ((ry | ((ra.wrapping_add(rb)) / 5)) & 147) | (ry & ((ra.wrapping_add(rb)) / 5));

    rm = ((lane3[40] as u32)
        & (lane4[(((lane3[8] as u32).wrapping_add(rj).wrapping_add(re)) & 0xffu32) as usize % 21] as u32))
        | (((lane3[40] as u32)
            | (lane4[(((lane3[8] as u32).wrapping_add(rj).wrapping_add(re)) & 0xffu32) as usize % 21] as u32))
            & (lane2[23] as u32));

    lane0[15] = (((((lane4[(lane3[20] as usize) % 21] as u32).wrapping_sub(48)) & (!(lane1[184] as u32)))
        | (((lane4[(lane3[20] as usize) % 21] as u32).wrapping_sub(48)) & 189)
        | (189 & !(lane1[184] as u32)))
        & (rm.wrapping_mul(rm).wrapping_mul(rm))) as u8;

    lane2[22] = lane2[22].wrapping_add((lane1[183] as u32) as u8);

    lane3[76] = (3u32.wrapping_mul(lane4[(lane1[1] as usize) % 21] as u32) ^ (lane3[0] as u32)) as u8;

    ra = (lane2[((((lane3[8] as u32).wrapping_add(rj.wrapping_add(re))) & 0xffu32) as usize) % 35] as u32);

    rf = ((((lane4[(lane1[178] as usize) % 21] as u32) & ra)
        | (((lane4[(lane1[178] as usize) % 21] as u32) | ra) & 209))
        .wrapping_mul(lane0[(lane1[13] as usize) % 20] as u32))
    .wrapping_mul((lane4[(lane1[26] as usize) % 21] as u32) >> 1);

    rg = (rf.wrapping_add(0x733ffff9u32))
        .wrapping_mul(198)
        .wrapping_sub(((rf.wrapping_add(0x733ffff9u32)).wrapping_mul(396).wrapping_add(212)) & 212)
        .wrapping_add(85);

    lane3[80] = ((lane3[36] as u32)
        .wrapping_add(rg ^ 148)
        .wrapping_add((rg ^ 107) << 1)
        .wrapping_sub(127)) as u8;

    lane3[84] = (((lane2[(lane3[64] as usize) % 35] as u32) & 245)
        | ((lane2[(lane3[20] as usize) % 35] as u32) & 10)) as u8;

    ra = (lane0[(lane3[68] as usize) % 20] as u32) | 81;

    lane2[18] = lane2[18].wrapping_sub(
        (((ra.wrapping_mul(ra).wrapping_mul(ra)) & !(lane0[15] as u32))
            | (((lane3[80] as u32) / 15) & (lane0[15] as u32))) as u8,
    );

    lane3[88] = ((lane3[8] as u32)
        .wrapping_add(rj)
        .wrapping_add(re)
        .wrapping_sub(lane0[(lane1[160] as usize) % 20] as u32)
        .wrapping_add(
            (lane4
                [(lane0[((((lane3[8] as u32).wrapping_add(rj).wrapping_add(re)) & 255) as usize) % 20] as usize) % 21]
                as u32
                / 3),
        )) as u8;

    rb = ((rr ^ (lane3[72] as u32)) & !198u32) | ((rs.wrapping_mul(rs)) & 198);

    rf = ((lane4[(lane1[69] as usize) % 21] as u32) & (lane1[172] as u32))
        | (((lane4[(lane1[69] as usize) % 21] as u32) | (lane1[172] as u32))
            & (((lane3[12] as u32).wrapping_sub(rb)).wrapping_add(77)));

    lane0[16] = (147u32
        .wrapping_sub(((lane3[72] as u32) & ((rf & 251) | 1)) | (((rf & 250) | (lane3[72] as u32)) & 198)))
        as u8;

    rc = ((lane4[(lane1[168] as usize) % 21] as u32) & (lane0[(lane1[29] as usize) % 20] as u32) & 7)
        | (((lane4[(lane1[168] as usize) % 21] as u32) | (lane0[(lane1[29] as usize) % 20] as u32)) & 6);

    rf = ((lane4[(lane1[155] as usize) % 21] as u32) & (lane1[105] as u32))
        | (((lane4[(lane1[155] as usize) % 21] as u32) | (lane1[105] as u32)) & 141);

    lane0[3] = lane0[3].wrapping_sub(lane4[(shl_shr_xor(rf as u8, rc)) as usize % 21]);

    lane1[5] = (ror8_or_zero(lane0[12], ((lane0[(lane1[61] as usize) % 20] as u32 / 5) & 7))
        ^ (!(lane2[(lane3[84] as usize) % 35] as u32) / 5)) as u8;

    lane1[198] = lane1[198].wrapping_add((lane1[3] as u32) as u8);

    ra = (162 | (lane2[(lane3[64] as usize) % 35] as u32));

    lane1[164] = lane1[164].wrapping_add(((ra.wrapping_mul(ra)) / 5) as u8);

    rg = ror8_or_zero(139, ((lane3[80] as u32) & 7));

    rc = (((lane4[(lane3[64] as usize) % 21] as u32)
        .wrapping_mul(lane4[(lane3[64] as usize) % 21] as u32)
        .wrapping_mul(lane4[(lane3[64] as usize) % 21] as u32))
        & 95)
        | ((lane0[(lane3[40] as usize) % 20] as u32) & !95u32);

    lane3[92] = ((rg & 12)
        | ((lane0[(lane3[20] as usize) % 20] as u32) & 12)
        | (rg & (lane0[(lane3[20] as usize) % 20] as u32))
        | rc) as u8;

    lane2[12] = lane2[12].wrapping_add(
        ((((lane1[103] as u32) & 32) | ((lane3[92] as u32) & ((lane1[103] as u32) | 60)) | 16) / 3) as u8,
    );

    lane3[96] = (lane1[143] as u32) as u8;

    lane3[100] = 27_u8;

    lane3[104] = (((((lane3[40] as u32) & !(lane2[8] as u32)) | ((lane1[35] as u32) & (lane2[8] as u32)))
        & (lane3[64] as u32))
        ^ 119) as u8;

    lane3[108] = (238
        & (((((lane3[40] as u32) & !(lane2[8] as u32)) | ((lane1[35] as u32) & (lane2[8] as u32)))
            & (lane3[64] as u32))
            << 1)) as u8;

    lane3[112] = ((!(lane3[64] as u32) & ((lane3[84] as u32) / 3)) ^ 49) as u8;

    lane3[116] = (98 & ((!(lane3[64] as u32) & ((lane3[84] as u32) / 3)) << 1)) as u8;

    ra = ((lane1[35] as u32) & (lane2[8] as u32)) | ((lane3[40] as u32) & !(lane2[8] as u32));

    rb = (ra & (lane3[64] as u32)) | (((lane3[84] as u32) / 3) & !(lane3[64] as u32));

    lane1[143] = ((lane3[96] as u32).wrapping_sub(
        (rb & (86u32.wrapping_add(((lane1[172] as u32) & 64) >> 1)))
            | ((((((lane1[172] as u32) & 65) >> 1) ^ 86)
                | ((!(lane3[64] as u32) & ((lane3[84] as u32) / 3))
                    | ((((lane3[40] as u32) & !(lane2[8] as u32))
                        | ((lane1[35] as u32) & (lane2[8] as u32)))
                        & (lane3[64] as u32))))
                & (lane3[100] as u32)),
    )) as u8;

    lane2[29] = 162_u8;

    ra = ((((lane4[(lane3[88] as usize) % 21] as u32) & 160)
        | ((lane0[(lane1[125] as usize) % 20] as u32) & 95))
        >> 1);

    rb = (lane2[(lane1[149] as usize) % 35] as u32) ^ ((lane1[43] as u32).wrapping_mul(lane1[43] as u32));

    lane0[15] = lane0[15].wrapping_add(((rb & ra) | ((ra | rb) & 115)) as u8);

    lane3[120] = ((lane3[64] as u32).wrapping_sub(lane0[(lane3[40] as usize) % 20] as u32)) as u8;

    lane1[95] = (lane4[(lane3[20] as usize) % 21] as u32) as u8;

    ra = ror8_or_zero(
        lane2[(lane3[80] as usize) % 35],
        ((lane2[(lane1[17] as usize) % 35] as u32)
            .wrapping_mul(lane2[(lane1[17] as usize) % 35] as u32)
            .wrapping_mul(lane2[(lane1[17] as usize) % 35] as u32))
            & 7,
    );

    lane0[7] = lane0[7].wrapping_sub((ra.wrapping_mul(ra)) as u8);

    lane2[8] = ((lane2[8] as u32).wrapping_sub(lane1[184] as u32).wrapping_add(
        (lane4[(lane1[202] as usize) % 21] as u32)
            .wrapping_mul(lane4[(lane1[202] as usize) % 21] as u32)
            .wrapping_mul(lane4[(lane1[202] as usize) % 21] as u32),
    )) as u8;

    lane0[16] = (((lane2[(lane1[102] as usize) % 35] as u32) << 1) & 132) as u8;

    lane3[124] = (((lane4[(lane3[40] as usize) % 21] as u32) >> 1) ^ (lane3[68] as u32)) as u8;

    lane0[7] = lane0[7].wrapping_sub(
        ((lane0[(lane1[191] as usize) % 20] as u32).wrapping_sub(
            (((lane4[(lane1[80] as usize) % 21] as u32) << 1) & !177u32)
                | ((lane4[(lane4[(lane3[88] as usize) % 21] as usize) % 21] as u32) & 177),
        )) as u8,
    );

    lane0[6] = (lane0[(lane1[119] as usize) % 20] as u32) as u8;

    ra = ((lane4[(lane1[190] as usize) % 21] as u32) & !209u32) | ((lane1[118] as u32) & 209);

    rb = (lane0[(lane3[120] as usize) % 20] as u32).wrapping_mul(lane0[(lane3[120] as usize) % 20] as u32);

    lane0[12] = (((lane0[(lane3[84] as usize) % 20] as u32)
        ^ ((lane2[(lane1[71] as usize) % 35] as u32).wrapping_add(lane2[(lane1[15] as usize) % 35] as u32)))
        & ((ra & rb) | ((ra | rb) & 27))) as u8;

    rb = ((lane1[32] as u32) & (lane2[(lane3[88] as usize) % 35] as u32))
        | (((lane1[32] as u32) | (lane2[(lane3[88] as usize) % 35] as u32)) & 23);

    rd = ((((lane4[(lane1[57] as usize) % 21] as u32).wrapping_mul(231)) & 169) | (rb & 86));

    rf = ((((lane0[(lane1[82] as usize) % 20] as u32) & !29u32)
        | ((lane4[(lane3[124] as usize) % 21] as u32) & 29))
        & 190)
        | ((lane4[((rd / 5) as usize) % 21] as u32) & !190u32);

    rh = (lane0[(lane3[40] as usize) % 20] as u32)
        .wrapping_mul(lane0[(lane3[40] as usize) % 20] as u32)
        .wrapping_mul(lane0[(lane3[40] as usize) % 20] as u32);

    rk = (rh & (lane1[82] as u32)) | (rh & 92) | ((lane1[82] as u32) & 92);

    lane3[128] = (((rf & rk) | ((rf | rk) & 192)) ^ (rd / 5)) as u8;

    lane2[25] ^= ((((lane0[(lane3[120] as usize) % 20] as u32) << 1).wrapping_mul(lane1[5] as u32))
        .wrapping_sub(
            rol8_or_zero(
                ((lane3[76] as u32) as u8),
                ((lane4[(lane3[124] as usize) % 21] as u32) & 7),
            ) & ((lane3[20] as u32).wrapping_add(110)),
        )) as u8;
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::blend;

    /// Run the blender with deterministic input (same seed pattern as rc test harness)
    /// and compare all four output buffers against precomputed interoperability vectors.
    fn run_blend_test(
        seed: i32,
        expected_b0: &[u8; 20],
        expected_b1: &[u8; 210],
        expected_b2: &[u8; 35],
        expected_b3: &[u8; 132],
    ) {
        let mut b0 = [0u8; 20];
        let mut b1 = [0u8; 210];
        let mut b2 = [0u8; 35];
        let mut b3 = [0u8; 132];
        let mut b4 = [0u8; 21];

        for (i, slot) in b0.iter_mut().enumerate() {
            *slot = ((i as i32 * 37 + seed) & 0xff) as u8;
        }
        for (i, slot) in b1.iter_mut().enumerate() {
            *slot = ((i as i32 * 73 + seed + 7) & 0xff) as u8;
        }
        for (i, slot) in b2.iter_mut().enumerate() {
            *slot = ((i as i32 * 51 + seed + 29) & 0xff) as u8;
        }
        for (i, slot) in b3.iter_mut().enumerate() {
            *slot = ((i as i32 * 19 + seed + 41) & 0xff) as u8;
        }
        for (i, slot) in b4.iter_mut().enumerate() {
            *slot = ((i as i32 * 97 + seed + 3) & 0xff) as u8;
        }

        blend(&mut b0, &mut b1, &mut b2, &mut b3, &b4);

        assert_eq!(&b0, expected_b0, "lane0 mismatch for seed {seed}");
        assert_eq!(&b1, expected_b1, "lane1 mismatch for seed {seed}");
        assert_eq!(&b2, expected_b2, "lane2 mismatch for seed {seed}");
        assert_eq!(&b3, expected_b3, "lane3 mismatch for seed {seed}");
    }

    #[test]
    fn blend_seed_13() {
        const B0: [u8; 20] = [
            0x0d, 0x32, 0x57, 0x52, 0xa1, 0xc6, 0x52, 0xae, 0x35, 0x5a, 0x0d, 0xa4, 0x0a, 0x64, 0xad, 0x0a, 0x04, 0x73,
            0xa7, 0x25,
        ];
        const B1: [u8; 210] = [
            0x14, 0x5d, 0x66, 0xef, 0xc2, 0x5e, 0xca, 0x13, 0x5c, 0xa5, 0xee, 0x37, 0x80, 0xc9, 0x12, 0x0c, 0xa4, 0xed,
            0x36, 0x80, 0xc8, 0x11, 0x47, 0x4b, 0xec, 0x35, 0x7e, 0xc7, 0x10, 0x59, 0xa2, 0xeb, 0x34, 0xe9, 0xcc, 0x0f,
            0xd5, 0xa1, 0xea, 0x33, 0x7c, 0xc5, 0x0e, 0x57, 0xa0, 0xe9, 0x32, 0xe3, 0xc4, 0x0d, 0x56, 0x9f, 0xe8, 0xd0,
            0x7a, 0xc3, 0x0c, 0x55, 0x9e, 0xe7, 0x30, 0x79, 0xc2, 0x0b, 0x54, 0x9d, 0xe6, 0x2f, 0x78, 0xc1, 0x0a, 0x53,
            0x9c, 0xe5, 0x2e, 0x77, 0xc0, 0x09, 0x52, 0x9b, 0xe4, 0x2d, 0x76, 0xbf, 0x08, 0x51, 0x9a, 0xe3, 0x2c, 0x75,
            0xbe, 0x07, 0x50, 0x99, 0xe2, 0xb7, 0x74, 0xbd, 0x06, 0x4f, 0x98, 0xe1, 0x2a, 0x73, 0xbc, 0x05, 0xd7, 0x97,
            0xe0, 0x29, 0x72, 0xbb, 0x04, 0x4d, 0x96, 0xdf, 0x28, 0x71, 0xba, 0x03, 0x4c, 0x95, 0xde, 0xfa, 0xa5, 0xb9,
            0x02, 0x4b, 0x94, 0xdd, 0x26, 0x6f, 0xb8, 0x01, 0x4a, 0x93, 0xdc, 0x25, 0x6e, 0xb7, 0x2e, 0x49, 0x92, 0xbc,
            0x24, 0x6d, 0xb6, 0xff, 0x48, 0x91, 0xda, 0x23, 0x6c, 0xb5, 0xfe, 0x47, 0x90, 0xd9, 0x22, 0x6b, 0xb4, 0xfd,
            0x46, 0x8f, 0x10, 0x21, 0x6a, 0xb3, 0xfc, 0x45, 0x8e, 0xd7, 0x20, 0x69, 0xb2, 0xfb, 0x44, 0x8d, 0xd6, 0x1f,
            0x68, 0xb1, 0xfa, 0x43, 0x8c, 0xd5, 0x1e, 0x67, 0xb0, 0xf9, 0x38, 0x8b, 0xd4, 0x1d, 0x66, 0xaf, 0xf8, 0x41,
            0x79, 0xd3, 0x1c, 0x65, 0xae, 0xf7, 0x40, 0x89, 0xd2, 0x1b, 0x64, 0xad,
        ];
        const B2: [u8; 35] = [
            0x2a, 0x15, 0x90, 0xc3, 0xcc, 0xa8, 0x5c, 0x8f, 0x13, 0xf5, 0x28, 0x5b, 0xda, 0x23, 0xb8, 0x27, 0x56, 0x8d,
            0xba, 0xf3, 0x26, 0x59, 0x4d, 0xbf, 0xf2, 0x4b, 0x58, 0x8b, 0x82, 0xa2, 0x21, 0x57, 0x8a, 0xba, 0xb8,
        ];
        const B3: [u8; 132] = [
            0xcf, 0x49, 0x5c, 0x6f, 0xf7, 0x95, 0xa8, 0xbb, 0x4c, 0xe1, 0xf4, 0x07, 0xcb, 0x2d, 0x40, 0x53, 0xae, 0x79,
            0x8c, 0x9f, 0x1c, 0xc5, 0xd8, 0xeb, 0x23, 0x11, 0x24, 0x37, 0x7f, 0x5d, 0x70, 0x83, 0xbd, 0xa9, 0xbc, 0xcf,
            0x39, 0xf5, 0x08, 0x1b, 0x85, 0x41, 0x54, 0x67, 0x53, 0x8d, 0xa0, 0xb3, 0x10, 0xd9, 0xec, 0xff, 0x1b, 0x25,
            0x38, 0x4b, 0xc7, 0x71, 0x84, 0x97, 0xaa, 0xbd, 0xd0, 0xe3, 0xe7, 0x09, 0x1c, 0x2f, 0xf9, 0x55, 0x68, 0x7b,
            0xf4, 0xa1, 0xb4, 0xc7, 0xa4, 0xed, 0x00, 0x13, 0x39, 0x39, 0x4c, 0x5f, 0x53, 0x85, 0x98, 0xab, 0x41, 0xd1,
            0xe4, 0xf7, 0x25, 0x1d, 0x30, 0x43, 0xdb, 0x69, 0x7c, 0x8f, 0x1b, 0xb5, 0xc8, 0xdb, 0xf0, 0x01, 0x14, 0x27,
            0x0e, 0x4d, 0x60, 0x73, 0x29, 0x99, 0xac, 0xbf, 0x20, 0xe5, 0xf8, 0x0b, 0x83, 0x31, 0x44, 0x57, 0xa2, 0x7d,
            0x90, 0xa3, 0xf0, 0xc9, 0xdc, 0xef,
        ];
        run_blend_test(13, &B0, &B1, &B2, &B3);
    }

    #[test]
    fn blend_seed_0() {
        const B0: [u8; 20] = [
            0x00, 0x25, 0x4a, 0x52, 0x94, 0xb9, 0xde, 0xd6, 0x28, 0x4d, 0x01, 0x97, 0x00, 0x32, 0x49, 0x32, 0x04, 0x73,
            0x9a, 0x84,
        ];
        const B1: [u8; 210] = [
            0x07, 0x50, 0x59, 0xe2, 0x52, 0x28, 0xbd, 0x06, 0x4f, 0x98, 0xe1, 0x2a, 0x73, 0xbc, 0x05, 0xaf, 0x97, 0xe0,
            0x29, 0x77, 0xbb, 0x04, 0x47, 0x66, 0xdf, 0x28, 0x71, 0xba, 0x03, 0x4c, 0x95, 0xde, 0x27, 0xea, 0xd7, 0x02,
            0xc8, 0x94, 0xdd, 0x26, 0x6f, 0xb8, 0x01, 0x4a, 0x93, 0xdc, 0x25, 0x62, 0xb7, 0x00, 0x49, 0x92, 0xdb, 0xd3,
            0x6d, 0xb6, 0xff, 0x48, 0x91, 0xda, 0x23, 0x6c, 0xb5, 0xfe, 0x47, 0x90, 0xd9, 0x22, 0x6b, 0xb4, 0xfd, 0x46,
            0x8f, 0xd8, 0x21, 0x6a, 0xb3, 0xfc, 0x45, 0x8e, 0xd7, 0x20, 0x69, 0xb2, 0xfb, 0x44, 0x8d, 0xd6, 0x1f, 0x68,
            0xb1, 0xfa, 0x43, 0x8c, 0xd5, 0xaa, 0x67, 0xb0, 0xf9, 0x42, 0x8b, 0xd4, 0x1d, 0x66, 0xaf, 0xf8, 0xd8, 0x8a,
            0xd3, 0x1c, 0x65, 0xae, 0xf7, 0x40, 0x89, 0xd2, 0x1b, 0x64, 0xad, 0xf6, 0x3f, 0x88, 0xd1, 0xc7, 0x64, 0xac,
            0xf5, 0x3e, 0x87, 0xd0, 0x19, 0x62, 0xab, 0xf4, 0x3d, 0x86, 0xcf, 0x18, 0x61, 0xaa, 0xb8, 0x3c, 0x85, 0xb7,
            0x17, 0x60, 0xa9, 0xf2, 0x3b, 0x84, 0xcd, 0x16, 0x5f, 0x45, 0xf1, 0x3a, 0x83, 0xcc, 0x15, 0x5e, 0xa7, 0xf0,
            0x39, 0x82, 0x03, 0x14, 0x5d, 0xa6, 0xef, 0x38, 0x81, 0xca, 0x13, 0x5c, 0xa5, 0xee, 0x37, 0x80, 0xc9, 0x12,
            0x5b, 0xa4, 0xed, 0x36, 0x7f, 0xc8, 0x11, 0x5a, 0xa3, 0xec, 0x38, 0x7e, 0xc7, 0x10, 0x59, 0xa2, 0xeb, 0x34,
            0x5f, 0xc6, 0x0f, 0x58, 0xa1, 0xea, 0x33, 0x7c, 0xc5, 0x0e, 0x57, 0xa0,
        ];
        const B2: [u8; 35] = [
            0x1d, 0x28, 0xc3, 0xb6, 0xdc, 0x95, 0x4f, 0x82, 0xa7, 0xe8, 0x1b, 0x4e, 0xfd, 0x79, 0x37, 0x1a, 0x77, 0x80,
            0xc1, 0xe6, 0x19, 0x4c, 0x80, 0xb2, 0xe5, 0xce, 0x4b, 0x7e, 0x75, 0xa2, 0xd0, 0x4a, 0x7d, 0xc1, 0xb8,
        ];
        const B3: [u8; 132] = [
            0x73, 0x3c, 0x4f, 0x62, 0x53, 0x88, 0x9b, 0xae, 0x44, 0xd4, 0xe7, 0xfa, 0xb5, 0x20, 0x33, 0x46, 0xae, 0x6c,
            0x7f, 0x92, 0x1c, 0xb8, 0xcb, 0xde, 0x16, 0x04, 0x17, 0x2a, 0x17, 0x50, 0x63, 0x76, 0x55, 0x9c, 0xaf, 0xc2,
            0xa4, 0xe8, 0xfb, 0x0e, 0x95, 0x34, 0x47, 0x5a, 0x10, 0x80, 0x93, 0xa6, 0x19, 0xcc, 0xdf, 0xf2, 0x1b, 0x18,
            0x2b, 0x3e, 0xc7, 0x64, 0x77, 0x8a, 0x9d, 0xb0, 0xc3, 0xd6, 0x30, 0xfc, 0x0f, 0x22, 0x79, 0x48, 0x5b, 0x6e,
            0x6a, 0x94, 0xa7, 0xba, 0x2f, 0xe0, 0xf3, 0x06, 0x74, 0x2c, 0x3f, 0x52, 0x71, 0x78, 0x8b, 0x9e, 0x35, 0xc4,
            0xd7, 0xea, 0x39, 0x10, 0x23, 0x36, 0xce, 0x5c, 0x6f, 0x82, 0x1b, 0xa8, 0xbb, 0xce, 0x77, 0xf4, 0x07, 0x1a,
            0x00, 0x40, 0x53, 0x66, 0x34, 0x8c, 0x9f, 0xb2, 0x02, 0xd8, 0xeb, 0xfe, 0xe3, 0x24, 0x37, 0x4a, 0x1b, 0x70,
            0x83, 0x96, 0xcf, 0xbc, 0xcf, 0xe2,
        ];
        run_blend_test(0, &B0, &B1, &B2, &B3);
    }

    #[test]
    fn blend_seed_255() {
        const B0: [u8; 20] = [
            0xff, 0x24, 0x49, 0xe6, 0x93, 0xb8, 0xb8, 0xe7, 0x27, 0x4c, 0x08, 0x96, 0x81, 0x73, 0x79, 0x5c, 0x00, 0x73,
            0x99, 0xc4,
        ];
        const B1: [u8; 210] = [
            0x06, 0x4f, 0x58, 0xe1, 0x52, 0x0f, 0xbc, 0x05, 0x4e, 0x97, 0xe0, 0x29, 0x72, 0xbb, 0x04, 0x1c, 0x96, 0xdf,
            0x28, 0x92, 0xba, 0x03, 0x57, 0x69, 0xde, 0x27, 0x70, 0xb9, 0x02, 0x4b, 0x94, 0xdd, 0x26, 0x4b, 0xe0, 0x01,
            0xc7, 0x93, 0xdc, 0x25, 0x6e, 0xb7, 0x00, 0x49, 0x92, 0xdb, 0x24, 0x5b, 0xb6, 0xff, 0x48, 0x91, 0xda, 0xcd,
            0x6c, 0xb5, 0xfe, 0x47, 0x90, 0xd9, 0x22, 0x6b, 0xb4, 0xfd, 0x46, 0x8f, 0xd8, 0x21, 0x6a, 0xb3, 0xfc, 0x45,
            0x8e, 0xd7, 0x20, 0x69, 0xb2, 0xfb, 0x44, 0x8d, 0xd6, 0x1f, 0x68, 0xb1, 0xfa, 0x43, 0x8c, 0xd5, 0x1e, 0x67,
            0xb0, 0xf9, 0x42, 0x8b, 0xd4, 0xb1, 0x66, 0xaf, 0xf8, 0x41, 0x8a, 0xd3, 0x1c, 0x65, 0xae, 0xf7, 0xbd, 0x89,
            0xd2, 0x1b, 0x64, 0xad, 0xf6, 0x3f, 0x88, 0xd1, 0x1a, 0x63, 0xac, 0xf5, 0x3e, 0x87, 0xd0, 0xc4, 0xa6, 0xab,
            0xf4, 0x3d, 0x86, 0xcf, 0x18, 0x61, 0xaa, 0xf3, 0x3c, 0x85, 0xce, 0x17, 0x60, 0xa9, 0x7d, 0x3b, 0x84, 0xba,
            0x16, 0x5f, 0xa8, 0xf1, 0x3a, 0x83, 0xcc, 0x15, 0x5e, 0x13, 0xf0, 0x39, 0x82, 0xcb, 0x14, 0x5d, 0xa6, 0xef,
            0x38, 0x81, 0x0b, 0x13, 0x5c, 0xa5, 0xee, 0x37, 0x80, 0xc9, 0x12, 0x5b, 0xa4, 0xed, 0x36, 0x7f, 0xc8, 0x11,
            0x5a, 0xa3, 0xec, 0x35, 0x7e, 0xc7, 0x10, 0x59, 0xa2, 0xeb, 0x38, 0x7d, 0xc6, 0x0f, 0x58, 0xa1, 0xea, 0x33,
            0x5d, 0xc5, 0x0e, 0x57, 0xa0, 0xe9, 0x32, 0x7b, 0xc4, 0x0d, 0x56, 0x9f,
        ];
        const B2: [u8; 35] = [
            0x1c, 0x37, 0x88, 0xb5, 0xdd, 0xf6, 0x4e, 0x81, 0x32, 0xe7, 0x1a, 0x4d, 0xf8, 0x25, 0xab, 0x19, 0x19, 0x7f,
            0xc8, 0xe5, 0x18, 0x4b, 0x54, 0xb1, 0xe4, 0x85, 0x4a, 0x7d, 0x38, 0xa2, 0xaa, 0x49, 0x7c, 0xd6, 0xb8,
        ];
        const B3: [u8; 132] = [
            0xa7, 0x3b, 0x4e, 0x61, 0x1f, 0x87, 0x9a, 0xad, 0x48, 0xd3, 0xe6, 0xf9, 0xac, 0x1f, 0x32, 0x45, 0x52, 0x6b,
            0x7e, 0x91, 0x78, 0xb7, 0xca, 0xdd, 0x15, 0x03, 0x16, 0x29, 0xcf, 0x4f, 0x62, 0x75, 0x0d, 0x9b, 0xae, 0xc1,
            0x7a, 0xe7, 0xfa, 0x0d, 0xb3, 0x33, 0x46, 0x59, 0x73, 0x7f, 0x92, 0xa5, 0x09, 0xcb, 0xde, 0xf1, 0x1b, 0x17,
            0x2a, 0x3d, 0xc7, 0x63, 0x76, 0x89, 0x9c, 0xaf, 0xc2, 0xd5, 0xcc, 0xfb, 0x0e, 0x21, 0xe3, 0x47, 0x5a, 0x6d,
            0x82, 0x93, 0xa6, 0xb9, 0x91, 0xdf, 0xf2, 0x05, 0x2a, 0x2b, 0x3e, 0x51, 0xe9, 0x77, 0x8a, 0x9d, 0x39, 0xc3,
            0xd6, 0xe9, 0xff, 0x0f, 0x22, 0x35, 0xcd, 0x5b, 0x6e, 0x81, 0x1b, 0xa7, 0xba, 0xcd, 0x77, 0xf3, 0x06, 0x19,
            0x00, 0x3f, 0x52, 0x65, 0x30, 0x8b, 0x9e, 0xb1, 0x02, 0xd7, 0xea, 0xfd, 0x08, 0x23, 0x36, 0x49, 0xf5, 0x6f,
            0x82, 0x95, 0xc4, 0xbb, 0xce, 0xe1,
        ];
        run_blend_test(255, &B0, &B1, &B2, &B3);
    }
}
