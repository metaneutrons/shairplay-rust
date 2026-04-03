#![allow(clippy::all, unused_assignments, non_snake_case, unused_mut, unused_variables, unused_parens)]

fn weird_ror8(input: u8, count: u32) -> u32 {
    if count == 0 { return 0; }
    let c = count & 7;
    ((input as u32 >> c) & 0xff) | ((input as u32 & 0xff) << (8u32.wrapping_sub(c)))
}

fn weird_rol8(input: u8, count: u32) -> u32 {
    if count == 0 { return 0; }
    let c = count & 7;
    (((input as u32) << c) & 0xff) | ((input as u32) >> (8u32.wrapping_sub(c)))
}

fn weird_rol32(input: u8, count: u32) -> u32 {
    if count == 0 { return 0; }
    ((input as u32) << count) ^ ((input as u32) >> (8u32.wrapping_sub(count)))
}

fn rol8(x: u8, y: u32) -> u8 {
    (((x as u16) << (y & 7)) | ((x as u16) >> (8 - (y & 7)))) as u8
}

fn rol8x(x: u8, y: u32) -> u32 {
    ((x as u32) << (y & 7)) | ((x as u32) >> (8u32.wrapping_sub(y & 7)))
}

pub fn garble(buffer0: &mut [u8; 20], buffer1: &mut [u8; 210], buffer2: &mut [u8; 35], buffer3: &mut [u8; 132], buffer4: &[u8; 21]) {
    let (mut tmp, mut tmp2, mut tmp3): (u32, u32, u32) = (0, 0, 0);
    #[allow(non_snake_case)]
    let (mut A, mut B, mut C, mut D, mut E, mut F, mut G, mut H, mut J, mut K, mut M): (u32,u32,u32,u32,u32,u32,u32,u32,u32,u32,u32) = (0,0,0,0,0,0,0,0,0,0,0);
    #[allow(non_snake_case)]
    let (mut R, mut S, mut T, mut U, mut V, mut W, mut X, mut Y, mut Z): (u32,u32,u32,u32,u32,u32,u32,u32,u32) = (0,0,0,0,0,0,0,0,0);

    // C: buffer2[12] = 0x14 + (((buffer1[64] & 92) | ((buffer1[99] / 3) & 35)) & buffer4[rol8x(buffer4[(buffer1[206] % 21)],4) % 21]);
    buffer2[12] = (0x14u32.wrapping_add((((buffer1[64] as u32) & 92) | (((buffer1[99] as u32) / 3) & 35)) & (buffer4[(rol8x(buffer4[(buffer1[206] as usize) % 21], 4) as usize) % 21] as u32))) as u8;

    // C: buffer1[4] = (buffer1[99] / 5) * (buffer1[99] / 5) * 2;
    buffer1[4] = (((buffer1[99] as u32) / 5).wrapping_mul((buffer1[99] as u32) / 5).wrapping_mul(2)) as u8;

    // C: buffer2[34] = 0xb8;
    buffer2[34] = (0xb8u32) as u8;

    // C: buffer1[153] ^= (buffer2[buffer1[203] % 35] * buffer2[buffer1[203] % 35] * buffer1[190]);
    buffer1[153] ^= (((buffer2[(buffer1[203] as usize) % 35] as u32).wrapping_mul(buffer2[(buffer1[203] as usize) % 35] as u32).wrapping_mul(buffer1[190] as u32))) as u8;

    // C: buffer0[3] -= (((buffer4[buffer1[205] % 21]>>1) & 80) | 0xe6440);
    buffer0[3] = buffer0[3].wrapping_sub((((((buffer4[(buffer1[205] as usize) % 21] as u32)>>1) & 80) | 0xe6440u32)) as u8);

    // C: buffer0[16] = 0x93;
    buffer0[16] = (0x93u32) as u8;

    // C: buffer0[13] = 0x62;
    buffer0[13] = (0x62u32) as u8;

    // C: buffer1[33] -= (buffer4[buffer1[36] % 21] & 0xf6);
    buffer1[33] = buffer1[33].wrapping_sub((((buffer4[(buffer1[36] as usize) % 21] as u32) & 0xf6u32)) as u8);

    // C: tmp2 = buffer2[buffer1[67] % 35];
    tmp2 = (buffer2[(buffer1[67] as usize) % 35] as u32);

    // C: buffer2[12] = 0x07;
    buffer2[12] = (0x07u32) as u8;

    // C: tmp = buffer0[buffer1[181] % 20];
    tmp = (buffer0[(buffer1[181] as usize) % 20] as u32);

    // C: buffer1[2] -= 3136;
    buffer1[2] = buffer1[2].wrapping_sub((3136u32 & 0xff) as u8);

    // C: buffer0[19] = buffer4[buffer1[58] % 21];
    buffer0[19] = ((buffer4[(buffer1[58] as usize) % 21] as u32)) as u8;

    // C: buffer3[0] = 92 - buffer2[buffer1[32] % 35];
    buffer3[0] = (92u32.wrapping_sub(buffer2[(buffer1[32] as usize) % 35] as u32)) as u8;

    // C: buffer3[4] = buffer2[buffer1[15] % 35] + 0x9e;
    buffer3[4] = ((buffer2[(buffer1[15] as usize) % 35] as u32).wrapping_add(0x9eu32)) as u8;

    // C: buffer1[34] += (buffer4[((buffer2[buffer1[15] % 35] + 0x9e) & 0xff) % 21] / 5);
    buffer1[34] = buffer1[34].wrapping_add(((buffer4[(((buffer2[(buffer1[15] as usize) % 35] as u32).wrapping_add(0x9eu32)) & 0xffu32) as usize % 21] / 5)) as u8);

    // C: buffer0[19] += 0xfffffee6 - ((buffer0[buffer3[4] % 20]>>1) & 102);
    buffer0[19] = buffer0[19].wrapping_add((0xfffffee6u32.wrapping_sub((((buffer0[(buffer3[4] as usize) % 20] as u32)>>1) & 102))) as u8);

    // C: buffer1[15] = (3*(((buffer1[72] >> (buffer4[buffer1[190] % 21] & 7)) ^ (buffer1[72] << ((7 - (buffer4[buffer1[190] % 21]-1)&7)))) - (3*buffer4[buffer1[126] % 21]))) ^ buffer1[15];
    buffer1[15] = (3u32.wrapping_mul((((buffer1[72] as u32) >> ((buffer4[(buffer1[190] as usize) % 21] as u32) & 7)) ^ ((buffer1[72] as u32) << ((7u32.wrapping_sub((buffer4[(buffer1[190] as usize) % 21] as u32).wrapping_sub(1)))&7))).wrapping_sub(3u32.wrapping_mul(buffer4[(buffer1[126] as usize) % 21] as u32))) ^ (buffer1[15] as u32)) as u8;

    // C: buffer0[15] ^= buffer2[buffer1[181] % 35] * buffer2[buffer1[181] % 35] * buffer2[buffer1[181] % 35];
    buffer0[15] ^= ((buffer2[(buffer1[181] as usize) % 35] as u32).wrapping_mul(buffer2[(buffer1[181] as usize) % 35] as u32).wrapping_mul(buffer2[(buffer1[181] as usize) % 35] as u32)) as u8;

    // C: buffer2[4] ^= buffer1[202]/3;
    buffer2[4] ^= ((buffer1[202] as u32)/3) as u8;

    // C: A = 92 - buffer0[buffer3[0] % 20];
    A = 92u32.wrapping_sub(buffer0[(buffer3[0] as usize) % 20] as u32);

    // C: E = (A & 0xc6) | (!buffer1[105] & 0xc6) | (A & (!buffer1[105]));
    E = (A & 0xc6u32) | (!(buffer1[105] as u32) & 0xc6u32) | (A & (!(buffer1[105] as u32)));

    // C: buffer2[1] += (E*E*E);
    buffer2[1] = buffer2[1].wrapping_add(((E.wrapping_mul(E).wrapping_mul(E))) as u8);

    // C: buffer0[19] ^= ((224 | (buffer4[buffer1[92] % 21] & 27)) * buffer2[buffer1[41] % 35]) / 3;
    buffer0[19] ^= (((224 | ((buffer4[(buffer1[92] as usize) % 21] as u32) & 27)).wrapping_mul(buffer2[(buffer1[41] as usize) % 35] as u32)) / 3) as u8;

    // C: buffer1[140] += weird_ror8(92, buffer1[5] & 7);
    buffer1[140] = buffer1[140].wrapping_add((weird_ror8(92, (buffer1[5] as u32) & 7)) as u8);

    // C: buffer2[12] += ((((!buffer1[4]) ^ buffer2[buffer1[12] % 35]) | buffer1[182]) & 192) | (((!buffer1[4]) ^ buffer2[buffer1[12] % 35]) & buffer1[182]);
    buffer2[12] = buffer2[12].wrapping_add((((((!(buffer1[4] as u32)) ^ (buffer2[(buffer1[12] as usize) % 35] as u32)) | (buffer1[182] as u32)) & 192) | (((!(buffer1[4] as u32)) ^ (buffer2[(buffer1[12] as usize) % 35] as u32)) & (buffer1[182] as u32))) as u8);

    // C: buffer1[36] += 125;
    buffer1[36] = buffer1[36].wrapping_add((125) as u8);

    // C: buffer1[124] = rol8x((((74 & buffer1[138]) | ((74 | buffer1[138]) & buffer0[15])) & buffer0[buffer1[43] % 20]) | (((74 & buffer1[138]) | ((74 | buffer1[138]) & buffer0[15]) | buffer0[buffer1[43] % 20]) & 95) as u8, 4);
    buffer1[124] = (rol8x(((((74u32 & (buffer1[138] as u32)) | ((74u32 | (buffer1[138] as u32)) & (buffer0[15] as u32))) & (buffer0[(buffer1[43] as usize) % 20] as u32)) | (((74u32 & (buffer1[138] as u32)) | ((74u32 | (buffer1[138] as u32)) & (buffer0[15] as u32)) | (buffer0[(buffer1[43] as usize) % 20] as u32)) & 95)) as u8, 4)) as u8;

    // C: buffer3[8] = ((((buffer0[buffer3[4] % 20] & 95)) & ((buffer4[buffer1[68] % 21] & 46) << 1)) | 16) ^ 92;
    buffer3[8] = ((((((buffer0[(buffer3[4] as usize) % 20] as u32) & 95)) & (((buffer4[(buffer1[68] as usize) % 21] as u32) & 46) << 1)) | 16) ^ 92) as u8;

    // C: A = buffer1[177] + buffer4[buffer1[79] % 21];
    A = (buffer1[177] as u32).wrapping_add(buffer4[(buffer1[79] as usize) % 21] as u32);

    // C: D = (((A >> 1) | ((3 * buffer1[148]) / 5)) & buffer2[1]) | ((A >> 1) & ((3 * buffer1[148])/5));
    D = (((A >> 1) | ((3u32.wrapping_mul(buffer1[148] as u32)) / 5)) & (buffer2[1] as u32)) | ((A >> 1) & ((3u32.wrapping_mul(buffer1[148] as u32))/5));

    // C: buffer3[12] =  (0u32.wrapping_sub(34).wrapping_sub(D));
    buffer3[12] = ((0u32.wrapping_sub(34).wrapping_sub(D))) as u8;

    // C: A = 8 - ((buffer2[22] & 7));     // NOTE: buffer2[22] = 74, so A is always 6 and B^C is just ror8(buffer1[33], 6);
    A = 8u32.wrapping_sub(((buffer2[22] as u32) & 7));     // NOTE: (buffer2[22] as u32) = 74, so A is always 6 and B^C is just ror8((buffer1[33] as u32), 6);

    // C: B = (buffer1[33] >> (A & 7));
    B = ((buffer1[33] as u32) >> (A & 7));

    // C: C = buffer1[33] << (buffer2[22] & 7);
    C = (buffer1[33] as u32) << ((buffer2[22] as u32) & 7);

    // C: buffer2[16] += ((buffer2[buffer3[0] % 35] & 159) | buffer0[buffer3[4] % 20] | 8) - ((B^C) | 128);
    buffer2[16] = buffer2[16].wrapping_add(((((buffer2[(buffer3[0] as usize) % 35] as u32) & 159) | (buffer0[(buffer3[4] as usize) % 20] as u32) | 8).wrapping_sub((B^C) | 128)) as u8);

    // C: buffer0[14] ^= buffer2[buffer3[12] % 35];
    buffer0[14] ^= ((buffer2[(buffer3[12] as usize) % 35] as u32)) as u8;

    // C: A = weird_rol8(buffer4[buffer0[buffer1[201] % 20] % 21], ((buffer2[buffer1[112] % 35] << 1) & 7));
    A = weird_rol8(buffer4[(buffer0[(buffer1[201] as usize) % 20] as usize) % 21], (((buffer2[(buffer1[112] as usize) % 35] as u32) << 1) & 7));

    // C: D = (buffer0[buffer1[208] % 20] & 131) | (buffer0[buffer1[164] % 20] & 124);
    D = ((buffer0[(buffer1[208] as usize) % 20] as u32) & 131) | ((buffer0[(buffer1[164] as usize) % 20] as u32) & 124);

    // C: buffer1[19] += (A & (D/5)) | ((A | (D/5)) & 37);
    buffer1[19] = buffer1[19].wrapping_add(((A & (D/5)) | ((A | (D/5)) & 37)) as u8);

    // C: buffer2[8] = weird_ror8(140, ((buffer4[buffer1[45] % 21] + 92) * (buffer4[buffer1[45] % 21] + 92)) & 7);
    buffer2[8] = (weird_ror8(140, (((buffer4[(buffer1[45] as usize) % 21] as u32).wrapping_add(92)).wrapping_mul((buffer4[(buffer1[45] as usize) % 21] as u32).wrapping_add(92))) & 7)) as u8;

    // C: buffer1[190] = 56;
    buffer1[190] = (56) as u8;

    // C: buffer2[8] ^= buffer3[0];
    buffer2[8] ^= ((buffer3[0] as u32)) as u8;

    // C: buffer1[53] = !((buffer0[buffer1[83] % 20] | 204)/5);
    buffer1[53] = (!(((buffer0[(buffer1[83] as usize) % 20] as u32) | 204)/5)) as u8;

    // C: buffer0[13] += buffer0[buffer1[41] % 20];
    buffer0[13] = buffer0[13].wrapping_add(((buffer0[(buffer1[41] as usize) % 20] as u32)) as u8);

    // C: buffer0[10] = ((buffer2[buffer3[0] % 35] & buffer1[2]) | ((buffer2[buffer3[0] % 35] | buffer1[2]) & buffer3[12])) / 15;
    buffer0[10] = ((((buffer2[(buffer3[0] as usize) % 35] as u32) & (buffer1[2] as u32)) | (((buffer2[(buffer3[0] as usize) % 35] as u32) | (buffer1[2] as u32)) & (buffer3[12] as u32))) / 15) as u8;

    // C: A = (((56 | (buffer4[buffer1[2] % 21] & 68)) | buffer2[buffer3[8] % 35]) & 42) | (((buffer4[buffer1[2] % 21] & 68) | 56) & buffer2[buffer3[8] % 35]);
    A = (((56 | ((buffer4[(buffer1[2] as usize) % 21] as u32) & 68)) | (buffer2[(buffer3[8] as usize) % 35] as u32)) & 42) | ((((buffer4[(buffer1[2] as usize) % 21] as u32) & 68) | 56) & (buffer2[(buffer3[8] as usize) % 35] as u32));

    // C: buffer3[16] = (A*A) + 110;
    buffer3[16] = (A.wrapping_mul(A).wrapping_add(110)) as u8;

    // C: buffer3[20] = 202 - buffer3[16];
    buffer3[20] = (202u32.wrapping_sub(buffer3[16] as u32)) as u8;

    // C: buffer3[24] = buffer1[151];
    buffer3[24] = ((buffer1[151] as u32)) as u8;

    // C: buffer2[13] ^= buffer4[buffer3[0] % 21];
    buffer2[13] ^= ((buffer4[(buffer3[0] as usize) % 21] as u32)) as u8;

    // C: B = ((buffer2[buffer1[179] % 35] - 38) & 177) | (buffer3[12] & 177);
    B = (((buffer2[(buffer1[179] as usize) % 35] as u32).wrapping_sub(38)) & 177) | ((buffer3[12] as u32) & 177);

    // C: C = ((buffer2[buffer1[179] % 35] - 38)) & buffer3[12];
    C = (((buffer2[(buffer1[179] as usize) % 35] as u32).wrapping_sub(38))) & (buffer3[12] as u32);

    // C: buffer3[28] = 30 + ((B | C) * (B | C));
    buffer3[28] = (30u32.wrapping_add((B | C).wrapping_mul(B | C))) as u8;

    // C: buffer3[32] = buffer3[28] + 62;
    buffer3[32] = ((buffer3[28] as u32).wrapping_add(62)) as u8;

    // C: A = ((buffer3[20] + (buffer3[0] & 74)) | !buffer4[buffer3[0] % 21]) & 121;
    A = (((buffer3[20] as u32).wrapping_add((buffer3[0] as u32) & 74)) | !(buffer4[(buffer3[0] as usize) % 21] as u32)) & 121;

    // C: B = ((buffer3[20] + (buffer3[0] & 74)) & !buffer4[buffer3[0] % 21]);
    B = (((buffer3[20] as u32).wrapping_add((buffer3[0] as u32) & 74)) & !(buffer4[(buffer3[0] as usize) % 21] as u32));

    // C: tmp3 = (A|B);
    tmp3 = (A|B);

    // C: C = ((((A|B) ^ 0xffffffa6) | buffer3[0]) & 4) | (((A|B) ^ 0xffffffa6) & buffer3[0]);
    C = ((((A|B) ^ 0xffffffa6u32) | (buffer3[0] as u32)) & 4) | (((A|B) ^ 0xffffffa6u32) & (buffer3[0] as u32));

    // C: buffer1[47] = (buffer2[buffer1[89] % 35] + C) ^ buffer1[47];
    buffer1[47] = (((buffer2[(buffer1[89] as usize) % 35] as u32).wrapping_add(C)) ^ (buffer1[47] as u32)) as u8;

    // C: buffer3[36] = (((rol8(((tmp & 179) + 68) as u8, 2) as u32) & buffer0[3]) | (tmp2 & !buffer0[3])) - 15;
    buffer3[36] = ((((rol8(((tmp & 179).wrapping_add(68)) as u8, 2) as u32) & (buffer0[3] as u32)) | (tmp2 & !(buffer0[3] as u32))).wrapping_sub(15)) as u8;

    // C: buffer1[123] ^= 221;
    buffer1[123] ^= (221) as u8;

    // C: A = ((buffer4[buffer3[0] % 21]) / 3) - buffer2[buffer3[4] % 35];
    A = (((buffer4[(buffer3[0] as usize) % 21] as u32)) / 3).wrapping_sub(buffer2[(buffer3[4] as usize) % 35] as u32);

    // C: C = (((buffer3[0] & 163) + 92) & 246) | (buffer3[0] & 92);
    C = ((((buffer3[0] as u32) & 163).wrapping_add(92)) & 246) | ((buffer3[0] as u32) & 92);

    // C: E = ((C | buffer3[24]) & 54) | (C & buffer3[24]);
    E = ((C | (buffer3[24] as u32)) & 54) | (C & (buffer3[24] as u32));

    // C: buffer3[40] = A - E;
    buffer3[40] = (A.wrapping_sub(E)) as u8;

    // C: buffer3[44] = tmp3 ^ 81 ^ (((buffer3[0] >> 1) & 101) + 26);
    buffer3[44] = (tmp3 ^ 81 ^ ((((buffer3[0] as u32) >> 1) & 101).wrapping_add(26))) as u8;

    // C: buffer3[48] = buffer2[buffer3[4] % 35] & 27;
    buffer3[48] = ((buffer2[(buffer3[4] as usize) % 35] as u32) & 27) as u8;

    // C: buffer3[52] = 27;
    buffer3[52] = (27) as u8;

    // C: buffer3[56] = 199;
    buffer3[56] = (199) as u8;

    // C: buffer3[64] = buffer3[4] + (((((((buffer3[40] | buffer3[24]) & 177) | (buffer3[40] & buffer3[24])) & ((((buffer4[buffer3[0] % 20] & 177) | 176)) | ((buffer4[buffer3[0] % 21]) & !3))) | ((((buffer3[40] & buffer3[24]) | ((buffer3[40] | buffer3[24]) & 177)) & 199) | ((((buffer4[buffer3[0] % 21] & 1) + 176) | (buffer4[buffer3[0] % 21] & !3)) & buffer3[56]))) & (!buffer3[52])) | buffer3[48]);
    buffer3[64] = ((buffer3[4] as u32).wrapping_add(((((((((buffer3[40] as u32) | (buffer3[24] as u32)) & 177) | ((buffer3[40] as u32) & (buffer3[24] as u32))) & (((((buffer4[(buffer3[0] as usize) % 20] as u32) & 177) | 176)) | (((buffer4[(buffer3[0] as usize) % 21] as u32)) & !3u32))) | (((((buffer3[40] as u32) & (buffer3[24] as u32)) | (((buffer3[40] as u32) | (buffer3[24] as u32)) & 177)) & 199) | (((((buffer4[(buffer3[0] as usize) % 21] as u32) & 1).wrapping_add(176)) | ((buffer4[(buffer3[0] as usize) % 21] as u32) & !3u32)) & (buffer3[56] as u32)))) & (!(buffer3[52] as u32))) | (buffer3[48] as u32)))) as u8;

    // C: buffer2[33] ^= buffer1[26];
    buffer2[33] ^= ((buffer1[26] as u32)) as u8;

    // C: buffer1[106] ^= buffer3[20] ^ 133;
    buffer1[106] ^= ((buffer3[20] as u32) ^ 133) as u8;

    // C: buffer2[30] = ((buffer3[64] / 3) - (275 | (buffer3[0] & 247))) ^ buffer0[buffer1[122] % 20];
    buffer2[30] = ((((buffer3[64] as u32) / 3).wrapping_sub(275 | ((buffer3[0] as u32) & 247))) ^ (buffer0[(buffer1[122] as usize) % 20] as u32)) as u8;

    // C: buffer1[22] = (buffer2[buffer1[90] % 35] & 95) | 68;
    buffer1[22] = (((buffer2[(buffer1[90] as usize) % 35] as u32) & 95) | 68) as u8;

    // C: A = (buffer4[buffer3[36] % 21] & 184) | (buffer2[buffer3[44] % 35] & !184);
    A = ((buffer4[(buffer3[36] as usize) % 21] as u32) & 184) | ((buffer2[(buffer3[44] as usize) % 35] as u32) & !184u32);

    // C: buffer2[18] += ((A*A*A) >> 1);
    buffer2[18] = buffer2[18].wrapping_add((((A.wrapping_mul(A).wrapping_mul(A)) >> 1)) as u8);

    // C: buffer2[5] -= buffer4[buffer1[92] % 21];
    buffer2[5] = buffer2[5].wrapping_sub(((buffer4[(buffer1[92] as usize) % 21] as u32)) as u8);

    // C: A = (((buffer1[41] & !24)|(buffer2[buffer1[183] % 35] & 24)) & (buffer3[16] + 53)) | (buffer3[20] & buffer2[buffer3[20] % 35]);
    A = ((((buffer1[41] as u32) & !24u32)|((buffer2[(buffer1[183] as usize) % 35] as u32) & 24)) & ((buffer3[16] as u32).wrapping_add(53))) | ((buffer3[20] as u32) & (buffer2[(buffer3[20] as usize) % 35] as u32));

    // C: B = (buffer1[17] & (!buffer3[44])) | (buffer0[buffer1[59] % 20] & buffer3[44]);
    B = ((buffer1[17] as u32) & (!(buffer3[44] as u32))) | ((buffer0[(buffer1[59] as usize) % 20] as u32) & (buffer3[44] as u32));

    // C: buffer2[18] ^= (A*B);
    buffer2[18] ^= ((A.wrapping_mul(B))) as u8;

    // C: A = weird_ror8(buffer1[11], buffer2[buffer1[28] % 35] & 7) & 7;
    A = weird_ror8(buffer1[11], (buffer2[(buffer1[28] as usize) % 35] as u32) & 7) & 7;

    // C: B = (((buffer0[buffer1[93] % 20] & !buffer0[14]) | (buffer0[14] & 150)) & !28) | (buffer1[7] & 28);
    B = ((((buffer0[(buffer1[93] as usize) % 20] as u32) & !(buffer0[14] as u32)) | ((buffer0[14] as u32) & 150)) & !28u32) | ((buffer1[7] as u32) & 28);

    // C: buffer2[22] = (((((B | weird_rol8(buffer2[buffer3[0] % 35], A)) & buffer2[33]) | (B & weird_rol8(buffer2[buffer3[0] % 35], A))) + 74) & 0xff);
    buffer2[22] = ((((((B | weird_rol8(((buffer2[(buffer3[0] as usize) % 35] as u32) as u8), A)) & (buffer2[33] as u32)) | (B & weird_rol8(((buffer2[(buffer3[0] as usize) % 35] as u32) as u8), A))).wrapping_add(74)) & 0xffu32)) as u8;

    // C: A = buffer4[(buffer0[buffer1[39] % 20] ^ 217) % 21]; // X5;
    A = (buffer4[(((buffer0[(buffer1[39] as usize) % 20] as u32) ^ 217) as usize) % 21] as u32); // X5;

    // C: buffer0[15] -= ((((buffer3[20] | buffer3[0]) & 214) | (buffer3[20] & buffer3[0])) & A) | ((((buffer3[20] | buffer3[0]) & 214) | (buffer3[20] & buffer3[0]) | A) & buffer3[32]);
    buffer0[15] = buffer0[15].wrapping_sub(((((((buffer3[20] as u32) | (buffer3[0] as u32)) & 214) | ((buffer3[20] as u32) & (buffer3[0] as u32))) & A) | (((((buffer3[20] as u32) | (buffer3[0] as u32)) & 214) | ((buffer3[20] as u32) & (buffer3[0] as u32)) | A) & (buffer3[32] as u32))) as u8);

    // C: B = (((buffer2[buffer1[57] % 35] & buffer0[buffer3[64] % 20]) | ((buffer0[buffer3[64] % 20] | buffer2[buffer1[57] % 35]) & 95) | (buffer3[64] & 45) | 82) & 32);
    B = ((((buffer2[(buffer1[57] as usize) % 35] as u32) & (buffer0[(buffer3[64] as usize) % 20] as u32)) | (((buffer0[(buffer3[64] as usize) % 20] as u32) | (buffer2[(buffer1[57] as usize) % 35] as u32)) & 95) | ((buffer3[64] as u32) & 45) | 82) & 32);

    // C: C = ((buffer2[buffer1[57] % 35] & buffer0[buffer3[64] % 20]) | ((buffer2[buffer1[57] % 35] | buffer0[buffer3[64] % 20]) & 95)) & ((buffer3[64] & 45) | 82);
    C = (((buffer2[(buffer1[57] as usize) % 35] as u32) & (buffer0[(buffer3[64] as usize) % 20] as u32)) | (((buffer2[(buffer1[57] as usize) % 35] as u32) | (buffer0[(buffer3[64] as usize) % 20] as u32)) & 95)) & (((buffer3[64] as u32) & 45) | 82);

    // C: D = ((((buffer3[0]/3) - (buffer3[64]|buffer1[22]))) ^ (buffer3[28] + 62) ^ ((B|C)));
    D = (((((buffer3[0] as u32)/3).wrapping_sub((buffer3[64] as u32)|(buffer1[22] as u32)))) ^ ((buffer3[28] as u32).wrapping_add(62)) ^ ((B|C)));

    // C: T = buffer0[(D & 0xff) % 20];
    T = buffer0[(((D & 0xffu32)) as usize) % 20] as u32;

    // C: buffer3[68] = (buffer0[buffer1[99] % 20] * buffer0[buffer1[99] % 20] * buffer0[buffer1[99] % 20] * buffer0[buffer1[99] % 20]) | buffer2[buffer3[64] % 35];
    buffer3[68] = ((buffer0[(buffer1[99] as usize) % 20] as u32).wrapping_mul(buffer0[(buffer1[99] as usize) % 20] as u32).wrapping_mul(buffer0[(buffer1[99] as usize) % 20] as u32).wrapping_mul(buffer0[(buffer1[99] as usize) % 20] as u32) | (buffer2[(buffer3[64] as usize) % 35] as u32)) as u8;

    // C: U = buffer0[buffer1[50] % 20]; // this is also v100;
    U = (buffer0[(buffer1[50] as usize) % 20] as u32); // this is also v100;

    // C: W = buffer2[buffer1[138] % 35];
    W = (buffer2[(buffer1[138] as usize) % 35] as u32);

    // C: X = buffer4[buffer1[39] % 21];
    X = (buffer4[(buffer1[39] as usize) % 21] as u32);

    // C: Y = buffer0[buffer1[4] % 20]; // this is also v120;
    Y = (buffer0[(buffer1[4] as usize) % 20] as u32); // this is also v120;

    // C: Z = buffer4[buffer1[202] % 21]; // also v124;
    Z = (buffer4[(buffer1[202] as usize) % 21] as u32); // also v124;

    // C: V = buffer0[buffer1[151] % 20];
    V = (buffer0[(buffer1[151] as usize) % 20] as u32);

    // C: S = buffer2[buffer1[14] % 35];
    S = (buffer2[(buffer1[14] as usize) % 35] as u32);

    // C: R = buffer0[buffer1[145] % 20];
    R = (buffer0[(buffer1[145] as usize) % 20] as u32);

    // C: A = (buffer2[buffer3[68] % 35] & buffer0[buffer1[209] % 20]) | ((buffer2[buffer3[68] % 35] | buffer0[buffer1[209] % 20]) & 24);
    A = ((buffer2[(buffer3[68] as usize) % 35] as u32) & (buffer0[(buffer1[209] as usize) % 20] as u32)) | (((buffer2[(buffer3[68] as usize) % 35] as u32) | (buffer0[(buffer1[209] as usize) % 20] as u32)) & 24);

    // C: B = weird_rol8(buffer4[buffer1[127] % 21], buffer2[buffer3[68] % 35] & 7);
    B = weird_rol8(((buffer4[(buffer1[127] as usize) % 21] as u32) as u8), (buffer2[(buffer3[68] as usize) % 35] as u32) & 7);

    // C: C = (A & buffer0[10]) | (B & !buffer0[10]);
    C = (A & (buffer0[10] as u32)) | (B & !(buffer0[10] as u32));

    // C: D = 7 ^ (buffer4[buffer2[buffer3[36] % 35] % 21] << 1);
    D = 7 ^ ((buffer4[(buffer2[(buffer3[36] as usize) % 35] as usize) % 21] as u32) << 1);

    // C: buffer3[72] = (C & 71) | (D & !71);
    buffer3[72] = ((C & 71) | (D & !71u32)) as u8;

    // C: buffer2[2] += (((buffer0[buffer3[20] % 20] << 1) & 159) | (buffer4[buffer1[190] % 21] & !159)) & ((((buffer4[buffer3[64] % 21] & 110) | (buffer0[buffer1[25] % 20] & !110)) & !150) | (buffer1[25] & 150));
    buffer2[2] = buffer2[2].wrapping_add((((((buffer0[(buffer3[20] as usize) % 20] as u32) << 1) & 159) | ((buffer4[(buffer1[190] as usize) % 21] as u32) & !159u32)) & (((((buffer4[(buffer3[64] as usize) % 21] as u32) & 110) | ((buffer0[(buffer1[25] as usize) % 20] as u32) & !110u32)) & !150u32) | ((buffer1[25] as u32) & 150))) as u8);

    // C: buffer2[14] -= ((buffer2[buffer3[20] % 35] & (buffer3[72] ^ buffer2[buffer1[100] % 35])) & !34) | (buffer1[97] & 34);
    buffer2[14] = buffer2[14].wrapping_sub(((((buffer2[(buffer3[20] as usize) % 35] as u32) & ((buffer3[72] as u32) ^ (buffer2[(buffer1[100] as usize) % 35] as u32))) & !34u32) | ((buffer1[97] as u32) & 34)) as u8);

    // C: buffer0[17] = 115;
    buffer0[17] = (115) as u8;

    // C: buffer1[23] ^= ((((((buffer4[buffer1[17] % 21] | buffer0[buffer3[20] % 20]) & buffer3[72]) | (buffer4[buffer1[17] % 21] & buffer0[buffer3[20] % 20])) & (buffer1[50]/3)) |;
    buffer1[23] ^= ((((((buffer4[(buffer1[17] as usize) % 21] as u32 | buffer0[(buffer3[20] as usize) % 20] as u32) & buffer3[72] as u32) | (buffer4[(buffer1[17] as usize) % 21] as u32 & buffer0[(buffer3[20] as usize) % 20] as u32)) & (buffer1[50] as u32 / 3)) |
                    ((((buffer4[(buffer1[17] as usize) % 21] as u32 | buffer0[(buffer3[20] as usize) % 20] as u32) & buffer3[72] as u32) | (buffer4[(buffer1[17] as usize) % 21] as u32 & buffer0[(buffer3[20] as usize) % 20] as u32) | (buffer1[50] as u32 / 3)) & 246)) << 1) as u8;

    // C: buffer0[13] = ((((((buffer0[buffer3[40] % 20] | buffer1[10]) & 82) | (buffer0[buffer3[40] % 20] & buffer1[10])) & 209) |;
    buffer0[13] = ((((((buffer0[(buffer3[40] as usize) % 20] as u32 | buffer1[10] as u32) & 82) | (buffer0[(buffer3[40] as usize) % 20] as u32 & buffer1[10] as u32)) & 209) |
                   ((buffer0[(buffer1[39] as usize) % 20] as u32) << 1) & 46) >> 1) as u8;

    // C: buffer2[33] -= buffer1[113] & 9;
    buffer2[33] = buffer2[33].wrapping_sub(((buffer1[113] as u32) & 9) as u8);

    // C: buffer2[28] -= ((((2 | (buffer1[110] & 222)) >> 1) & !223) | (buffer3[20] & 223));
    buffer2[28] = buffer2[28].wrapping_sub((((((2 | ((buffer1[110] as u32) & 222)) >> 1) & !223u32) | ((buffer3[20] as u32) & 223))) as u8);

    // C: J = weird_rol8((V | Z) as u8, (U & 7));                   // OK;
    J = weird_rol8((V | Z) as u8, (U & 7));                   // OK;

    // C: A = (buffer2[16] & T) | (W & (!buffer2[16]));
    A = ((buffer2[16] as u32) & T) | (W & (!(buffer2[16] as u32)));

    // C: B = (buffer1[33] & 17) | (X & !17);
    B = ((buffer1[33] as u32) & 17) | (X & !17u32);

    // C: E = ((Y | ((A+B) / 5)) & 147) |;
    E = ((Y | ((A.wrapping_add(B)) / 5)) & 147) | (Y & ((A.wrapping_add(B)) / 5));

    // C: M = (buffer3[40] & buffer4[((buffer3[8] + J + E) & 0xff) % 21]) |;
    M = ((buffer3[40] as u32) & (buffer4[(((buffer3[8] as u32).wrapping_add(J).wrapping_add(E)) & 0xffu32) as usize % 21] as u32)) |
      (((buffer3[40] as u32) | (buffer4[(((buffer3[8] as u32).wrapping_add(J).wrapping_add(E)) & 0xffu32) as usize % 21] as u32)) & (buffer2[23] as u32));

    // C: buffer0[15] = (((buffer4[buffer3[20] % 21] - 48) & (!buffer1[184])) | ((buffer4[buffer3[20] % 21] - 48) & 189) | (189 & !buffer1[184])) & (M*M*M);
    buffer0[15] = (((((buffer4[(buffer3[20] as usize) % 21] as u32).wrapping_sub(48)) & (!(buffer1[184] as u32))) | (((buffer4[(buffer3[20] as usize) % 21] as u32).wrapping_sub(48)) & 189) | (189 & !(buffer1[184] as u32))) & (M.wrapping_mul(M).wrapping_mul(M))) as u8;

    // C: buffer2[22] += buffer1[183];
    buffer2[22] = buffer2[22].wrapping_add(((buffer1[183] as u32)) as u8);

    // C: buffer3[76] = (3 * buffer4[buffer1[1] % 21]) ^ buffer3[0];
    buffer3[76] = (3u32.wrapping_mul(buffer4[(buffer1[1] as usize) % 21] as u32) ^ (buffer3[0] as u32)) as u8;

    // C: A = buffer2[((buffer3[8] + (J + E)) & 0xff) % 35];
    A = (buffer2[((((buffer3[8] as u32).wrapping_add(J.wrapping_add(E))) & 0xffu32) as usize) % 35] as u32);

    // C: F = (((buffer4[buffer1[178] % 21] & A) | ((buffer4[buffer1[178] % 21] | A) & 209)) * buffer0[buffer1[13] % 20]) * (buffer4[buffer1[26] % 21] >> 1);
    F = ((((buffer4[(buffer1[178] as usize) % 21] as u32) & A) | (((buffer4[(buffer1[178] as usize) % 21] as u32) | A) & 209)).wrapping_mul(buffer0[(buffer1[13] as usize) % 20] as u32)).wrapping_mul((buffer4[(buffer1[26] as usize) % 21] as u32) >> 1);

    // C: G = (F + 0x733ffff9) * 198 - (((F + 0x733ffff9) * 396 + 212) & 212) + 85;
    G = (F.wrapping_add(0x733ffff9u32)).wrapping_mul(198).wrapping_sub(((F.wrapping_add(0x733ffff9u32)).wrapping_mul(396).wrapping_add(212)) & 212).wrapping_add(85);

    // C: buffer3[80] = buffer3[36] + (G ^ 148) + ((G ^ 107) << 1) - 127;
    buffer3[80] = ((buffer3[36] as u32).wrapping_add(G ^ 148).wrapping_add((G ^ 107) << 1).wrapping_sub(127)) as u8;

    // C: buffer3[84] = ((buffer2[buffer3[64] % 35]) & 245) | (buffer2[buffer3[20] % 35] & 10);
    buffer3[84] = ((((buffer2[(buffer3[64] as usize) % 35] as u32)) & 245) | ((buffer2[(buffer3[20] as usize) % 35] as u32) & 10)) as u8;

    // C: A = buffer0[buffer3[68] % 20] | 81;
    A = (buffer0[(buffer3[68] as usize) % 20] as u32) | 81;

    // C: buffer2[18] -= ((A*A*A) & !buffer0[15]) | ((buffer3[80] / 15) & buffer0[15]);
    buffer2[18] = buffer2[18].wrapping_sub((((A.wrapping_mul(A).wrapping_mul(A)) & !(buffer0[15] as u32)) | (((buffer3[80] as u32) / 15) & (buffer0[15] as u32))) as u8);

    // C: buffer3[88] = buffer3[8] + J + E - buffer0[buffer1[160] % 20] + (buffer4[buffer0[((buffer3[8] + J + E) & 255) % 20] % 21] / 3);
    buffer3[88] = ((buffer3[8] as u32).wrapping_add(J).wrapping_add(E).wrapping_sub(buffer0[(buffer1[160] as usize) % 20] as u32).wrapping_add((buffer4[(buffer0[((((buffer3[8] as u32).wrapping_add(J).wrapping_add(E)) & 255) as usize) % 20] as usize) % 21] as u32 / 3))) as u8;

    // C: B = ((R ^ buffer3[72]) & !198) | ((S * S) & 198);
    B = ((R ^ (buffer3[72] as u32)) & !198u32) | ((S.wrapping_mul(S)) & 198);

    // C: F = (buffer4[buffer1[69] % 21] & buffer1[172]) | ((buffer4[buffer1[69] % 21] | buffer1[172] ) & ((buffer3[12] - B) + 77));
    F = ((buffer4[(buffer1[69] as usize) % 21] as u32) & (buffer1[172] as u32)) | (((buffer4[(buffer1[69] as usize) % 21] as u32) | (buffer1[172] as u32) ) & (((buffer3[12] as u32).wrapping_sub(B)).wrapping_add(77)));

    // C: buffer0[16] = 147 - ((buffer3[72] & ((F & 251) | 1)) | (((F & 250) | buffer3[72]) & 198));
    buffer0[16] = (147u32.wrapping_sub(((buffer3[72] as u32) & ((F & 251) | 1)) | (((F & 250) | (buffer3[72] as u32)) & 198))) as u8;

    // C: C = (buffer4[buffer1[168] % 21] & buffer0[buffer1[29] % 20] & 7) | ((buffer4[buffer1[168] % 21] | buffer0[buffer1[29] % 20]) & 6);
    C = ((buffer4[(buffer1[168] as usize) % 21] as u32) & (buffer0[(buffer1[29] as usize) % 20] as u32) & 7) | (((buffer4[(buffer1[168] as usize) % 21] as u32) | (buffer0[(buffer1[29] as usize) % 20] as u32)) & 6);

    // C: F = (buffer4[buffer1[155] % 21] & buffer1[105]) | ((buffer4[buffer1[155] % 21] | buffer1[105]) & 141);
    F = ((buffer4[(buffer1[155] as usize) % 21] as u32) & (buffer1[105] as u32)) | (((buffer4[(buffer1[155] as usize) % 21] as u32) | (buffer1[105] as u32)) & 141);

    // C: buffer0[3] -= buffer4[(weird_rol32(F as u8, C)) as usize % 21];
    buffer0[3] = buffer0[3].wrapping_sub((buffer4[(weird_rol32(F as u8, C)) as usize % 21]) as u8);

    // C: buffer1[5] = weird_ror8(buffer0[12], ((buffer0[buffer1[61] % 20] / 5) & 7)) ^ (((!buffer2[buffer3[84] % 35]) & 0xffffffff) / 5);
    buffer1[5] = (weird_ror8(buffer0[12], ((buffer0[(buffer1[61] as usize) % 20] as u32 / 5) & 7)) ^ ((!(buffer2[(buffer3[84] as usize) % 35] as u32) & 0xffffffffu32) / 5)) as u8;

    // C: buffer1[198] += buffer1[3];
    buffer1[198] = buffer1[198].wrapping_add(((buffer1[3] as u32)) as u8);

    // C: A = (162 | buffer2[buffer3[64] % 35]);
    A = (162 | (buffer2[(buffer3[64] as usize) % 35] as u32));

    // C: buffer1[164] += ((A*A)/5);
    buffer1[164] = buffer1[164].wrapping_add((((A.wrapping_mul(A))/5)) as u8);

    // C: G = weird_ror8(139, (buffer3[80] & 7));
    G = weird_ror8(139, ((buffer3[80] as u32) & 7));

    // C: C = ((buffer4[buffer3[64] % 21] * buffer4[buffer3[64] % 21] * buffer4[buffer3[64] % 21]) & 95) | (buffer0[buffer3[40] % 20] & !95);
    C = (((buffer4[(buffer3[64] as usize) % 21] as u32).wrapping_mul(buffer4[(buffer3[64] as usize) % 21] as u32).wrapping_mul(buffer4[(buffer3[64] as usize) % 21] as u32)) & 95) | ((buffer0[(buffer3[40] as usize) % 20] as u32) & !95u32);

    // C: buffer3[92] = (G & 12) | (buffer0[buffer3[20] % 20] & 12) | (G & buffer0[buffer3[20] % 20]) | C;
    buffer3[92] = ((G & 12) | ((buffer0[(buffer3[20] as usize) % 20] as u32) & 12) | (G & (buffer0[(buffer3[20] as usize) % 20] as u32)) | C) as u8;

    // C: buffer2[12] += ((buffer1[103] & 32) | (buffer3[92] & ((buffer1[103] | 60))) | 16)/3;
    buffer2[12] = buffer2[12].wrapping_add(((((buffer1[103] as u32) & 32) | ((buffer3[92] as u32) & (((buffer1[103] as u32) | 60))) | 16)/3) as u8);

    // C: buffer3[96] = buffer1[143];
    buffer3[96] = ((buffer1[143] as u32)) as u8;

    // C: buffer3[100] = 27;
    buffer3[100] = (27) as u8;

    // C: buffer3[104] = (((buffer3[40] & !buffer2[8]) | (buffer1[35] & buffer2[8])) & buffer3[64]) ^ 119;
    buffer3[104] = (((((buffer3[40] as u32) & !(buffer2[8] as u32)) | ((buffer1[35] as u32) & (buffer2[8] as u32))) & (buffer3[64] as u32)) ^ 119) as u8;

    // C: buffer3[108] = 238 & ((((buffer3[40] & !buffer2[8]) | (buffer1[35] & buffer2[8])) & buffer3[64]) << 1);
    buffer3[108] = (238 & (((((buffer3[40] as u32) & !(buffer2[8] as u32)) | ((buffer1[35] as u32) & (buffer2[8] as u32))) & (buffer3[64] as u32)) << 1)) as u8;

    // C: buffer3[112] = (!buffer3[64] & (buffer3[84] / 3)) ^ 49;
    buffer3[112] = ((!(buffer3[64] as u32) & ((buffer3[84] as u32) / 3)) ^ 49) as u8;

    // C: buffer3[116] = 98 & ((!buffer3[64] & (buffer3[84] / 3)) << 1);
    buffer3[116] = (98 & ((!(buffer3[64] as u32) & ((buffer3[84] as u32) / 3)) << 1)) as u8;

    // C: A = (buffer1[35] & buffer2[8]) | (buffer3[40] & !buffer2[8]);
    A = ((buffer1[35] as u32) & (buffer2[8] as u32)) | ((buffer3[40] as u32) & !(buffer2[8] as u32));

    // C: B = (A & buffer3[64]) | (((buffer3[84] / 3) & !buffer3[64]));
    B = (A & (buffer3[64] as u32)) | ((((buffer3[84] as u32) / 3) & !(buffer3[64] as u32)));

    // C: buffer1[143] = buffer3[96] - ((B & (86 + ((buffer1[172] & 64) >> 1))) | (((((buffer1[172] & 65) >> 1) ^ 86) | ((!buffer3[64] & (buffer3[84] / 3)) | (((buffer3[40] & !buffer2[8]) | (buffer1[35] & buffer2[8])) & buffer3[64]))) & buffer3[100]));
    buffer1[143] = ((buffer3[96] as u32).wrapping_sub((B & (86u32.wrapping_add(((buffer1[172] as u32) & 64) >> 1))) | ((((((buffer1[172] as u32) & 65) >> 1) ^ 86) | ((!(buffer3[64] as u32) & ((buffer3[84] as u32) / 3)) | ((((buffer3[40] as u32) & !(buffer2[8] as u32)) | ((buffer1[35] as u32) & (buffer2[8] as u32))) & (buffer3[64] as u32)))) & (buffer3[100] as u32)))) as u8;

    // C: buffer2[29] = 162;
    buffer2[29] = (162) as u8;

    // C: A = ((((buffer4[buffer3[88] % 21]) & 160) | (buffer0[buffer1[125] % 20] & 95)) >> 1);
    A = (((((buffer4[(buffer3[88] as usize) % 21] as u32)) & 160) | ((buffer0[(buffer1[125] as usize) % 20] as u32) & 95)) >> 1);

    // C: B = buffer2[buffer1[149] % 35] ^ (buffer1[43] * buffer1[43]);
    B = (buffer2[(buffer1[149] as usize) % 35] as u32) ^ ((buffer1[43] as u32).wrapping_mul(buffer1[43] as u32));

    // C: buffer0[15] += (B&A) | ((A|B) & 115);
    buffer0[15] = buffer0[15].wrapping_add(((B&A) | ((A|B) & 115)) as u8);

    // C: buffer3[120] = buffer3[64] - buffer0[buffer3[40] % 20];
    buffer3[120] = ((buffer3[64] as u32).wrapping_sub(buffer0[(buffer3[40] as usize) % 20] as u32)) as u8;

    // C: buffer1[95] = buffer4[buffer3[20] % 21];
    buffer1[95] = ((buffer4[(buffer3[20] as usize) % 21] as u32)) as u8;

    // C: A = weird_ror8(buffer2[buffer3[80] % 35], (buffer2[buffer1[17] % 35] * buffer2[buffer1[17] % 35] * buffer2[buffer1[17] % 35]) & 7);
    A = weird_ror8(buffer2[(buffer3[80] as usize) % 35], ((buffer2[(buffer1[17] as usize) % 35] as u32).wrapping_mul(buffer2[(buffer1[17] as usize) % 35] as u32).wrapping_mul(buffer2[(buffer1[17] as usize) % 35] as u32)) & 7);

    // C: buffer0[7] -= (A*A);
    buffer0[7] = buffer0[7].wrapping_sub(((A.wrapping_mul(A))) as u8);

    // C: buffer2[8] = buffer2[8] - buffer1[184] + (buffer4[buffer1[202] % 21] * buffer4[buffer1[202] % 21] * buffer4[buffer1[202] % 21]);
    buffer2[8] = ((buffer2[8] as u32).wrapping_sub(buffer1[184] as u32).wrapping_add((buffer4[(buffer1[202] as usize) % 21] as u32).wrapping_mul(buffer4[(buffer1[202] as usize) % 21] as u32).wrapping_mul(buffer4[(buffer1[202] as usize) % 21] as u32))) as u8;

    // C: buffer0[16] = (buffer2[buffer1[102] % 35] << 1) & 132;
    buffer0[16] = (((buffer2[(buffer1[102] as usize) % 35] as u32) << 1) & 132) as u8;

    // C: buffer3[124] = (buffer4[buffer3[40] % 21] >> 1) ^ buffer3[68];
    buffer3[124] = (((buffer4[(buffer3[40] as usize) % 21] as u32) >> 1) ^ (buffer3[68] as u32)) as u8;

    // C: buffer0[7] -= (buffer0[buffer1[191] % 20] - (((buffer4[buffer1[80] % 21] << 1) & !177) | (buffer4[buffer4[buffer3[88] % 21] % 21] & 177)));
    buffer0[7] = buffer0[7].wrapping_sub((((buffer0[(buffer1[191] as usize) % 20] as u32).wrapping_sub((((buffer4[(buffer1[80] as usize) % 21] as u32) << 1) & !177u32) | ((buffer4[(buffer4[(buffer3[88] as usize) % 21] as usize) % 21] as u32) & 177)))) as u8);

    // C: buffer0[6] = buffer0[buffer1[119] % 20];
    buffer0[6] = ((buffer0[(buffer1[119] as usize) % 20] as u32)) as u8;

    // C: A = (buffer4[buffer1[190] % 21] & !209) | (buffer1[118] & 209);
    A = ((buffer4[(buffer1[190] as usize) % 21] as u32) & !209u32) | ((buffer1[118] as u32) & 209);

    // C: B = buffer0[buffer3[120] % 20] * buffer0[buffer3[120] % 20];
    B = (buffer0[(buffer3[120] as usize) % 20] as u32).wrapping_mul(buffer0[(buffer3[120] as usize) % 20] as u32);

    // C: buffer0[12] = (buffer0[buffer3[84] % 20] ^ (buffer2[buffer1[71] % 35] + buffer2[buffer1[15] % 35])) & ((A & B) | ((A | B) & 27));
    buffer0[12] = (((buffer0[(buffer3[84] as usize) % 20] as u32) ^ ((buffer2[(buffer1[71] as usize) % 35] as u32).wrapping_add(buffer2[(buffer1[15] as usize) % 35] as u32))) & ((A & B) | ((A | B) & 27))) as u8;

    // C: B = (buffer1[32] & buffer2[buffer3[88] % 35]) | ((buffer1[32] | buffer2[buffer3[88] % 35]) & 23);
    B = ((buffer1[32] as u32) & (buffer2[(buffer3[88] as usize) % 35] as u32)) | (((buffer1[32] as u32) | (buffer2[(buffer3[88] as usize) % 35] as u32)) & 23);

    // C: D = (((buffer4[buffer1[57] % 21] * 231) & 169) | (B & 86));
    D = ((((buffer4[(buffer1[57] as usize) % 21] as u32).wrapping_mul(231)) & 169) | (B & 86));

    // C: F = (((buffer0[buffer1[82] % 20] & !29) | (buffer4[buffer3[124] % 21] & 29)) & 190) | (buffer4[(D/5) % 21] & !190);
    F = ((((buffer0[(buffer1[82] as usize) % 20] as u32) & !29u32) | ((buffer4[(buffer3[124] as usize) % 21] as u32) & 29)) & 190) | ((buffer4[((D/5) as usize) % 21] as u32) & !190u32);

    // C: H = buffer0[buffer3[40] % 20] * buffer0[buffer3[40] % 20] * buffer0[buffer3[40] % 20];
    H = (buffer0[(buffer3[40] as usize) % 20] as u32).wrapping_mul(buffer0[(buffer3[40] as usize) % 20] as u32).wrapping_mul(buffer0[(buffer3[40] as usize) % 20] as u32);

    // C: K = (H & buffer1[82]) | (H & 92) | (buffer1[82] & 92);
    K = (H & (buffer1[82] as u32)) | (H & 92) | ((buffer1[82] as u32) & 92);

    // C: buffer3[128] = ((F & K) | ((F | K) & 192)) ^ (D/5);
    buffer3[128] = (((F & K) | ((F | K) & 192)) ^ (D/5)) as u8;

    // C: buffer2[25] ^= ((buffer0[buffer3[120] % 20] << 1) * buffer1[5]) - (weird_rol8(buffer3[76], (buffer4[buffer3[124] % 21] & 7)) & (buffer3[20] + 110));
    buffer2[25] ^= ((((buffer0[(buffer3[120] as usize) % 20] as u32) << 1).wrapping_mul(buffer1[5] as u32)).wrapping_sub(weird_rol8(((buffer3[76] as u32) as u8), ((buffer4[(buffer3[124] as usize) % 21] as u32) & 7)) & ((buffer3[20] as u32).wrapping_add(110)))) as u8;

}

#[cfg(test)]
mod tests {
use super::garble;

/// Run garble with deterministic input (same seed pattern as C test harness)
/// and compare all 4 output buffers against pre-computed C reference values.
fn run_garble_test(seed: i32, expected_b0: &[u8; 20], expected_b1: &[u8; 210], expected_b2: &[u8; 35], expected_b3: &[u8; 132]) {
    let mut b0 = [0u8; 20];
    let mut b1 = [0u8; 210];
    let mut b2 = [0u8; 35];
    let mut b3 = [0u8; 132];
    let mut b4 = [0u8; 21];

    for i in 0..20  { b0[i] = ((i as i32 * 37 + seed) & 0xff) as u8; }
    for i in 0..210 { b1[i] = ((i as i32 * 73 + seed + 7) & 0xff) as u8; }
    for i in 0..35  { b2[i] = ((i as i32 * 51 + seed + 29) & 0xff) as u8; }
    for i in 0..132 { b3[i] = ((i as i32 * 19 + seed + 41) & 0xff) as u8; }
    for i in 0..21  { b4[i] = ((i as i32 * 97 + seed + 3) & 0xff) as u8; }

    garble(&mut b0, &mut b1, &mut b2, &mut b3, &b4);

    assert_eq!(&b0, expected_b0, "buffer0 mismatch for seed {seed}");
    assert_eq!(&b1, expected_b1, "buffer1 mismatch for seed {seed}");
    assert_eq!(&b2, expected_b2, "buffer2 mismatch for seed {seed}");
    assert_eq!(&b3, expected_b3, "buffer3 mismatch for seed {seed}");
}

    #[test]
    fn garble_seed_13() {
        const B0: [u8; 20] = [
            0x0d,0x32,0x57,0x52,0xa1,0xc6,0x52,0xae,0x35,0x5a,0x0d,0xa4,0x0a,0x64,0xad,0x0a,
            0x04,0x73,0xa7,0x25,
        ];
        const B1: [u8; 210] = [
            0x14,0x5d,0x66,0xef,0xc2,0x5e,0xca,0x13,0x5c,0xa5,0xee,0x37,0x80,0xc9,0x12,0x0c,
            0xa4,0xed,0x36,0x80,0xc8,0x11,0x47,0x4b,0xec,0x35,0x7e,0xc7,0x10,0x59,0xa2,0xeb,
            0x34,0xe9,0xcc,0x0f,0xd5,0xa1,0xea,0x33,0x7c,0xc5,0x0e,0x57,0xa0,0xe9,0x32,0xe3,
            0xc4,0x0d,0x56,0x9f,0xe8,0xd0,0x7a,0xc3,0x0c,0x55,0x9e,0xe7,0x30,0x79,0xc2,0x0b,
            0x54,0x9d,0xe6,0x2f,0x78,0xc1,0x0a,0x53,0x9c,0xe5,0x2e,0x77,0xc0,0x09,0x52,0x9b,
            0xe4,0x2d,0x76,0xbf,0x08,0x51,0x9a,0xe3,0x2c,0x75,0xbe,0x07,0x50,0x99,0xe2,0xb7,
            0x74,0xbd,0x06,0x4f,0x98,0xe1,0x2a,0x73,0xbc,0x05,0xd7,0x97,0xe0,0x29,0x72,0xbb,
            0x04,0x4d,0x96,0xdf,0x28,0x71,0xba,0x03,0x4c,0x95,0xde,0xfa,0xa5,0xb9,0x02,0x4b,
            0x94,0xdd,0x26,0x6f,0xb8,0x01,0x4a,0x93,0xdc,0x25,0x6e,0xb7,0x2e,0x49,0x92,0xbc,
            0x24,0x6d,0xb6,0xff,0x48,0x91,0xda,0x23,0x6c,0xb5,0xfe,0x47,0x90,0xd9,0x22,0x6b,
            0xb4,0xfd,0x46,0x8f,0x10,0x21,0x6a,0xb3,0xfc,0x45,0x8e,0xd7,0x20,0x69,0xb2,0xfb,
            0x44,0x8d,0xd6,0x1f,0x68,0xb1,0xfa,0x43,0x8c,0xd5,0x1e,0x67,0xb0,0xf9,0x38,0x8b,
            0xd4,0x1d,0x66,0xaf,0xf8,0x41,0x79,0xd3,0x1c,0x65,0xae,0xf7,0x40,0x89,0xd2,0x1b,
            0x64,0xad,
        ];
        const B2: [u8; 35] = [
            0x2a,0x15,0x90,0xc3,0xcc,0xa8,0x5c,0x8f,0x13,0xf5,0x28,0x5b,0xda,0x23,0xb8,0x27,
            0x56,0x8d,0xba,0xf3,0x26,0x59,0x4d,0xbf,0xf2,0x4b,0x58,0x8b,0x82,0xa2,0x21,0x57,
            0x8a,0xba,0xb8,
        ];
        const B3: [u8; 132] = [
            0xcf,0x49,0x5c,0x6f,0xf7,0x95,0xa8,0xbb,0x4c,0xe1,0xf4,0x07,0xcb,0x2d,0x40,0x53,
            0xae,0x79,0x8c,0x9f,0x1c,0xc5,0xd8,0xeb,0x23,0x11,0x24,0x37,0x7f,0x5d,0x70,0x83,
            0xbd,0xa9,0xbc,0xcf,0x39,0xf5,0x08,0x1b,0x85,0x41,0x54,0x67,0x53,0x8d,0xa0,0xb3,
            0x10,0xd9,0xec,0xff,0x1b,0x25,0x38,0x4b,0xc7,0x71,0x84,0x97,0xaa,0xbd,0xd0,0xe3,
            0xe7,0x09,0x1c,0x2f,0xf9,0x55,0x68,0x7b,0xf4,0xa1,0xb4,0xc7,0xa4,0xed,0x00,0x13,
            0x39,0x39,0x4c,0x5f,0x53,0x85,0x98,0xab,0x41,0xd1,0xe4,0xf7,0x25,0x1d,0x30,0x43,
            0xdb,0x69,0x7c,0x8f,0x1b,0xb5,0xc8,0xdb,0xf0,0x01,0x14,0x27,0x0e,0x4d,0x60,0x73,
            0x29,0x99,0xac,0xbf,0x20,0xe5,0xf8,0x0b,0x83,0x31,0x44,0x57,0xa2,0x7d,0x90,0xa3,
            0xf0,0xc9,0xdc,0xef,
        ];
        run_garble_test(13, &B0, &B1, &B2, &B3);
    }

    #[test]
    fn garble_seed_0() {
        const B0: [u8; 20] = [
            0x00,0x25,0x4a,0x52,0x94,0xb9,0xde,0xd6,0x28,0x4d,0x01,0x97,0x00,0x32,0x49,0x32,
            0x04,0x73,0x9a,0x84,
        ];
        const B1: [u8; 210] = [
            0x07,0x50,0x59,0xe2,0x52,0x28,0xbd,0x06,0x4f,0x98,0xe1,0x2a,0x73,0xbc,0x05,0xaf,
            0x97,0xe0,0x29,0x77,0xbb,0x04,0x47,0x66,0xdf,0x28,0x71,0xba,0x03,0x4c,0x95,0xde,
            0x27,0xea,0xd7,0x02,0xc8,0x94,0xdd,0x26,0x6f,0xb8,0x01,0x4a,0x93,0xdc,0x25,0x62,
            0xb7,0x00,0x49,0x92,0xdb,0xd3,0x6d,0xb6,0xff,0x48,0x91,0xda,0x23,0x6c,0xb5,0xfe,
            0x47,0x90,0xd9,0x22,0x6b,0xb4,0xfd,0x46,0x8f,0xd8,0x21,0x6a,0xb3,0xfc,0x45,0x8e,
            0xd7,0x20,0x69,0xb2,0xfb,0x44,0x8d,0xd6,0x1f,0x68,0xb1,0xfa,0x43,0x8c,0xd5,0xaa,
            0x67,0xb0,0xf9,0x42,0x8b,0xd4,0x1d,0x66,0xaf,0xf8,0xd8,0x8a,0xd3,0x1c,0x65,0xae,
            0xf7,0x40,0x89,0xd2,0x1b,0x64,0xad,0xf6,0x3f,0x88,0xd1,0xc7,0x64,0xac,0xf5,0x3e,
            0x87,0xd0,0x19,0x62,0xab,0xf4,0x3d,0x86,0xcf,0x18,0x61,0xaa,0xb8,0x3c,0x85,0xb7,
            0x17,0x60,0xa9,0xf2,0x3b,0x84,0xcd,0x16,0x5f,0x45,0xf1,0x3a,0x83,0xcc,0x15,0x5e,
            0xa7,0xf0,0x39,0x82,0x03,0x14,0x5d,0xa6,0xef,0x38,0x81,0xca,0x13,0x5c,0xa5,0xee,
            0x37,0x80,0xc9,0x12,0x5b,0xa4,0xed,0x36,0x7f,0xc8,0x11,0x5a,0xa3,0xec,0x38,0x7e,
            0xc7,0x10,0x59,0xa2,0xeb,0x34,0x5f,0xc6,0x0f,0x58,0xa1,0xea,0x33,0x7c,0xc5,0x0e,
            0x57,0xa0,
        ];
        const B2: [u8; 35] = [
            0x1d,0x28,0xc3,0xb6,0xdc,0x95,0x4f,0x82,0xa7,0xe8,0x1b,0x4e,0xfd,0x79,0x37,0x1a,
            0x77,0x80,0xc1,0xe6,0x19,0x4c,0x80,0xb2,0xe5,0xce,0x4b,0x7e,0x75,0xa2,0xd0,0x4a,
            0x7d,0xc1,0xb8,
        ];
        const B3: [u8; 132] = [
            0x73,0x3c,0x4f,0x62,0x53,0x88,0x9b,0xae,0x44,0xd4,0xe7,0xfa,0xb5,0x20,0x33,0x46,
            0xae,0x6c,0x7f,0x92,0x1c,0xb8,0xcb,0xde,0x16,0x04,0x17,0x2a,0x17,0x50,0x63,0x76,
            0x55,0x9c,0xaf,0xc2,0xa4,0xe8,0xfb,0x0e,0x95,0x34,0x47,0x5a,0x10,0x80,0x93,0xa6,
            0x19,0xcc,0xdf,0xf2,0x1b,0x18,0x2b,0x3e,0xc7,0x64,0x77,0x8a,0x9d,0xb0,0xc3,0xd6,
            0x30,0xfc,0x0f,0x22,0x79,0x48,0x5b,0x6e,0x6a,0x94,0xa7,0xba,0x2f,0xe0,0xf3,0x06,
            0x74,0x2c,0x3f,0x52,0x71,0x78,0x8b,0x9e,0x35,0xc4,0xd7,0xea,0x39,0x10,0x23,0x36,
            0xce,0x5c,0x6f,0x82,0x1b,0xa8,0xbb,0xce,0x77,0xf4,0x07,0x1a,0x00,0x40,0x53,0x66,
            0x34,0x8c,0x9f,0xb2,0x02,0xd8,0xeb,0xfe,0xe3,0x24,0x37,0x4a,0x1b,0x70,0x83,0x96,
            0xcf,0xbc,0xcf,0xe2,
        ];
        run_garble_test(0, &B0, &B1, &B2, &B3);
    }

    #[test]
    fn garble_seed_255() {
        const B0: [u8; 20] = [
            0xff,0x24,0x49,0xe6,0x93,0xb8,0xb8,0xe7,0x27,0x4c,0x08,0x96,0x81,0x73,0x79,0x5c,
            0x00,0x73,0x99,0xc4,
        ];
        const B1: [u8; 210] = [
            0x06,0x4f,0x58,0xe1,0x52,0x0f,0xbc,0x05,0x4e,0x97,0xe0,0x29,0x72,0xbb,0x04,0x1c,
            0x96,0xdf,0x28,0x92,0xba,0x03,0x57,0x69,0xde,0x27,0x70,0xb9,0x02,0x4b,0x94,0xdd,
            0x26,0x4b,0xe0,0x01,0xc7,0x93,0xdc,0x25,0x6e,0xb7,0x00,0x49,0x92,0xdb,0x24,0x5b,
            0xb6,0xff,0x48,0x91,0xda,0xcd,0x6c,0xb5,0xfe,0x47,0x90,0xd9,0x22,0x6b,0xb4,0xfd,
            0x46,0x8f,0xd8,0x21,0x6a,0xb3,0xfc,0x45,0x8e,0xd7,0x20,0x69,0xb2,0xfb,0x44,0x8d,
            0xd6,0x1f,0x68,0xb1,0xfa,0x43,0x8c,0xd5,0x1e,0x67,0xb0,0xf9,0x42,0x8b,0xd4,0xb1,
            0x66,0xaf,0xf8,0x41,0x8a,0xd3,0x1c,0x65,0xae,0xf7,0xbd,0x89,0xd2,0x1b,0x64,0xad,
            0xf6,0x3f,0x88,0xd1,0x1a,0x63,0xac,0xf5,0x3e,0x87,0xd0,0xc4,0xa6,0xab,0xf4,0x3d,
            0x86,0xcf,0x18,0x61,0xaa,0xf3,0x3c,0x85,0xce,0x17,0x60,0xa9,0x7d,0x3b,0x84,0xba,
            0x16,0x5f,0xa8,0xf1,0x3a,0x83,0xcc,0x15,0x5e,0x13,0xf0,0x39,0x82,0xcb,0x14,0x5d,
            0xa6,0xef,0x38,0x81,0x0b,0x13,0x5c,0xa5,0xee,0x37,0x80,0xc9,0x12,0x5b,0xa4,0xed,
            0x36,0x7f,0xc8,0x11,0x5a,0xa3,0xec,0x35,0x7e,0xc7,0x10,0x59,0xa2,0xeb,0x38,0x7d,
            0xc6,0x0f,0x58,0xa1,0xea,0x33,0x5d,0xc5,0x0e,0x57,0xa0,0xe9,0x32,0x7b,0xc4,0x0d,
            0x56,0x9f,
        ];
        const B2: [u8; 35] = [
            0x1c,0x37,0x88,0xb5,0xdd,0xf6,0x4e,0x81,0x32,0xe7,0x1a,0x4d,0xf8,0x25,0xab,0x19,
            0x19,0x7f,0xc8,0xe5,0x18,0x4b,0x54,0xb1,0xe4,0x85,0x4a,0x7d,0x38,0xa2,0xaa,0x49,
            0x7c,0xd6,0xb8,
        ];
        const B3: [u8; 132] = [
            0xa7,0x3b,0x4e,0x61,0x1f,0x87,0x9a,0xad,0x48,0xd3,0xe6,0xf9,0xac,0x1f,0x32,0x45,
            0x52,0x6b,0x7e,0x91,0x78,0xb7,0xca,0xdd,0x15,0x03,0x16,0x29,0xcf,0x4f,0x62,0x75,
            0x0d,0x9b,0xae,0xc1,0x7a,0xe7,0xfa,0x0d,0xb3,0x33,0x46,0x59,0x73,0x7f,0x92,0xa5,
            0x09,0xcb,0xde,0xf1,0x1b,0x17,0x2a,0x3d,0xc7,0x63,0x76,0x89,0x9c,0xaf,0xc2,0xd5,
            0xcc,0xfb,0x0e,0x21,0xe3,0x47,0x5a,0x6d,0x82,0x93,0xa6,0xb9,0x91,0xdf,0xf2,0x05,
            0x2a,0x2b,0x3e,0x51,0xe9,0x77,0x8a,0x9d,0x39,0xc3,0xd6,0xe9,0xff,0x0f,0x22,0x35,
            0xcd,0x5b,0x6e,0x81,0x1b,0xa7,0xba,0xcd,0x77,0xf3,0x06,0x19,0x00,0x3f,0x52,0x65,
            0x30,0x8b,0x9e,0xb1,0x02,0xd7,0xea,0xfd,0x08,0x23,0x36,0x49,0xf5,0x6f,0x82,0x95,
            0xc4,0xbb,0xce,0xe1,
        ];
        run_garble_test(255, &B0, &B1, &B2, &B3);
    }

}
