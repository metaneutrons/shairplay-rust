//! Constant data for the FairPlay key exchange, kept as binary files next to this module.
//!
//! The tables, keys and messages are plain constants whose values the protocol fixes.
//! See `docs/fairplay-provenance.md` for where they come from.
//!
//! Each file is a plain byte image. Tables of 32-bit words are stored little endian.

/// Read `N` little-endian 32-bit words from a byte image of `4 * N` bytes.
const fn le_words<const N: usize, const B: usize>(bytes: &[u8; B]) -> [u32; N] {
    assert!(B == 4 * N);
    let mut out = [0u32; N];
    let mut i = 0;
    while i < N {
        out[i] = u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        i += 1;
    }
    out
}

pub(crate) static KS_PAGES: [u8; 10240] = *include_bytes!("fairplay_data/ks_pages.bin");
pub(crate) static MSG_PAGES: [u8; 36864] = *include_bytes!("fairplay_data/msg_pages.bin");
pub(crate) static PERM_FWD: [u8; 4096] = *include_bytes!("fairplay_data/perm_fwd.bin");
pub(crate) static PERM_PAGES: [u8; 36864] = *include_bytes!("fairplay_data/perm_pages.bin");
pub(crate) static PERM_OUT: [u8; 4096] = *include_bytes!("fairplay_data/perm_out.bin");
pub(crate) static MIX_0: [u32; 256] = le_words(include_bytes!("fairplay_data/mix_0.bin"));
pub(crate) static MIX_1: [u32; 256] = le_words(include_bytes!("fairplay_data/mix_1.bin"));
pub(crate) static MIX_2: [u32; 256] = le_words(include_bytes!("fairplay_data/mix_2.bin"));
pub(crate) static MIX_3: [u32; 256] = le_words(include_bytes!("fairplay_data/mix_3.bin"));
pub(crate) static MIX_MSG: [u32; 1024] = le_words(include_bytes!("fairplay_data/mix_msg.bin"));
pub(crate) static MASK_Z: [u8; 16] = *include_bytes!("fairplay_data/mask_z.bin");
pub(crate) static MASK_X: [u8; 16] = *include_bytes!("fairplay_data/mask_x.bin");
pub(crate) static MASK_T: [u8; 16] = *include_bytes!("fairplay_data/mask_t.bin");
pub(crate) static SESSION_INIT: [u8; 16] = *include_bytes!("fairplay_data/session_init.bin");
pub(crate) static STATIC_A: [u8; 17] = *include_bytes!("fairplay_data/static_a.bin");
pub(crate) static STATIC_B: [u8; 47] = *include_bytes!("fairplay_data/static_b.bin");
pub(crate) static SAP_DEFAULT: [u8; 276] = *include_bytes!("fairplay_data/sap_default.bin");
pub(crate) static MSG_KEYS: [u8; 576] = *include_bytes!("fairplay_data/msg_keys.bin");
pub(crate) static MSG_IVS: [u8; 64] = *include_bytes!("fairplay_data/msg_ivs.bin");
pub(crate) static REPLIES: [u8; 568] = *include_bytes!("fairplay_data/replies.bin");
pub(crate) static HEADER: [u8; 12] = *include_bytes!("fairplay_data/header.bin");
pub(crate) static BLEND_SEED_0: [u8; 20] = *include_bytes!("fairplay_data/blend_seed_0.bin");
pub(crate) static BLEND_SEED_2: [u8; 35] = *include_bytes!("fairplay_data/blend_seed_2.bin");
pub(crate) static BLEND_AUX: [u8; 21] = *include_bytes!("fairplay_data/blend_aux.bin");
pub(crate) static OUT_TAPS: [u8; 11] = *include_bytes!("fairplay_data/out_taps.bin");
