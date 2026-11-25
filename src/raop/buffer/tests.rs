use super::*;
use aes::cipher::{BlockModeEncrypt, block_padding::NoPadding};

// Valid stereo AAC-ELD access units at 44.1 kHz, 480 samples per channel.
// The PNS frame leaves synthesis history that is audible in subsequent silence.
const PNS: &[u8] = &[0x04, 0xa0, 0xd0, 0xc0, 0x14, 0x1a, 0x18, 0x00];
const SILENT: &[u8] = &[0x00, 0xa0, 0x50, 0x00];
const STARTUP: &[u8] = &[0x00, 0x68, 0x34, 0x00];
const AAC_ELD_FIXTURE: &[u8] =
    include_bytes!("../../../tests/data/aac-eld/stereo-44100-512.aaceld");
const AAC_ELD_FIXTURE_MAGIC: &[u8] = b"RAOP-AAC-ELD\x01";
const AAC_ELD_512_ASC: &[u8] = &[0xf8, 0xe8, 0x40, 0x00];
const AES_KEY: [u8; 16] = [
    0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0, 0x31, 0x75, 0xb9, 0xfd, 0x42, 0x86, 0xca, 0x0e,
];
const AES_IV: [u8; 16] = [
    0xa1, 0x3c, 0x7e, 0x19, 0x54, 0x8b, 0xd2, 0x60, 0x05, 0xf7, 0x2a, 0x9d, 0x41, 0xce, 0x83, 0x36,
];

fn buffer() -> RaopBuffer {
    RaopBuffer::new_aac_eld(44_100, 2, 480, &[0; 16], &[0; 16]).unwrap()
}

fn packet(seqnum: u16, payload: &[u8]) -> Vec<u8> {
    packet_at(seqnum, u32::from(seqnum) * 480, payload)
}

fn packet_at(seqnum: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    packet[2..4].copy_from_slice(&seqnum.to_be_bytes());
    packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn aac_eld_access_units() -> Vec<&'static [u8]> {
    assert!(AAC_ELD_FIXTURE.starts_with(AAC_ELD_FIXTURE_MAGIC));
    let mut offset = AAC_ELD_FIXTURE_MAGIC.len();
    let count = u16::from_be_bytes([AAC_ELD_FIXTURE[offset], AAC_ELD_FIXTURE[offset + 1]]);
    offset += 2;
    let mut access_units = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        assert!(offset + 2 <= AAC_ELD_FIXTURE.len());
        let length = usize::from(u16::from_be_bytes([
            AAC_ELD_FIXTURE[offset],
            AAC_ELD_FIXTURE[offset + 1],
        ]));
        offset += 2;
        assert!(length > 0 && offset + length <= AAC_ELD_FIXTURE.len());
        access_units.push(&AAC_ELD_FIXTURE[offset..offset + length]);
        offset += length;
    }
    assert_eq!(offset, AAC_ELD_FIXTURE.len());
    access_units
}

fn raw_aac_eld_decoder() -> rusty_aac::decode::Decoder {
    let config = rusty_aac::config::parse(AAC_ELD_512_ASC).unwrap();
    rusty_aac::decode::Decoder::with_stream_config(config).unwrap()
}

fn raw_aac_eld_reference(access_units: &[&[u8]]) -> Vec<Vec<f32>> {
    let mut decoder = raw_aac_eld_decoder();
    access_units
        .iter()
        .map(|access_unit| {
            let decoded = decoder.decode(access_unit, None).unwrap();
            assert_eq!(decoded.sample_rate, 44_100);
            assert_eq!(decoded.channels, 2);
            assert_eq!(decoded.frames(), 512);
            decoded.samples
        })
        .collect()
}

fn aac_eld_512_buffer(key: &[u8; 16], iv: &[u8; 16]) -> RaopBuffer {
    RaopBuffer::new_aac_eld(44_100, 2, 512, key, iv).unwrap()
}

fn encrypted_packet(seqnum: u16, access_unit: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let mut packet = packet_at(seqnum, u32::from(seqnum) * 512, access_unit);
    let payload = &mut packet[12..];
    let encrypted_len = payload.len() / 16 * 16;
    if encrypted_len != 0 {
        cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
            .encrypt_padded::<NoPadding>(&mut payload[..encrypted_len], encrypted_len)
            .unwrap();
    }
    packet
}

fn dequeue_512(buffer: &mut RaopBuffer) -> Vec<f32> {
    let samples = buffer
        .dequeue(false)
        .expect("queued AAC-ELD frame")
        .to_vec();
    assert_eq!(samples.len(), 1024);
    assert!(samples.iter().all(|sample| sample.is_finite()));
    samples
}

fn dequeue(buffer: &mut RaopBuffer) -> Vec<f32> {
    let samples = buffer.dequeue(false).expect("queued frame").to_vec();
    assert_eq!(samples.len(), 960);
    assert!(samples.iter().all(|sample| sample.is_finite()));
    samples
}

fn fresh_silence() -> Vec<f32> {
    let mut buffer = buffer();
    assert_eq!(buffer.queue(&packet(1, SILENT), true), 1);
    let samples = dequeue(&mut buffer);
    assert!(samples.iter().all(|&sample| sample == 0.0));
    samples
}

fn ordered_pcm() -> Vec<Vec<f32>> {
    let mut buffer = buffer();
    for (seqnum, payload) in [(1, PNS), (2, SILENT), (3, SILENT)] {
        assert_eq!(buffer.queue(&packet(seqnum, payload), true), 1);
    }
    let frames: Vec<_> = (0..3).map(|_| dequeue(&mut buffer)).collect();
    assert!(frames[0].iter().any(|sample| sample.abs() > 0.001));
    assert!(frames[1].iter().any(|sample| sample.abs() > 0.001));
    assert!(buffer.dequeue(false).is_none());
    frames
}

#[test]
fn aac_eld_reordered_packets_match_ordered_pcm() {
    let expected = ordered_pcm();
    let mut buffer = buffer();
    for (seqnum, payload) in [(1, PNS), (3, SILENT), (2, SILENT)] {
        assert_eq!(buffer.queue(&packet(seqnum, payload), true), 1);
    }
    for frame in expected {
        assert_eq!(dequeue(&mut buffer), frame);
    }
}

#[test]
fn aac_eld_retransmissions_and_duplicates_preserve_pcm() {
    let expected = ordered_pcm();
    let mut buffer = buffer();
    assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
    assert_eq!(dequeue(&mut buffer), expected[0]);
    assert_eq!(buffer.queue(&packet(3, SILENT), true), 1);
    assert_eq!(buffer.queue(&packet(3, SILENT), true), 0);
    assert!(buffer.dequeue(false).is_none(), "wait for sequence 2");
    assert!(
        buffer.dequeue(false).is_none(),
        "waiting must preserve history"
    );
    // A control-channel retransmission supplies the original RTP packet.
    assert_eq!(buffer.queue(&packet(2, SILENT), true), 1);
    assert_eq!(dequeue(&mut buffer), expected[1]);
    assert_eq!(buffer.queue(&packet(2, PNS), true), 0, "stale retransmit");
    assert_eq!(dequeue(&mut buffer), expected[2]);
}

#[test]
fn aac_eld_missing_packet_resets_history_and_rejects_late_retransmit() {
    let expected = fresh_silence();
    let mut buffer = buffer();
    assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
    dequeue(&mut buffer);
    assert_eq!(buffer.queue(&packet(3, SILENT), true), 1);
    assert_eq!(buffer.dequeue(true).unwrap(), expected, "conceal missing 2");
    assert_eq!(buffer.queue(&packet(2, PNS), true), 0);
    assert_eq!(dequeue(&mut buffer), expected, "restart after the gap");
}

#[test]
fn aac_eld_full_buffer_skips_missing_packet_and_resets_history() {
    let expected = fresh_silence();
    let mut buffer = buffer();
    assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
    dequeue(&mut buffer);
    for seqnum in 3..=33 {
        assert_eq!(buffer.queue(&packet(seqnum, SILENT), true), 1);
    }
    assert_eq!(
        dequeue(&mut buffer),
        expected,
        "full window conceals missing 2"
    );
    assert_eq!(
        dequeue(&mut buffer),
        expected,
        "history reset after missing 2"
    );
}

#[test]
fn aac_eld_invalid_access_unit_emits_silence_and_resets_history() {
    let expected = fresh_silence();
    for payload in [&[][..], &PNS[..3]] {
        let mut buffer = buffer();
        assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
        dequeue(&mut buffer);
        assert_eq!(buffer.queue(&packet(2, payload), true), 1);
        assert_eq!(buffer.queue(&packet(3, SILENT), true), 1);
        assert_eq!(
            dequeue(&mut buffer),
            expected,
            "conceal invalid access unit"
        );
        assert_eq!(
            dequeue(&mut buffer),
            expected,
            "discard partial decoder state"
        );
    }
}

#[test]
fn aac_eld_flush_discards_synthesis_history_and_queued_frames() {
    let expected = fresh_silence();
    for next_seq in [2, -1] {
        let mut buffer = buffer();
        assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
        dequeue(&mut buffer);
        assert_eq!(buffer.queue(&packet(2, PNS), true), 1);
        buffer.flush(next_seq);
        assert!(buffer.dequeue(false).is_none());
        assert_eq!(buffer.queue(&packet(2, SILENT), true), 1);
        assert_eq!(dequeue(&mut buffer), expected);
    }
}

#[test]
fn aac_eld_sequence_resync_discards_synthesis_history_and_queued_frames() {
    let expected = fresh_silence();
    let mut buffer = buffer();
    assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
    dequeue(&mut buffer);
    assert_eq!(buffer.queue(&packet(2, PNS), true), 1);
    // Next expected is 2; 34 is the first sequence outside the 32-slot window.
    assert_eq!(buffer.queue(&packet(34, SILENT), true), 1);
    assert_eq!(dequeue(&mut buffer), expected);
    assert!(buffer.dequeue(false).is_none());
    assert_eq!(buffer.queue(&packet(2, PNS), true), 0);
}

#[test]
fn aac_eld_reordering_across_sequence_wrap_preserves_history() {
    let expected = ordered_pcm();
    let mut buffer = buffer();
    for (seqnum, payload) in [(u16::MAX, PNS), (1, SILENT), (0, SILENT)] {
        assert_eq!(buffer.queue(&packet(seqnum, payload), true), 1);
    }
    for frame in expected {
        assert_eq!(dequeue(&mut buffer), frame);
    }
}

#[test]
fn aac_eld_config_encodes_negotiated_format() {
    for (rate, channels, frame_samples, bytes) in [
        (44_100, 2, 480, [0xf8, 0xe8, 0x50, 0x00]),
        (48_000, 2, 480, [0xf8, 0xe6, 0x50, 0x00]),
        (48_000, 1, 512, [0xf8, 0xe6, 0x20, 0x00]),
    ] {
        let config = aac_eld_audio_specific_config(rate, channels, frame_samples).unwrap();
        assert_eq!(config, bytes);
        let buffer = RaopBuffer::new_aac_eld(rate, channels, frame_samples, &[0; 16], &[0; 16])
            .expect("supported AAC-ELD format");
        assert_eq!(buffer.format().sample_rate, rate);
        assert_eq!(buffer.format().num_channels, channels);
    }
}

#[test]
fn aac_eld_config_rejects_unsupported_parameters() {
    for (rate, channels, frame_samples) in [
        (0, 2, 480),
        (44_101, 2, 480),
        (44_100, 0, 480),
        (44_100, 3, 480),
        (44_100, 2, 0),
        (44_100, 2, 1024),
    ] {
        assert!(
            RaopBuffer::new_aac_eld(rate, channels, frame_samples, &[0; 16], &[0; 16]).is_none()
        );
    }
}

#[test]
fn aac_eld_startup_marker_does_not_advance_sequence_or_decoder() {
    let expected = ordered_pcm();
    let mut buffer = buffer();
    assert_eq!(buffer.queue(&packet(0, STARTUP), true), 0);
    assert!(buffer.dequeue(true).is_none());
    assert_eq!(buffer.queue(&packet(1, PNS), true), 1);
    assert_eq!(dequeue(&mut buffer), expected[0]);
    // Even an out-of-window marker must not trigger resynchronization.
    assert_eq!(buffer.queue(&packet(100, STARTUP), true), 0);
    assert_eq!(buffer.queue(&packet(2, STARTUP), true), 0);
    assert_eq!(buffer.queue(&packet(2, SILENT), true), 1);
    assert_eq!(dequeue(&mut buffer), expected[1]);
    // The marker is codec-specific; the same bytes are valid L16 samples.
    let mut pcm = RaopBuffer::new_unencrypted("96 L16/44100/2", "").unwrap();
    assert_eq!(pcm.queue(&packet(1, STARTUP), true), 1);
    assert_eq!(pcm.dequeue(true).unwrap().len(), 2);
}

#[test]
fn aac_eld_real_access_units_decrypt_and_match_raw_decoder_reference() {
    assert!(AES_KEY.iter().any(|&byte| byte != 0));
    assert!(AES_IV.iter().any(|&byte| byte != 0));
    let access_units = aac_eld_access_units();
    assert_eq!(access_units.len(), 5);
    assert!(
        access_units
            .iter()
            .all(|access_unit| access_unit.len() > 32 && access_unit.len() % 16 != 0)
    );
    let reference = raw_aac_eld_reference(&access_units);
    assert!(
        reference[1..]
            .iter()
            .flatten()
            .any(|sample| sample.abs() > 0.001)
    );

    let mut buffer = aac_eld_512_buffer(&AES_KEY, &AES_IV);
    for (index, access_unit) in access_units.iter().enumerate() {
        let seqnum = index as u16 + 1;
        let packet = encrypted_packet(seqnum, access_unit, &AES_KEY, &AES_IV);
        assert_eq!(buffer.queue(&packet, true), 1);
    }

    for expected in reference {
        assert_eq!(dequeue_512(&mut buffer), expected);
    }
    assert!(buffer.dequeue(false).is_none());
}

#[test]
fn aac_eld_real_access_units_reordered_after_decryption_match_playback_order() {
    let access_units = aac_eld_access_units();
    let reference = raw_aac_eld_reference(&access_units);
    let mut buffer = aac_eld_512_buffer(&AES_KEY, &AES_IV);

    for (seqnum, index) in [(1, 0), (3, 2), (2, 1), (5, 4), (4, 3)] {
        let packet = encrypted_packet(seqnum, access_units[index], &AES_KEY, &AES_IV);
        assert_eq!(buffer.queue(&packet, true), 1);
    }

    for expected in reference {
        assert_eq!(dequeue_512(&mut buffer), expected);
    }
}

#[test]
fn aac_eld_real_access_unit_does_not_match_with_wrong_key_or_iv() {
    let access_units = aac_eld_access_units();
    let access_unit = access_units[1];
    let expected = raw_aac_eld_reference(&[access_unit]).remove(0);
    assert!(expected.iter().any(|sample| sample.abs() > 0.001));

    let mut wrong_key = AES_KEY;
    wrong_key[0] ^= 1;
    let mut wrong_iv = AES_IV;
    wrong_iv[0] ^= 1;
    for (key, iv) in [(&wrong_key, &AES_IV), (&AES_KEY, &wrong_iv)] {
        let mut buffer = aac_eld_512_buffer(key, iv);
        let packet = encrypted_packet(1, access_unit, &AES_KEY, &AES_IV);
        assert_eq!(buffer.queue(&packet, true), 1);
        assert_ne!(dequeue_512(&mut buffer), expected);
    }
}

#[test]
fn aac_eld_adts_looking_raw_unit_is_rejected_and_resets_history() {
    // A valid-looking ADTS AAC-LC header declaring a 39-byte frame. It is not
    // a raw AAC-ELD access unit and must not trigger the stream-level ADTS path.
    const ADTS_LOOKING_INVALID_ELD: &[u8] = &[
        0xff, 0xf1, 0x50, 0x80, 0x04, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let access_units = aac_eld_access_units();
    let after_reset = raw_aac_eld_reference(&[access_units[1]]).remove(0);
    let mut decoder = raw_aac_eld_decoder();
    assert!(decoder.decode(ADTS_LOOKING_INVALID_ELD, None).is_err());

    let mut buffer = aac_eld_512_buffer(&AES_KEY, &AES_IV);
    let first = encrypted_packet(1, access_units[0], &AES_KEY, &AES_IV);
    assert_eq!(buffer.queue(&first, true), 1);
    dequeue_512(&mut buffer);

    let invalid = encrypted_packet(2, ADTS_LOOKING_INVALID_ELD, &AES_KEY, &AES_IV);
    assert_eq!(buffer.queue(&invalid, true), 1);
    assert!(dequeue_512(&mut buffer).iter().all(|&sample| sample == 0.0));

    let next = encrypted_packet(3, access_units[1], &AES_KEY, &AES_IV);
    assert_eq!(buffer.queue(&next, true), 1);
    assert_eq!(dequeue_512(&mut buffer), after_reset);
}
