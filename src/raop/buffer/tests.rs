use super::*;

// Valid stereo AAC-ELD access units at 44.1 kHz, 480 samples per channel.
// The PNS frame leaves synthesis history that is audible in subsequent silence.
const PNS: &[u8] = &[0x04, 0xa0, 0xd0, 0xc0, 0x14, 0x1a, 0x18, 0x00];
const SILENT: &[u8] = &[0x00, 0xa0, 0x50, 0x00];
const STARTUP: &[u8] = &[0x00, 0x68, 0x34, 0x00];

fn buffer() -> RaopBuffer {
    RaopBuffer::new_aac_eld(44_100, 2, 480, &[0; 16], &[0; 16]).unwrap()
}

fn packet(seqnum: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    packet[2..4].copy_from_slice(&seqnum.to_be_bytes());
    packet[4..8].copy_from_slice(&(u32::from(seqnum) * 480).to_be_bytes());
    // These short access units fit in the clear tail of an AES-CBC packet.
    packet.extend_from_slice(payload);
    packet
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
