//! AirPlay feature flags.
//!
//! 64-bit bitmask declared in mDNS `features` TXT record.
//! Reference: <https://emanuelecozzi.net/docs/airplay2/features/>

/// Individual AirPlay feature flags.
/// Source: <https://emanuelecozzi.net/docs/airplay2/features/>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AirPlayFeature {
    /// Bit 0 — AirPlay video v1
    SupportsAirPlayVideoV1 = 0,
    /// Bit 1 — AirPlay photo
    SupportsAirPlayPhoto = 1,
    /// Bit 5 — AirPlay slideshow
    SupportsAirPlaySlideshow = 5,
    /// Bit 7 — AirPlay screen mirroring
    SupportsAirPlayScreen = 7,
    /// Bit 9 — AirPlay audio
    SupportsAirPlayAudio = 9,
    /// Bit 11 — Audio redundancy
    AudioRedundant = 11,
    /// Bit 14 — FairPlay authentication
    Authentication4 = 14,
    /// Bit 15 — Receive artwork image
    MetadataArtwork = 15,
    /// Bit 16 — Receive track progress
    MetadataProgress = 16,
    /// Bit 17 — Receive NowPlaying via DAAP
    MetadataNowPlayingDaap = 17,
    /// Bit 18 — Audio format support 0
    AudioFormats0 = 18,
    /// Bit 19 — Audio format support 1
    AudioFormats1 = 19,
    /// Bit 20 — Audio format support 2
    AudioFormats2 = 20,
    /// Bit 21 — Audio format support 3
    AudioFormats3 = 21,
    /// Bit 23 — RSA authentication (legacy, not used)
    Authentication1 = 23,
    /// Bit 26 — MFi authentication
    Authentication8Mfi = 26,
    /// Bit 27 — Legacy pairing
    SupportsLegacyPairing = 27,
    /// Bit 30 — Unified advertiser info
    HasUnifiedAdvertiserInfo = 30,
    /// Bit 32 — Volume control (when NOT CarPlay)
    SupportsVolume = 32,
    /// Bit 33 — Video play queue
    SupportsAirPlayVideoPlayQueue = 33,
    /// Bit 34 — AirPlay from cloud
    SupportsAirPlayFromCloud = 34,
    /// Bit 35 — TLS PSK
    SupportsTlsPsk = 35,
    /// Bit 38 — Unified media control
    SupportsUnifiedMediaControl = 38,
    /// Bit 40 — Buffered audio (AP2)
    SupportsBufferedAudio = 40,
    /// Bit 41 — PTP timing (AP2)
    SupportsPtp = 41,
    /// Bit 42 — Screen multi-codec
    SupportsScreenMultiCodec = 42,
    /// Bit 43 — System pairing
    SupportsSystemPairing = 43,
    /// Bit 44 — Valeria screen sender
    IsApValeriaScreenSender = 44,
    /// Bit 46 — HomeKit pairing and access control
    SupportsHkPairingAndAccessControl = 46,
    /// Bit 48 — CoreUtils pairing and encryption
    SupportsCoreUtilsPairingAndEncryption = 48,
    /// Bit 49 — AirPlay video v2
    SupportsAirPlayVideoV2 = 49,
    /// Bit 50 — Receive NowPlaying via binary plist (overrides bit 17)
    MetadataNowPlayingBplist = 50,
    /// Bit 51 — Unified pair-setup and MFi
    SupportsUnifiedPairSetupAndMfi = 51,
    /// Bit 52 — Extended SETPEERS message
    SupportsSetPeersExtendedMessage = 52,
    /// Bit 54 — AP sync (multi-room)
    SupportsApSync = 54,
    /// Bit 55 — Wake on LAN
    SupportsWoL55 = 55,
    /// Bit 56 — Wake on LAN (alternate)
    SupportsWoL56 = 56,
    /// Bit 58 — Hangdog remote control (requires isAppleTV/isAppleAudioAccessory)
    SupportsHangdogRemoteControl = 58,
    /// Bit 59 — Audio stream connection setup
    SupportsAudioStreamConnectionSetup = 59,
    /// Bit 60 — Audio media data control (requires bit 59)
    SupportsAudioMediaDataControl = 60,
    /// Bit 61 — RFC 2198 redundancy
    SupportsRfc2198Redundancy = 61,
}

/// Build a 64-bit features bitmask from a set of feature flags.
pub fn features_from(flags: &[AirPlayFeature]) -> u64 {
    let mut val: u64 = 0;
    for &f in flags {
        val |= 1u64 << (f as u8);
    }
    val
}

/// Format features as the mDNS `features=` value: `"0x{lo},0x{hi}"`.
pub fn features_to_mdns(features: u64) -> String {
    let lo = features & 0xFFFFFFFF;
    let hi = (features >> 32) & 0xFFFFFFFF;
    format!("0x{:X},0x{:X}", lo, hi)
}

/// Features for an audio-only AirPlay 2 receiver.
///
/// Based on shairport-sync's proven AP2 features (0x1C340405D4A00)
/// Returns the feature bitmask for the receiver based on enabled compile-time features.
pub fn receiver_features() -> u64 {
    use AirPlayFeature::*;

    #[allow(unused_mut)]
    let mut bits: Vec<AirPlayFeature> = vec![
        // Core audio
        SupportsAirPlayAudio,
        AudioRedundant,
        Authentication4,              // FairPlay
        MetadataArtwork,
        MetadataProgress,
        MetadataNowPlayingDaap,
        AudioFormats0,
        AudioFormats1,
        Authentication1,
        SupportsLegacyPairing,
        HasUnifiedAdvertiserInfo,
        SupportsVolume,
        SupportsUnifiedMediaControl,
        SupportsBufferedAudio,
        SupportsPtp,
        SupportsHkPairingAndAccessControl,
        SupportsCoreUtilsPairingAndEncryption,
        MetadataNowPlayingBplist,
        SupportsSetPeersExtendedMessage,
        SupportsAirPlayVideoV2,       // needed for AP2 audio despite the name
        SupportsAudioStreamConnectionSetup,
        SupportsAudioMediaDataControl,
        SupportsRfc2198Redundancy,
    ];

    #[allow(unused_mut)]
    let mut val = features_from(&bits);

    #[cfg(feature = "video")]
    {
        val |= features_from(&[
            SupportsAirPlayVideoV1,
            SupportsAirPlayScreen,
            SupportsScreenMultiCodec,
        ]);
    }

    val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_bits_correct() {
        assert_eq!(1u64 << (AirPlayFeature::SupportsAirPlayAudio as u8), 1 << 9);
        assert_eq!(1u64 << (AirPlayFeature::SupportsPtp as u8), 1 << 41);
        assert_eq!(1u64 << (AirPlayFeature::SupportsHangdogRemoteControl as u8), 1 << 58);
    }

    #[test]
    fn features_from_builds_bitmask() {
        let f = features_from(&[AirPlayFeature::SupportsAirPlayAudio, AirPlayFeature::SupportsPtp]);
        assert!(f & (1 << 9) != 0);
        assert!(f & (1 << 41) != 0);
        assert!(f & (1 << 0) == 0);
    }

    #[test]
    fn mdns_format() {
        let f = 0x1234567890ABCDEFu64;
        let s = features_to_mdns(f);
        assert_eq!(s, "0x90ABCDEF,0x12345678");
    }

    #[test]
    fn audio_receiver_has_required_bits() {
        let f = receiver_features();
        // Core AP2 requirements (from shairport-sync)
        assert!(f & (1 << 9) != 0, "SupportsAirPlayAudio");
        assert!(f & (1 << 11) != 0, "AudioRedundant");
        assert!(f & (1 << 40) != 0, "SupportsBufferedAudio");
        assert!(f & (1 << 41) != 0, "SupportsPtp");
        assert!(f & (1 << 14) != 0, "Authentication4 (FairPlay)");
        assert!(f & (1 << 38) != 0, "SupportsUnifiedMediaControl");
        assert!(f & (1 << 46) != 0, "SupportsHKPairing");
        assert!(f & (1 << 48) != 0, "SupportsCoreUtilsPairing");
    }
}
