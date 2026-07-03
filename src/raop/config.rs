// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Fabian Schmieder

//! Single Source of Truth (SSOT) for global AirPlay receiver capabilities and profiles.

/// Global device hardware model advertised to Apple clients.
pub(crate) const GLOBAL_MODEL: &str = "AppleTV2,1";

/// RTSP/mDNS protocol version for AirPlay 2.
#[cfg(feature = "ap2")]
pub(crate) const AP2_PROTOVERS: &str = "1.1";

/// Software build/source version reported in GET /info and mDNS.
#[cfg(feature = "ap2")]
pub(crate) const AP2_SRCVERS: &str = "366.0";

/// AP2 status flag: audio output is available.
#[cfg(feature = "ap2")]
pub(crate) const AP2_STATUS_AUDIO_ATTACHED: u32 = 1 << 2;

/// AP2 status flag (bit 9): one-time HomeKit pairing (a PIN) is required. A PIN
/// accessory advertises this whether paired or not — matches real Apple TVs.
#[cfg(feature = "ap2")]
pub(crate) const AP2_STATUS_ONE_TIME_PAIRING_REQUIRED: u32 = 1 << 9;

/// AP2 status flag (bit 10): the accessory has completed HomeKit access-control
/// setup (i.e. it is paired). Advertised alongside bit 9 once paired.
#[cfg(feature = "ap2")]
pub(crate) const AP2_STATUS_DEVICE_SETUP_FOR_HK_ACCESS_CONTROL: u32 = 1 << 10;

/// Build AP2 statusFlags for the selected pairing mode.
///
/// Matches the flag *structure* real Apple TVs advertise (`flags=0x18644` =
/// bits 2,6,9,10,15,16): a PIN accessory always keeps bit 9
/// (`OneTimePairingRequired`) and, once paired, *adds* bit 10
/// (`DeviceSetupForHKAccessControl`) — so `sf=0x204` unpaired, `sf=0x604` paired.
///
/// Do NOT instead clear bit 9 to `0x004`: that is a transient (PIN-less)
/// accessory's flag value, so the sender treats us as transient and attempts a
/// transient pair-setup we must reject (stalling the connection). And bit 10
/// *without* bit 9 (`0x404`) makes the sender attempt transient on every
/// connection. Bit 9 says "I'm a PIN device"; bit 10 says "already set up".
#[cfg(feature = "ap2")]
pub(crate) fn ap2_status_flags(requires_pin_pairing: bool, already_paired: bool) -> u32 {
    let mut flags = AP2_STATUS_AUDIO_ATTACHED;
    if requires_pin_pairing {
        flags |= AP2_STATUS_ONE_TIME_PAIRING_REQUIRED;
        if already_paired {
            flags |= AP2_STATUS_DEVICE_SETUP_FOR_HK_ACCESS_CONTROL;
        }
    }
    flags
}

#[cfg(all(test, feature = "ap2"))]
mod status_flag_tests {
    use super::*;

    #[test]
    fn status_flags_match_apple_tv_structure() {
        assert_eq!(ap2_status_flags(false, false), 0x004, "transient (PIN-less)");
        assert_eq!(ap2_status_flags(false, true), 0x004, "transient (paired irrelevant)");
        assert_eq!(ap2_status_flags(true, false), 0x204, "PIN, unpaired");
        assert_eq!(
            ap2_status_flags(true, true),
            0x604,
            "PIN, paired (bits 9+10, like Apple TV)"
        );
    }
}

// --- Screen Mirroring (Video) Display Specifications ---
// Only consumed by the `video` screen-mirroring path in handlers_ap2.

/// Width in pixels advertised for the virtual display target.
#[cfg(feature = "video")]
pub(crate) const MIRRORING_WIDTH: i64 = 1920;

/// Height in pixels advertised for the virtual display target.
#[cfg(feature = "video")]
pub(crate) const MIRRORING_HEIGHT: i64 = 1080;

/// Frame rate advertised for the virtual display target.
#[cfg(feature = "video")]
pub(crate) const MIRRORING_FPS: i64 = 60;

/// Static UUID tag for the virtual display target.
#[cfg(feature = "video")]
pub(crate) const MIRRORING_UUID: &str = "shairplay_display";

/// Display features bitmask advertised for screen mirroring.
#[cfg(feature = "video")]
pub(crate) const MIRRORING_FEATURES: i64 = 2;
