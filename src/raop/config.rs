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

/// AP2 status flag: a one-time PIN is required for normal HomeKit pairing.
#[cfg(feature = "ap2")]
pub(crate) const AP2_STATUS_ONE_TIME_PAIRING_REQUIRED: u32 = 1 << 9;

/// Build AP2 statusFlags for the selected pairing mode.
#[cfg(feature = "ap2")]
pub(crate) fn ap2_status_flags(requires_pin_pairing: bool) -> u32 {
    let mut flags = AP2_STATUS_AUDIO_ATTACHED;
    if requires_pin_pairing {
        flags |= AP2_STATUS_ONE_TIME_PAIRING_REQUIRED;
    }
    flags
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
