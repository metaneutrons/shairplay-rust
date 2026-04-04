//! Networking layer — TCP server, mDNS discovery, PTP timing, feature flags.

#[cfg(feature = "ap2")]
pub mod features;
pub mod mdns;
#[cfg(feature = "ap2")]
pub mod ptp;
pub mod server;
