//! Audio codec implementations (ALAC, AAC, resampling).

pub mod alac;
#[cfg(feature = "resample")]
pub mod resample;

#[cfg(feature = "ap2")]
pub mod aac;
