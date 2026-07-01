//! Audio codec implementations (ALAC, AAC, resampling).

pub(crate) mod alac;
#[cfg(feature = "resample")]
pub(crate) mod resample;

#[cfg(feature = "ap2")]
pub(crate) mod aac;
