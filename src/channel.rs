//! The Japanese terrestrial (ISDB-T) UHF channel plan.
//!
//! Physical channels 13 through 52, six megahertz apart, based at the UHF13
//! centre frequency. This is a published allocation, not a device property —
//! every tuner that receives Japanese terrestrial television uses these same
//! numbers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JapaneseTerrestrialChannelError {
    UnsupportedPhysicalChannel(i32),
}

/// Centre frequency of a Japanese UHF physical channel, in Hz.
///
/// The published allocation: ch13 is 473.142857 MHz and each channel is one
/// 6 MHz step above. **Deliberately unvalidated** — which channels are usable
/// is a policy that differs by caller, and stating it here would force one
/// caller's policy on the other. See [`JapaneseTerrestrialChannel`] for the
/// broadcast allocation, and a concrete device crate's frequency conversion (its own `freq_khz`) for the tuner's PLL range.
pub fn uhf_centre_frequency_hz(physical_channel: u32) -> u32 {
    473_142_857 + (physical_channel - 13) * 6_000_000
}

/// The same value in kHz, rounded — what a tuner PLL takes.
pub fn uhf_centre_frequency_khz(physical_channel: u32) -> u32 {
    uhf_centre_frequency_hz(physical_channel).div_ceil(1_000)
}

/// A Japanese terrestrial (UHF) physical channel and its centre frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JapaneseTerrestrialChannel {
    physical_channel: i32,
}

impl JapaneseTerrestrialChannel {
    /// First channel in the current Japanese terrestrial broadcast allocation.
    pub const FIRST_PHYSICAL_CHANNEL: i32 = 13;
    /// Last channel in the current allocation; channels 53–62 were reassigned to mobile.
    pub const LAST_PHYSICAL_CHANNEL: i32 = 52;

    pub fn new(physical_channel: i32) -> Result<Self, JapaneseTerrestrialChannelError> {
        if !(Self::FIRST_PHYSICAL_CHANNEL..=Self::LAST_PHYSICAL_CHANNEL).contains(&physical_channel)
        {
            return Err(JapaneseTerrestrialChannelError::UnsupportedPhysicalChannel(
                physical_channel,
            ));
        }
        Ok(Self { physical_channel })
    }

    pub fn physical_channel(&self) -> i32 {
        self.physical_channel
    }

    pub fn frequency_hz(&self) -> u32 {
        uhf_centre_frequency_hz(self.physical_channel as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uhf13_is_the_arib_base_frequency() {
        assert_eq!(
            JapaneseTerrestrialChannel::new(13).unwrap().frequency_hz(),
            473_142_857
        );
    }

    #[test]
    fn each_channel_steps_by_six_megahertz() {
        // ch23 is the channel every hardware verification uses.
        let ch23 = JapaneseTerrestrialChannel::new(23).unwrap();
        assert_eq!(ch23.frequency_hz(), 473_142_857 + 10 * 6_000_000);
        assert_eq!(ch23.physical_channel(), 23);

        let ch52 = JapaneseTerrestrialChannel::new(52).unwrap();
        assert_eq!(ch52.frequency_hz(), 473_142_857 + 39 * 6_000_000);
    }

    #[test]
    fn channels_outside_the_terrestrial_band_are_rejected() {
        for channel in [12, 53, 0, -1] {
            assert_eq!(
                JapaneseTerrestrialChannel::new(channel),
                Err(JapaneseTerrestrialChannelError::UnsupportedPhysicalChannel(
                    channel
                ))
            );
        }
    }

    #[test]
    fn the_frequency_of_the_last_channel_does_not_overflow() {
        // 473142857 + 39*6000000 = 707142857, well inside u32.
        assert_eq!(
            JapaneseTerrestrialChannel::new(52).unwrap().frequency_hz(),
            707_142_857
        );
    }
}
