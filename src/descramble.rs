//! Packet dispositions reported by transport-stream descramblers.

/// Counts what a descrambler did with each transport packet in a successful
/// batch.
///
/// These fields are deliberately not collapsed into a success ratio:
/// [`Self::decrypted`] is workload, not health, and can be low on a healthy
/// clear-heavy multiplex. [`Self::broken`] is the silent-degradation signal,
/// [`Self::transport_error`] is a reception signal, and a batch-level `Err`
/// remains the abandonment signal for the caller to count separately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DescrambleDispositionCounts {
    /// Packets whose encrypted payload was decrypted.
    pub decrypted: usize,
    /// Packets already clear and passed through unchanged.
    pub unscrambled: usize,
    /// Scrambled packets with no decryptable payload.
    pub no_payload: usize,
    /// Packets explicitly passed through because their transport-error bit was set.
    pub transport_error: usize,
    /// Packets with broken geometry that the implementation left unchanged.
    pub broken: usize,
}
