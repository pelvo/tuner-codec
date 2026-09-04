//! Packetized elementary stream (PES) reassembly.
//!
//! Semantics are pinned exactly to the wire format, so the implementation can
//! be differentially tested against a recorded hardware capture.
//!
//! Platform-neutral: no OS APIs, so it compiles unchanged for the Linux port.

use std::collections::HashMap;

use crate::ts::TransportStreamPacket;

/// 90 kHz timestamps are 33-bit values split across five marker-interleaved bytes.
const TIMESTAMP_BYTE_COUNT: usize = 5;

/// Format-imposed maximum for a length-declared PES, including its six-byte
/// prefix.
///
/// ISO/IEC 13818-1 defines `PES_packet_length` as a 16-bit count of the bytes
/// following that field. The largest legal packet is therefore the six-byte
/// prefix plus `u16::MAX`; a smaller cap rejects legal input and a larger cap
/// is unreachable for a length-declared packet.
pub const DECLARED_LENGTH_MAX_PES: usize = 6 + u16::MAX as usize;

/// Heuristic cap for a length-zero PES terminated by the next unit start.
///
/// ISO/IEC 13818-1 permits length zero only for video elementary streams in a
/// transport stream, so the format supplies no upper bound. A video PES is one
/// whole access unit, and an IDR at the top profile is routinely hundreds of
/// kilobytes. At the declared-length cap the assembler would reject exactly the
/// keyframes a joining client waits for, so this separate limit remains a
/// deliberately generous judgement call.
pub const UNBOUNDED_MAX_PES: usize = 4 * 1_024 * 1_024;

/// The PTS modulus: 33 bits of 90 kHz ticks, or about 26.5 hours.
pub const PTS_MODULUS: u64 = 1 << 33;

/// Half of the 33-bit PTS range. At exactly this distance the signed-delta
/// convention selects the negative interpretation.
const PTS_HALF_RANGE: u64 = 1 << 32;

/// The shortest signed delta from `previous` to `current` in the 33-bit PTS
/// domain.
///
/// Both inputs are normalized to 33 bits. A forward distance below `2^32` is
/// positive; a distance at or above `2^32` is interpreted as the corresponding
/// negative step. This is the single wrap rule shared by timestamp unwrapping
/// and presentation-clock projection.
pub fn signed_pts_delta(current: u64, previous: u64) -> i64 {
    let forward = current.wrapping_sub(previous) & (PTS_MODULUS - 1);
    if forward >= PTS_HALF_RANGE {
        forward as i64 - PTS_MODULUS as i64
    } else {
        forward as i64
    }
}

/// The 33-bit value out of a five-byte PES timestamp field, in 90 kHz ticks.
///
/// This is the one place the marker-interleaved bit layout is written down.
/// Strict packet parsing validates the marker bits and prefix first; the
/// field-level helpers and tests then share this extraction.
pub fn pts_ticks(bytes: &[u8]) -> u64 {
    debug_assert!(bytes.len() >= TIMESTAMP_BYTE_COUNT);
    (u64::from((bytes[0] >> 1) & 0x07) << 30)
        | (u64::from(bytes[1]) << 22)
        | (u64::from((bytes[2] >> 1) & 0x7F) << 15)
        | (u64::from(bytes[3]) << 7)
        | u64::from((bytes[4] >> 1) & 0x7F)
}

/// Encodes a raw 33-bit PTS as its five-byte marker-interleaved field.
///
/// This is primarily fixture support, kept beside [`pts_ticks`] so consumers
/// do not grow a second copy of the wire layout merely to construct a PES in a
/// test.
pub fn pts_field(ticks: u64) -> [u8; TIMESTAMP_BYTE_COUNT] {
    let ticks = ticks & (PTS_MODULUS - 1);
    [
        0x21 | (((ticks >> 30) as u8 & 0x07) << 1),
        (ticks >> 22) as u8,
        0x01 | (((ticks >> 15) as u8 & 0x7F) << 1),
        (ticks >> 7) as u8,
        0x01 | ((ticks as u8 & 0x7F) << 1),
    ]
}

/// Converts 90 kHz ticks to milliseconds.
pub fn ticks_to_ms(ticks: u64) -> u64 {
    ticks / 90
}

/// Converts 90 kHz ticks to microseconds without first losing the fractional
/// millisecond portion.
pub fn ticks_to_us(ticks: u64) -> u64 {
    ticks * 100 / 9
}

/// Decodes one five-byte PES timestamp field into milliseconds.
pub fn pts_to_ms(bytes: &[u8]) -> u64 {
    ticks_to_ms(pts_ticks(bytes))
}

/// Decodes one five-byte PES timestamp field into microseconds.
pub fn pts_to_us(bytes: &[u8]) -> u64 {
    ticks_to_us(pts_ticks(bytes))
}

/// Result of unwrapping one raw PTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtsUnwrapOutcome {
    /// Continuous 90 kHz ticks, or the normalized raw value when a new epoch
    /// had to be established.
    pub ticks: u64,
    /// True when applying the signed delta would leave the public `u64` domain,
    /// so the unwrapper safely discarded its prior epoch and re-baselined.
    pub epoch_reset: bool,
}

/// Rolling 33-bit PTS unwrapper for one packet identifier.
///
/// A 90 kHz PTS wraps every ~26.5 hours. Each raw value is folded into the
/// continuous timeline by adding [`signed_pts_delta`] to the last extended
/// value. Small reverse steps therefore remain reverse steps instead of being
/// mistaken for a nearly 26.5-hour jump.
///
/// Unwrapping deliberately happens in the *ticks* domain. `2^33` ticks is
/// 95_443_717_688.888... microseconds, not an integer, so using a microsecond
/// modulus would inject a fractional-microsecond error at every wrap.
#[derive(Debug, Default)]
pub struct PtsUnwrap {
    last_raw: Option<u64>,
    last_extended: Option<u64>,
}

impl PtsUnwrap {
    /// Explicitly starts a new timestamp epoch.
    pub fn reset(&mut self) {
        self.last_raw = None;
        self.last_extended = None;
    }

    /// Folds one raw 33-bit PTS into a continuous tick count and reports if the
    /// previous epoch had to be discarded.
    ///
    /// The public timeline remains `u64` for compatibility. If a valid signed
    /// delta would produce a negative value or overflow `u64`, wrapping or
    /// saturation would silently corrupt time. Instead this method treats the
    /// raw value as the first observation of a new epoch and sets
    /// [`PtsUnwrapOutcome::epoch_reset`].
    pub fn unwrap_ticks_with_status(&mut self, raw: u64) -> PtsUnwrapOutcome {
        let raw = raw & (PTS_MODULUS - 1);
        let (Some(last_raw), Some(last_extended)) = (self.last_raw, self.last_extended) else {
            self.last_raw = Some(raw);
            self.last_extended = Some(raw);
            return PtsUnwrapOutcome {
                ticks: raw,
                epoch_reset: false,
            };
        };

        let extended = i128::from(last_extended) + i128::from(signed_pts_delta(raw, last_raw));
        let Ok(extended) = u64::try_from(extended) else {
            self.last_raw = Some(raw);
            self.last_extended = Some(raw);
            return PtsUnwrapOutcome {
                ticks: raw,
                epoch_reset: true,
            };
        };

        self.last_raw = Some(raw);
        self.last_extended = Some(extended);
        PtsUnwrapOutcome {
            ticks: extended,
            epoch_reset: false,
        }
    }

    /// Folds one raw 33-bit PTS into a continuous tick count.
    ///
    /// This compatibility method preserves the original signature. Call
    /// [`Self::unwrap_ticks_with_status`] when the owner must flush dependent
    /// state after an automatic epoch reset.
    pub fn unwrap_ticks(&mut self, raw: u64) -> u64 {
        self.unwrap_ticks_with_status(raw).ticks
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketizedElementaryStreamError {
    TransportError { packet_identifier: u16 },
    ScrambledPacket { packet_identifier: u16 },
    InvalidStartCodePrefix,
    InvalidOptionalHeader,
    InvalidTimestamp,
    PacketTooLarge { maximum: usize, actual: usize },
}

pub type PesResult<T> = Result<T, PacketizedElementaryStreamError>;

/// Borrowed header and payload view of one 188-byte transport packet.
///
/// This is the zero-allocation entry point for feed-driven routing. Invalid
/// sync, reserved adaptation control, or impossible adaptation geometry yield
/// `None`; PES-specific conditions such as transport-error and scrambling bits
/// remain present for [`PesDemux`] to report through [`PesResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportStreamPacketView<'a> {
    pub transport_error_indicator: bool,
    pub payload_unit_start_indicator: bool,
    pub packet_identifier: u16,
    pub scrambling_control: u8,
    pub continuity_counter: u8,
    pub has_payload: bool,
    pub payload: &'a [u8],
}

/// Parses the borrowed fields PES routing needs without allocating a payload
/// vector or constructing an owned [`TransportStreamPacket`].
pub fn transport_stream_packet_view(packet: &[u8]) -> Option<TransportStreamPacketView<'_>> {
    if packet.len() != TransportStreamPacket::BYTE_COUNT
        || packet[0] != TransportStreamPacket::SYNC_BYTE
    {
        return None;
    }
    let adaptation_field_control = (packet[3] >> 4) & 0x03;
    if adaptation_field_control == 0 {
        return None;
    }
    let has_adaptation_field = adaptation_field_control & 0x02 != 0;
    let has_payload = adaptation_field_control & 0x01 != 0;
    let mut payload_offset = 4usize;
    if has_adaptation_field {
        payload_offset += 1 + usize::from(packet[4]);
        if payload_offset > packet.len() {
            return None;
        }
    }
    Some(TransportStreamPacketView {
        transport_error_indicator: packet[1] & 0x80 != 0,
        payload_unit_start_indicator: packet[1] & 0x40 != 0,
        packet_identifier: (u16::from(packet[1] & 0x1F) << 8) | u16::from(packet[2]),
        scrambling_control: packet[3] >> 6,
        continuity_counter: packet[3] & 0x0F,
        has_payload,
        payload: if has_payload {
            &packet[payload_offset..]
        } else {
            &[]
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketizedElementaryStream {
    pub packet_identifier: u16,
    pub stream_identifier: u8,
    pub presentation_timestamp_90khz: Option<u64>,
    pub decoding_timestamp_90khz: Option<u64>,
    pub elementary_bytes: Vec<u8>,
}

impl PacketizedElementaryStream {
    pub fn payload_byte_count(&self) -> usize {
        self.elementary_bytes.len()
    }
}

/// Borrowed view of one PES header and the elementary bytes currently present.
///
/// For a bounded PES supplied as only its unit-start transport payload, the
/// elementary slice ends at the supplied bytes. Once an assembler supplies the
/// complete PES, the same parser yields the complete elementary payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketizedElementaryStreamView<'a> {
    pub stream_identifier: u8,
    pub presentation_timestamp_90khz: Option<u64>,
    pub decoding_timestamp_90khz: Option<u64>,
    pub elementary_bytes: &'a [u8],
}

/// Reads only the PES start-code prefix and stream identifier.
///
/// Kept separate from full optional-header parsing so hot paths that only ask
/// whether a payload begins a video PES need inspect four bytes, not construct
/// or validate an unrelated transport object.
pub fn packetized_elementary_stream_identifier(bytes: &[u8]) -> PesResult<u8> {
    if bytes.len() < 4 || bytes[..3] != [0x00, 0x00, 0x01] {
        return Err(PacketizedElementaryStreamError::InvalidStartCodePrefix);
    }
    Ok(bytes[3])
}

/// Parses a PES optional header and returns a borrowed elementary-payload view.
pub fn parse_packetized_elementary_stream(
    bytes: &[u8],
) -> PesResult<PacketizedElementaryStreamView<'_>> {
    let stream_identifier = packetized_elementary_stream_identifier(bytes)?;
    if bytes.len() < 6 {
        return Err(PacketizedElementaryStreamError::InvalidOptionalHeader);
    }

    let declared_packet_length = (usize::from(bytes[4]) << 8) | usize::from(bytes[5]);
    let packet_end = if declared_packet_length == 0 {
        bytes.len()
    } else {
        (6 + declared_packet_length).min(bytes.len())
    };

    // ISO/IEC 13818-1 private_stream_2 has no optional PES header. ARIB
    // superimpose data uses it, so its elementary payload starts immediately
    // after PES_packet_length and carries no PTS or DTS.
    if stream_identifier == 0xBF {
        return Ok(PacketizedElementaryStreamView {
            stream_identifier,
            presentation_timestamp_90khz: None,
            decoding_timestamp_90khz: None,
            elementary_bytes: &bytes[6..packet_end],
        });
    }

    if bytes.len() < 9 || bytes[6] & 0xC0 != 0x80 {
        return Err(PacketizedElementaryStreamError::InvalidOptionalHeader);
    }
    let optional_header_byte_count = usize::from(bytes[8]);
    let payload_offset = 9 + optional_header_byte_count;
    if payload_offset > packet_end {
        return Err(PacketizedElementaryStreamError::InvalidOptionalHeader);
    }

    let timestamp_flags = (bytes[7] >> 6) & 0x03;
    let (presentation_timestamp, decoding_timestamp) = match timestamp_flags {
        0 => (None, None),
        2 => {
            if optional_header_byte_count < 5 {
                return Err(PacketizedElementaryStreamError::InvalidOptionalHeader);
            }
            (Some(parse_timestamp(&bytes[9..14], 2)?), None)
        }
        3 => {
            if optional_header_byte_count < 10 {
                return Err(PacketizedElementaryStreamError::InvalidOptionalHeader);
            }
            (
                Some(parse_timestamp(&bytes[9..14], 3)?),
                Some(parse_timestamp(&bytes[14..19], 1)?),
            )
        }
        _ => return Err(PacketizedElementaryStreamError::InvalidOptionalHeader),
    };

    Ok(PacketizedElementaryStreamView {
        stream_identifier,
        presentation_timestamp_90khz: presentation_timestamp,
        decoding_timestamp_90khz: decoding_timestamp,
        elementary_bytes: &bytes[payload_offset..packet_end],
    })
}

/// Reassembles one PID's PES packets from a transport-packet feed.
#[derive(Debug)]
pub struct PacketizedElementaryStreamAssembler {
    packet_identifier: u16,
    buffered_bytes: Vec<u8>,
    last_continuity_counter: Option<u8>,
    continuity_drop_count: u64,
    maximum_packet_byte_count: usize,
}

impl PacketizedElementaryStreamAssembler {
    /// Builds an assembler able to accept every length-declared PES.
    pub fn new(packet_identifier: u16) -> Self {
        Self::with_max(packet_identifier, DECLARED_LENGTH_MAX_PES)
    }

    /// Builds an assembler with an explicit per-PES byte limit.
    pub fn with_max(packet_identifier: u16, maximum_packet_byte_count: usize) -> Self {
        Self {
            packet_identifier,
            buffered_bytes: Vec::new(),
            last_continuity_counter: None,
            continuity_drop_count: 0,
            maximum_packet_byte_count,
        }
    }

    pub fn packet_identifier(&self) -> u16 {
        self.packet_identifier
    }

    /// Number of continuity gaps that discarded an in-progress PES.
    pub fn continuity_drop_count(&self) -> u64 {
        self.continuity_drop_count
    }

    /// Feeds one transport packet. Any error resets the assembler before it is
    /// propagated to the caller.
    pub fn append(
        &mut self,
        packet: &TransportStreamPacket,
    ) -> PesResult<Vec<PacketizedElementaryStream>> {
        self.append_view(TransportStreamPacketView {
            transport_error_indicator: packet.transport_error_indicator,
            payload_unit_start_indicator: packet.payload_unit_start_indicator,
            packet_identifier: packet.packet_identifier,
            scrambling_control: packet.scrambling_control,
            continuity_counter: packet.continuity_counter,
            has_payload: packet.has_payload,
            payload: &packet.payload,
        })
    }

    /// Finishes the PES currently buffered from the bytes received so far.
    ///
    /// This is for finite feeds whose final PES has no following unit start.
    /// A complete length-declared packet is normally returned by [`Self::append`]
    /// and leaves nothing to flush; an unbounded or truncated final packet is
    /// parsed from the bytes available. Continuity state is retained so a feed
    /// that resumes behaves like one uninterrupted stream.
    pub fn flush(&mut self) -> PesResult<Option<PacketizedElementaryStream>> {
        let outcome = if self.buffered_bytes.is_empty() {
            Ok(None)
        } else {
            self.parse_packet(&self.buffered_bytes).map(Some)
        };
        self.buffered_bytes.clear();
        outcome
    }

    fn append_view(
        &mut self,
        packet: TransportStreamPacketView<'_>,
    ) -> PesResult<Vec<PacketizedElementaryStream>> {
        if packet.packet_identifier != self.packet_identifier {
            return Ok(Vec::new());
        }
        let outcome = self.append_validated(packet);
        if outcome.is_err() {
            self.reset();
        }
        outcome
    }

    fn append_validated(
        &mut self,
        packet: TransportStreamPacketView<'_>,
    ) -> PesResult<Vec<PacketizedElementaryStream>> {
        if packet.transport_error_indicator {
            return Err(PacketizedElementaryStreamError::TransportError {
                packet_identifier: self.packet_identifier,
            });
        }
        if packet.scrambling_control != 0 {
            return Err(PacketizedElementaryStreamError::ScrambledPacket {
                packet_identifier: self.packet_identifier,
            });
        }
        if !packet.has_payload {
            return Ok(Vec::new());
        }

        if let Some(last) = self.last_continuity_counter {
            if packet.continuity_counter == last {
                return Ok(Vec::new());
            }
            if packet.continuity_counter != (last + 1) & 0x0F {
                self.continuity_drop_count += 1;
                self.buffered_bytes.clear();
                if !packet.payload_unit_start_indicator {
                    self.last_continuity_counter = Some(packet.continuity_counter);
                    return Ok(Vec::new());
                }
            }
        }
        self.last_continuity_counter = Some(packet.continuity_counter);

        let mut completed = Vec::new();
        if packet.payload_unit_start_indicator {
            // An unbounded (declared length 0) packet is only terminated by the
            // arrival of the next unit start.
            if let Some(finished) = self.complete_buffered_packet(true)? {
                completed.push(finished);
            }
            self.buffered_bytes.clear();
        } else if self.buffered_bytes.is_empty() {
            return Ok(completed);
        }

        self.append_bounded(packet.payload)?;
        self.validate_start_code_prefix()?;
        if let Some(finished) = self.complete_buffered_packet(false)? {
            completed.push(finished);
            self.buffered_bytes.clear();
        }
        Ok(completed)
    }

    fn append_bounded(&mut self, bytes: &[u8]) -> PesResult<()> {
        let actual = self.buffered_bytes.len() + bytes.len();
        if bytes.len() > self.maximum_packet_byte_count || actual > self.maximum_packet_byte_count {
            return Err(PacketizedElementaryStreamError::PacketTooLarge {
                maximum: self.maximum_packet_byte_count,
                actual,
            });
        }
        self.buffered_bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Rejects a buffer as soon as it cannot become a `00 00 01` start code,
    /// without waiting for all three bytes to arrive.
    fn validate_start_code_prefix(&self) -> PesResult<()> {
        let buffered = &self.buffered_bytes;
        let invalid = (!buffered.is_empty() && buffered[0] != 0)
            || (buffered.len() >= 2 && buffered[1] != 0)
            || (buffered.len() >= 3 && buffered[2] != 1);
        if invalid {
            return Err(PacketizedElementaryStreamError::InvalidStartCodePrefix);
        }
        Ok(())
    }

    fn complete_buffered_packet(
        &self,
        allowing_unbounded_length: bool,
    ) -> PesResult<Option<PacketizedElementaryStream>> {
        if self.buffered_bytes.len() < 6 {
            return Ok(None);
        }

        let declared_packet_length =
            (usize::from(self.buffered_bytes[4]) << 8) | usize::from(self.buffered_bytes[5]);
        if declared_packet_length == 0 {
            if !allowing_unbounded_length {
                return Ok(None);
            }
            return self.parse_packet(&self.buffered_bytes).map(Some);
        }

        let total_packet_byte_count = 6 + declared_packet_length;
        if self.buffered_bytes.len() < total_packet_byte_count {
            return Ok(None);
        }
        self.parse_packet(&self.buffered_bytes[..total_packet_byte_count])
            .map(Some)
    }

    fn parse_packet(&self, bytes: &[u8]) -> PesResult<PacketizedElementaryStream> {
        let parsed = parse_packetized_elementary_stream(bytes)?;

        Ok(PacketizedElementaryStream {
            packet_identifier: self.packet_identifier,
            stream_identifier: parsed.stream_identifier,
            presentation_timestamp_90khz: parsed.presentation_timestamp_90khz,
            decoding_timestamp_90khz: parsed.decoding_timestamp_90khz,
            elementary_bytes: parsed.elementary_bytes.to_vec(),
        })
    }

    fn reset(&mut self) {
        self.buffered_bytes.clear();
        self.last_continuity_counter = None;
    }
}

/// Feed-driven PES router over whole 188-byte transport packets.
///
/// Only packet identifiers registered with [`Self::watch`] are assembled.
/// Each PID owns an independent assembler and timestamp clock, so a continuity
/// break on one elementary stream cannot disturb another. Unlike a prior
/// ad hoc PES router, errors remain distinguishable through [`PesResult`].
#[derive(Debug)]
pub struct PesDemux {
    assemblers: HashMap<u16, PacketizedElementaryStreamAssembler>,
    clocks: HashMap<u16, PtsUnwrap>,
    maximum_packet_byte_count: usize,
}

impl PesDemux {
    /// Builds a router able to accept every length-declared PES.
    pub fn new() -> Self {
        Self::with_max(DECLARED_LENGTH_MAX_PES)
    }

    /// Builds a router whose watched PIDs all use the given per-PES cap.
    pub fn with_max(maximum_packet_byte_count: usize) -> Self {
        Self {
            assemblers: HashMap::new(),
            clocks: HashMap::new(),
            maximum_packet_byte_count,
        }
    }

    /// Starts assembling `packet_identifier`.
    ///
    /// Idempotent: a repeating PMT may rediscover the same PID without
    /// resetting its in-progress PES or its unwrapped clock.
    pub fn watch(&mut self, packet_identifier: u16) {
        let maximum = self.maximum_packet_byte_count;
        self.assemblers.entry(packet_identifier).or_insert_with(|| {
            PacketizedElementaryStreamAssembler::with_max(packet_identifier, maximum)
        });
        self.clocks.entry(packet_identifier).or_default();
    }

    /// Whether `packet_identifier` is currently being assembled.
    pub fn watching(&self, packet_identifier: u16) -> bool {
        self.assemblers.contains_key(&packet_identifier)
    }

    /// Continuity gaps observed by one watched PID, or zero when it is not
    /// watched.
    pub fn continuity_drop_count(&self, packet_identifier: u16) -> u64 {
        self.assemblers.get(&packet_identifier).map_or(
            0,
            PacketizedElementaryStreamAssembler::continuity_drop_count,
        )
    }

    /// Feeds one raw 188-byte packet without allocating a payload vector.
    pub fn push(&mut self, packet: &[u8; 188]) -> PesResult<Vec<PacketizedElementaryStream>> {
        let Some(packet) = transport_stream_packet_view(packet) else {
            return Ok(Vec::new());
        };
        self.route(packet)
    }

    /// Feeds an already-decoded transport packet.
    pub fn push_parsed(
        &mut self,
        packet: &TransportStreamPacket,
    ) -> PesResult<Vec<PacketizedElementaryStream>> {
        self.route(TransportStreamPacketView {
            transport_error_indicator: packet.transport_error_indicator,
            payload_unit_start_indicator: packet.payload_unit_start_indicator,
            packet_identifier: packet.packet_identifier,
            scrambling_control: packet.scrambling_control,
            continuity_counter: packet.continuity_counter,
            has_payload: packet.has_payload,
            payload: &packet.payload,
        })
    }

    fn route(
        &mut self,
        packet: TransportStreamPacketView<'_>,
    ) -> PesResult<Vec<PacketizedElementaryStream>> {
        let Some(assembler) = self.assemblers.get_mut(&packet.packet_identifier) else {
            return Ok(Vec::new());
        };
        let mut completed = assembler.append_view(packet)?;
        let clock = self.clocks.entry(packet.packet_identifier).or_default();
        for stream in &mut completed {
            if let Some(raw) = stream.presentation_timestamp_90khz {
                stream.presentation_timestamp_90khz = Some(clock.unwrap_ticks(raw));
            }
        }
        Ok(completed)
    }
}

impl Default for PesDemux {
    fn default() -> Self {
        Self::new()
    }
}

/// Decodes a 33-bit 90 kHz timestamp from its five marker-interleaved bytes.
fn parse_timestamp(bytes: &[u8], expected_prefix: u8) -> PesResult<u64> {
    if bytes.len() != TIMESTAMP_BYTE_COUNT
        || bytes[0] >> 4 != expected_prefix
        || bytes[0] & 0x01 != 1
        || bytes[2] & 0x01 != 1
        || bytes[4] & 0x01 != 1
    {
        return Err(PacketizedElementaryStreamError::InvalidTimestamp);
    }

    Ok(pts_ticks(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp_bytes(value: u64, prefix: u8) -> [u8; TIMESTAMP_BYTE_COUNT] {
        let mut bytes = pts_field(value);
        bytes[0] = (prefix << 4) | (bytes[0] & 0x0F);
        bytes
    }

    /// Builds a PES packet with an optional PTS (and DTS), then a payload.
    fn pes_packet(
        stream_identifier: u8,
        pts: Option<u64>,
        dts: Option<u64>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut optional = Vec::new();
        let flags = match (pts, dts) {
            (Some(pts), Some(dts)) => {
                optional.extend_from_slice(&timestamp_bytes(pts, 3));
                optional.extend_from_slice(&timestamp_bytes(dts, 1));
                0xC0
            }
            (Some(pts), None) => {
                optional.extend_from_slice(&timestamp_bytes(pts, 2));
                0x80
            }
            _ => 0x00,
        };

        let mut bytes = vec![0x00, 0x00, 0x01, stream_identifier];
        let body_length = 3 + optional.len() + payload.len();
        bytes.push(((body_length >> 8) & 0xFF) as u8);
        bytes.push((body_length & 0xFF) as u8);
        bytes.push(0x80); // marker bits '10'
        bytes.push(flags);
        bytes.push(optional.len() as u8);
        bytes.extend_from_slice(&optional);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn transport_packets(pid: u16, pes: &[u8], first_continuity: u8) -> Vec<TransportStreamPacket> {
        pes.chunks(184)
            .enumerate()
            .map(|(index, chunk)| {
                let mut bytes = vec![0xFFu8; TransportStreamPacket::BYTE_COUNT];
                bytes[0] = TransportStreamPacket::SYNC_BYTE;
                bytes[1] = ((pid >> 8) & 0x1F) as u8;
                if index == 0 {
                    bytes[1] |= 0x40;
                }
                bytes[2] = (pid & 0xFF) as u8;
                bytes[3] = 0x10 | ((first_continuity + index as u8) & 0x0F);
                bytes[4..4 + chunk.len()].copy_from_slice(chunk);
                TransportStreamPacket::parse(&bytes).unwrap()
            })
            .collect()
    }

    #[test]
    fn decodes_a_33_bit_timestamp_round_trip() {
        let value = 0x123_4567;
        assert_eq!(
            parse_timestamp(&timestamp_bytes(value, 2), 2).unwrap(),
            value
        );
    }

    #[test]
    fn decodes_the_maximum_33_bit_timestamp() {
        let value = (1u64 << 33) - 1;
        assert_eq!(
            parse_timestamp(&timestamp_bytes(value, 2), 2).unwrap(),
            value
        );
    }

    #[test]
    fn signed_pts_delta_uses_the_modulus_and_half_range() {
        assert_eq!(signed_pts_delta(45_000, PTS_MODULUS - 45_000), 90_000);
        assert_eq!(signed_pts_delta(PTS_MODULUS - 45_000, 45_000), -90_000);
        assert_eq!(
            signed_pts_delta(PTS_HALF_RANGE - 1, 0),
            PTS_HALF_RANGE as i64 - 1
        );
        assert_eq!(
            signed_pts_delta(PTS_HALF_RANGE, 0),
            -(PTS_HALF_RANGE as i64)
        );
    }

    #[test]
    fn unwrapping_before_scaling_preserves_the_exact_frame_delta() {
        let before = PTS_MODULUS - 1_500;
        let after = 1_503;
        let mut clock = PtsUnwrap::default();

        let unwrapped_before = clock.unwrap_ticks(before);
        let unwrapped_after = clock.unwrap_ticks(after);

        assert_eq!(unwrapped_after - unwrapped_before, 3_003);
        assert_eq!(
            ticks_to_us(unwrapped_after) - ticks_to_us(unwrapped_before),
            3_003 * 100 / 9
        );
    }

    #[test]
    fn unwrapping_preserves_a_small_reverse_step_across_the_rollover() {
        let before = PTS_MODULUS - 45_000;
        let after = 45_000;
        let mut clock = PtsUnwrap::default();

        assert_eq!(clock.unwrap_ticks(before), before);
        assert_eq!(clock.unwrap_ticks(after), PTS_MODULUS + after);
        assert_eq!(clock.unwrap_ticks(before), before);
    }

    #[test]
    fn resetting_the_unwrapper_starts_a_new_epoch() {
        let mut clock = PtsUnwrap::default();
        clock.unwrap_ticks(PTS_MODULUS - 45_000);
        assert_eq!(clock.unwrap_ticks(45_000), PTS_MODULUS + 45_000);

        clock.reset();

        assert_eq!(clock.unwrap_ticks(45_000), 45_000);
    }

    #[test]
    fn an_unrepresentable_reverse_step_rebaselines_without_wrapping_u64() {
        let mut clock = PtsUnwrap::default();
        assert_eq!(clock.unwrap_ticks(100), 100);

        let outcome = clock.unwrap_ticks_with_status(PTS_MODULUS - 100);

        assert_eq!(
            outcome,
            PtsUnwrapOutcome {
                ticks: PTS_MODULUS - 100,
                epoch_reset: true,
            }
        );
        assert_eq!(clock.unwrap_ticks(100), PTS_MODULUS + 100);
    }

    #[test]
    fn rejects_a_timestamp_with_a_cleared_marker_bit() {
        let mut bytes = timestamp_bytes(90_000, 2);
        bytes[2] &= 0xFE;
        assert_eq!(
            parse_timestamp(&bytes, 2),
            Err(PacketizedElementaryStreamError::InvalidTimestamp)
        );
    }

    #[test]
    fn rejects_a_timestamp_with_the_wrong_prefix() {
        let bytes = timestamp_bytes(90_000, 2);
        assert_eq!(
            parse_timestamp(&bytes, 3),
            Err(PacketizedElementaryStreamError::InvalidTimestamp)
        );
    }

    #[test]
    fn assembles_a_bounded_packet_with_pts_only() {
        // Arrange
        let payload = [0xAA; 32];
        let pes = pes_packet(0xE0, Some(90_000), None, &payload);
        let packets = transport_packets(0x0100, &pes, 0);
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        // Act
        let completed: Vec<_> = packets
            .iter()
            .flat_map(|packet| assembler.append(packet).unwrap())
            .collect();

        // Assert
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].stream_identifier, 0xE0);
        assert_eq!(completed[0].presentation_timestamp_90khz, Some(90_000));
        assert_eq!(completed[0].decoding_timestamp_90khz, None);
        assert_eq!(completed[0].elementary_bytes, payload);
        assert_eq!(completed[0].payload_byte_count(), 32);
    }

    #[test]
    fn assembles_a_packet_carrying_both_pts_and_dts() {
        let payload = [0x5A; 16];
        let pes = pes_packet(0xE0, Some(126_000), Some(90_000), &payload);
        let packets = transport_packets(0x0100, &pes, 3);
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        let completed: Vec<_> = packets
            .iter()
            .flat_map(|packet| assembler.append(packet).unwrap())
            .collect();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].presentation_timestamp_90khz, Some(126_000));
        assert_eq!(completed[0].decoding_timestamp_90khz, Some(90_000));
    }

    #[test]
    fn reassembles_a_packet_spanning_several_transport_packets() {
        let payload = vec![0x3C; 700];
        let pes = pes_packet(0xE0, Some(45_000), None, &payload);
        let packets = transport_packets(0x0100, &pes, 0);
        assert!(packets.len() > 3, "fixture must span multiple packets");
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        let completed: Vec<_> = packets
            .iter()
            .flat_map(|packet| assembler.append(packet).unwrap())
            .collect();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].elementary_bytes, payload);
    }

    #[test]
    fn ignores_packets_for_another_packet_identifier() {
        let pes = pes_packet(0xE0, None, None, &[0x01, 0x02]);
        let packets = transport_packets(0x0200, &pes, 0);
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        assert!(assembler.append(&packets[0]).unwrap().is_empty());
    }

    #[test]
    fn rejects_a_scrambled_packet() {
        let pes = pes_packet(0xE0, None, None, &[0x01]);
        let mut packet = transport_packets(0x0100, &pes, 0)[0].clone();
        packet.scrambling_control = 2;
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        assert_eq!(
            assembler.append(&packet),
            Err(PacketizedElementaryStreamError::ScrambledPacket {
                packet_identifier: 0x0100
            })
        );
    }

    #[test]
    fn rejects_a_packet_flagged_with_a_transport_error() {
        let pes = pes_packet(0xE0, None, None, &[0x01]);
        let mut packet = transport_packets(0x0100, &pes, 0)[0].clone();
        packet.transport_error_indicator = true;
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        assert_eq!(
            assembler.append(&packet),
            Err(PacketizedElementaryStreamError::TransportError {
                packet_identifier: 0x0100
            })
        );
    }

    #[test]
    fn rejects_a_payload_without_the_start_code_prefix() {
        let mut pes = pes_packet(0xE0, None, None, &[0x01]);
        pes[2] = 0x02; // 00 00 02 is not a PES start code
        let packets = transport_packets(0x0100, &pes, 0);
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        assert_eq!(
            assembler.append(&packets[0]),
            Err(PacketizedElementaryStreamError::InvalidStartCodePrefix)
        );
    }

    #[test]
    fn reports_the_per_instance_packet_limit() {
        let pes = pes_packet(0xE0, None, None, &[0x01]);
        let packet = &transport_packets(0x0100, &pes, 0)[0];
        let mut assembler = PacketizedElementaryStreamAssembler::with_max(0x0100, 128);

        assert_eq!(
            assembler.append(packet),
            Err(PacketizedElementaryStreamError::PacketTooLarge {
                maximum: 128,
                actual: 184,
            })
        );
    }

    #[test]
    fn accepts_the_maximum_declared_length_packet() {
        let payload = vec![0x5A; usize::from(u16::MAX) - 3];
        let pes = pes_packet(0xBD, None, None, &payload);
        assert_eq!(pes.len(), 6 + usize::from(u16::MAX));
        let packets = pes
            .chunks(184)
            .enumerate()
            .map(|(index, chunk)| TransportStreamPacket {
                transport_error_indicator: false,
                payload_unit_start_indicator: index == 0,
                transport_priority: false,
                packet_identifier: 0x0100,
                scrambling_control: 0,
                continuity_counter: index as u8 & 0x0F,
                has_adaptation_field: chunk.len() < 184,
                has_payload: true,
                payload: chunk.to_vec(),
            })
            .collect::<Vec<_>>();
        let mut assembler =
            PacketizedElementaryStreamAssembler::with_max(0x0100, DECLARED_LENGTH_MAX_PES);

        let completed = packets
            .iter()
            .flat_map(|packet| assembler.append(packet).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].elementary_bytes, payload);
    }

    #[test]
    fn rejects_an_optional_header_without_its_marker_bits() {
        let mut pes = pes_packet(0xE0, None, None, &[0x01, 0x02, 0x03]);
        pes[6] = 0x40; // marker bits must be '10'
        let packets = transport_packets(0x0100, &pes, 0);
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        assert_eq!(
            assembler.append(&packets[0]),
            Err(PacketizedElementaryStreamError::InvalidOptionalHeader)
        );
    }

    #[test]
    fn an_error_resets_the_assembler_for_the_next_unit_start() {
        let good = pes_packet(0xE0, Some(90_000), None, &[0x11; 8]);
        let mut bad = pes_packet(0xE0, None, None, &[0x01]);
        bad[6] = 0x40;
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        assert!(assembler
            .append(&transport_packets(0x0100, &bad, 0)[0])
            .is_err());
        let completed: Vec<_> = transport_packets(0x0100, &good, 0)
            .iter()
            .flat_map(|packet| assembler.append(packet).unwrap())
            .collect();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].presentation_timestamp_90khz, Some(90_000));
    }

    #[test]
    fn an_unbounded_packet_completes_on_the_next_unit_start() {
        // Declared length 0 (legal for video): terminated by the next start.
        // The payload is sized to fill the 184-byte transport payload exactly
        // (9 PES header + 5 PTS bytes + 170), because an unbounded packet has
        // no length to stop at and would otherwise absorb the trailing filler.
        let payload = [0x77; 170];
        let mut unbounded = pes_packet(0xE0, Some(90_000), None, &payload);
        unbounded[4] = 0;
        unbounded[5] = 0;
        let mut assembler = PacketizedElementaryStreamAssembler::new(0x0100);

        let first = transport_packets(0x0100, &unbounded, 0);
        let completed_before: Vec<_> = first
            .iter()
            .flat_map(|packet| assembler.append(packet).unwrap())
            .collect();
        assert!(completed_before.is_empty());

        // The next unit start both flushes the unbounded packet and completes
        // its own bounded packet, so a single append yields two.
        let next = pes_packet(0xE0, Some(93_000), None, &[0x22; 8]);
        let continuity = first.len() as u8;
        let completed = assembler
            .append(&transport_packets(0x0100, &next, continuity)[0])
            .unwrap();

        assert_eq!(completed.len(), 2);
        assert_eq!(completed[0].presentation_timestamp_90khz, Some(90_000));
        assert_eq!(completed[0].elementary_bytes, payload);
        assert_eq!(completed[1].presentation_timestamp_90khz, Some(93_000));
        assert_eq!(completed[1].elementary_bytes, [0x22; 8]);
    }

    #[test]
    fn rewatching_a_pid_does_not_reset_routing_mid_packet() {
        let payload = vec![0x3C; 700];
        let pes = pes_packet(0xE0, Some(45_000), None, &payload);
        let packets = transport_packets(0x0100, &pes, 0);
        let mut demux = PesDemux::with_max(UNBOUNDED_MAX_PES);
        let mut completed = Vec::new();

        for packet in &packets {
            demux.watch(0x0100);
            completed.extend(demux.push_parsed(packet).unwrap());
        }

        assert!(demux.watching(0x0100));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].elementary_bytes, payload);
    }

    #[test]
    fn routing_preserves_the_assemblers_scrambled_packet_error() {
        let pes = pes_packet(0xE0, None, None, &[0x01]);
        let mut packet = transport_packets(0x0100, &pes, 0)[0].clone();
        packet.scrambling_control = 2;
        let mut demux = PesDemux::new();
        demux.watch(0x0100);

        assert_eq!(
            demux.push_parsed(&packet),
            Err(PacketizedElementaryStreamError::ScrambledPacket {
                packet_identifier: 0x0100,
            })
        );
    }

    /// Builds a video-style PES packet with `PES_packet_length` fixed at
    /// zero — the wire convention ISO/IEC 13818-1 reserves for a video
    /// elementary stream whose access unit is too large to declare up
    /// front. Termination then depends entirely on the next unit-start
    /// packet, which is exactly the case [`UNBOUNDED_MAX_PES`] exists to
    /// accept and [`DECLARED_LENGTH_MAX_PES`] cannot.
    fn unbounded_video_pes_packet(stream_identifier: u8, pts: u64, payload: &[u8]) -> Vec<u8> {
        let optional = timestamp_bytes(pts, 2);
        let mut bytes = vec![0x00, 0x00, 0x01, stream_identifier];
        bytes.push(0x00); // PES_packet_length high byte -- zero declares "unbounded"
        bytes.push(0x00); // PES_packet_length low byte
        bytes.push(0x80); // marker bits '10'
        bytes.push(0x80); // PTS-only flag
        bytes.push(optional.len() as u8);
        bytes.extend_from_slice(&optional);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn synthetic_unbounded_video_pes_needs_the_unbounded_cap() {
        const VIDEO_PID: u16 = 0x0111;
        // `unbounded_video_pes_packet` writes a 9-byte PES prefix (start
        // code, stream id, zeroed PES_packet_length, marker byte, flags
        // byte, optional-header length byte) plus a `TIMESTAMP_BYTE_COUNT`
        // PTS field before the payload. Round the minimum payload down to
        // whatever header-plus-payload total lands on an exact 184-byte TS
        // packet boundary, so no final TS packet is ever partial --
        // `transport_packets` then never pads a short last chunk, so no
        // filler byte can be folded into the reassembled PES, and the byte
        // count asserted below is honestly every byte this test put on the
        // wire.
        const PES_HEADER_BYTE_COUNT: usize = 9 + TIMESTAMP_BYTE_COUNT;
        const MINIMUM_PAYLOAD_BYTE_COUNT: usize = DECLARED_LENGTH_MAX_PES + 4_096;
        const UNALIGNED_TOTAL_BYTE_COUNT: usize =
            PES_HEADER_BYTE_COUNT + MINIMUM_PAYLOAD_BYTE_COUNT;
        const ALIGNED_TOTAL_BYTE_COUNT: usize =
            UNALIGNED_TOTAL_BYTE_COUNT - (UNALIGNED_TOTAL_BYTE_COUNT % 184);
        const PAYLOAD_BYTE_COUNT: usize = ALIGNED_TOTAL_BYTE_COUNT - PES_HEADER_BYTE_COUNT;
        let payload: Vec<u8> = (0..PAYLOAD_BYTE_COUNT)
            .map(|index| (index % 256) as u8)
            .collect();
        let pes = unbounded_video_pes_packet(0xE0, 90_000, &payload);
        let video_packets = transport_packets(VIDEO_PID, &pes, 0);

        // A real capture opens with a run of transport-scrambled packets
        // before the descrambler is armed; the router must surface each as
        // `ScrambledPacket` rather than folding it into the elementary
        // stream, and must recover cleanly once clear packets resume.
        let junk_pes = pes_packet(0xE0, None, None, &[0u8; 512]);
        let mut scrambled_prefix_packets = transport_packets(VIDEO_PID, &junk_pes, 0);
        for packet in &mut scrambled_prefix_packets {
            packet.scrambling_control = 2;
        }

        // A trailing unit-start packet is what actually flushes an
        // unbounded (declared-length-zero) PES: the assembler has no other
        // signal that the access unit ended.
        let closing_pes = pes_packet(0xE0, Some(90_100), None, &[0xAB; 8]);
        let closing_packets = transport_packets(VIDEO_PID, &closing_pes, video_packets.len() as u8);

        let mut unbounded = PesDemux::with_max(UNBOUNDED_MAX_PES);
        unbounded.watch(VIDEO_PID);
        let mut unbounded_units = Vec::new();
        let mut scrambled_packet_count = 0usize;
        for packet in scrambled_prefix_packets
            .iter()
            .chain(video_packets.iter())
            .chain(closing_packets.iter())
        {
            match unbounded.push_parsed(packet) {
                Ok(units) => unbounded_units.extend(units),
                Err(PacketizedElementaryStreamError::ScrambledPacket { packet_identifier }) => {
                    assert_eq!(packet_identifier, VIDEO_PID);
                    scrambled_packet_count += 1;
                }
                Err(error) => panic!("unexpected unbounded-cap error: {error:?}"),
            }
        }
        assert_eq!(scrambled_packet_count, scrambled_prefix_packets.len());
        assert_eq!(unbounded_units.len(), 2);
        assert_eq!(unbounded_units[0].payload_byte_count(), PAYLOAD_BYTE_COUNT);
        assert_eq!(unbounded_units[1].payload_byte_count(), 8);
    }

    #[test]
    fn synthetic_unbounded_video_pes_exceeds_the_declared_length_cap() {
        const VIDEO_PID: u16 = 0x0111;
        // `unbounded_video_pes_packet` writes a 9-byte PES prefix (start
        // code, stream id, zeroed PES_packet_length, marker byte, flags
        // byte, optional-header length byte) plus a `TIMESTAMP_BYTE_COUNT`
        // PTS field before the payload. Round the minimum payload down to
        // whatever header-plus-payload total lands on an exact 184-byte TS
        // packet boundary, so no final TS packet is ever partial --
        // `transport_packets` then never pads a short last chunk, so no
        // filler byte can be folded into the reassembled PES, and the byte
        // count asserted below is honestly every byte this test put on the
        // wire.
        const PES_HEADER_BYTE_COUNT: usize = 9 + TIMESTAMP_BYTE_COUNT;
        const MINIMUM_PAYLOAD_BYTE_COUNT: usize = DECLARED_LENGTH_MAX_PES + 4_096;
        const UNALIGNED_TOTAL_BYTE_COUNT: usize =
            PES_HEADER_BYTE_COUNT + MINIMUM_PAYLOAD_BYTE_COUNT;
        const ALIGNED_TOTAL_BYTE_COUNT: usize =
            UNALIGNED_TOTAL_BYTE_COUNT - (UNALIGNED_TOTAL_BYTE_COUNT % 184);
        const PAYLOAD_BYTE_COUNT: usize = ALIGNED_TOTAL_BYTE_COUNT - PES_HEADER_BYTE_COUNT;
        let payload: Vec<u8> = (0..PAYLOAD_BYTE_COUNT)
            .map(|index| (index % 256) as u8)
            .collect();
        let pes = unbounded_video_pes_packet(0xE0, 90_000, &payload);
        let video_packets = transport_packets(VIDEO_PID, &pes, 0);

        let mut declared = PesDemux::with_max(DECLARED_LENGTH_MAX_PES);
        declared.watch(VIDEO_PID);
        let error = video_packets
            .iter()
            .find_map(|packet| declared.push_parsed(packet).err())
            .expect("a PES this large must exceed the declared-length cap before the feed ends");

        let PacketizedElementaryStreamError::PacketTooLarge { maximum, actual } = error else {
            panic!("expected PacketTooLarge, got {error:?}");
        };
        assert_eq!(maximum, DECLARED_LENGTH_MAX_PES);
        assert!(actual > maximum);
    }
}
