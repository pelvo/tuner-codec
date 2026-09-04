//! MPEG-2 transport-stream packet parsing and framing.
//!
//! Semantics are pinned exactly to the wire format, so the implementation can
//! be differentially tested against a recorded capture.
//!
//! This module is platform-neutral: no OS APIs, no allocation beyond the
//! payload/buffer vectors, so it compiles unchanged for the Linux port.

/// Errors raised while decoding a single 188-byte transport packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportStreamPacketError {
    InvalidPacketLength(usize),
    InvalidSyncByte(u8),
    ReservedAdaptationFieldControl,
    AdaptationFieldTooLarge(usize),
}

/// A decoded transport-stream packet header plus its payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportStreamPacket {
    pub transport_error_indicator: bool,
    pub payload_unit_start_indicator: bool,
    pub transport_priority: bool,
    pub packet_identifier: u16,
    pub scrambling_control: u8,
    pub continuity_counter: u8,
    pub has_adaptation_field: bool,
    pub has_payload: bool,
    pub payload: Vec<u8>,
}

impl TransportStreamPacket {
    pub const BYTE_COUNT: usize = 188;
    pub const SYNC_BYTE: u8 = 0x47;

    /// Decodes one packet. `bytes` must be exactly [`Self::BYTE_COUNT`] long.
    pub fn parse(bytes: &[u8]) -> Result<Self, TransportStreamPacketError> {
        if bytes.len() != Self::BYTE_COUNT {
            return Err(TransportStreamPacketError::InvalidPacketLength(bytes.len()));
        }
        if bytes[0] != Self::SYNC_BYTE {
            return Err(TransportStreamPacketError::InvalidSyncByte(bytes[0]));
        }

        let adaptation_field_control = (bytes[3] >> 4) & 0x03;
        if adaptation_field_control == 0 {
            return Err(TransportStreamPacketError::ReservedAdaptationFieldControl);
        }
        let has_adaptation_field = adaptation_field_control & 0x02 != 0;
        let has_payload = adaptation_field_control & 0x01 != 0;

        let mut payload_offset = 4usize;
        if has_adaptation_field {
            let adaptation_field_length = bytes[payload_offset] as usize;
            payload_offset += 1 + adaptation_field_length;
            if payload_offset > bytes.len() {
                return Err(TransportStreamPacketError::AdaptationFieldTooLarge(
                    adaptation_field_length,
                ));
            }
        }

        Ok(Self {
            transport_error_indicator: bytes[1] & 0x80 != 0,
            payload_unit_start_indicator: bytes[1] & 0x40 != 0,
            transport_priority: bytes[1] & 0x20 != 0,
            packet_identifier: (u16::from(bytes[1] & 0x1F) << 8) | u16::from(bytes[2]),
            scrambling_control: bytes[3] >> 6,
            continuity_counter: bytes[3] & 0x0F,
            has_adaptation_field,
            has_payload,
            payload: if has_payload {
                bytes[payload_offset..].to_vec()
            } else {
                Vec::new()
            },
        })
    }
}

/// Errors raised by the framer when its bounded buffer would be exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportStreamFramerError {
    InputTooLarge { maximum: usize, actual: usize },
}

/// Re-synchronizing framer that turns an arbitrary byte stream into packets.
///
/// The buffer is bounded so a desynchronized feed cannot grow without limit.
#[derive(Debug, Default)]
pub struct TransportStreamFramer {
    buffered_bytes: Vec<u8>,
}

impl TransportStreamFramer {
    pub const MAXIMUM_INPUT_BYTE_COUNT: usize = TransportStreamPacket::BYTE_COUNT * 1_024;

    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `bytes` and drains every complete, synchronized packet.
    pub fn append(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<TransportStreamPacket>, TransportStreamFramerError> {
        let combined = self.buffered_bytes.len() + bytes.len();
        if bytes.len() > Self::MAXIMUM_INPUT_BYTE_COUNT || combined > Self::MAXIMUM_INPUT_BYTE_COUNT
        {
            return Err(TransportStreamFramerError::InputTooLarge {
                maximum: Self::MAXIMUM_INPUT_BYTE_COUNT,
                actual: combined,
            });
        }

        self.buffered_bytes.extend_from_slice(bytes);
        let mut packets = Vec::new();
        let mut consumed = 0usize;

        while self.buffered_bytes.len() - consumed >= TransportStreamPacket::BYTE_COUNT {
            let Some(offset) = self.synchronized_packet_offset(consumed) else {
                consumed = self.possible_packet_prefix_offset(consumed);
                break;
            };
            consumed = offset;
            if self.buffered_bytes.len() - consumed < TransportStreamPacket::BYTE_COUNT {
                break;
            }
            let end = consumed + TransportStreamPacket::BYTE_COUNT;
            // The offset is sync-aligned by construction, so a decode failure
            // here means the packet body itself is malformed. Skip it rather
            // than aborting the whole batch: the framer's required
            // "drop and continue" behaviour on a damaged multiplex.
            if let Ok(packet) = TransportStreamPacket::parse(&self.buffered_bytes[consumed..end]) {
                packets.push(packet);
            }
            consumed = end;
        }

        if consumed > 0 {
            self.buffered_bytes.drain(..consumed);
        }
        Ok(packets)
    }

    fn synchronized_packet_offset(&self, start_offset: usize) -> Option<usize> {
        let buffered = self.buffered_bytes.len();
        (start_offset..buffered)
            .filter(|&offset| self.buffered_bytes[offset] == TransportStreamPacket::SYNC_BYTE)
            .find(|&offset| {
                let next = offset + TransportStreamPacket::BYTE_COUNT;
                (offset == start_offset
                    && buffered - start_offset == TransportStreamPacket::BYTE_COUNT)
                    || (next < buffered
                        && self.buffered_bytes[next] == TransportStreamPacket::SYNC_BYTE)
            })
    }

    fn possible_packet_prefix_offset(&self, start_offset: usize) -> usize {
        (start_offset..self.buffered_bytes.len())
            .rev()
            .find(|&offset| self.buffered_bytes[offset] == TransportStreamPacket::SYNC_BYTE)
            .unwrap_or(self.buffered_bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(pid: u16, adaptation_field_control: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; TransportStreamPacket::BYTE_COUNT];
        bytes[0] = TransportStreamPacket::SYNC_BYTE;
        bytes[1] = ((pid >> 8) & 0x1F) as u8;
        bytes[2] = (pid & 0xFF) as u8;
        bytes[3] = (adaptation_field_control & 0x03) << 4;
        bytes
    }

    #[test]
    fn parses_header_fields() {
        // Arrange
        let mut bytes = packet(0x0100, 0x01);
        bytes[1] |= 0xE0; // error + unit-start + priority
        bytes[3] |= 0xC0 | 0x0B; // scrambling control 3, continuity 11

        // Act
        let parsed = TransportStreamPacket::parse(&bytes).unwrap();

        // Assert
        assert!(parsed.transport_error_indicator);
        assert!(parsed.payload_unit_start_indicator);
        assert!(parsed.transport_priority);
        assert_eq!(parsed.packet_identifier, 0x0100);
        assert_eq!(parsed.scrambling_control, 3);
        assert_eq!(parsed.continuity_counter, 11);
        assert!(!parsed.has_adaptation_field);
        assert!(parsed.has_payload);
        assert_eq!(parsed.payload.len(), 184);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            TransportStreamPacket::parse(&[0x47; 187]),
            Err(TransportStreamPacketError::InvalidPacketLength(187))
        );
    }

    #[test]
    fn rejects_bad_sync_byte() {
        let mut bytes = packet(0x0100, 0x01);
        bytes[0] = 0x46;
        assert_eq!(
            TransportStreamPacket::parse(&bytes),
            Err(TransportStreamPacketError::InvalidSyncByte(0x46))
        );
    }

    #[test]
    fn rejects_reserved_adaptation_field_control() {
        assert_eq!(
            TransportStreamPacket::parse(&packet(0x0100, 0x00)),
            Err(TransportStreamPacketError::ReservedAdaptationFieldControl)
        );
    }

    #[test]
    fn rejects_oversized_adaptation_field() {
        let mut bytes = packet(0x0100, 0x03);
        bytes[4] = 200; // longer than the remaining packet
        assert_eq!(
            TransportStreamPacket::parse(&bytes),
            Err(TransportStreamPacketError::AdaptationFieldTooLarge(200))
        );
    }

    #[test]
    fn adaptation_only_packet_has_no_payload() {
        let mut bytes = packet(0x0100, 0x02);
        bytes[4] = 10;
        let parsed = TransportStreamPacket::parse(&bytes).unwrap();
        assert!(parsed.has_adaptation_field);
        assert!(!parsed.has_payload);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn framer_drains_whole_packets_and_keeps_remainder() {
        // Arrange
        let mut framer = TransportStreamFramer::new();
        let mut feed = packet(0x0100, 0x01);
        feed.extend_from_slice(&packet(0x0101, 0x01));
        feed.extend_from_slice(&[0x47, 0x00]); // partial third packet

        // Act
        let packets = framer.append(&feed).unwrap();

        // Assert
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].packet_identifier, 0x0100);
        assert_eq!(packets[1].packet_identifier, 0x0101);
    }

    #[test]
    fn framer_resynchronizes_after_leading_garbage() {
        let mut framer = TransportStreamFramer::new();
        let mut feed = vec![0xFFu8; 7];
        feed.extend_from_slice(&packet(0x0160, 0x01));
        feed.extend_from_slice(&packet(0x0160, 0x01));

        let packets = framer.append(&feed).unwrap();

        assert_eq!(packets.len(), 2);
        assert!(packets.iter().all(|p| p.packet_identifier == 0x0160));
    }

    #[test]
    fn framer_rejects_input_beyond_its_bound() {
        let mut framer = TransportStreamFramer::new();
        let oversized = vec![0u8; TransportStreamFramer::MAXIMUM_INPUT_BYTE_COUNT + 1];

        assert_eq!(
            framer.append(&oversized),
            Err(TransportStreamFramerError::InputTooLarge {
                maximum: 192_512,
                actual: TransportStreamFramer::MAXIMUM_INPUT_BYTE_COUNT + 1,
            })
        );
    }

    #[test]
    fn framer_accepts_input_across_multiple_appends() {
        let mut framer = TransportStreamFramer::new();
        let one = packet(0x1FFF, 0x01);

        assert_eq!(framer.append(&one[..100]).unwrap().len(), 0);
        let mut rest = one[100..].to_vec();
        rest.extend_from_slice(&packet(0x1FFF, 0x01));
        let packets = framer.append(&rest).unwrap();

        assert_eq!(packets.len(), 2);
    }
}
