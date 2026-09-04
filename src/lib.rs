//! Broadcast standards shared by every tuner device.
//!
//! Nothing here is specific to any device, vendor, or transport. The contents
//! are published standards — ISO/IEC 13818-1 transport streams, ARIB STD-B25
//! MULTI2 descrambling, and the Japanese terrestrial channel plan — so a
//! second device family reuses this crate unchanged.
//!
//! The rule that keeps it that way: no USB, no opcodes, no VID/PID constants,
//! no vendor command vocabulary. If something here needs to know which device
//! is attached, it belongs in a concrete device crate instead.

pub mod channel;
pub mod descramble;
pub mod multi2;
pub mod pes;
pub mod ts;

pub use multi2::{Multi2, Multi2Error};
