// This file is a Rust port of libaribb25's `multi2.c` and the TS-packet
// descramble procedure of its `arib_std_b25.c`
// (https://github.com/tsukumijima/libaribb25, the maintained fork of
// stz2012/libarib25),
// licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain a
// copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
//
// Per License section 4(b), this file has been modified from the original C
// source. Changes made:
//
//   - Ported from C to safe Rust: raw pointer arithmetic and manual buffer
//     bookkeeping are replaced with slices, arrays, and `Result`-based error
//     handling (`Multi2Error`) instead of C return codes.
//   - The block cipher's Feistel rounds and key schedule (mirroring
//     `multi2.c`'s `set_system_key`/`set_scramble_key` state machine) are
//     reimplemented as the free functions `pi1`..`pi4`, `core_schedule`,
//     `core_encrypt`, and `core_decrypt` in this file, operating on a
//     `CoreData` type and `[u32; 8]` word arrays rather than the original
//     C struct's mutable fields.
//   - The TS-packet descramble procedure of `arib_std_b25.c` is folded into
//     this module as `Multi2::descramble_ts_packet` and
//     `Multi2::descramble_ts_packets`, rather than being driven by a
//     separate `B_CAS_CARD`/`ARIB_STD_B25` C driver object.
//   - Test vectors and the test harness are new; none are carried over from
//     the original C test driver (`td.c`).
//
//! MULTI2 cipher (ARIB STD-B25) — faithful scalar port of libaribb25's
//! `multi2.c`, plus the TS-packet descramble procedure of its `arib_std_b25.c`.
//!
//! Key layout (from `multi2.c` + `arib_std_b25.c` + `b_cas_card.c`):
//! - System key: 256 bits (32 bytes), loaded as 8 big-endian u32s
//!   (`set_system_key`). In the B25 layer it comes from the B-CAS card's
//!   initial-settings response (`B_CAS_INIT_STATUS.system_key`).
//! - CBC init (IV): 64 bits (8 bytes; `set_init_cbc`), also from the card's
//!   initial-settings response (`B_CAS_INIT_STATUS.init_cbc`). It is the IV for
//!   EVERY CBC call — it does not chain across calls/packets.
//! - Scramble key: 128 bits (16 bytes; `set_scramble_key`), the card's ECM
//!   decode reply copied verbatim (`memcpy(dst->scramble_key, rbuf+6, 16)`).
//!   Layout is **bytes [0..8] = odd CW, bytes [8..16] = even CW**
//!   (`CORE_DATA scr[2]; /* 0: odd, 1: even */`, and the DEBUG dump in
//!   `proc_ecm_arib_std_b25` prints `scramble_key[0..8]` as "odd"). Each 64-bit
//!   half is expanded by the key schedule against the system key into a work
//!   key (`wrk[0]` odd / `wrk[1]` even).
//!
//! Round count: `create_multi2` defaults to 4, and both the `b25` test driver
//! (`td.c`, `-r round (integer, default=4)`) and a macOS B25 decoder
//! (`B25Decoder.cpp`, `multi2_round = 4`) use 4. [`Multi2::new`] matches that.

use std::fmt;

use crate::descramble::DescrambleDispositionCounts;

/// Round count used by the ARIB STD-B25 layer (`multi2_round = 4`).
pub const DEFAULT_ROUND: u32 = 4;

/// Size of one MPEG transport-stream packet.
pub const TS_PACKET_LEN: usize = 188;

/// Which 64-bit control word (scramble key half) to operate with.
///
/// Maps to `multi2.c`'s `type` argument: `type == 0x02` selects the even work
/// key (`wrk[1]`), anything else the odd one (`wrk[0]`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScrambleKey {
    /// Odd CW — `wrk[0]`, schedule of `scramble_key[0..8]`.
    Odd,
    /// Even CW — `wrk[1]`, schedule of `scramble_key[8..16]`.
    Even,
}

impl ScrambleKey {
    /// Select the key for a TS packet's `transport_scrambling_control` value
    /// (bits 7-6 of header byte 3), exactly as `multi2.c`'s
    /// `if(type == 0x02) prm = wrk+1; else prm = wrk+0;`:
    /// 2 (0x80) → even, 3 (0xC0) → odd, and the reserved value 1 (0x40) also
    /// falls through to **odd** — libaribb25 decrypts TSC=1 packets with the
    /// odd key rather than passing them through.
    pub fn from_tsc(tsc: u8) -> Self {
        if tsc == 2 {
            ScrambleKey::Even
        } else {
            ScrambleKey::Odd
        }
    }
}

/// Errors from the MULTI2 API, mirroring `multi2_error_code.h`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Multi2Error {
    /// Crypto op requested before [`Multi2::set_scramble_key`] (or after
    /// [`Multi2::clear_scramble_key`]): C `MULTI2_ERROR_UNSET_SCRAMBLE_KEY`.
    UnsetScrambleKey,
    /// Empty buffer passed to a CBC op: C returns
    /// `MULTI2_ERROR_INVALID_PARAMETER` for `size < 1`.
    EmptyBuffer,
}

impl fmt::Display for Multi2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Multi2Error::UnsetScrambleKey => write!(f, "scramble key is not set"),
            Multi2Error::EmptyBuffer => write!(f, "buffer must be at least 1 byte"),
        }
    }
}

impl std::error::Error for Multi2Error {}

/// Outcome of [`Multi2::descramble_ts_packet`], mirroring the branches in
/// `put_arib_std_b25` (`arib_std_b25.c`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TsAction {
    /// TSC != 0 with a payload: payload was MULTI2-CBC decrypted and the two
    /// TSC bits in byte 3 were cleared (`curr[3] &= 0x3f`).
    Decrypted,
    /// TSC == 0: packet is not scrambled; passed through verbatim.
    Unscrambled,
    /// TSC != 0 but adaptation-field-only (`adaptation_field_control & 1 == 0`)
    /// or zero-length payload: no crypto, only the TSC bits were cleared.
    NoPayload,
    /// `transport_error_indicator` set: passed through verbatim (C appends it
    /// to the output without parsing).
    TransportError,
    /// Broken adaptation-field geometry (`n < 1` with a payload, or
    /// adaptation field running past the packet end): C drops the packet from
    /// its output stream (`curr += 1; continue`); left untouched here.
    Broken,
}

/// C `CORE_DATA`: one 64-bit block as two u32 halves. `l` is the big-endian
/// u32 of bytes [0..4], `r` of bytes [4..8].
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct CoreData {
    l: u32,
    r: u32,
}

impl CoreData {
    fn from_be(bytes: &[u8]) -> Self {
        CoreData {
            l: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            r: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    fn to_be(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.l.to_be_bytes());
        out[4..8].copy_from_slice(&self.r.to_be_bytes());
        out
    }
}

// The π functions, ported 1:1 from `core_pi1`..`core_pi4` (wrapping u32
// arithmetic matches C's unsigned overflow semantics; `left_rotate_uint32` ==
// `u32::rotate_left` for the counts used here, which are never 0).

fn pi1(src: CoreData) -> CoreData {
    CoreData {
        l: src.l,
        r: src.r ^ src.l,
    }
}

fn pi2(src: CoreData, a: u32) -> CoreData {
    let t0 = src.r.wrapping_add(a);
    let t1 = t0.rotate_left(1).wrapping_add(t0).wrapping_sub(1);
    let t2 = t1.rotate_left(4) ^ t1;
    CoreData {
        l: src.l ^ t2,
        r: src.r,
    }
}

fn pi3(src: CoreData, a: u32, b: u32) -> CoreData {
    let t0 = src.l.wrapping_add(a);
    let t1 = t0.rotate_left(2).wrapping_add(t0).wrapping_add(1);
    let t2 = t1.rotate_left(8) ^ t1;
    let t3 = t2.wrapping_add(b);
    let t4 = t3.rotate_left(1).wrapping_sub(t3);
    let t5 = t4.rotate_left(16) ^ (t4 | src.l);
    CoreData {
        l: src.l,
        r: src.r ^ t5,
    }
}

fn pi4(src: CoreData, a: u32) -> CoreData {
    let t0 = src.r.wrapping_add(a);
    let t1 = t0.rotate_left(2).wrapping_add(t0).wrapping_add(1);
    CoreData {
        l: src.l ^ t1,
        r: src.r,
    }
}

/// C `core_schedule`: expand a 64-bit data key against the 256-bit system key
/// into the 8-word work key.
fn core_schedule(sys: &[u32; 8], dkey: CoreData) -> [u32; 8] {
    let b1 = pi1(dkey);
    let b2 = pi2(b1, sys[0]);
    let b3 = pi3(b2, sys[1], sys[2]);
    let b4 = pi4(b3, sys[3]);
    let b5 = pi1(b4);
    let b6 = pi2(b5, sys[4]);
    let b7 = pi3(b6, sys[5], sys[6]);
    let b8 = pi4(b7, sys[7]);
    let b9 = pi1(b8);
    [b2.l, b3.r, b4.l, b5.r, b6.l, b7.r, b8.l, b9.r]
}

/// C `core_encrypt` (one 8-byte block, no CBC).
fn core_encrypt(src: CoreData, w: &[u32; 8], round: u32) -> CoreData {
    let mut d = src;
    for _ in 0..round {
        d = pi2(pi1(d), w[0]);
        d = pi4(pi3(d, w[1], w[2]), w[3]);
        d = pi2(pi1(d), w[4]);
        d = pi4(pi3(d, w[5], w[6]), w[7]);
    }
    d
}

/// C `core_decrypt` (inverse round: π4⁻¹=π4 keyed tail, i.e. the C order).
fn core_decrypt(src: CoreData, w: &[u32; 8], round: u32) -> CoreData {
    let mut d = src;
    for _ in 0..round {
        d = pi3(pi4(d, w[7]), w[5], w[6]);
        d = pi1(pi2(d, w[4]));
        d = pi3(pi4(d, w[3]), w[1], w[2]);
        d = pi1(pi2(d, w[0]));
    }
    d
}

/// MULTI2 cipher context — the Rust analogue of C's `MULTI2` +
/// `MULTI2_PRIVATE_DATA`.
///
/// Usage mirrors the B25 layer: create with the card's system key + CBC init
/// once, then [`set_scramble_key`](Multi2::set_scramble_key) on every ECM
/// update.
pub struct Multi2 {
    sys: [u32; 8],
    cbc_init: CoreData,
    scr: [CoreData; 2], // [odd, even]
    wrk: [[u32; 8]; 2], // [odd, even]
    round: u32,
    scramble_key_set: bool,
}

impl Multi2 {
    /// Create a cipher with the given 256-bit system key and 64-bit CBC init
    /// (both from the B-CAS card initial-settings response in the B25 layer).
    /// Round count defaults to [`DEFAULT_ROUND`] (= 4) as in `create_multi2`.
    /// No scramble key is set yet; crypto ops return
    /// [`Multi2Error::UnsetScrambleKey`] until [`Multi2::set_scramble_key`].
    pub fn new(system_key: &[u8; 32], init_cbc: &[u8; 8]) -> Self {
        let mut sys = [0u32; 8];
        for (i, w) in sys.iter_mut().enumerate() {
            *w = u32::from_be_bytes([
                system_key[i * 4],
                system_key[i * 4 + 1],
                system_key[i * 4 + 2],
                system_key[i * 4 + 3],
            ]);
        }
        Multi2 {
            sys,
            cbc_init: CoreData::from_be(init_cbc),
            scr: [CoreData::default(); 2],
            wrk: [[0u32; 8]; 2],
            round: DEFAULT_ROUND,
            scramble_key_set: false,
        }
    }

    /// [`Multi2::new`] + [`Multi2::set_scramble_key`] in one call — the state
    /// the B25 layer is in after a successful ECM decode.
    pub fn with_scramble_key(
        system_key: &[u8; 32],
        init_cbc: &[u8; 8],
        scramble_key: &[u8; 16],
    ) -> Self {
        let mut m2 = Self::new(system_key, init_cbc);
        m2.set_scramble_key(scramble_key);
        m2
    }

    /// C `set_round`. The ARIB STD-B25 layer always uses 4.
    pub fn set_round(&mut self, round: u32) {
        self.round = round;
    }

    /// Current round count (default 4).
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Whether an ECM-derived odd/even scramble key is installed.
    pub fn is_ready(&self) -> bool {
        self.scramble_key_set
    }

    /// C `set_scramble_key`: load the 16-byte B-CAS ECM reply and expand both
    /// halves into work keys. **Layout: bytes [0..8] = odd CW, [8..16] = even
    /// CW** (see module docs).
    pub fn set_scramble_key(&mut self, scramble_key: &[u8; 16]) {
        self.scr[0] = CoreData::from_be(&scramble_key[0..8]);
        self.scr[1] = CoreData::from_be(&scramble_key[8..16]);
        self.wrk[0] = core_schedule(&self.sys, self.scr[0]);
        self.wrk[1] = core_schedule(&self.sys, self.scr[1]);
        self.scramble_key_set = true;
    }

    /// C `clear_scramble_key`: zero the scramble and work keys.
    pub fn clear_scramble_key(&mut self) {
        self.scr = [CoreData::default(); 2];
        self.wrk = [[0u32; 8]; 2];
        self.scramble_key_set = false;
    }

    fn work_key(&self, key: ScrambleKey) -> Result<&[u32; 8], Multi2Error> {
        if !self.scramble_key_set {
            return Err(Multi2Error::UnsetScrambleKey);
        }
        Ok(match key {
            ScrambleKey::Odd => &self.wrk[0],
            ScrambleKey::Even => &self.wrk[1],
        })
    }

    /// Raw MULTI2 block encryption (`core_encrypt` on the selected work key,
    /// no CBC). Not exposed by the C API; provided for KATs and diagnostics.
    pub fn encrypt_block(&self, key: ScrambleKey, block: &[u8; 8]) -> Result<[u8; 8], Multi2Error> {
        let w = self.work_key(key)?;
        Ok(core_encrypt(CoreData::from_be(block), w, self.round).to_be())
    }

    /// Raw MULTI2 block decryption (`core_decrypt`, no CBC).
    pub fn decrypt_block(&self, key: ScrambleKey, block: &[u8; 8]) -> Result<[u8; 8], Multi2Error> {
        let w = self.work_key(key)?;
        Ok(core_decrypt(CoreData::from_be(block), w, self.round).to_be())
    }

    /// C `encrypt_multi2`: CBC encrypt `buf` in place. The IV is always the
    /// configured `init_cbc` — it does NOT chain across calls. A trailing
    /// partial block (< 8 bytes) is encrypted CFB-style: XOR with
    /// `E(last_chain)` keystream bytes.
    pub fn encrypt_cbc(&self, key: ScrambleKey, buf: &mut [u8]) -> Result<(), Multi2Error> {
        let w = self.work_key(key)?;
        if buf.is_empty() {
            return Err(Multi2Error::EmptyBuffer);
        }
        let mut chain = self.cbc_init;
        let full = buf.len() / 8 * 8;
        let (body, tail) = buf.split_at_mut(full);
        for blk in body.chunks_exact_mut(8) {
            let mut src = CoreData::from_be(blk);
            src.l ^= chain.l;
            src.r ^= chain.r;
            chain = core_encrypt(src, w, self.round);
            blk.copy_from_slice(&chain.to_be());
        }
        if !tail.is_empty() {
            let ks = core_encrypt(chain, w, self.round).to_be();
            for (b, k) in tail.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
        }
        Ok(())
    }

    /// C `decrypt_multi2`: CBC decrypt `buf` in place (IV = `init_cbc`, never
    /// chained across calls; partial tail uses the same `E(last_chain)`
    /// keystream as encryption).
    pub fn decrypt_cbc(&self, key: ScrambleKey, buf: &mut [u8]) -> Result<(), Multi2Error> {
        let w = self.work_key(key)?;
        if buf.is_empty() {
            return Err(Multi2Error::EmptyBuffer);
        }
        let mut cbc = self.cbc_init;
        let full = buf.len() / 8 * 8;
        let (body, tail) = buf.split_at_mut(full);
        for blk in body.chunks_exact_mut(8) {
            let src = CoreData::from_be(blk);
            let mut dst = core_decrypt(src, w, self.round);
            dst.l ^= cbc.l;
            dst.r ^= cbc.r;
            cbc = src;
            blk.copy_from_slice(&dst.to_be());
        }
        if !tail.is_empty() {
            let ks = core_encrypt(cbc, w, self.round).to_be();
            for (b, k) in tail.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
        }
        Ok(())
    }

    /// Descramble one 188-byte MPEG-TS packet in place, following
    /// `put_arib_std_b25` in `arib_std_b25.c` byte-for-byte:
    ///
    /// - Caller must present a sync-aligned packet (the C caller resyncs
    ///   first); byte 0 is not re-checked here.
    /// - `transport_error_indicator` (bit 7 of byte 1) → pass through
    ///   verbatim ([`TsAction::TransportError`]).
    /// - Payload offset: byte 4; if `adaptation_field_control` (bits 5-4 of
    ///   byte 3) has bit 1 set, skip `pkt[4] + 1` more bytes (adaptation
    ///   field length byte + field); payload length `n = 188 - offset`
    ///   (184 without an adaptation field).
    /// - Broken geometry (`n < 1` with payload present, or `n < 0`) →
    ///   [`TsAction::Broken`], packet left untouched (C drops it).
    /// - `transport_scrambling_control` (bits 7-6 of byte 3): 0 → verbatim
    ///   ([`TsAction::Unscrambled`]); otherwise decrypt the payload with
    ///   [`ScrambleKey::from_tsc`] (2 = even, 3 = odd, reserved 1 = odd!)
    ///   and clear both TSC bits (`pkt[3] &= 0x3f`). With no payload only
    ///   the TSC bits are cleared ([`TsAction::NoPayload`]).
    ///
    /// Stream-level concerns are the caller's job: libaribb25 only descrambles
    /// PIDs bound to a program's ECM-decoded decryptor and passes everything
    /// else through with TSC bits intact.
    pub fn descramble_ts_packet(&self, pkt: &mut [u8; 188]) -> Result<TsAction, Multi2Error> {
        let tei = (pkt[1] >> 7) & 0x01;
        let tsc = (pkt[3] >> 6) & 0x03;
        let afc = (pkt[3] >> 4) & 0x03;

        if tei != 0 {
            return Ok(TsAction::TransportError);
        }

        // Payload geometry — computed before the TSC check in C, and the
        // broken-packet skip happens even for unscrambled packets.
        let mut off = 4usize;
        let n: usize = if afc & 0x02 != 0 {
            off += pkt[4] as usize + 1;
            let nn = 188i64 - off as i64;
            if nn < 1 && (nn < 0 || afc & 0x01 != 0) {
                return Ok(TsAction::Broken);
            }
            nn.max(0) as usize
        } else {
            188 - 4
        };

        if tsc == 0 {
            return Ok(TsAction::Unscrambled);
        }
        if afc & 0x01 == 0 {
            // No payload: C just clears the TSC bits.
            pkt[3] &= 0x3f;
            return Ok(TsAction::NoPayload);
        }

        // n >= 1 is guaranteed here: afc has bit 0 set, so n < 1 was Broken.
        self.decrypt_cbc(ScrambleKey::from_tsc(tsc), &mut pkt[off..off + n])?;
        pkt[3] &= 0x3f;
        Ok(TsAction::Decrypted)
    }

    /// Descrambles each packet independently. A packet that cannot be decrypted —
    /// corrupt, unscrambled, adaptation-only — is left as the disposition says and
    /// does **not** stop the rest of the batch. Returns the disposition histogram;
    /// a low decrypted count is normal on a clear-heavy multiplex and is not a
    /// health signal.
    ///
    /// The previous implementation failed the whole batch on any odd packet, and
    /// its caller discarded the error, so one unusual packet silently left an
    /// entire buffer scrambled.
    pub fn descramble_ts_packets(
        &self,
        packets: &mut [u8],
    ) -> Result<DescrambleDispositionCounts, Multi2Error> {
        if packets.is_empty() {
            return Err(Multi2Error::EmptyBuffer);
        }

        let mut counts = DescrambleDispositionCounts::default();
        for chunk in packets.chunks_exact_mut(TS_PACKET_LEN) {
            let packet: &mut [u8; TS_PACKET_LEN] = chunk.try_into().unwrap();
            match self.descramble_ts_packet(packet)? {
                TsAction::Decrypted => counts.decrypted += 1,
                TsAction::Unscrambled => counts.unscrambled += 1,
                TsAction::NoPayload => counts.no_payload += 1,
                TsAction::TransportError => counts.transport_error += 1,
                TsAction::Broken => counts.broken += 1,
            }
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle_input(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (index * 13 + (index >> 1) + 0x31) as u8)
            .collect()
    }

    fn synthetic_oracle_cipher() -> Multi2 {
        let system_key = std::array::from_fn(|index| index as u8);
        let cbc_init = std::array::from_fn(|index| 0xa0 + index as u8);
        let scramble_key = std::array::from_fn(|index| 0x40 + index as u8);
        Multi2::with_scramble_key(&system_key, &cbc_init, &scramble_key)
    }

    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len() / 2)
            .map(|index| {
                u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex byte")
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Known-answer vectors generated by the scalar reference implementation.
    // Setup A (schedule + block KATs): sys = 00..1f, init_cbc = a0..a7,
    //   scramble key = 00..0f (odd CW 00..07, even CW 08..0f).
    // Setup B (CBC + TS KATs): same sys/cbc, scramble key = 30..3f
    //   (odd CW 30..37, even CW 38..3f), round = 4.
    // ------------------------------------------------------------------

    const SCHED_ODD_SYS00_1F: [u32; 8] = [
        0xccff3157, 0x1021f5d1, 0x40142236, 0x5035d7e7, 0x6d8b4109, 0x97d97d03, 0xee5a46a4,
        0x79833ba7,
    ];
    const SCHED_EVEN_SYS00_1F: [u32; 8] = [
        0xc4f7395f, 0x80027422, 0x78bab3a7, 0xf8b8c785, 0xc73ff311, 0xfca7c5a9, 0xbce781f8,
        0x40404451,
    ];

    const BLK_IN: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const BLK_ENC_R1: [u8; 8] = [0x6c, 0xda, 0x85, 0xfc, 0x63, 0xb1, 0x6f, 0x2c];
    const BLK_ENC_R2: [u8; 8] = [0xbb, 0x81, 0x49, 0x5c, 0xe3, 0x36, 0x2b, 0x1f];
    const BLK_ENC_R4: [u8; 8] = [0xcc, 0x9d, 0xc3, 0x9f, 0xd0, 0x05, 0xa3, 0x2b];
    const BLK_ENC_R8: [u8; 8] = [0xfb, 0x86, 0xcd, 0x85, 0x37, 0x4f, 0xb3, 0x36];

    const CBC_PT48: [u8; 48] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f,
    ];
    const CBC_PT27: [u8; 27] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    ];
    const CBC_ENC_ODD_48: [u8; 48] = [
        0x44, 0x1d, 0x9f, 0x22, 0x04, 0xa3, 0xde, 0x53, 0x54, 0xf6, 0x0c, 0x49, 0x29, 0xb0, 0xf7,
        0x4e, 0xb6, 0xe7, 0x65, 0x99, 0x47, 0x09, 0x3b, 0x46, 0xfb, 0x92, 0xaf, 0xa3, 0x91, 0xf8,
        0x2c, 0xfb, 0x36, 0xb6, 0x62, 0x76, 0xff, 0x11, 0x11, 0x07, 0x95, 0x63, 0x6e, 0x9e, 0x16,
        0xa4, 0x3b, 0x96,
    ];
    const CBC_ENC_EVEN_48: [u8; 48] = [
        0x9e, 0xdd, 0xb2, 0x45, 0x1b, 0xa0, 0x11, 0x63, 0xf6, 0xff, 0x3f, 0x91, 0x31, 0x67, 0x93,
        0x6b, 0xb7, 0xef, 0x02, 0x2c, 0xd7, 0x9e, 0x04, 0x54, 0x23, 0xf8, 0xdb, 0xc3, 0x4d, 0x2c,
        0x9e, 0xea, 0xb3, 0x3e, 0x39, 0x88, 0x4d, 0xb2, 0xde, 0x3d, 0xff, 0xf4, 0x04, 0x9e, 0xbb,
        0xbd, 0xcd, 0xeb,
    ];
    const CBC_ENC_ODD_27: [u8; 27] = [
        0xcd, 0xbe, 0xe0, 0x5b, 0x98, 0x74, 0xb1, 0x9e, 0x4e, 0xf0, 0x0a, 0xdf, 0x2a, 0xa3, 0xfc,
        0xb6, 0x75, 0xbf, 0xdb, 0xa1, 0x9d, 0x03, 0x4e, 0x27, 0xcd, 0xf3, 0x19,
    ];
    const CBC_ENC_EVEN_27: [u8; 27] = [
        0x8a, 0x71, 0xac, 0xf7, 0xbe, 0xd0, 0xe4, 0x74, 0x86, 0x25, 0x32, 0x45, 0x9b, 0x72, 0xe1,
        0x9b, 0xf8, 0x1c, 0x9e, 0x94, 0x7f, 0x87, 0x68, 0x0c, 0x19, 0xaa, 0x84,
    ];

    fn sys_a() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn cbc_a() -> [u8; 8] {
        let mut k = [0u8; 8];
        for (i, b) in k.iter_mut().enumerate() {
            *b = 0xa0 + i as u8;
        }
        k
    }

    /// Setup A: schedule/block KAT cipher (scr = 00..0f).
    fn cipher_setup_a() -> Multi2 {
        let mut m2 = Multi2::new(&sys_a(), &cbc_a());
        let mut scr = [0u8; 16];
        for (i, b) in scr.iter_mut().enumerate() {
            *b = i as u8;
        }
        m2.set_scramble_key(&scr);
        m2
    }

    /// Setup B: CBC/TS KAT cipher (scr = 30..3f, round = 4).
    fn cipher_setup_b() -> Multi2 {
        let mut m2 = Multi2::new(&sys_a(), &cbc_a());
        let mut scr = [0u8; 16];
        for (i, b) in scr.iter_mut().enumerate() {
            *b = 0x30 + i as u8;
        }
        m2.set_scramble_key(&scr);
        m2
    }

    #[test]
    fn default_round_is_4() {
        assert_eq!(Multi2::new(&[0u8; 32], &[0u8; 8]).round(), 4);
    }

    #[test]
    fn key_schedule_kat() {
        let m2 = cipher_setup_a();
        assert_eq!(m2.wrk[0], SCHED_ODD_SYS00_1F);
        assert_eq!(m2.wrk[1], SCHED_EVEN_SYS00_1F);
    }

    #[test]
    fn block_encrypt_kat_rounds() {
        let mut m2 = cipher_setup_a();
        for (round, expect) in [
            (1, BLK_ENC_R1),
            (2, BLK_ENC_R2),
            (4, BLK_ENC_R4),
            (8, BLK_ENC_R8),
        ] {
            m2.set_round(round);
            let ct = m2.encrypt_block(ScrambleKey::Odd, &BLK_IN).unwrap();
            assert_eq!(ct, expect, "round {round} encrypt");
            let pt = m2.decrypt_block(ScrambleKey::Odd, &ct).unwrap();
            assert_eq!(pt, BLK_IN, "round {round} decrypt inverts");
        }
    }

    #[test]
    fn cbc_encrypt_kat() {
        let m2 = cipher_setup_b();
        let mut buf = CBC_PT48;
        m2.encrypt_cbc(ScrambleKey::Odd, &mut buf).unwrap();
        assert_eq!(buf, CBC_ENC_ODD_48);

        let mut buf = CBC_PT48;
        m2.encrypt_cbc(ScrambleKey::Even, &mut buf).unwrap();
        assert_eq!(buf, CBC_ENC_EVEN_48);

        // 27 bytes: exercises the CFB-style partial tail.
        let mut buf = CBC_PT27;
        m2.encrypt_cbc(ScrambleKey::Odd, &mut buf).unwrap();
        assert_eq!(buf, CBC_ENC_ODD_27);

        let mut buf = CBC_PT27;
        m2.encrypt_cbc(ScrambleKey::Even, &mut buf).unwrap();
        assert_eq!(buf, CBC_ENC_EVEN_27);
    }

    #[test]
    fn cbc_decrypt_kat() {
        let m2 = cipher_setup_b();
        let mut buf = CBC_ENC_ODD_48;
        m2.decrypt_cbc(ScrambleKey::Odd, &mut buf).unwrap();
        assert_eq!(buf, CBC_PT48);

        let mut buf = CBC_ENC_EVEN_48;
        m2.decrypt_cbc(ScrambleKey::Even, &mut buf).unwrap();
        assert_eq!(buf, CBC_PT48);

        let mut buf = CBC_ENC_ODD_27;
        m2.decrypt_cbc(ScrambleKey::Odd, &mut buf).unwrap();
        assert_eq!(buf, CBC_PT27);

        let mut buf = CBC_ENC_EVEN_27;
        m2.decrypt_cbc(ScrambleKey::Even, &mut buf).unwrap();
        assert_eq!(buf, CBC_PT27);
    }

    #[test]
    fn cbc_iv_does_not_chain_across_calls() {
        // Every CBC call restarts from init_cbc: two separate single-block
        // encryptions equal the first two blocks of one combined encryption
        // ONLY for block 0; block 1 differs (IV vs chained ciphertext).
        let m2 = cipher_setup_b();
        let mut two = CBC_PT48;
        m2.encrypt_cbc(ScrambleKey::Odd, &mut two[..16]).unwrap();

        let mut blk0 = CBC_PT48;
        m2.encrypt_cbc(ScrambleKey::Odd, &mut blk0[..8]).unwrap();
        let mut blk1 = CBC_PT48;
        m2.encrypt_cbc(ScrambleKey::Odd, &mut blk1[8..16]).unwrap();

        assert_eq!(two[..8], blk0[..8]);
        assert_ne!(two[8..16], blk1[8..16]);
    }

    #[test]
    fn cbc_roundtrip_all_lengths() {
        // Deterministic xorshift PRNG (no external deps): round-trip encrypt→
        // decrypt for lengths 1..=64 (covers 0..8 byte partial tails) and
        // rounds 1..=8, both keys.
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 1..=8u32 {
            let mut m2r = cipher_setup_b();
            m2r.set_round(round);
            for len in 1..=64usize {
                let mut pt = vec![0u8; len];
                for b in pt.iter_mut() {
                    *b = next() as u8;
                }
                for key in [ScrambleKey::Odd, ScrambleKey::Even] {
                    let mut buf = pt.clone();
                    m2r.encrypt_cbc(key, &mut buf).unwrap();
                    if round == 4 && len > 8 {
                        assert_ne!(buf, pt, "ciphertext should differ from plaintext");
                    }
                    m2r.decrypt_cbc(key, &mut buf).unwrap();
                    assert_eq!(buf, pt, "round {round} len {len} key {key:?}");
                }
            }
        }
    }

    #[test]
    fn unset_scramble_key_errors() {
        let mut m2 = Multi2::new(&sys_a(), &cbc_a());
        let mut buf = [0u8; 8];
        assert_eq!(
            m2.decrypt_cbc(ScrambleKey::Odd, &mut buf),
            Err(Multi2Error::UnsetScrambleKey)
        );
        assert_eq!(
            m2.encrypt_block(ScrambleKey::Even, &buf),
            Err(Multi2Error::UnsetScrambleKey)
        );
        m2.set_scramble_key(&[0u8; 16]);
        m2.decrypt_cbc(ScrambleKey::Odd, &mut buf).unwrap();
        m2.clear_scramble_key();
        assert_eq!(
            m2.decrypt_cbc(ScrambleKey::Odd, &mut buf),
            Err(Multi2Error::UnsetScrambleKey)
        );
    }

    #[test]
    fn empty_buffer_errors() {
        let m2 = cipher_setup_b();
        assert_eq!(
            m2.encrypt_cbc(ScrambleKey::Odd, &mut []),
            Err(Multi2Error::EmptyBuffer)
        );
        assert_eq!(
            m2.decrypt_cbc(ScrambleKey::Even, &mut []),
            Err(Multi2Error::EmptyBuffer)
        );
    }

    #[test]
    fn matches_synthetic_oracle_for_full_and_partial_blocks() {
        let cipher = synthetic_oracle_cipher();
        let vectors = [
            (2, 1, "e2"),
            (3, 7, "6aceaf7d9f5591"),
            (2, 8, "28e0541bff168c2d"),
            (3, 9, "27d7dd4a1517304d0f"),
            (2, 17, "28e0541bff168c2d081f8edce75f4acc0f"),
            (
                3,
                33,
                "27d7dd4a1517304d279f5517da42689473e44e86ac6e280d688d5b0ebd187606a5", // gate-allow: synthetic KAT, index-derived plaintext, no real key material
            ),
        ];
        for (scrambling_control, len, expected) in vectors {
            let mut actual = oracle_input(len);
            cipher
                .decrypt_cbc(ScrambleKey::from_tsc(scrambling_control), &mut actual)
                .expect("decrypt vector");
            assert_eq!(actual, unhex(expected));
        }
    }

    #[test]
    fn ts_packet_descrambling_preserves_header_and_clears_control_bits() {
        let cipher = synthetic_oracle_cipher();
        let mut packet = [0u8; TS_PACKET_LEN];
        packet[0..4].copy_from_slice(&[0x47, 0x01, 0x23, 0xb5]);
        packet[4] = 3;
        packet[5..8].copy_from_slice(&[0x10, 0x20, 0x30]);
        packet[8..].copy_from_slice(&oracle_input(180));
        let header = packet[..8].to_vec();
        let mut expected_payload = oracle_input(180);
        cipher
            .decrypt_cbc(ScrambleKey::Even, &mut expected_payload)
            .expect("expected payload");

        assert_eq!(
            cipher.descramble_ts_packet(&mut packet),
            Ok(TsAction::Decrypted)
        );
        assert_eq!(&packet[..3], &header[..3]);
        assert_eq!(packet[3], header[3] & 0x3f);
        assert_eq!(&packet[4..8], &header[4..8]);
        assert_eq!(&packet[8..], expected_payload);
        assert_eq!(
            cipher.descramble_ts_packet(&mut packet),
            Ok(TsAction::Unscrambled)
        );
    }

    #[test]
    fn malformed_packet_does_not_stop_other_packets_in_batch() {
        let cipher = synthetic_oracle_cipher();

        let mut decryptable = [0u8; TS_PACKET_LEN];
        decryptable[0] = 0x47;
        decryptable[3] = 0x90;
        let mut expected_decrypted = decryptable;
        assert_eq!(
            cipher.descramble_ts_packet(&mut expected_decrypted),
            Ok(TsAction::Decrypted)
        );

        let mut malformed = decryptable;
        malformed[3] = 0xb0;
        malformed[4] = 200;
        let original_malformed = malformed;

        let mut packets = Vec::with_capacity(TS_PACKET_LEN * 2);
        packets.extend_from_slice(&malformed);
        packets.extend_from_slice(&decryptable);

        assert_eq!(
            cipher.descramble_ts_packets(&mut packets),
            Ok(DescrambleDispositionCounts {
                decrypted: 1,
                broken: 1,
                ..DescrambleDispositionCounts::default()
            })
        );
        assert_eq!(&packets[..TS_PACKET_LEN], original_malformed.as_slice());
        assert_eq!(&packets[TS_PACKET_LEN..], expected_decrypted.as_slice());
    }

    // ------------------------------------------------------------------
    // TS-packet KATs: full 188-byte packets run through the reference
    // arib_std_b25 unlock procedure on the C side. Setup B keys, round 4.
    // ------------------------------------------------------------------

    const TS_EVEN_AFC3_IN: [u8; 188] = [
        0x47, 0x00, 0x51, 0xb7, 0x07, 0x24, 0x5b, 0x92, 0xc9, 0x00, 0x37, 0x6e, 0xa5, 0xdc, 0x13,
        0x4a, 0x81, 0xb8, 0xef, 0x26, 0x5d, 0x94, 0xcb, 0x02, 0x39, 0x70, 0xa7, 0xde, 0x15, 0x4c,
        0x83, 0xba, 0xf1, 0x28, 0x5f, 0x96, 0xcd, 0x04, 0x3b, 0x72, 0xa9, 0xe0, 0x17, 0x4e, 0x85,
        0xbc, 0xf3, 0x2a, 0x61, 0x98, 0xcf, 0x06, 0x3d, 0x74, 0xab, 0xe2, 0x19, 0x50, 0x87, 0xbe,
        0xf5, 0x2c, 0x63, 0x9a, 0xd1, 0x08, 0x3f, 0x76, 0xad, 0xe4, 0x1b, 0x52, 0x89, 0xc0, 0xf7,
        0x2e, 0x65, 0x9c, 0xd3, 0x0a, 0x41, 0x78, 0xaf, 0xe6, 0x1d, 0x54, 0x8b, 0xc2, 0xf9, 0x30,
        0x67, 0x9e, 0xd5, 0x0c, 0x43, 0x7a, 0xb1, 0xe8, 0x1f, 0x56, 0x8d, 0xc4, 0xfb, 0x32, 0x69,
        0xa0, 0xd7, 0x0e, 0x45, 0x7c, 0xb3, 0xea, 0x21, 0x58, 0x8f, 0xc6, 0xfd, 0x34, 0x6b, 0xa2,
        0xd9, 0x10, 0x47, 0x7e, 0xb5, 0xec, 0x23, 0x5a, 0x91, 0xc8, 0xff, 0x36, 0x6d, 0xa4, 0xdb,
        0x12, 0x49, 0x80, 0xb7, 0xee, 0x25, 0x5c, 0x93, 0xca, 0x01, 0x38, 0x6f, 0xa6, 0xdd, 0x14,
        0x4b, 0x82, 0xb9, 0xf0, 0x27, 0x5e, 0x95, 0xcc, 0x03, 0x3a, 0x71, 0xa8, 0xdf, 0x16, 0x4d,
        0x84, 0xbb, 0xf2, 0x29, 0x60, 0x97, 0xce, 0x05, 0x3c, 0x73, 0xaa, 0xe1, 0x18, 0x4f, 0x86,
        0xbd, 0xf4, 0x2b, 0x62, 0x99, 0xd0, 0x07, 0x3e,
    ];
    const TS_EVEN_AFC3_OUT: [u8; 188] = [
        0x47, 0x00, 0x51, 0x37, 0x07, 0x24, 0x5b, 0x92, 0xc9, 0x00, 0x37, 0x6e, 0xee, 0xca, 0xb9,
        0x36, 0x43, 0x0b, 0x37, 0x37, 0x07, 0xc8, 0xb9, 0x06, 0xa4, 0x63, 0xda, 0xfe, 0x97, 0xe4,
        0xf3, 0x00, 0xe9, 0x4d, 0xa2, 0x37, 0x12, 0x9a, 0x18, 0xf7, 0x6c, 0xde, 0xc9, 0x6f, 0xec,
        0x54, 0x82, 0xb7, 0x3b, 0x2d, 0x48, 0xda, 0x18, 0x59, 0x7f, 0x5e, 0x36, 0xa8, 0x08, 0x2f,
        0xbe, 0x55, 0x1e, 0xc7, 0x7c, 0x4f, 0xf3, 0x0e, 0xcb, 0xa3, 0xb1, 0x87, 0x0d, 0xc8, 0x7b,
        0xb7, 0x08, 0x57, 0x59, 0xab, 0x4e, 0xc7, 0xe5, 0x9a, 0xe4, 0xab, 0x14, 0x1d, 0xe9, 0xb4,
        0x10, 0x7a, 0x83, 0x43, 0x84, 0xa0, 0xc1, 0x7d, 0x53, 0x1d, 0xf4, 0x59, 0x7d, 0xac, 0xd5,
        0xd9, 0x49, 0xc6, 0x79, 0xae, 0x6e, 0xfe, 0x87, 0x5b, 0x15, 0x01, 0x1c, 0x4d, 0xab, 0x6f,
        0x22, 0x2b, 0x7d, 0x10, 0xff, 0xd9, 0xe4, 0xdb, 0x5a, 0xb7, 0x15, 0xe6, 0x54, 0x41, 0x45,
        0x91, 0xe6, 0x74, 0xb5, 0x42, 0x63, 0xaf, 0x7c, 0xc0, 0x83, 0xbc, 0x27, 0x3f, 0xac, 0x63,
        0xd7, 0x62, 0x3e, 0xd4, 0x81, 0xf3, 0x36, 0xe2, 0xe1, 0xa7, 0x40, 0xae, 0x79, 0x28, 0xbb,
        0x92, 0xbe, 0x1b, 0x19, 0x2b, 0x27, 0xbe, 0x16, 0x0e, 0x8b, 0x04, 0x7f, 0x2b, 0xcd, 0x14,
        0xb6, 0xd8, 0x56, 0xe6, 0x23, 0x00, 0x27, 0x2f,
    ];
    const TS_ODD_AFC1_IN: [u8; 188] = [
        0x47, 0x40, 0x51, 0xd3, 0xed, 0x24, 0x5b, 0x92, 0xc9, 0x00, 0x37, 0x6e, 0xa5, 0xdc, 0x13,
        0x4a, 0x81, 0xb8, 0xef, 0x26, 0x5d, 0x94, 0xcb, 0x02, 0x39, 0x70, 0xa7, 0xde, 0x15, 0x4c,
        0x83, 0xba, 0xf1, 0x28, 0x5f, 0x96, 0xcd, 0x04, 0x3b, 0x72, 0xa9, 0xe0, 0x17, 0x4e, 0x85,
        0xbc, 0xf3, 0x2a, 0x61, 0x98, 0xcf, 0x06, 0x3d, 0x74, 0xab, 0xe2, 0x19, 0x50, 0x87, 0xbe,
        0xf5, 0x2c, 0x63, 0x9a, 0xd1, 0x08, 0x3f, 0x76, 0xad, 0xe4, 0x1b, 0x52, 0x89, 0xc0, 0xf7,
        0x2e, 0x65, 0x9c, 0xd3, 0x0a, 0x41, 0x78, 0xaf, 0xe6, 0x1d, 0x54, 0x8b, 0xc2, 0xf9, 0x30,
        0x67, 0x9e, 0xd5, 0x0c, 0x43, 0x7a, 0xb1, 0xe8, 0x1f, 0x56, 0x8d, 0xc4, 0xfb, 0x32, 0x69,
        0xa0, 0xd7, 0x0e, 0x45, 0x7c, 0xb3, 0xea, 0x21, 0x58, 0x8f, 0xc6, 0xfd, 0x34, 0x6b, 0xa2,
        0xd9, 0x10, 0x47, 0x7e, 0xb5, 0xec, 0x23, 0x5a, 0x91, 0xc8, 0xff, 0x36, 0x6d, 0xa4, 0xdb,
        0x12, 0x49, 0x80, 0xb7, 0xee, 0x25, 0x5c, 0x93, 0xca, 0x01, 0x38, 0x6f, 0xa6, 0xdd, 0x14,
        0x4b, 0x82, 0xb9, 0xf0, 0x27, 0x5e, 0x95, 0xcc, 0x03, 0x3a, 0x71, 0xa8, 0xdf, 0x16, 0x4d,
        0x84, 0xbb, 0xf2, 0x29, 0x60, 0x97, 0xce, 0x05, 0x3c, 0x73, 0xaa, 0xe1, 0x18, 0x4f, 0x86,
        0xbd, 0xf4, 0x2b, 0x62, 0x99, 0xd0, 0x07, 0x3e,
    ];
    const TS_ODD_AFC1_OUT: [u8; 188] = [
        0x47, 0x40, 0x51, 0x13, 0x38, 0xab, 0x3a, 0x21, 0xcd, 0xd1, 0x58, 0xfb, 0x78, 0x1b, 0xb1,
        0xb9, 0xb1, 0x56, 0x19, 0x2a, 0x34, 0x07, 0x1d, 0x4f, 0x9c, 0xa3, 0x55, 0x14, 0x75, 0xdb,
        0x0e, 0x1a, 0x38, 0x42, 0xe3, 0x28, 0x6e, 0x8a, 0xa2, 0xef, 0x4b, 0x6e, 0x36, 0xb3, 0x7e,
        0x69, 0xcb, 0xa7, 0x77, 0xa0, 0x8e, 0xc2, 0xa3, 0xfd, 0x14, 0x3f, 0x9d, 0x5e, 0x39, 0xf6,
        0x78, 0xab, 0x43, 0xb2, 0xf6, 0xeb, 0x6f, 0x57, 0x10, 0xa6, 0x35, 0xa1, 0x9b, 0xf7, 0x97,
        0x81, 0x1d, 0x47, 0x75, 0x10, 0xd6, 0x36, 0x4a, 0x08, 0x85, 0xa9, 0x43, 0x43, 0x51, 0xf4,
        0xcc, 0x14, 0xb4, 0x97, 0xe6, 0x17, 0xf7, 0xf0, 0x24, 0x4f, 0x24, 0x3f, 0xe4, 0x8f, 0xe0,
        0x2b, 0x56, 0x79, 0x91, 0xd2, 0x6d, 0xfb, 0x5c, 0x7b, 0x07, 0x48, 0x64, 0x75, 0x48, 0xf0,
        0x55, 0x6a, 0xf5, 0xd5, 0xcf, 0xc7, 0x7b, 0x81, 0xe3, 0x41, 0x24, 0xa5, 0x1c, 0x9f, 0x6c,
        0xd5, 0xe0, 0xe1, 0x92, 0xb8, 0xbe, 0x85, 0x52, 0x56, 0x62, 0x95, 0xac, 0x85, 0x1b, 0xf3,
        0xe1, 0xaf, 0x57, 0xb1, 0x6e, 0x5b, 0x1f, 0x50, 0x0e, 0xe8, 0xc2, 0x5e, 0x0e, 0x9b, 0x3f,
        0x82, 0x3b, 0x08, 0x21, 0x1c, 0x63, 0x54, 0x54, 0xee, 0x3d, 0x82, 0xfc, 0xa1, 0x64, 0x23,
        0xf0, 0x6b, 0x35, 0x3d, 0xe3, 0x7b, 0x0d, 0x6c,
    ];
    const TS_EVEN_TAIL_IN: [u8; 188] = [
        0x47, 0x00, 0x51, 0xb9, 0x08, 0x24, 0x5b, 0x92, 0xc9, 0x00, 0x37, 0x6e, 0xa5, 0xdc, 0x13,
        0x4a, 0x81, 0xb8, 0xef, 0x26, 0x5d, 0x94, 0xcb, 0x02, 0x39, 0x70, 0xa7, 0xde, 0x15, 0x4c,
        0x83, 0xba, 0xf1, 0x28, 0x5f, 0x96, 0xcd, 0x04, 0x3b, 0x72, 0xa9, 0xe0, 0x17, 0x4e, 0x85,
        0xbc, 0xf3, 0x2a, 0x61, 0x98, 0xcf, 0x06, 0x3d, 0x74, 0xab, 0xe2, 0x19, 0x50, 0x87, 0xbe,
        0xf5, 0x2c, 0x63, 0x9a, 0xd1, 0x08, 0x3f, 0x76, 0xad, 0xe4, 0x1b, 0x52, 0x89, 0xc0, 0xf7,
        0x2e, 0x65, 0x9c, 0xd3, 0x0a, 0x41, 0x78, 0xaf, 0xe6, 0x1d, 0x54, 0x8b, 0xc2, 0xf9, 0x30,
        0x67, 0x9e, 0xd5, 0x0c, 0x43, 0x7a, 0xb1, 0xe8, 0x1f, 0x56, 0x8d, 0xc4, 0xfb, 0x32, 0x69,
        0xa0, 0xd7, 0x0e, 0x45, 0x7c, 0xb3, 0xea, 0x21, 0x58, 0x8f, 0xc6, 0xfd, 0x34, 0x6b, 0xa2,
        0xd9, 0x10, 0x47, 0x7e, 0xb5, 0xec, 0x23, 0x5a, 0x91, 0xc8, 0xff, 0x36, 0x6d, 0xa4, 0xdb,
        0x12, 0x49, 0x80, 0xb7, 0xee, 0x25, 0x5c, 0x93, 0xca, 0x01, 0x38, 0x6f, 0xa6, 0xdd, 0x14,
        0x4b, 0x82, 0xb9, 0xf0, 0x27, 0x5e, 0x95, 0xcc, 0x03, 0x3a, 0x71, 0xa8, 0xdf, 0x16, 0x4d,
        0x84, 0xbb, 0xf2, 0x29, 0x60, 0x97, 0xce, 0x05, 0x3c, 0x73, 0xaa, 0xe1, 0x18, 0x4f, 0x86,
        0xbd, 0xf4, 0x2b, 0x62, 0x99, 0xd0, 0x07, 0x3e,
    ];
    const TS_EVEN_TAIL_OUT: [u8; 188] = [
        0x47, 0x00, 0x51, 0x39, 0x08, 0x24, 0x5b, 0x92, 0xc9, 0x00, 0x37, 0x6e, 0xa5, 0x0e, 0xe4,
        0xae, 0x28, 0x72, 0xa5, 0x71, 0x80, 0xd4, 0x37, 0x04, 0xa3, 0x8f, 0x20, 0x1b, 0x68, 0xcf,
        0xbc, 0x4e, 0xaf, 0xb2, 0x12, 0xed, 0x91, 0x0f, 0x16, 0x17, 0xa2, 0x01, 0x49, 0xdb, 0xd6,
        0xcd, 0x2b, 0xb6, 0xb3, 0x63, 0x7c, 0xed, 0xc6, 0x91, 0x57, 0x39, 0x63, 0x99, 0xdc, 0x50,
        0x25, 0x8b, 0xf2, 0xc8, 0x3e, 0x13, 0xbb, 0x9e, 0xba, 0xf4, 0xd8, 0xa1, 0x6c, 0xc9, 0x95,
        0x97, 0xec, 0x9b, 0x6d, 0x2a, 0xf9, 0x50, 0x41, 0x2e, 0x9c, 0x96, 0xe6, 0x77, 0x68, 0xae,
        0x5a, 0xd0, 0x48, 0x9e, 0xef, 0xeb, 0xb2, 0x94, 0x54, 0x9e, 0x0c, 0x53, 0x7f, 0xbd, 0x1b,
        0xfe, 0x24, 0x47, 0x91, 0xf8, 0x71, 0x30, 0xfe, 0x0d, 0x82, 0x7f, 0x0d, 0xcd, 0x20, 0x57,
        0x45, 0xef, 0xb9, 0x34, 0xa3, 0xd4, 0x8b, 0xbb, 0x8b, 0x73, 0xfb, 0x45, 0x52, 0xd7, 0xa8,
        0xfd, 0x80, 0x0f, 0x9e, 0x35, 0xce, 0x60, 0x62, 0x61, 0xf6, 0x8c, 0x71, 0x34, 0xc0, 0x43,
        0x31, 0xfa, 0xf6, 0x29, 0x8b, 0x71, 0xdd, 0xc2, 0x3b, 0xd4, 0x17, 0x8b, 0x04, 0xd2, 0xa9,
        0x57, 0x22, 0x70, 0x5a, 0x16, 0x07, 0xaf, 0xbc, 0x3d, 0xa0, 0x2f, 0xd2, 0x35, 0x4d, 0x22,
        0x13, 0x7d, 0x45, 0xac, 0x71, 0xc4, 0x5e, 0x8d,
    ];
    const TS_RSV_TSC1_IN: [u8; 188] = [
        0x47, 0x00, 0x51, 0x5e, 0xed, 0x24, 0x5b, 0x92, 0xc9, 0x00, 0x37, 0x6e, 0xa5, 0xdc, 0x13,
        0x4a, 0x81, 0xb8, 0xef, 0x26, 0x5d, 0x94, 0xcb, 0x02, 0x39, 0x70, 0xa7, 0xde, 0x15, 0x4c,
        0x83, 0xba, 0xf1, 0x28, 0x5f, 0x96, 0xcd, 0x04, 0x3b, 0x72, 0xa9, 0xe0, 0x17, 0x4e, 0x85,
        0xbc, 0xf3, 0x2a, 0x61, 0x98, 0xcf, 0x06, 0x3d, 0x74, 0xab, 0xe2, 0x19, 0x50, 0x87, 0xbe,
        0xf5, 0x2c, 0x63, 0x9a, 0xd1, 0x08, 0x3f, 0x76, 0xad, 0xe4, 0x1b, 0x52, 0x89, 0xc0, 0xf7,
        0x2e, 0x65, 0x9c, 0xd3, 0x0a, 0x41, 0x78, 0xaf, 0xe6, 0x1d, 0x54, 0x8b, 0xc2, 0xf9, 0x30,
        0x67, 0x9e, 0xd5, 0x0c, 0x43, 0x7a, 0xb1, 0xe8, 0x1f, 0x56, 0x8d, 0xc4, 0xfb, 0x32, 0x69,
        0xa0, 0xd7, 0x0e, 0x45, 0x7c, 0xb3, 0xea, 0x21, 0x58, 0x8f, 0xc6, 0xfd, 0x34, 0x6b, 0xa2,
        0xd9, 0x10, 0x47, 0x7e, 0xb5, 0xec, 0x23, 0x5a, 0x91, 0xc8, 0xff, 0x36, 0x6d, 0xa4, 0xdb,
        0x12, 0x49, 0x80, 0xb7, 0xee, 0x25, 0x5c, 0x93, 0xca, 0x01, 0x38, 0x6f, 0xa6, 0xdd, 0x14,
        0x4b, 0x82, 0xb9, 0xf0, 0x27, 0x5e, 0x95, 0xcc, 0x03, 0x3a, 0x71, 0xa8, 0xdf, 0x16, 0x4d,
        0x84, 0xbb, 0xf2, 0x29, 0x60, 0x97, 0xce, 0x05, 0x3c, 0x73, 0xaa, 0xe1, 0x18, 0x4f, 0x86,
        0xbd, 0xf4, 0x2b, 0x62, 0x99, 0xd0, 0x07, 0x3e,
    ];
    const TS_RSV_TSC1_OUT: [u8; 188] = [
        0x47, 0x00, 0x51, 0x1e, 0x38, 0xab, 0x3a, 0x21, 0xcd, 0xd1, 0x58, 0xfb, 0x78, 0x1b, 0xb1,
        0xb9, 0xb1, 0x56, 0x19, 0x2a, 0x34, 0x07, 0x1d, 0x4f, 0x9c, 0xa3, 0x55, 0x14, 0x75, 0xdb,
        0x0e, 0x1a, 0x38, 0x42, 0xe3, 0x28, 0x6e, 0x8a, 0xa2, 0xef, 0x4b, 0x6e, 0x36, 0xb3, 0x7e,
        0x69, 0xcb, 0xa7, 0x77, 0xa0, 0x8e, 0xc2, 0xa3, 0xfd, 0x14, 0x3f, 0x9d, 0x5e, 0x39, 0xf6,
        0x78, 0xab, 0x43, 0xb2, 0xf6, 0xeb, 0x6f, 0x57, 0x10, 0xa6, 0x35, 0xa1, 0x9b, 0xf7, 0x97,
        0x81, 0x1d, 0x47, 0x75, 0x10, 0xd6, 0x36, 0x4a, 0x08, 0x85, 0xa9, 0x43, 0x43, 0x51, 0xf4,
        0xcc, 0x14, 0xb4, 0x97, 0xe6, 0x17, 0xf7, 0xf0, 0x24, 0x4f, 0x24, 0x3f, 0xe4, 0x8f, 0xe0,
        0x2b, 0x56, 0x79, 0x91, 0xd2, 0x6d, 0xfb, 0x5c, 0x7b, 0x07, 0x48, 0x64, 0x75, 0x48, 0xf0,
        0x55, 0x6a, 0xf5, 0xd5, 0xcf, 0xc7, 0x7b, 0x81, 0xe3, 0x41, 0x24, 0xa5, 0x1c, 0x9f, 0x6c,
        0xd5, 0xe0, 0xe1, 0x92, 0xb8, 0xbe, 0x85, 0x52, 0x56, 0x62, 0x95, 0xac, 0x85, 0x1b, 0xf3,
        0xe1, 0xaf, 0x57, 0xb1, 0x6e, 0x5b, 0x1f, 0x50, 0x0e, 0xe8, 0xc2, 0x5e, 0x0e, 0x9b, 0x3f,
        0x82, 0x3b, 0x08, 0x21, 0x1c, 0x63, 0x54, 0x54, 0xee, 0x3d, 0x82, 0xfc, 0xa1, 0x64, 0x23,
        0xf0, 0x6b, 0x35, 0x3d, 0xe3, 0x7b, 0x0d, 0x6c,
    ];

    #[test]
    fn ts_even_afc3_kat() {
        // tsc=2 (even), adaptation field len 7 → payload at 12, n=176.
        let m2 = cipher_setup_b();
        let mut pkt = TS_EVEN_AFC3_IN;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Decrypted);
        assert_eq!(pkt, TS_EVEN_AFC3_OUT);
    }

    #[test]
    fn ts_odd_afc1_kat() {
        // tsc=3 (odd), no adaptation field → payload at 4, n=184.
        let m2 = cipher_setup_b();
        let mut pkt = TS_ODD_AFC1_IN;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Decrypted);
        assert_eq!(pkt, TS_ODD_AFC1_OUT);
    }

    #[test]
    fn ts_even_partial_tail_kat() {
        // tsc=2, adaptation field len 8 → payload at 13, n=175 (not a
        // multiple of 8: exercises the CBC partial-tail keystream).
        let m2 = cipher_setup_b();
        let mut pkt = TS_EVEN_TAIL_IN;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Decrypted);
        assert_eq!(pkt, TS_EVEN_TAIL_OUT);
    }

    #[test]
    fn ts_reserved_tsc1_decrypts_with_odd_key() {
        // tsc=1 (reserved 0x40): libaribb25 does NOT pass it through — the
        // `type == 0x02` check falls through to the odd work key. Expected
        // payload bytes are identical to the odd-key packet's.
        let m2 = cipher_setup_b();
        let mut pkt = TS_RSV_TSC1_IN;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Decrypted);
        assert_eq!(pkt, TS_RSV_TSC1_OUT);
        assert_eq!(pkt[4..], TS_ODD_AFC1_OUT[4..]);
    }

    #[test]
    fn ts_unscrambled_passthrough() {
        let m2 = cipher_setup_b();
        let mut pkt = TS_ODD_AFC1_IN;
        pkt[3] = 0x13; // tsc=0, afc=1, cc=3
        let orig = pkt;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Unscrambled);
        assert_eq!(pkt, orig);
    }

    #[test]
    fn ts_no_payload_clears_tsc_only() {
        let m2 = cipher_setup_b();
        let mut pkt = TS_EVEN_AFC3_IN;
        pkt[3] = 0xa7; // tsc=2, afc=2 (adaptation only), cc=7
        pkt[4] = 100; // adaptation field ends at 105; no payload follows
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::NoPayload);
        let mut expect = TS_EVEN_AFC3_IN;
        expect[3] = 0x27; // only the TSC bits cleared
        expect[4] = 100;
        assert_eq!(pkt, expect);
    }

    #[test]
    fn ts_adaptation_only_full_packet() {
        // afc=2 with adaptation_field_length=183 → n=0: NOT broken (the C
        // condition requires n<0 or payload-present), TSC bits cleared.
        let m2 = cipher_setup_b();
        let mut pkt = TS_EVEN_AFC3_IN;
        pkt[3] = 0xe3; // tsc=3, afc=2, cc=3
        pkt[4] = 183;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::NoPayload);
        assert_eq!(pkt[3] & 0xc0, 0);
    }

    #[test]
    fn ts_broken_adaptation_geometry() {
        let m2 = cipher_setup_b();
        // adaptation_field_length=200 with afc=3 → n = 188-205 < 0 → broken,
        // packet left byte-for-byte intact (C drops it from the stream).
        let mut pkt = TS_EVEN_AFC3_IN;
        pkt[4] = 200;
        let orig = pkt;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Broken);
        assert_eq!(pkt, orig);

        // Broken check happens before the TSC check: even tsc=0 is Broken.
        let mut pkt = TS_EVEN_AFC3_IN;
        pkt[3] = 0x37; // tsc=0, afc=3
        pkt[4] = 200;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::Broken);
    }

    #[test]
    fn ts_tei_passthrough() {
        let m2 = cipher_setup_b();
        let mut pkt = TS_ODD_AFC1_IN;
        pkt[1] |= 0x80; // transport_error_indicator
        let orig = pkt;
        let action = m2.descramble_ts_packet(&mut pkt).unwrap();
        assert_eq!(action, TsAction::TransportError);
        assert_eq!(pkt, orig);
    }
}
