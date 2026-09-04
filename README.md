# tuner-codec

`tuner-codec` is a Rust implementation of broadcast standards used by
Japanese terrestrial (ISDB-T) digital television: MPEG-TS/PES framing, the
Japanese terrestrial channel plan, and ARIB STD-B25 MULTI2 descrambling.

`multi2.rs` is a Rust port of [libaribb25](https://github.com/tsukumijima/libaribb25)'s
`multi2.c` and the TS-packet descramble procedure of its `arib_std_b25.c`,
originally authored by MOGI Kazuhiro / MARUMO Manufacturing (2007-2012) and
stz2012 (2012), and licensed under the Apache License, Version 2.0. See
[NOTICE](NOTICE) for the full upstream attribution, [LICENSE](LICENSE) for
the license text, and [CREDITS.md](CREDITS.md) for the standards it
implements. `multi2.rs` itself carries the required section 4(b) change
notice at the top of the file.

USB endpoints, vendor commands, device identities, filesystem search policy,
HTTP, and any particular receiver's product state do not belong here — this
crate does not know about any of them.

## Crate layout

```text
crates/tuner-codec/
├── Cargo.toml
├── LICENSE                   # Apache License, Version 2.0
├── NOTICE                    # Required third-party attribution (libaribb25)
├── README.md
├── CREDITS.md                # Upstream projects and standards cited
└── src/
    ├── lib.rs                # Public modules and re-exports
    ├── channel.rs            # Japanese terrestrial channel plan
    ├── ts.rs                 # 188-byte MPEG-TS packet parsing and resynchronization
    ├── pes.rs                # Packetized elementary-stream assembly
    ├── descramble.rs         # Shared packet descrambling coordination
    └── multi2.rs             # ARIB STD-B25 MULTI2 implementation
```

Tests live inline as `#[cfg(test)]` modules beside the code they cover; the
crate ships no `tests/` directory and no binary fixtures.

## Module boundaries

- `channel` validates current Japanese terrestrial allocations and performs
  physical-channel/frequency calculations.
- `ts` accepts arbitrarily chunked input, restores packet alignment, and
  exposes MPEG-TS headers and payloads.
- `pes` reassembles elementary-stream packets across TS boundaries and
  handles bounded and unbounded PES lengths.
- `multi2` implements the ARIB STD-B25 MULTI2 cipher and TS-packet descramble
  procedure without locating keys or talking to conditional-access hardware —
  it operates purely on a system key, CBC init vector, and scramble key
  supplied by the caller.
- `descramble` coordinates per-packet descramble decisions and disposition
  counting shared by callers of `multi2`.

This crate does not read key material from disk, a smart card, or any other
source. Key sourcing — where the system key, CBC init, and scramble key come
from — is a deployment concern of the application that constructs a
`Multi2`, not of this crate.

## Build and test

```sh
cargo check -p tuner-codec
cargo test -p tuner-codec
cargo doc -p tuner-codec --no-deps
```

Tests cover standard/reference vectors, malformed-input behavior,
transport-stream resynchronization, and PES assembly, all against
programmatically generated fixtures — the crate ships no binary broadcast
captures.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
`multi2.rs` carries an additional change notice at the top of the file, as
required by License section 4(b).
