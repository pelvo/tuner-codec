# Credits

`tuner-codec` builds on the work of the following projects and standards.

## libaribb25

`src/multi2.rs` is a Rust port of `multi2.c` and the TS-packet descramble
procedure of `arib_std_b25.c` from libaribb25, licensed under the Apache
License, Version 2.0.

- Copyright (c) 2012 stz2012 <tslroom@hotmail.com>
- Copyright (c) 2007-2012 MOGI, Kazuhiro <kazhiro@marumo.ne.jp>, MARUMO
  Manufacturing (https://www.marumo.ne.jp/)

See [NOTICE](NOTICE) for the full upstream attribution text.

## Standards

- **ARIB STD-B25**: Conditional Access System (CAS) specification for
  digital broadcasting, published by the Association of Radio Industries and
  Businesses (ARIB). Defines the MULTI2 cipher and TS-packet descramble
  procedure implemented in `multi2.rs`.
- **ISO/IEC 13818-1** (MPEG-2 Systems): defines the MPEG transport stream
  and packetized elementary stream (PES) formats implemented in `ts.rs` and
  `pes.rs`.
