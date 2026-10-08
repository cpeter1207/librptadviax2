# librptadviax2 requirements

## Approved requirements

- **IA-001:** “I want the network I/O to be separated from the protocol implementation.”
- **IA-002:** “I want the protocol implementation to be separate from the codecs.”
- **IA-003:** “To satisfy the stand-alone controller requirements as well as future requirements, we should create our own IAX2 implementation that can construct and serialize outgoing packets and deserialize incoming packets.”
- **IA-004:** “Codec support should be added through plugable codec adapters that depend on released codec libraries when ever possible.”
- **IA-005:** “We should avoid implementing our own codecs unless there is no release implementation available.”
- **IA-006:** “Initial codec support should target ASL3 compatibility.”
- **IA-007:** The implementation guide must require reviewing Asterisk and ASL3 source for behavior not established in the ASL3 manual; target complete behavioral interoperability with ASL3 for the agreed in-scope linking behavior.

## First protocol slice

- **IA-008:** The protocol layer parses an IAX2 full-frame fixed header from bytes, exposes its wire fields without owning network I/O, and returns a typed error for truncated or non-full frames. Its expected byte order and full-frame flag are derived from RFC 5456 and Asterisk's IAX2 header definitions.
- **IA-009:** Full-frame subclass values follow Asterisk's canonical encoding: values below `0x80` remain plain, larger single-bit values use the exponent form, and `0xff` decodes as `-1`.
- **IA-010:** IAX2 text frames validate frame type 7, subclass 0, and UTF-8 payloads while preserving the text for application-level signaling.
- **IA-011:** A call-token retry replaces the final empty CALLTOKEN IE in the original IAX control payload with the opaque token returned by the peer, preserving earlier IE bytes and rejecting malformed payloads, a missing/incorrect final empty token IE, and token values that exceed the IE length field.
- **IA-012:** MD5 authentication parses AUTHREQ methods and challenge IEs, builds an AUTHREP full frame containing lowercase hexadecimal MD5 of the exact challenge bytes followed immediately by the configured secret, and verifies responses against semicolon-separated secret alternatives with case-insensitive hexadecimal comparison, matching Asterisk's IAX2 authentication behavior.
- **IA-013:** Initial outbound NEW frames use zero destination/sequence state, encode the NEW command canonically, and end with one empty CALLTOKEN IE for Asterisk-compatible token negotiation.
- **IA-014:** A single-owner outbound session advances NEW through optional CALLTOKEN retry, optional MD5 AUTHREQ/AUTHREP, and ACCEPT or REJECT. It validates call identities, reliable sequence numbers, and the selected format against the peer-advertised CAPABILITY (falling back to FORMAT when CAPABILITY is absent); it acknowledges ACCEPT/REJECT and repeats cached replies for retransmitted reliable setup frames. Clock, retransmission timers, socket I/O, and media remain outside this handshake slice.
- **IA-015:** An established outbound session may issue one PING at a time. It replies to peer PING with a timestamp-echoing PONG; ACKs every valid PONG, reports whether its timestamp matched the outstanding probe, and clears only a matching probe; accepts peer ACKs without changing sequence state; and resends the same PONG for an identical reliable PING retransmission. The caller owns probe scheduling and network I/O.
- **IA-016:** The first media codec adapter is G.711 μ-law, backed by a released codec library. It advertises the RFC 5456 format bit `0x00000004` at 8 kHz, converts normalized mono `f32` PCM to and from μ-law without allocating, and remains separate from IAX packet parsing and UDP datagram I/O.
- **IA-017:** The outbound UDP client retransmits its outstanding reliable setup frame when its response is lost. Retransmissions retain the source call, sequence, timestamp, and payload, set the destination retransmission flag, and refresh the incoming sequence from the setup state. The default schedule matches Asterisk's four-transmission policy: 100 ms initial delay, tenfold interval growth capped at 10 seconds; an earlier caller timeout still bounds setup.
