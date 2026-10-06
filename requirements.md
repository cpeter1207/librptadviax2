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
