# librptadviax2

An independent Rust IAX2 implementation for rpt_advanced. It will keep packet
construction/parsing separate from network I/O and codec adapters. Codec
implementations belong in adapters that use released libraries where available;
this project does not implement audio codecs.

The standalone product loads this library for outbound and inbound ULAW links.
The inbound listener applies Asterisk-compatible call tokens and product
authorization, then routes accepted calls to bounded peer queues. This is the
initial AllStarLink interoperability slice; it does not claim complete ASL3
interoperability. Source
revisions, compatibility evidence, and the required Asterisk/ASL3 source-review
policy are recorded in the
[rpt_advanced IAX2 compatibility matrix](https://github.com/cpeter1207/rpt_advanced/blob/main/doc/architecture/standalone-iax2-compatibility.md).

## Local checks

```sh
cargo fmt --check
cargo test --all-targets --locked
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
make coverage
```

The client ABI is versioned and released as a shared object. Complete ASL3
call/session behavior and live peer interoperability remain to be verified.
