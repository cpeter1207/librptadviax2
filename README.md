# librptadviax2

An independent Rust IAX2 implementation for rpt_advanced. It keeps packet
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

## Optional readiness executor

The separate `rptadv_iax2_async_descriptor_v1` capability leaves the synchronous
client/server descriptors unchanged. Check its ABI, capability, and readable
`struct_size` before using its function slots. One shared runtime can serve all
peers and listeners; no operation here belongs in an audio callback.

Configure a peer's borrowed jitter descriptor before attaching it. A successful
`peer_attach` is one-shot: only its bounded, serialized callback may access the
peer until `peer_detach` returns. The callback may request `peer_stop`, including
while the control owner is waiting in detach. Stop alone does not release peer
or callback-context ownership. Detach runs off the Tokio executor, joins the
last callback and receive task, and makes context release safe. Afterwards the
peer may only be observed for diagnostics or destroyed. Retain this DSO through
detach and retain any borrowed jitter capability/DSO through peer destruction.
Without new ingress, turns fall back to the jitter concealment quantum (80 ULAW
samples at 8 kHz, or 10 ms). A nonempty mailbox that makes no progress waits for
readiness or that timer, avoiding a busy loop while the downstream ring is full.

`server_enable(runtime, server)` transfers a listener's receive socket/router to
Tokio; repeated enable is a no-op success. Its existing `poll` call stays on a
serialized, off-executor control owner and processes a separate 64-packet NEW
admission queue. Established packets go directly to bounded peer queues even
during slow authorization. A separate 64-command route queue acknowledges route
installation before ACCEPT is sent. Receipt timestamps are preserved through
routing; full queues drop new arrivals without blocking unrelated peers.
Raw HANGUP packets never retire routes: the peer validates them, and its released
generation is reaped after destruction, so dropped/invalid HANGUPs cannot strand
the live peer or suppress a retry.
Destroy an enabled server off-executor to stop and join its receiver. Receiver
termination marks established queues failed and wakes their owners. Registrations
and enabled listeners retain their own runtime references, so releasing the
caller's runtime handle does not invalidate them.

`peer_observe` copies jitter and real mailbox counters on the exclusive peer
owner (or after detach); control threads must consume the host's copied snapshot,
not read live jitter state concurrently. Rust listener `ingress_stats()` provides
NEW-queue occupancy/full drops and active-route count without a routing lock.

## Release integration

Alpha5 retains SONAME `librptadviax2.so.1` and the existing synchronous ABI 1.
Debian 13 release assets provide `librptadv-iax2-client1` and
`librptadv-iax2-client-dev` for amd64 and arm64. Consumers select an explicit
release tag and use the versioned dynamic library; IAX packages are not currently
included in the shared signed package index.

The optional async table composes a host-supplied packet-jitter descriptor; the
host retains that descriptor's dynamic library until peer destruction. Peers
configured this way may emit event `RPTADV_IAX2_EVENT_GAP` (7), whose length is an
ordered count of missing 8 kHz source samples, not a PCM-buffer length. Forward
that count to the shared PCM ring's counted-gap operation before later PCM.
Only the ring performs concealment; this library does not fill gaps with zeros
or run a second PLC. Unconfigured synchronous peers do not emit this event.

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
