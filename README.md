# librptadviax2

An independent Rust IAX2 implementation for rpt_advanced. It keeps packet
construction/parsing separate from network I/O and codec adapters. Codec
implementations belong in adapters that use released libraries where available;
this project does not implement audio codecs.

The standalone product loads this library for outbound and inbound audio links.
The optional `dial_account` client-descriptor tail also supports ordinary outgoing
provider calls with a separate account username, caller identity, destination and
context. Check `struct_size` through that field before access. These calls reuse
the same codec/media, async owner and teardown operations; the existing numeric
AllStarLink dial path is unchanged. Destinations retain short numbers and telephone
symbols without a second cost/emergency-number policy.

## Configured provider accounts

The optional server ABI2 tail adds `configure_accounts`, `register_account`,
`poll_accounts`, and `dial_provider_account`. Check `struct_size` through each
required slot: the released 56-byte table prefix is unchanged; the complete table
was 88 bytes in alpha11. Bind options retain their 48-byte prefix and have a 64-byte complete
record. Account arrays use the exact ABI1 record stride declared in the header.

Configure an opaque account label, nonzero configuration generation, resolved
provider endpoint, username, literal secret, and local admission binding.
A binding may contain a nondecimal configured local name, up to 63 UTF-8 bytes.
Changed settings require a new generation. Validated replacements retire changed
owners atomically; unchanged accounts retain their existing lifetime. Provider
caller/display/context fields are untrusted data and never become an ASL node or
mailbox authorization. The consumer applies mailbox/PIN and command policy.

After `server_enable`, registration, refresh, authenticated REGREL, incoming
MD5 authentication, and `dial_provider_account` share the listener's source port
and existing router. The consumer refreshes using the actual granted interval;
absent REFRESH means 60 seconds. The registration primitive performs one bounded
transaction and does not schedule refresh. Provider transport uses UDP and MD5
challenge authentication; it provides no media/signaling encryption.

`poll_accounts` applies configured endpoint/account matching and CALLTOKEN before
MD5 authentication, then invokes the separate provider policy/ownership callbacks.
Metadata is borrowed only during the callback. Accept returning zero transfers
one peer; a nonzero result retains library ownership and sends best-effort HANGUP
before release. Rust `prepare_*`/`Prepared*::run`/`finish_poll` split permits network
waits and foreign callbacks outside the short listener/control lock. Execute
blocking work off the shared executor. Retirements fence late route installs,
returns, and media. A timeout requests no teardown acknowledgment: retained call
and operation owners still retain their actual socket resources. Destroy the
server only after in-flight entries/callbacks are quiescent; close/drop every peer
before unloading its DSO. Route capacity returns only after actual receiver cleanup.

One listener admits at most 64 configured accounts and 64 provider reservations,
including calls, registration operations, and pending authentication. Existing
NEW, route-command, and per-peer ingress queues remain bounded at 64 items.
Configured phone providers offer only verified PCMU/PCMA at 8 kHz with 20 ms packets
(160 encoded bytes/samples). Unsupported offers or packet shapes fail closed.
Their composed neutral jitter profile is 20/40/100 ms; generic/numeric IAX and the
independent client `dial_account` retain their existing codec and jitter policy.
Retain the borrowed neutral jitter descriptor's DSO until the peer is destroyed.

This callable account/media layer still requires product configuration and host
composition. Mailbox/PIN, radio attachment, and live-provider acceptance remain
separate consumer work.

## Prepared listener configuration

The optional 112-byte server tail adds `prepare_configuration_batch`,
`commit_configuration_batch`, and `destroy_configuration_batch`; the released
88-byte account prefix stays unchanged. Require the complete tail and all three
slots before using a transaction. Sequential per-listener replacement is not a
safe fallback: it may retire calls before another listener fails preparation.

Prepare copies complete numeric binding and provider account replacements for
all distinct retained listeners, validates and allocates every replacement, then
reserves the whole cohort. Conflicting configuration changes return busy while
normal poll, registration, dial, and media continue against the old configuration.
A failed or destroyed preparation leaves old account and numeric lifetimes intact.
An empty numeric/account replacement disables admission and retires those owners
at commit, permitting socket cleanup afterward.

A valid reserved token commits once with no allocation, callbacks, network waits,
or recoverable late failure. All listener locks are acquired in address order and
held until the complete cohort is published. Unchanged owners keep their exact
lifetimes. Commit or destroy consumes the token; retain all listeners and their
DSO until then. Null consumption is harmless; a reused or invalid nonnull token
violates the caller contract. No Rust mutex guard crosses a C return.

This is a listener transaction, not a claim about an external product's commit
point. The consumer must finish its other fallible preparation and know whether
product publication occurred before consuming the listener token as a commit.

## Original receive time

The optional client ABI 2 `poll_timed` slot preserves the released 136-byte prefix;
check through its 144-byte table prefix before accessing it. Its caller-sized ABI 1 record is
72 bytes on supported native 64-bit Linux. The ordinary `poll` remains untimed. Use one
poll mode per exclusive peer owner; legacy polling rejects after timed activation.

Capture a stable Host clock epoch and `reference_now_ns` **before** provider entry.
Only `TIMED_BIRTH` grants original-time qualification. At first exposure, the
provider subtracts genuine kernel RX age plus a conservative 5 ms uncertainty from
that fixed reference. It caches the result for the whole original span, including
every PCM partial/retry/suffix. Underflow, missing/future/unrepresentable receipt,
legacy caller-supplied ingress time, concealment and gaps never supply a fresh birth.
`source_start` is the checked per-epoch playout PCM cursor, including gaps and delay
insertion; it is not claimed to be an IAX wire clock or DTMF interval. IAX digits
remain private untimed events.

Owned UDP sockets request `SO_TIMESTAMPING` software RX stamps, without the
`SO_TIMESTAMP[NS]` options that can synthesize a missing stamp during dequeue.
Linux timestamp activation may be deferred; packets without an actual RX record
remain unqualified. One nonblocking CLOEXEC `timerfd` monitors realtime steps with
`CANCEL_ON_SET`, plus a fixed realtime/monotonic anchor. Its checked absolute 2262
deadline fits signed 64-bit native ktime and is never rearmed. Initial unavailable
qualification leaves private control/media usable. Later clock qualification loss
is sticky and revokes retained epochs; protocol teardown continues without rebase.

Retained source media older than 500 ms retires actual packet jitter, decoded PCM
and codec history. `TIMED_DISCONTINUITY` names the new **target** epoch. No fresh
Audio/Gap is exposed until the consumer acknowledges that exact target **after**
its prior ring, DSP and RF owners actually retire; stale acknowledgments cannot
release a newer target. Private control can continue while retirement is pending.
A native reset failure stays closed until peer teardown. This timing capability
does not itself authorize mailbox access or RF.

## Timed prepared transmission

The optional client slots `send_prepared_audio_timed` and `retire_egress` extend
the table to 160 bytes, preserving both released 136 and timed RX 144-byte prefixes.
Only these explicitly negotiated phone operations implement the transmit age
contract; ordinary numeric and independent generic prepared-send behavior remains.
The first profile is PCMU/PCMA at 8 kHz and 20 ms, exactly 160 encoded bytes/source frames.

Retire egress before its first timed send and each source discontinuity. A completed
serial local retirement returns a checked TX epoch token, independent of RX epochs.
It resets the actual encoder and cancels old local PCM eligibility. The consumer
also abandons its old staged items; their old tokens cannot send after retirement.
A failed reset stays closed until teardown. A previously committed legacy PCM full
frame remains `Pending` until real ACK or teardown: it keeps its reliable OSeq hole
while PCM retries are suppressed. Text/key/control reliability remains intact.
Successful prior UDP sends cannot be recalled; completion claims no remote ACK.

For a prepared packet, sample `elapsed_ms` **first**, then the Host reference and
the oldest contributing original PCM age. Add the remaining 500 ms age budget to
that earlier native floor, rounding down and checking overflow. Unknown/future
source age or a saturated native clock cannot qualify a packet. Keep this absolute
deadline and TX token unchanged through partial encoding, retained buffers and
`WouldBlock`. The provider rechecks the actual native deadline inside the short
account lifetime guard immediately before nonblocking UDP commit. `Expired` is
distinct from `WouldBlock`, and neither commits PCM.

Timed PCM travels only in Mini frames. Reliable full Voice frames announce codec
and timestamp with **zero PCM**, including first use, Mini wrap and timestamp
discontinuity/long silence. Lost initial markers can lose media until their reliable
retry; expired PCM is never retransmitted. Marker/control sequence ownership remains
intact. Retirements cannot claim a clean protocol shutdown merely because local
media is canceled. The independent Asterisk fixture checks both G.711 modes,
incoming/outgoing setup and actual Mini wrap; live-provider/NAT/RF acceptance remains
separate work.

The kernel contracts are documented in [Linux timestamping](https://docs.kernel.org/networking/timestamping.html)
and [timerfd](https://man7.org/linux/man-pages/man2/timerfd_create.2.html). The fixed
ancillary layout follows Linux v6.18 `__sock_recv_timestamp`: this exclusively owned
Internet UDP socket subscribes to no other ancillary records and never reads the
error queue. Missing/short records and `MSG_CTRUNC` never qualify; `MSG_TRUNC` drops
the partial datagram. IPv6 scope/flow and mapped IPv4 endpoints retain the actual
owned socket family. Tests use owned child-only syscall faults, never host clock changes.

Codec providers supply ULAW, ALAW, GSM, G.723.1, G.726 AAL2, Dialogic ADPCM,
SLIN, LPC10, G.729, Speex, iLBC, G.726, G.722, SLIN16, Speex16, and Opus.
ULAW remains the first preference. IAX iLBC uses 30 ms; 20 ms interoperability is
pending. G.723.1 sends 6.3 kb/s and accepts 5.3/6.3 kb/s. Siren7, Siren14 and G.719
are not offered.
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
Without new ingress, turns fall back to the negotiated codec's concealment
quantum. A nonempty mailbox that makes no progress waits for
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

The library uses SONAME `librptadviax2.so.2` and client/server ABI 2.
The optional async descriptor remains ABI 1. Codec providers use neutral ABI 1.
Debian 13 release assets provide `librptadv-iax2-client2` and
`librptadv-iax2-client-dev` for amd64 and arm64. Consumers select an explicit
release tag and use the versioned dynamic library. Packages are also available
from the [shared signed APT repository](https://cpeter1207.github.io/USBRadioPlus/).

Generic/numeric packet-jitter buffering starts at 180 ms, with a 160 ms minimum
and a 500 ms maximum. Valid voice resumes playout after a radio-unkey event even when the
peer does not send another radio-key event.

Validated empty voice packets do not enter audio playout. Unexpected peer
termination writes one error with the local/remote call identifiers and protocol
sequence state. Explicit local hangup and peer destruction do not log that error.
Packet contents and authentication material are not included.

Late full packets are acknowledged without repeating their events or applying
their obsolete acknowledgement credit to newer sends. A sequence
gap requests the missing frames with VNAK while the call stays connected.
Incoming VNAK requests replay retained, sent frames without changing their
normal retry limit or deadline. Call identity and acknowledgement checks still
apply. This recovery does not change packet-jitter or PCM buffering settings.

The optional async table composes a host-supplied packet-jitter descriptor; the
host retains that descriptor's dynamic library until peer destruction. Peers
configured this way may emit event `RPTADV_IAX2_EVENT_GAP` (7), whose length is an
ordered count of missing negotiated-rate source samples, not a PCM-buffer length. Forward
that count to the shared PCM ring's counted-gap operation before later PCM.
The codec first supplies its own supported concealment. Only the remaining gap
is sent to the shared ring for fallback concealment. Codec-recovered samples
are not concealed again. Unconfigured synchronous peers do not emit this event.

## Local checks

```sh
cargo fmt --check
cargo test --all-targets --locked
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
make coverage
make provider-interop-check
```

The explicit platform gate `provider-interop-check` uses the quality image's
Asterisk as a loopback-only independent provider. The C smoke consumer uses the
installed header and candidate DSO for call-token/MD5 setup, G.711 echo media,
registration, refresh, release, incoming and outgoing provider calls, hangup,
wrong-secret rejection and endpoint cleanup. Asterisk is a test tool;
the runtime library and ordinary Debian package build do not depend on a PBX.
Live-provider, NAT and radio acceptance remain unverified.

The client ABI is versioned and released as a shared object. Complete ASL3
call/session behavior and live peer interoperability remain to be verified.
