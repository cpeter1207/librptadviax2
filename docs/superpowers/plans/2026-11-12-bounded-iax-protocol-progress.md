# Bounded IAX Protocol Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans after explicit plan approval. Steps use checkbox syntax for tracking.

**Goal:** Keep the sole IAX owner servicing real protocol obligations while its downstream source refuses a digit, PCM suffix, or discontinuity.

**Architecture:** Separate protocol admission from ordered source release in the existing peer. Reuse the existing poll_timed callback with an explicit versioned request, and reuse the existing bounded provider source queue. Do not add a host read-ahead buffer, scheduler, protocol owner, or unbounded storage.

**Tech Stack:** Rust, the existing C-compatible sized records, Tokio peer ownership, real loopback UDP, released codec and jitter DSOs.

**Spec:** Parent prerequisite assignment; rpt_advanced ADR 0037 (single serialized owner), ADR 0044 (ordered phone source and original age), and existing IAX alpha12 source 4e7026c5234a7c7fb61907bbe56fbaef3a18963b. Related controller boundary: /home/codex/rpt-development/phone-iax-accounts/rust/standalone/src/host_services/iax_phone_tests.rs.

## Status and limits

The parent approved local implementation after independent review. Publication, release, deployment and controller activation remain unauthorized. The explicitly granted test-only container run completed: formatting and compilation passed, invalid-request state preservation passed, and the owner regression reached the intended alpha12 ABI 2 rejection. Later ACK/order assertions have not executed yet.

No publication, release, deployment, live provider call, RF, or credential use. Protect the shared 2 CPU / 4 GB production server. Run only after an explicit test-slot grant, through the maintained constrained launcher: one container, 1 CPU, 1536 MiB, no swap, 256 PIDs, one build/test worker. The launcher must freshly pull the approved maintained image and record its digest.

## Proposed request contract

Retain client descriptor ABI 2, its existing poll_timed function pointer and all existing offsets, and SONAME 2. Define a sized timed request ABI 2, 80 bytes on supported native 64-bit platforms:

- Bytes 0..72: unchanged timed-event prefix and output interpretation.
- Bytes 72..76: input request_flags, 0 for ordinary delivery, 1 for SERVICE_ONLY.
- Bytes 76..80: reserved, required zero.
- Validate size, ABI identity, flags and reserved before accessing the peer or performing any socket, queue, sequence, retry, clock, reset or egress work.
- Existing ABI 1 requests retain their required current ordinary-delivery behavior.
- The unchanged 160-byte client descriptor cannot prove ABI 2 record support. Before advertising or activating the private timed capability, the consumer must successfully perform an ABI 2 request on its serialized peer owner; rejection makes that call unavailable and triggers cleanup. A future released package floor must name the actual provider version, never an invented version. No source callback may advertise this capability based only on table size.
- A successful SERVICE_ONLY call returns only NONE or DISCONTINUITY metadata. It never returns Audio, Gap, Digit, Text, RadioKey or RadioUnkey, never writes sample/text buffers, and never advances the delivery cursor except the explicit existing reset that starts a new media epoch.
- HANGUP, retry exhaustion, transport failure, account retirement and source-storage exhaustion return a terminal negative result through this same call. Terminal invalidation is explicitly different from accepting or dropping a refused source event.
- Alpha12 rejects ABI 2 before its peer conversion at ffi.rs:950. It clears output fields but leaves the caller input prefix, unknown tail and every peer state unchanged. A consumer must treat rejection as unavailable and fail closed, not fall back to ABI 1 or ordinary read-ahead.
- A larger ABI 1 tail is not negotiation: alpha12 would ignore it and might consume a source event.

The Rust boundary translates the request to a typed SourceDelivery enum (Deliver or ServiceOnly). Keep the old public poll_timed method as the ordinary-delivery entry to the shared implementation; do not duplicate the protocol engine.

## Bounded ownership and ordering

The existing pending_events limit is exactly MAX_EARLY_EVENTS = 64. It is currently an early-answer queue. Reuse that one queue and that one total 64-entry limit for early and deferred source records; do not add a second 64-entry queue or increase the limit. Keep the ingress mailbox, reliable window, reply queue and jitter capacities unchanged.

ABI 2 explicitly opts into the private phone profile: PCMU or PCMA, 8 kHz, exactly 160 encoded voice bytes / 160 samples / 20 ms for nonempty voice. The host's 160-frame buffer is not proof of a wire bound. Alpha12 client.rs::validate_phone_payload already enforces the 160-byte nonempty payload when provider_ownership is present; the ABI 2 contract states and checks that profile for every opt-in peer. Validate the negotiated profile and every already retained media shape before consuming ignored early TEXT, resetting any media, or latching ABI 2. Invalid activation leaves the complete peer state unchanged. Unsupported negotiated formats reject activation without entering this mode. A new malformed or oversized voice packet terminates the activated call before source acceptance or ACK. ABI 1 retains its existing generic formats and payload behavior for peers that never opt in. Successful ABI 2 activation latches the private source profile for that peer's lifetime; subsequent ordinary delivery through Rust poll_timed or ABI 1 cannot revive generic payload or visible-TEXT semantics on the same activated call.

Private TEXT remains deliberately ignored, matching rust/standalone/src/iax/timed.rs and host_services/iax_phone.rs. It is protocol-validated/acknowledged but not retained as a source item, not interpreted as ASL, and not converted into a digit. Radio key/unkey callbacks remain ignored by the private consumer, but their provider playout effects remain scalar ordered source work. ACK, retransmission, authentication and terminal lifecycle semantics are unchanged. Unsupported required protocol input is an explicit error, not silently dropped accepted control.

Each deferred phone voice record retains its original boxed datagram, checked payload range, original arrival Instant and Receipt. Moving the shared InboundDatagram allocation avoids another owned payload buffer or copy. Do not allocate a mapped Span while staging raw voice; create its one immutable mapped birth on first source release from the original Receipt. Already selected/decoded spans keep their existing mapped Span unchanged. Dedicated synchronous receive may allocate one exact-length retained datagram after reservation from the existing transient receive buffer. No decoded PCM copy or maximum-size packet allocation is added.

The pure deferred voice bound is 64 x 172 = 11,008 original datagram bytes for full voice, or 64 x 164 = 10,496 for mini voice. Scalar digits and radio effects need no retained payload allocation. Existing early-answer decoded phone PCM can occupy the same queue: at 160 f32 samples, at most 640 bytes per slot and 40,960 bytes across all 64 slots. A mixed early/deferred queue is bounded by 40,960 bytes, not that bound plus 11,008. Private-profile activation consumes already accepted ignored TEXT and validates the existing retained media shape before advertising capability; it does not retain generic 65,527-byte source payloads. Existing ingress and transient protocol parsing limits are unchanged.

Compared with alpha12, this makes the existing early-answer queue active during established-call refusal, so it is not memory-neutral in that state; no extra queue or PCM buffer is added. The temporary native amd64 / Rust 1.88 layout probe measured the existing PendingEvent at 96 bytes and a proposed Ready-or-Voice slot at 96 bytes. Its owned voice fields were Box<[u8]>, Instant, Option<Receipt>, timestamp u32, payload offset/length u16/u16, and mini bool. Both VecDeque instances had actual capacity 64 and 6,144 bytes of slot storage, so the measured metadata delta was zero. The original InboundDatagram measured 88 bytes. The proposed pure full-voice backlog therefore totals 17,152 bytes of payload plus slot storage, and the mixed early/deferred maximum is 47,104 bytes, excluding allocator bookkeeping and existing shared Span mappings. These are prototype layout measurements, not a completed implementation or RSS measurement. Recheck the actual final type and allocations during implementation. The temporary measurement code is retained only in ignored .work/protocol-progress-layout-probe.rs. Shared input ownership moves into a record; optional VecDeque growth is the only new queue metadata allocation, bounded to the existing 64 slots. The dedicated receive copy is explicit above.

Reserve queue capacity and complete owned-record preparation before committing a new source-bearing frame or acknowledging it as accepted. Allocation failure or a 65th source record is sticky terminal before that item is accepted; previously accepted control is never evicted or overwritten. Ignored TEXT, pure ACKs and valid duplicates require no source slot.

The transport admission stage validates call identity, sequence and retransmission rules, handles real cumulative ACK credit, retries and protocol replies, and stages source-bearing effects in receive order. The delivery stage alone decodes/adopts voice into jitter, advances existing direct PCM/playout suffixes, applies source-visible radio key/unkey effects, and publishes source coordinates. The queue preserves protocol admission order, not invented wire-order PCM. A host-held item and an already selected direct/jitter PCM remainder are source-release barriers: later staged digit/text or key/unkey effects cannot pass them. Drain the earlier selected remainder using its existing owner before later source records. For voice not yet selected by jitter, retain current ordinary polling semantics: admit deferred voice in protocol order; jitter may release it later or in corrected media order, and a subsequent control event may be exposed before that not-yet-due voice exactly as ordinary polling already permits. Do not make raw receive order override jitter reordering. Track the selected source owner so this priority does not accidentally bypass older early-answer events. Do not call ordinary poll with scratch output to simulate service.

Reserve source storage before committing a new source-bearing frame or acknowledging it as accepted. Repeated or invalid frames that produce no new source item do not spend a slot. If a new item requires a 65th slot, stop that call with sticky terminal source-storage exhaustion; do not evict an earlier digit, overwrite PCM, accept the item, or claim successful retirement. Existing ingress reject-new network-loss policy is unchanged. This proposal does not promise successful completion under unbounded hostile traffic.

SERVICE_ONLY does not render, advance or replace retained direct PCM or a pending jitter decode. Source release must drain their earlier suffix before later deferred source records. Protocol retries, ACK handling and reply flushing remain bounded by the existing 64-frame transport turn and 64-frame reliable/reply windows.

The original Receipt and any already mapped Span birth survive staging and retries. Host-held source metadata and accepted offsets remain unchanged. The delivery cursor advances only for actual source publication. Existing 500 ms expiry and clock-revocation retirement still run during service: discard only invalidated media, preserve queued private control, publish the exact discontinuity target, and never renew birth. Include every deferred voice Receipt in timed_deadline, retained-expiry checks, cutoff handling and media-only retirement cleanup; current alpha12 only checks event.pcm.span. Pure ACKs and duplicate frames still process when all 64 source slots are occupied. A refusal that crosses expiry is invalidation, not a promise to deliver stale PCM later.

Remote teardown or a terminal transport/protocol condition fences all subsequent source and timed egress. Use one sticky peer terminal state checked by source poll, prepare, send and retire operations; report_poll_error only logs, and timed.failed alone does not fence timed egress. The host discards its held source item on terminal retirement and uses the existing call cleanup path. A Pending TX retirement becomes Complete only through genuine ACK ownership removal; timeout/teardown is terminal, not an invented ACK or reusable TX token.

## Review focus

- Source-bearing full frames carry cumulative ACK fields: reserve ownership before any acceptance side effect.
- Retained direct PCM and jitter pending decode must not be overwritten by later voice.
- Radio key/unkey playout effects must not move ahead of earlier source records.
- Expiry or clock loss during refusal must preserve digits while retiring media and decoder history.
- Short, unknown-version, unknown-flag and nonzero-reserved requests must reject without changing peer state.

## Task 1: Prove the refusal gap and fail-closed request

**Files:** src/client_protocol_progress_tests.rs, test-only module inclusion in src/client_unit_tests.rs; later src/ffi_tests.rs and tests/abi_header_smoke.c.

- [x] Run refused_digit_keeps_real_ack_progress_and_later_source_order and observe the expected alpha12 failure: SERVICE_ONLY ABI 2 is rejected, not a compiler error. Observed 2026-11-12: status -1, event NONE, held digit 5 unchanged; later ACK/order assertions did not run.
- [x] Assert the rejected request leaves an outstanding real legacy PCM frame pending and a queued real ACK readable by an ordinary poll; no sequence, source cursor, timed mode or retirement state changes. Guard the 72-byte prefix and 80-byte tail bounds.
- [ ] Keep the first test's real owner and UDP path. No direct acknowledge_reliable_frames calls, invented completion tokens, fake receipt timestamps or extra consumer.
- [ ] Do not change production until the independent review and parent approval resolve this complete contract.

### First regression prepared

The test uses linked_peer, real DatagramPump and PeerDriver, real UDP digits and ACK, and the retained descriptor poll_timed pointer.

1. Poll real digit 5 into a single host-held item. Refuse it.
2. Commit a real legacy PCM full frame, verify it was received on UDP, and require TX retirement Pending.
3. Queue later digit 6. Start the real owner; on each turn call SERVICE_ONLY and retry retirement, without accepting the held 5.
4. Require three successful owner turns with Pending and the exact same held item. No application event can escape service.
5. Queue a real ACK with ISeq 2, then later 160-sample voice and digit 7. Require retirement Complete(2) while 5 is still refused.
6. Permit the host to accept. Observe 5, 6, Audio(160), 7 exactly once in that order. Confirm the audio has genuine original birth and source positions do not move on digit/service turns.
7. Latch the first Complete receipt rather than beginning a fresh retirement each turn. Bound report processing with one absolute deadline, then quiesce the driver and pump before releasing their runtime.

### Task 2: Implement one shared admission/release path

**Files:** src/client.rs, src/client_timed.rs, src/ingress.rs for ownership transfer only, src/playout.rs only where required, src/ffi.rs, include/rptadv_iax2_client.h.

- [x] Add the validated sized request, typed delivery mode and explicit private G.711 / 20 ms profile. Preserve ordinary ABI 1 behavior and reject unsupported activation before state changes.
- [x] Split existing receive protocol acceptance from source-visible effects. Reuse the one 64-entry queue; retain encoded voice with its real Receipt.
- [x] Service retries/replies and at most 64 receive packets without source rendering, then expose only reset or terminal status.
- [x] Make storage overflow and terminal errors sticky for source and timed egress, without a false Complete token.
- [x] Run the first regression GREEN, then the next distinct cases before further integration.

### Task 3: Cover retained media, terminal paths and consumer join

**Files:** src/client_protocol_progress_tests.rs, src/ffi_tests.rs, src/playout_tests.rs as needed. The consumer owner handles its separate controller workspace.

- [ ] Hold a partial 40-sample delivery with a host-refused suffix and 120 provider-retained samples. Queue later source and real ACK. Require Complete while all held bytes, offsets, media epoch, source start and mapped birth remain unchanged; later accept each sample once before later events.
- [ ] Repeat through the real installed jitter DSO with an already selected pending decoded suffix: no staged digit/key/unkey may pass that selected remainder. Separately verify that not-yet-selected reordered/not-due voice retains existing jitter and ordinary control-order semantics.
- [ ] Reject unsupported codec activation or invalid retained media shape with no state change, including no ignored-TEXT drain or mode latch. Verify successful activation stays private through later Rust poll_timed and ABI 1 delivery. Reject malformed/oversized new phone voice before acceptance/ACK; preserve ignored private TEXT without source retention. Measure the full 64-slot early/deferred mixture and allocator/copy counts.
- [ ] At 64 queued source items, process pure and duplicate ACKs without consuming a new source slot. Then submit the 65th new reliable digit. Require terminal, no ACK acceptance of that item, no earlier control eviction, and no storage growth.
- [ ] Expire actual reliable work during source refusal. Require bounded terminal notification without fabricating TX completion. Exercise actual remote HANGUP independently.
- [ ] Exercise source age beyond 500 ms and clock loss: retain digits, retire media/history, require exact reset acknowledgment, and forbid stale PCM or freshened birth.
- [ ] Exercise reply WouldBlock, ordinary reliable retransmit, invalid/duplicate frames and a healthy second peer under a stalled/flooded peer.
- [ ] Join SERVICE_ONLY to the existing serialized host step before retrying a held source/reset. Keep one host item and existing 160-frame PCM buffer; null-sink inspection remains non-consuming. Update dynamic capability/package floors only after a real prerequisite release exists.
- [ ] Update concise interface documentation and the applicable controller ADR. Run affected tests, formatting, lint, Cppcheck, ABI smoke and component coverage first. Record exact source/image/test evidence. Full native platform/coverage gates and publication remain separate approvals.

## Targeted verification command

After a grant, through /home/codex/rpt-development/workflow-resource-reporting/tools/run-in-quality-container.sh with RPTADV_CONTAINER_PROFILE=constrained and the approved freshly pulled maintained image:

cargo test --locked --lib client::unit_tests::protocol_progress::refused_digit_keeps_real_ack_progress_and_later_source_order -- --exact --nocapture

Observed command: cargo test --locked --lib client::unit_tests::protocol_progress -- --nocapture. Both prepared cases compiled; one passed and the owner case failed at the intended missing-capability assertion. Exit 101. No GREEN, production fix, full suite, lint, static analysis or coverage claim follows from this run.

## Recorded preparation evidence

- 2026-11-12: fresh image digest 1f9c78834e9851db876a15bb88e5e9c0b99ede2997172a9615892ea61f545554; IAX alpha12, ring alpha6, jitter alpha24, Rust 1.88.0.
- Test-only formatting and cargo fmt check passed.
- Two behavioral regressions compiled: invalid request/state preservation PASS; owner refusal capability RED at alpha12's ABI 2 rejection. Later ACK/order assertions remain unexecuted.
- Temporary exact layout probe PASS: existing and proposed 96-byte slot, capacity 64, 6,144-byte slot storage, delta zero. Probe source removed from shipping tests after recording.
- Both authorized constrained containers exited and slots were released. No production edits, publication, release, deployment, live calls or RF.
- Logs: .work/protocol-progress-red.log and .work/protocol-progress-layout.log. Exact commands and exclusions: .work/quality-progress.md.

Local implementation checkpoint: all seven prepared protocol_progress cases passed on the approved fresh constrained image. This is targeted evidence, not full verification or release readiness. See .work/quality-progress.md.


## Local code-review regressions

The first implementation checkpoint was 1f69f1a69a3532500b966174baca84856c5e7d5f. The next fresh constrained run compiled successfully and ran 16 cases: 12 passed and four failed. Independent deferred-voice cases proved that an empty output buffer could let a later digit pass voice A or let voice B overwrite A. A third test proved that a later selected remainder could pass an older early-answer PCM item. A real 65-datagram pre-reset burst proved that already retired receipts still consumed source slots. The log is .work/protocol-progress-review-red.log.

The local repair preserves the selected-source barrier even when decoding or rendering returns retryable OutputFull. A bounded early-prefix count keeps all previously accepted early events ahead of a later selected direct or jitter remainder. Media retirement subtracts only retired early media from that count and preserves controls. Service still commits legal protocol sequence and ACK information for valid pre-cutoff voice, but does not reserve or retain that already invalidated source.

ABI2 validation now reads the optional tail using the original caller-allocation raw pointer before creating a mutable reference to the 72-byte prefix. Physical 4-byte, 72-byte, and 80-byte caller records, untouched ABI1 tails, malformed requests, and guard bytes are tested separately. Native execution is not proof of Rust pointer-provenance safety; Miri has not run.

Actual representation measurements in the 16-case run confirmed the proposed 96-byte source slot and 6,144-byte 64-slot metadata bound. Shared ownership transfer retained 10,496 mini-frame bytes or 11,008 full-frame bytes, with zero new exact phone-payload allocations. Reserved mini admission made zero total allocations; full admission made 64 existing protocol-response allocations. The repaired state adds one byte for the early-prefix counter to the previous three-byte service state; a measurement assertion is prepared. Allocator bookkeeping, existing Span mappings, and existing ingress/protocol buffers remain outside these payload-plus-slot totals. No new source queue or host buffer was introduced.

The repaired 18-case batch passed on the same freshly pulled constrained image (exit 0): all four exact RED regressions, installed jitter cases, physical-size request tests, and stale full-voice sequence/ACK preservation passed. The measured service state is four bytes, with unchanged source-slot and payload bounds. See .work/protocol-progress-review-green.log. Broader suite, static analysis, ABI smoke, coverage, consumer integration, and publication remain separate pending gates.

### Bounded follow-on qualification

Nonmutating formatting/lint, all-target Clippy, exhaustive Cppcheck, exact ABI2 C layout assertions, selected existing parser/session/client/source/ordinary ABI regressions, public ABI tests, optimized candidate DSO SONAME verification, and dynamically linked C smoke ran on the constrained fresh maintained image. There were 283 passing selected tests and one IPv6 setup failure. The source-time fixture could not bind [::1] because IPv6 was disabled for the container and loopback. The fixture and production source-time files are unchanged from alpha12. No network setting or assertion was changed; IPv6 remains unverified locally. The complete run exited 1 and the test container was cleaned. Detailed per-stage results are retained in .work/protocol-progress-qualification-summary.txt. This is not the full native platform/coverage gate or release readiness.
