/* SPDX-License-Identifier: GPL-2.0-only */
/** @file rptadv_iax2_client.h
 * @brief Versioned C ABI for provider-backed standalone IAX2 media.
 */
#ifndef RPTADV_IAX2_CLIENT_H
#define RPTADV_IAX2_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <rptadv_codec.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Serialized bounded peer turn; zero continues, a negative result stops delivery.
 * The callback may use the peer's existing synchronous API. No provider peer
 * borrow is live while it runs. Its context stays valid until detach returns.
 */
typedef int32_t (*rptadv_iax2_step_v1)(void *context);

/** Copied owner-thread diagnostics, layout-compatible with product observation ABI 1. */
struct rptadv_iax2_peer_observation_v1 {
    uint32_t struct_size; /**< Caller-provided readable/writable size, at least 112. */
    uint32_t abi_version; /**< One. */
    uint32_t jitter_queued_packets; /**< Retained jitter packets. */
    uint32_t jitter_delay_samples; /**< Current jitter target delay. */
    uint64_t jitter_buffered_span_samples; /**< Retained jitter timestamp span. */
    uint64_t jitter_duplicate_drops; /**< Duplicate packet drops. */
    uint64_t jitter_late_drops; /**< Late packet drops. */
    uint64_t jitter_full_drops; /**< Full jitter queue drops. */
    uint64_t jitter_missing_samples; /**< Counted missing source samples. */
    uint64_t jitter_insertion_samples; /**< Counted inserted source samples. */
    uint64_t jitter_skipped_samples; /**< Counted skipped source samples. */
    uint64_t jitter_limit_resets; /**< Hard-bound jitter resets. */
    uint64_t jitter_overload_drops; /**< Overload-recovery packet drops. */
    uint64_t jitter_overload_span_samples; /**< Overload-recovery source span. */
    uint64_t ingress_overflow_drops; /**< Shared/dedicated mailbox full-queue drops. */
    uint32_t ingress_queued_packets; /**< Current mailbox occupancy. */
    uint32_t ingress_capacity_packets; /**< Maximum retained mailbox packets. */
    uint64_t egress_datagrams; /**< Datagrams accepted by the local socket, not remote delivery. */
    uint64_t egress_would_block; /**< Actual socket WouldBlock results. */
    uint64_t egress_reliable_retries; /**< Successfully resent reliable frames. */
    uint32_t egress_reliable_pending; /**< Current committed reliable window occupancy. */
    uint32_t egress_reply_pending; /**< Current bounded best-effort reply queue occupancy. */
};

/** Optional readiness executor, versioned independently of client/server ABI 2.
 * One runtime serves all peers. Audio callbacks never call this interface.
 * Stop is nonblocking; detach/destroy run off executor and wait for quiescence.
 * Every registration must be detached before unloading this shared object.
 */
struct rptadv_iax2_async_descriptor_v1 {
    uint32_t struct_size; /**< Complete readable table size. */
    uint32_t abi_version; /**< One. */
    uint8_t capability[16]; /**< NUL-padded rptadv.iaxasync. */
    int32_t (*runtime_create)(void **runtime); /**< Failure clears output. */
    void (*runtime_destroy)(void *runtime); /**< Releases the caller's runtime owner. */
    /** Attach once per peer and borrow it exclusively until detach. Only the
     * callback may use peer operations while attached. Success is one-shot even
     * after stop/detach; a detached peer may only be observed or destroyed.
     * Failure clears registration and neither invokes nor retains context.
     */
    int32_t (*peer_attach)(void *runtime, void *peer, rptadv_iax2_step_v1 step,
                          void *context, void **registration);
    void (*peer_stop)(void *registration); /**< Callback-safe nonblocking stop request. */
    /** Stop and wait off-executor before releasing peer/context. Control calls
     * are serialized; an executing callback may still call peer_stop while this
     * waits. Never detach from a callback or use registration after this returns.
     */
    void (*peer_detach)(void *registration);
    /** Configure a borrowed neutral jitter descriptor before the first attach.
     * Keep descriptor and its DSO alive until peer destruction. Returns zero on
     * success, negative on invalid capability, already configured, or attached.
     */
    int32_t (*peer_configure_jitter)(void *peer, const void *descriptor);
    /** Enable asynchronous socket routing for a bound synchronous server.
     * Call off-executor with exclusive server ownership. Returns zero on success
     * (including repeated enable), negative on invalid input or setup failure.
     * Poll remains serialized off-executor and handles only bounded queued NEW
     * calls. Established calls route independently, including during policy work.
     * Server destroy joins the receiver; keep this DSO loaded until it returns.
     */
    int32_t (*server_enable)(void *runtime, void *server);
    /** Copy diagnostics only from the exclusive callback owner or after detach.
     * Never call concurrently with peer media/jitter operations. The output must
     * supply struct_size >= 112 and ABI 1. Zero succeeds; negative leaves output
     * unchanged (including when jitter or async ingress is not configured).
     */
    int32_t (*peer_observe)(void *peer, struct rptadv_iax2_peer_observation_v1 *output);
    /** Signal a retained peer owner without blocking. Keep registration alive
     * through this call; quiesce all callers before peer_detach returns. */
    void (*peer_wake)(void *registration);
    /** Set the owner's next product turn relative to this call, in nanoseconds.
     * UINT64_MAX clears the deadline; zero is due now. Call only on the peer
     * owner. Protocol and jitter deadlines remain independently scheduled. */
    int32_t (*peer_set_deadline)(void *peer, uint64_t wake_after_ns);
};

/** Obtain optional async ABI 1; existing synchronous clients need not use it. */
const struct rptadv_iax2_async_descriptor_v1 *rptadv_iax2_async_descriptor_v1(void);

#define RPTADV_IAX2_CLIENT_ABI_VERSION 2U
/** Synchronous inbound-listener ABI revision. */
#define RPTADV_IAX2_SERVER_ABI_VERSION 2U
#define RPTADV_IAX2_EVENT_NONE 0U
#define RPTADV_IAX2_EVENT_AUDIO 1U
#define RPTADV_IAX2_EVENT_TEXT 2U
#define RPTADV_IAX2_EVENT_HANGUP 3U
#define RPTADV_IAX2_EVENT_DIGIT 4U
#define RPTADV_IAX2_EVENT_RADIO_KEY 5U
#define RPTADV_IAX2_EVENT_RADIO_UNKEY 6U
/** Only jitter-configured peers emit this counted input-rate loss span (no PCM data). */
#define RPTADV_IAX2_EVENT_GAP 7U
/** No fresh PCM/gap until exact previous media-owner retirement is acknowledged. */
#define RPTADV_IAX2_EVENT_DISCONTINUITY 8U
/** Original birth is qualified; absent means private/unqualified media only. */
#define RPTADV_IAX2_TIMED_BIRTH 1U
/** Pending retirement TARGET; private/control events can continue meanwhile. */
#define RPTADV_IAX2_TIMED_DISCONTINUITY 2U

/** Caller-sized ABI1 in/out record,72 bytes on supported native64 platforms.
 * Inputs must be captured BEFORE poll_timed entry. Birth subtracts original age
 * plus5ms uncertainty from that fixed reference, once per original span; every
 * PCM partial/suffix retains it. Underflow/missing/future receipt never qualifies.
 * Digits remain legacy private untimed IAX digits; no source interval is invented.
 */
struct rptadv_iax2_timed_event_v1 {
    uint32_t struct_size; /**< At least sizeof this record; future tails untouched. */
    uint32_t abi_version; /**< One. */
    uint64_t host_clock_epoch; /**< INPUT stable nonzero Host clock identity. */
    uint64_t reference_now_ns; /**< INPUT time captured BEFORE this provider call. */
    uint64_t acknowledged_media_epoch; /**< INPUT TARGET whose actual old owners retired. */
    uint32_t event_kind; /**< OUTPUT ordinary event or DISCONTINUITY. */
    uint32_t flags; /**< OUTPUT TIMED_BIRTH / TIMED_DISCONTINUITY bits. */
    size_t event_length; /**< OUTPUT samples/bytes or required PCM capacity on1. */
    uint64_t media_epoch; /**< OUTPUT epoch / pending retirement TARGET. */
    uint64_t source_start; /**< OUTPUT playout PCM cursor incl gaps/insertion, not wire time. */
    uint64_t born_ns; /**< OUTPUT immutable original birth, valid ONLY with TIMED_BIRTH. */
};

/** Immutable prepared packet expiry,24 bytes on native64. Sample elapsed_ms FIRST,
 * then the Host clock reference and oldest contributing PCM age. Compute deadline
 * as that earlier native floor plus the remaining500ms age budget, rounding down.
 * Never refresh it on WouldBlock, partial input/output, or retained retries.
 */
struct rptadv_iax2_timed_send_v1 {
    uint32_t struct_size; /**< At least this complete record. */
    uint32_t abi_version; /**< One. */
    uint64_t egress_epoch; /**< Exact completed local retirement token, not RX epoch. */
    uint32_t deadline_ms; /**< Absolute peer elapsed deadline; saturation refuses PCM. */
    uint32_t reserved; /**< Zero. */
};

/** One explicitly selected bidirectional neutral profile. */
struct rptadv_iax2_codec_selection_v2 {
    uint32_t struct_size; /**< Complete readable record size. */
    uint32_t profile_id; /**< Neutral codec ID, not an IAX format bit. */
    const char *provider_path; /**< NUL-terminated trusted DSO path, copied at open. */
};

/** Borrowed configuration for an outbound provider-backed call. */
struct rptadv_iax2_dial_options_v2 {
    uint32_t struct_size;              /**< Complete structure size. */
    uint32_t abi_version;              /**< Must be ABI version 2. */
    const uint8_t *remote_address;     /**< Numeric IPv4:port or [IPv6]:port. */
    size_t remote_address_length;      /**< Address byte count. */
    uint16_t local_call_number;        /**< Nonzero 15-bit local call number. */
    uint16_t reserved;                 /**< Must be zero. */
    const uint8_t *local_node;         /**< Decimal local node number. */
    size_t local_node_length;          /**< Local-node byte count. */
    const uint8_t *remote_node;        /**< Decimal requested remote node. */
    size_t remote_node_length;         /**< Remote-node byte count. */
    const uint8_t *secret;             /**< UTF-8 IAX secret, used for MD5 challenge. */
    size_t secret_length;              /**< Secret byte count. */
    uint32_t timeout_ms;               /**< Nonzero bounded setup timeout. */
    const void *catalog;              /**< Catalog borrowed for dial; never NULL. */
};

/** Provider call options, distinct from numeric AllStarLink caller/node identity.
 * All strings are UTF-8 with explicit byte lengths; NEW fields are at most 255
 * bytes and contain no controls. Empty caller/name/context fields are permitted.
 * Strings/catalog are borrowed only during dial. Number policies belong to the
 * provider. No secret is included in NEW or diagnostic messages.
 */
struct rptadv_iax2_account_dial_options_v1 {
    uint32_t struct_size; /**< Complete readable option size. */
    uint32_t abi_version; /**< One. */
    const uint8_t *remote_address; /**< Resolved numeric IP:port or [IPv6]:port. */
    size_t remote_address_length; /**< Address byte count. */
    uint16_t local_call_number; /**< Unique nonzero 15-bit IAX call number. */
    uint16_t reserved; /**< Zero. */
    const uint8_t *username; /**< Nonempty provider account username. */
    size_t username_length; /**< Username byte count. */
    const uint8_t *destination; /**< Nonempty provider destination, not rewritten. */
    size_t destination_length; /**< Destination byte count. */
    const uint8_t *caller_number; /**< Optional caller number. */
    size_t caller_number_length; /**< Caller-number byte count. */
    const uint8_t *caller_name; /**< Optional caller display name. */
    size_t caller_name_length; /**< Display-name byte count. */
    const uint8_t *context; /**< Optional provider dial context. */
    size_t context_length; /**< Context byte count. */
    const uint8_t *secret; /**< Challenge-response secret. */
    size_t secret_length; /**< Secret byte count. */
    uint32_t timeout_ms; /**< Nonzero total setup/answer timeout. */
    const void *catalog; /**< Borrowed codec catalog; never NULL. */
};

/** One-owner client operations; all peer calls are serialized by the caller. */
struct rptadv_iax2_client_descriptor_v2 {
    uint32_t struct_size; /**< Complete descriptor size. */
    uint32_t abi_version; /**< Exact ABI version. */
    uint8_t capability[16]; /**< NUL-padded "rptadv.iax2.v2". */
    /** Load and validate explicitly selected providers off audio. Copies paths;
     * clears output on failure. Opened peers/listeners retain their own owners. */
    int32_t (*open_catalog)(const struct rptadv_iax2_codec_selection_v2 *selections,
                            size_t count, void **catalog);
    /** Release caller catalog ownership after catalog calls finish; NULL is harmless. */
    void (*close_catalog)(void *catalog);
    /** Dial a resolved remote endpoint. Success returns one peer handle. */
    int32_t (*dial)(const struct rptadv_iax2_dial_options_v2 *options, void **peer);
    /** Return the negotiated linear PCM rate in samples per second. */
    uint32_t (*sample_rate_hz)(const void *peer);
    /** Send an ASL text message as one reliable IAX text frame. */
    int32_t (*send_text)(void *peer, const uint8_t *bytes, size_t length);
    /** Poll one event; length is samples for audio, bytes for text/digit, zero for
     * radio key/unkey. A return of one with EVENT_NONE reports required PCM
     * capacity in event_length; pending native decode/PLC is retained for retry. */
    int32_t (*poll)(void *peer, float *samples, size_t sample_capacity,
                    uint8_t *text, size_t text_capacity, uint32_t *event_kind,
                    size_t *event_length);
    /** Send HANGUP and mark the local call ended. */
    int32_t (*hangup)(void *peer);
    /** Best-effort HANGUP then destroy a uniquely owned peer handle. */
    void (*destroy)(void *peer);
    /** Send one completed DTMF digit (0-9, A-D, *, or #). */
    int32_t (*send_digit)(void *peer, uint8_t digit);
    /** Consume source PCM once in the retained encoder. Returns neutral status
     * 0..5 and the installed codec result. OutputFull consumes nothing. A
     * negative return means invalid arguments/record. Empty flush drains state. */
    int32_t (*prepare_audio)(void *peer, const float *samples, size_t count,
        uint8_t *output, size_t capacity, uint32_t flush,
        struct rptadv_codec_encode_result_v1 *result);
    /** Deliberately abandon expired/discontinuous input and encoder history. */
    int32_t (*reset_encoder)(void *peer);
    /** Send a prepared packet without re-encoding. Zero transfers ownership,
     * one means uncommitted WouldBlock, negative means failure. Source packet
     * frames, encoded bytes and timestamp milliseconds are independent. */
    int32_t (*send_prepared_audio)(void *peer, const uint8_t *bytes, size_t count,
        uint32_t packet_frames, uint32_t timestamp_ms);
    /** Read the call clock on the exclusive peer owner; NULL returns zero. */
    uint32_t (*elapsed_ms)(const void *peer);
    /** Optional tail: check struct_size through this field before accessing it.
     * Dial using distinct provider identity; clears peer on every failure.
     * Returned handles use the existing peer operations and ownership contract.
     */
    int32_t (*dial_account)(const struct rptadv_iax2_account_dial_options_v1 *options,
                           void **peer);
    /** Optional offset136/full144 tail; check physical descriptor size first.
     * Exclusive peer owner; use this OR legacy poll, never alternate modes.
     * Short records reject before a full-size reference/write. First target is1;
     * acknowledge only after genuine previous ring/DSP/RF retirement. Stale ack
     * never releases a later target. No fresh Audio/Gap while reset is pending.
     * Linux original RX/time qualification loss is sticky; control remains usable.
     */
    int32_t (*poll_timed)(void *peer, float *samples, size_t sample_capacity,
        uint8_t *text, size_t text_capacity, struct rptadv_iax2_timed_event_v1 *record);
    /** Optional offset144/full152:PCMU/PCMA8k20ms.0 Accepted,1 WouldBlock,
     *2 Expired/stale token; negative failure. No PCM is committed on1/2.
     * Reliable codec/timestamp markers carry ZERO PCM; actual media is Mini only.
     * Caller retains the unchanged packet/deadline/token on WouldBlock.
     */
    int32_t (*send_prepared_audio_timed)(void *peer, const uint8_t *bytes, size_t count,
        uint32_t packet_frames, uint32_t timestamp_ms, const struct rptadv_iax2_timed_send_v1 *timing);
    /** Optional offset152/full160:serial local retirement before initial timed
     * send and every source discontinuity.0 returns new TX epoch,1 Pending,
     * negative failure. Epoch output cleared on1/failure. Retires encoder history
     * and old local PCM eligibility; caller drops old staged items. Old token
     * cannot send after retirement. Previously successful UDP cannot be recalled.
     * Unacknowledged legacy PCM full-frames remain Pending until real ACK/teardown
     * instead of erasing their OSeq hole; PCM retries suppressed, control preserved.
     * Empty reliable markers remain protocol obligations, with no remote ACK claim.
     */
    int32_t (*retire_egress)(void *peer, uint64_t *egress_epoch);
};

/**
 * Return the immutable process-lifetime IAX2 client descriptor.
 *
 * All strings and buffers passed through the table are borrowed only for the
 * duration of the call. A peer handle has one serialized owner and is destroyed
 * exactly once. Setup, UDP, codec, and text operations are control/media-worker
 * work and must never be called from a real-time audio callback.
 *
 * Dial returns zero on success; negative values indicate invalid input,
 * network failure, timeout, peer rejection, unsupported format, or protocol
 * failure. Poll returns zero for a successful poll, with event_kind set to one
 * of the event constants above; one requests a larger PCM buffer and negative
 * means failure. Prepare and send-prepared have their documented distinct status
 * conventions. Other callbacks return zero on success and negative on failure.
 */
const struct rptadv_iax2_client_descriptor_v2 *rptadv_iax2_client_descriptor_v2(void);

/** Borrowed UTF-8 bytes, without NUL. No input pointer is retained. */
struct rptadv_iax2_bytes_v1 {
    const uint8_t *data; /**< NULL only when length is zero. */
    size_t length;       /**< Exact readable byte count. */
};

/** Fixed address value: family0 absent,4 IPv4,6 IPv6. */
struct rptadv_iax2_endpoint_v1 {
    uint16_t family;       /**< Independent of platform AF_* values. */
    uint16_t port;         /**< Host-order UDP port. */
    uint8_t address[16];   /**< Network-order IPv4 first4 or IPv6 all16 octets. */
    uint32_t flowinfo;     /**< IPv6 flow information, otherwise zero. */
    uint32_t scope_id;     /**< IPv6 interface scope, otherwise zero. */
};

/** Copied provider configuration. Arrays use this exact ABI1 record stride.
 * No controls/NUL are accepted in text. Secrets are literal, including semicolons.
 * Transport authentication never grants mailbox, command or RF authorization.
 */
struct rptadv_iax2_provider_account_v1 {
    uint32_t struct_size; /**< Exactly sizeof this ABI1 record. */
    uint32_t abi_version; /**< Exactly1. */
    uint64_t generation; /**< Nonzero; changed settings require a new value. */
    struct rptadv_iax2_bytes_v1 account; /**< Opaque nonempty label, at most64 bytes. */
    struct rptadv_iax2_bytes_v1 local_binding; /**< Configured binding, at most63 bytes. */
    struct rptadv_iax2_bytes_v1 remote_address; /**< Numeric endpoint, at most64 bytes. */
    struct rptadv_iax2_bytes_v1 username; /**< Nonempty login, at most255 bytes. */
    struct rptadv_iax2_bytes_v1 secret; /**< Nonempty MD5 secret, at most255 bytes. */
    uint32_t authentication_timeout_ms; /**< Nonzero incoming authentication lifetime. */
    uint32_t reserved; /**< Must be zero. */
};

/** Explicit registration, refresh or authenticated release; no automatic refresh. */
struct rptadv_iax2_registration_options_v1 {
    uint32_t struct_size; /**< Complete readable record size. */
    uint32_t abi_version; /**< Exactly1. */
    struct rptadv_iax2_bytes_v1 account; /**< Exact configured label. */
    uint64_t generation; /**< Exact configured generation. */
    uint16_t refresh; /**< Nonzero requested interval in seconds. */
    uint16_t release; /**< Zero register/refresh, one REGREL. */
    uint32_t timeout_ms; /**< Nonzero total operation timeout. */
};

/** Caller-sized output, cleared on failure after size validation. */
struct rptadv_iax2_registration_result_v1 {
    uint32_t struct_size; /**< Supplied writable size, returned provider record size. */
    uint32_t abi_version; /**< Returned ABI1. */
    uint16_t refresh; /**< Granted seconds; absent REFRESH defaults to60. */
    uint16_t reserved; /**< Zero. */
    struct rptadv_iax2_endpoint_v1 local; /**< Actual bound listener socket. */
    struct rptadv_iax2_endpoint_v1 apparent; /**< Registrar address, family0 if absent. */
};

/** Outgoing call using configured identity, endpoint and secret. */
struct rptadv_iax2_provider_dial_options_v1 {
    uint32_t struct_size; /**< Complete readable record size. */
    uint32_t abi_version; /**< Exactly1. */
    uint64_t generation; /**< Exact configured generation. */
    struct rptadv_iax2_bytes_v1 account; /**< Exact configured label, at most64 bytes. */
    struct rptadv_iax2_bytes_v1 destination; /**< Nonempty, at most255 bytes. */
    struct rptadv_iax2_bytes_v1 caller_number; /**< Optional untrusted number, at most255 bytes. */
    struct rptadv_iax2_bytes_v1 caller_name; /**< Optional untrusted name, at most255 bytes. */
    struct rptadv_iax2_bytes_v1 context; /**< Optional context, at most255 bytes. */
    uint32_t timeout_ms; /**< Nonzero total setup/answer timeout. */
    uint32_t reserved; /**< Must be zero. */
};

/** Copied-value call receipt, with no borrowed text or credentials. */
struct rptadv_iax2_provider_call_receipt_v1 {
    uint32_t struct_size; /**< Complete readable/writable record size. */
    uint32_t abi_version; /**< Exactly1. */
    uint64_t account_generation; /**< Exact configured generation. */
    uint64_t call_generation; /**< Nonzero listener-local call ownership generation. */
    uint64_t format; /**< Negotiated codec bit. */
    uint16_t local_call; /**< Local15-bit call number. */
    uint16_t remote_call; /**< Remote15-bit call number. */
    uint32_t reserved; /**< Zero. */
    struct rptadv_iax2_endpoint_v1 local; /**< Actual bound listener endpoint. */
    struct rptadv_iax2_endpoint_v1 remote; /**< Actual resolved provider endpoint. */
};

/** Metadata borrowed only during one incoming callback. Caller fields are untrusted. */
struct rptadv_iax2_provider_incoming_v1 {
    uint32_t struct_size; /**< Complete readable record size. */
    uint32_t abi_version; /**< Exactly1. */
    struct rptadv_iax2_provider_call_receipt_v1 receipt; /**< Exact transport receipt. */
    struct rptadv_iax2_bytes_v1 account; /**< Configured account. */
    struct rptadv_iax2_bytes_v1 local_binding; /**< Configured local admission binding. */
    struct rptadv_iax2_bytes_v1 username; /**< Authenticated transport login. */
    struct rptadv_iax2_bytes_v1 called; /**< Untrusted called number. */
    struct rptadv_iax2_bytes_v1 caller_number; /**< Untrusted caller, never an ASL node. */
    struct rptadv_iax2_bytes_v1 caller_name; /**< Untrusted display name. */
    struct rptadv_iax2_bytes_v1 context; /**< Untrusted context. */
};

/** Zero permits transport-authenticated admission; no callback pointer is retained. */
typedef int32_t (*rptadv_iax2_provider_authorize_v1)(void *context,
    const struct rptadv_iax2_provider_incoming_v1 *metadata);
/** Zero transfers the unique peer, nonzero leaves provider ownership for destruction.
 * Metadata is borrowed only during the callback. A transferred peer retains its
 * actual server/account generation fence even if retirement races this callback.
 */
typedef int32_t (*rptadv_iax2_provider_accept_v1)(void *context,
    const struct rptadv_iax2_provider_incoming_v1 *metadata, void *peer);

/** Borrowed options for one UDP listener serving configured local nodes/accounts. */
struct rptadv_iax2_server_options_v2 {
    uint32_t struct_size;             /**< Complete readable option size. */
    uint32_t abi_version;             /**< RPTADV_IAX2_SERVER_ABI_VERSION. */
    const uint8_t *bind_address;      /**< Numeric IPv4:port or [IPv6]:port. */
    size_t bind_address_length;      /**< Address byte count, excluding NUL. */
    const uint8_t *local_nodes;       /**< Comma-separated decimal node numbers. */
    size_t local_nodes_length;       /**< Node-list byte count, excluding NUL. */
    const void *catalog;             /**< Catalog retained independently by listener. */
    /** Optional tail. Old48byte options remain accepted; partial tails reject.
     * Empty local_nodes is valid only with a nonempty valid account array. */
    const struct rptadv_iax2_provider_account_v1 *accounts;
    size_t account_count; /**< At most64 accounts, copied before bind returns. */
};

/** Authorize an inbound node/source pair; zero permits admission.
 * Strings and context are borrowed only during the enclosing poll call.
 */
typedef int32_t (*rptadv_iax2_authorize_v1)(void *context,
    const uint8_t *local, size_t local_length,
    const uint8_t *remote, size_t remote_length,
    const uint8_t *source, size_t source_length);

/** Accept an established peer: zero transfers ownership to the caller.
 * A nonzero result leaves ownership with the provider, which destroys the peer.
 * Strings and context are borrowed only during the enclosing poll call.
 */
typedef int32_t (*rptadv_iax2_accept_v1)(void *context,
    const uint8_t *local, size_t local_length,
    const uint8_t *remote, size_t remote_length,
    const uint8_t *source, size_t source_length, void *peer);

/** Synchronous control operations; no callback is retained. Optional operations
 * share this listener's socket/router and source port. No control mutex is held
 * across foreign callbacks or network/route waits, so policy may reconfigure
 * this listener. Each peer still has one serialized media owner.
 */
struct rptadv_iax2_server_descriptor_v2 {
    uint32_t struct_size;    /**< Complete readable descriptor size. */
    uint32_t abi_version;    /**< RPTADV_IAX2_SERVER_ABI_VERSION. */
    uint8_t capability[16];  /**< NUL-padded rptadv.iaxsrv2. */
    /** Return zero and one listener handle, or negative and a NULL handle. */
    int32_t (*bind)(const struct rptadv_iax2_server_options_v2 *options, void **listener);
    /** Service at most one datagram; return 1 for work, 0 if idle, negative on error.
     * Both callbacks must be present to admit new calls. now_seconds is Unix time
     * for existing call-token validation. Provider calls cannot reach numeric policy.
     */
    int32_t (*poll)(void *listener, uint32_t now_seconds,
        rptadv_iax2_authorize_v1 authorize, rptadv_iax2_accept_v1 accept, void *context);
    /** Replace the comma-separated node list without dropping established calls. */
    int32_t (*set_local_nodes)(void *listener, const uint8_t *nodes, size_t length);
    /** Destroy once after all in-flight entries and callbacks return; NULL is harmless.
     * Stop/destroy all peer owners before unloading this DSO. Retained peers keep
     * their actual socket resources; timeout alone is not a teardown receipt. */
    void (*destroy)(void *listener);
    /** Optional tail: check struct_size through each required function slot.
     * Atomically validate/copy the whole replacement. Changed owners retire;
     * their retained peers reject media until the product closes/destroys them. */
    int32_t (*configure_accounts)(void *listener,
        const struct rptadv_iax2_provider_account_v1 *accounts, size_t count);
    /** Explicit register/refresh/release on this listener's source socket.
     * Requires async server_enable. Run off-executor without a product control lock.
     * The product drives refresh using the actual granted interval. */
    int32_t (*register_account)(void *listener,
        const struct rptadv_iax2_registration_options_v1 *options,
        struct rptadv_iax2_registration_result_v1 *result);
    /** Mixed numeric/provider admission, distinct policy and ownership callbacks.
     * MD5 verifies before provider_authorize. Missing callbacks reject the call.
     * Poll drives bounded pending-auth retries/expiry and released-route cleanup. */
    int32_t (*poll_accounts)(void *listener, uint32_t now_seconds,
        rptadv_iax2_authorize_v1 authorize, rptadv_iax2_accept_v1 accept,
        rptadv_iax2_provider_authorize_v1 provider_authorize,
        rptadv_iax2_provider_accept_v1 provider_accept, void *context);
    /** Outgoing configured-account call, on the same source port as registration.
     * Requires async server_enable. Clears peer/result on failure after validation.
     * Existing client dial_account remains unchanged, with its own dedicated socket. */
    int32_t (*dial_provider_account)(void *listener,
        const struct rptadv_iax2_provider_dial_options_v1 *options, void **peer,
        struct rptadv_iax2_provider_call_receipt_v1 *receipt);
};

/** Borrow the immutable listener table while this shared library remains loaded. */
const struct rptadv_iax2_server_descriptor_v2 *rptadv_iax2_server_descriptor_v2(void);

#ifdef __cplusplus
}
#endif
#endif
