/* SPDX-License-Identifier: GPL-2.0-only */
/** @file rptadv_iax2_client.h
 * @brief Versioned C ABI for the standalone ULAW IAX2 client.
 */
#ifndef RPTADV_IAX2_CLIENT_H
#define RPTADV_IAX2_CLIENT_H

#include <stddef.h>
#include <stdint.h>

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
};

/** Optional readiness executor, independent of the unchanged client/server ABI.
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
};

/** Obtain optional async ABI 1; existing synchronous clients need not use it. */
const struct rptadv_iax2_async_descriptor_v1 *rptadv_iax2_async_descriptor_v1(void);

#define RPTADV_IAX2_CLIENT_ABI_VERSION 1U
/** Existing synchronous inbound-listener ABI revision. */
#define RPTADV_IAX2_SERVER_ABI_VERSION 1U
#define RPTADV_IAX2_EVENT_NONE 0U
#define RPTADV_IAX2_EVENT_AUDIO 1U
#define RPTADV_IAX2_EVENT_TEXT 2U
#define RPTADV_IAX2_EVENT_HANGUP 3U
#define RPTADV_IAX2_EVENT_DIGIT 4U
#define RPTADV_IAX2_EVENT_RADIO_KEY 5U
#define RPTADV_IAX2_EVENT_RADIO_UNKEY 6U
/** Only jitter-configured peers emit this counted input-rate loss span (no PCM data). */
#define RPTADV_IAX2_EVENT_GAP 7U

/** Borrowed configuration for an outbound ULAW-only call. */
struct rptadv_iax2_dial_options_v1 {
    uint32_t struct_size;              /**< Complete structure size. */
    uint32_t abi_version;              /**< Must be ABI version 1. */
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
};

/** One-owner client operations; all peer calls are serialized by the caller. */
struct rptadv_iax2_client_descriptor_v1 {
    uint32_t struct_size; /**< Complete descriptor size. */
    uint32_t abi_version; /**< Exact ABI version. */
    uint8_t capability[16]; /**< NUL-padded "rptadv.iax2.v1". */
    /** Dial a resolved remote endpoint. Success returns one peer handle. */
    int32_t (*dial)(const struct rptadv_iax2_dial_options_v1 *options, void **peer);
    /** Return the negotiated linear PCM rate in samples per second. */
    uint32_t (*sample_rate_hz)(const void *peer);
    /** Encode mono F32 at 8 kHz with sample-contiguous timestamps. Zero samples
     * end a burst; the next burst anchors to call time. Gaps above 160 ms also
     * reanchor callers without an idle marker. Failed sends do not advance time. */
    int32_t (*send_audio)(void *peer, const float *samples, size_t sample_count);
    /** Send an ASL text message as one reliable IAX text frame. */
    int32_t (*send_text)(void *peer, const uint8_t *bytes, size_t length);
    /** Poll one event; length is samples for audio, bytes for text/digit, zero for radio key/unkey. */
    int32_t (*poll)(void *peer, float *samples, size_t sample_capacity,
                    uint8_t *text, size_t text_capacity, uint32_t *event_kind,
                    size_t *event_length);
    /** Send HANGUP and mark the local call ended. */
    int32_t (*hangup)(void *peer);
    /** Best-effort HANGUP then destroy a uniquely owned peer handle. */
    void (*destroy)(void *peer);
    /** Send one completed DTMF digit (0-9, A-D, *, or #). */
    int32_t (*send_digit)(void *peer, uint8_t digit);
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
 * of the event constants above; it returns negative on failure. Other operation
 * callbacks return zero on success and negative on failure.
 */
const struct rptadv_iax2_client_descriptor_v1 *rptadv_iax2_client_descriptor_v1(void);

/** Borrowed options for one UDP listener serving configured local nodes. */
struct rptadv_iax2_server_options_v1 {
    uint32_t struct_size;             /**< Complete readable option size. */
    uint32_t abi_version;             /**< RPTADV_IAX2_SERVER_ABI_VERSION. */
    const uint8_t *bind_address;      /**< Numeric IPv4:port or [IPv6]:port. */
    size_t bind_address_length;      /**< Address byte count, excluding NUL. */
    const uint8_t *local_nodes;       /**< Comma-separated decimal node numbers. */
    size_t local_nodes_length;       /**< Node-list byte count, excluding NUL. */
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

/** Existing one-owner synchronous listener operations; no callback is retained. */
struct rptadv_iax2_server_descriptor_v1 {
    uint32_t struct_size;    /**< Complete readable descriptor size. */
    uint32_t abi_version;    /**< RPTADV_IAX2_SERVER_ABI_VERSION. */
    uint8_t capability[16];  /**< NUL-padded rptadv.iaxsrv1. */
    /** Return zero and one listener handle, or negative and a NULL handle. */
    int32_t (*bind)(const struct rptadv_iax2_server_options_v1 *options, void **listener);
    /** Service at most one datagram; return 1 for work, 0 if idle, negative on error.
     * Both callbacks must be present to admit new calls. now_seconds is Unix time
     * for existing call-token validation. All calls on one handle are serialized.
     */
    int32_t (*poll)(void *listener, uint32_t now_seconds,
        rptadv_iax2_authorize_v1 authorize, rptadv_iax2_accept_v1 accept, void *context);
    /** Replace the comma-separated node list without dropping established calls. */
    int32_t (*set_local_nodes)(void *listener, const uint8_t *nodes, size_t length);
    /** Destroy once after poll returns; NULL is harmless. */
    void (*destroy)(void *listener);
};

/** Borrow the immutable listener table while this shared library remains loaded. */
const struct rptadv_iax2_server_descriptor_v1 *rptadv_iax2_server_descriptor_v1(void);

#ifdef __cplusplus
}
#endif
#endif
