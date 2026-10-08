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

#define RPTADV_IAX2_CLIENT_ABI_VERSION 1U
#define RPTADV_IAX2_EVENT_NONE 0U
#define RPTADV_IAX2_EVENT_AUDIO 1U
#define RPTADV_IAX2_EVENT_TEXT 2U
#define RPTADV_IAX2_EVENT_HANGUP 3U
#define RPTADV_IAX2_EVENT_DIGIT 4U
#define RPTADV_IAX2_EVENT_RADIO_KEY 5U
#define RPTADV_IAX2_EVENT_RADIO_UNKEY 6U

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
    /** Encode and send normalized mono F32 audio samples at 8 kHz. */
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

#ifdef __cplusplus
}
#endif
#endif
