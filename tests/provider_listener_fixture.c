/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "rptadv_iax2_client.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct rptadv_iax2_server_options_v2) == 64, "server options layout");
_Static_assert(sizeof(struct rptadv_iax2_server_descriptor_v2) == 112, "server transaction tail layout");
_Static_assert(offsetof(struct rptadv_iax2_server_descriptor_v2, prepare_configuration_batch) == 88,
    "prepared configuration preserves the released account prefix");
_Static_assert(offsetof(struct rptadv_iax2_server_descriptor_v2, configure_accounts) == 56, "released server prefix");
_Static_assert(offsetof(struct rptadv_iax2_server_descriptor_v2, dial_provider_account) == 80, "shared outgoing slot");
_Static_assert(sizeof(struct rptadv_iax2_provider_account_v1) == 104, "account record stride");
_Static_assert(sizeof(struct rptadv_iax2_registration_options_v1) == 40, "registration options layout");
_Static_assert(sizeof(struct rptadv_iax2_registration_result_v1) == 68, "registration output layout");
_Static_assert(sizeof(struct rptadv_iax2_provider_dial_options_v1) == 104, "dial options layout");
_Static_assert(sizeof(struct rptadv_iax2_provider_call_receipt_v1) == 96, "call receipt layout");
_Static_assert(sizeof(struct rptadv_iax2_provider_incoming_v1) == 216, "incoming layout");

static struct rptadv_iax2_bytes_v1 text(const char *value)
{
    return (struct rptadv_iax2_bytes_v1){ (const uint8_t *)value, strlen(value) };
}

static uint64_t now_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static uint64_t now_ms(void) { return now_ns() / 1000000; }

static void *catalog_open(const struct rptadv_iax2_client_descriptor_v2 *api, unsigned profile)
{
    char path[4096];
    const char *directory = getenv("RPTADV_CODEC_DIR");
    int length = snprintf(path, sizeof(path), "%s%slibrptadv_codec_g711.so.1", directory ? directory : "", directory ? "/" : "");
    if (length < 0 || (size_t)length >= sizeof(path)) return NULL;
    struct rptadv_iax2_codec_selection_v2 selection = { .struct_size = sizeof(selection), .profile_id = profile, .provider_path = path };
    void *catalog = NULL;
    return api->open_catalog(&selection, 1, &catalog) == 0 ? catalog : NULL;
}

struct live_policy {
    const struct rptadv_iax2_async_descriptor_v1 *async;
    unsigned queued, samples_before, after_delay;
    int edited, restored;
};

static int same_queue(const struct rptadv_iax2_peer_observation_v1 *a,
                      const struct rptadv_iax2_peer_observation_v1 *b)
{
    return a->jitter_queued_packets == b->jitter_queued_packets &&
           a->jitter_buffered_span_samples == b->jitter_buffered_span_samples &&
           a->jitter_limit_resets == b->jitter_limit_resets &&
           a->jitter_overload_drops == b->jitter_overload_drops;
}

static int live_policy_turn(struct live_policy *p, void *peer, size_t received)
{
    struct rptadv_iax2_peer_observation_v1 before = { .struct_size = sizeof(before), .abi_version = 1 };
    struct rptadv_iax2_peer_observation_v1 after = before;
    const int supported = p->async->struct_size >=
        offsetof(struct rptadv_iax2_async_descriptor_v1, peer_set_private_jitter) +
        sizeof(p->async->peer_set_private_jitter) && p->async->peer_set_private_jitter;
    if (p->async->peer_observe(peer, &before) != 0) return 0;
    if (!p->edited && received && before.jitter_queued_packets && before.jitter_delay_samples > 320) {
        p->queued = before.jitter_queued_packets;
        p->samples_before = (unsigned)received;
        if (supported) {
            if (p->async->peer_set_private_jitter(peer, 80, 20, 40) == 0 ||
                p->async->peer_observe(peer, &after) != 0 || !same_queue(&before, &after) ||
                before.jitter_delay_samples != after.jitter_delay_samples ||
                p->async->peer_set_private_jitter(peer, 20, 20, 40) != 0) return 0;
        }
        if (p->async->peer_observe(peer, &after) != 0 || !same_queue(&before, &after)) return 0;
        p->edited = 1;
    } else if (p->edited && !p->restored && received >= p->samples_before + 1600) {
        p->after_delay = before.jitter_delay_samples;
        if (p->after_delay > 320 || !supported) {
            fprintf(stderr, "live private jitter expected_max=320 observed=%u callback=%d queued_at_edit=%u subsequent_audio=%zu\n",
                    p->after_delay, supported, p->queued, received - p->samples_before);
            return 0;
        }
        if (p->async->peer_set_private_jitter(peer, 30, 85, 140) != 0 ||
            p->async->peer_observe(peer, &after) != 0 || !same_queue(&before, &after)) return 0;
        p->restored = 1;
    }
    return 1;
}

struct echo_state {
    const struct rptadv_iax2_client_descriptor_v2 *api;
    void *peer;
    struct live_policy *policy;
    struct rptadv_iax2_timed_send_v1 send_time;
    uint8_t encoded[512];
    size_t received, qualified, prepared_bytes;
    uint32_t prepared_frames, prepared_timestamp, timestamp_offset;
    uint64_t acknowledged, cursor, epoch, next;
    double energy;
    int prepared;
    atomic_int outcome;
};

/* Bounded native turn. Only the unique call owner accesses this state until
 * peer_detach joins the final callback. -1 fails, 0 continues, 1 completes. */
static int echo_turn(struct echo_state *state)
{
    const struct rptadv_iax2_client_descriptor_v2 *api = state->api;
    void *peer = state->peer;
    float source[160], output[4096];
    uint8_t body[4096];
    for (size_t i = 0; i < 160; ++i) source[i] = 0.25f;
    if (!state->prepared && now_ms() >= state->next) {
        /* Native floor FIRST, then generation of this new test tone block.
         * The remaining500ms budget/deadline stays unchanged on WouldBlock. */
        uint32_t native = api->elapsed_ms(peer);
        if (native > UINT32_MAX - 500) return -1;
        state->send_time.deadline_ms = native + 500;
        state->prepared_timestamp = native + state->timestamp_offset;
        struct rptadv_codec_encode_result_v1 coded = { .struct_size = sizeof(coded) };
        if (api->prepare_audio(peer, source, 160, state->encoded, sizeof(state->encoded), 0, &coded) != 0 ||
            coded.consumed_frames != 160 || coded.encoded_bytes == 0) return -1;
        state->prepared_bytes = coded.encoded_bytes;
        state->prepared_frames = coded.packet_frames;
        state->prepared = 1;
    }
    if (state->prepared) {
        int sent = api->send_prepared_audio_timed(peer, state->encoded, state->prepared_bytes, state->prepared_frames, state->prepared_timestamp, &state->send_time);
        if (sent == 0) { state->prepared = 0; state->next += 20; }
        else if (sent != 1) return -1;
    }
    struct rptadv_iax2_timed_event_v1 timed = { .struct_size = sizeof(timed),
        .abi_version = 1, .host_clock_epoch = 1, .reference_now_ns = now_ns(),
        .acknowledged_media_epoch = state->acknowledged };
    if (api->poll_timed(peer, output, 4096, body, sizeof(body), &timed) != 0) return -1;
    if (timed.flags & RPTADV_IAX2_TIMED_DISCONTINUITY) {
        if (state->policy && state->policy->edited) return -1;
        if (timed.event_kind == RPTADV_IAX2_EVENT_AUDIO || timed.event_kind == RPTADV_IAX2_EVENT_GAP) return -1;
        /* This fixture owns no retained downstream PCM/DSP/RF context. Its
         * old output is already consumed; acknowledge this actual target. */
        state->acknowledged = timed.media_epoch;
        state->cursor = 0;
        state->epoch = timed.media_epoch;
    }
    if (timed.event_kind == RPTADV_IAX2_EVENT_AUDIO || timed.event_kind == RPTADV_IAX2_EVENT_GAP) {
        if (timed.media_epoch != state->epoch || timed.source_start != state->cursor) return -1;
        state->cursor += timed.event_length;
    }
    if (timed.event_kind == RPTADV_IAX2_EVENT_AUDIO) {
        if (timed.flags & RPTADV_IAX2_TIMED_BIRTH) {
            if (timed.born_ns > timed.reference_now_ns - 5000000) return -1;
            state->qualified += timed.event_length;
        }
        state->received += timed.event_length;
        for (size_t i = 0; i < timed.event_length; ++i) state->energy += output[i] * output[i];
    }
    if (state->policy && !live_policy_turn(state->policy, peer, state->received)) return -1;
    if (state->received >= 1600 && state->qualified >= 1600 && state->energy > 1 &&
        (!state->policy || (state->policy->restored && state->received >= state->policy->samples_before + 2240))) return 1;
    return 0;
}

static int32_t attached_echo_step(void *context)
{
    struct echo_state *state = context;
    int result = echo_turn(state);
    if (result == 0) {
        uint64_t now = now_ms();
        uint64_t until_next = state->next > now ? (state->next - now) * 1000000U : 1000000U;
        if (state->policy->async->peer_set_deadline(state->peer, until_next) == 0) return 0;
        result = -1;
    }
    atomic_store_explicit(&state->outcome, result, memory_order_release);
    return -1;
}

static size_t echo(const struct rptadv_iax2_client_descriptor_v2 *api, void *peer,
                   uint32_t timestamp_offset, struct live_policy *policy, void *runtime)
{
    uint64_t tx_epoch = 0;
    if (api->retire_egress(peer, &tx_epoch) != 0 || !tx_epoch) return 0;
    struct echo_state state = { .api = api, .peer = peer, .policy = policy,
        .timestamp_offset = timestamp_offset, .next = now_ms(),
        .send_time = { .struct_size = sizeof(state.send_time), .abi_version = 1, .egress_epoch = tx_epoch } };
    atomic_init(&state.outcome, 0);
    void *registration = NULL;
    if (runtime && (!policy || policy->async->peer_attach(runtime, peer, attached_echo_step,
            &state, &registration) != 0 || !registration)) return 0;
    const uint64_t deadline = now_ms() + 4000;
    int result = 0;
    while (result == 0 && now_ms() < deadline) {
        result = registration ? atomic_load_explicit(&state.outcome, memory_order_acquire) : echo_turn(&state);
        if (result == 0) {
            struct timespec wait = { .tv_nsec = 1000000 };
            nanosleep(&wait, NULL);
        }
    }
    if (registration) policy->async->peer_detach(registration);
    return result == 1 ? state.received : 0;
}

static int phone_jitter(const struct rptadv_iax2_async_descriptor_v1 *async, void *peer, const void *descriptor, unsigned configured, unsigned *delay)
{
    struct rptadv_iax2_peer_observation_v1 observation = { .struct_size = sizeof(observation), .abi_version = 1 };
    if (!async || async->abi_version != 1 || !async->peer_observe || !async->peer_configure_jitter) return 0;
    const int has_policy = async->struct_size >=
        offsetof(struct rptadv_iax2_async_descriptor_v1, peer_configure_private_jitter) +
        sizeof(async->peer_configure_private_jitter) && async->peer_configure_private_jitter;
    if (configured && has_policy) {
        if (async->peer_configure_private_jitter(peer, descriptor, 30, 85, 140) != 0) return 0;
    } else if (async->peer_configure_jitter(peer, descriptor) != 0) return 0;
    if (async->peer_observe(peer, &observation) != 0) return 0;
    *delay = observation.jitter_delay_samples;
    const unsigned expected = configured ? 680U : 320U;
    if (*delay != expected || (configured && !has_policy)) {
        fprintf(stderr, "native phone jitter expected=%u observed=%u policy_callback=%d\n",
                expected, *delay, has_policy);
        return 0;
    }
    return 1;
}

struct incoming {
    void *peer;
    uint16_t port;
    unsigned authorized;
    unsigned format;
    unsigned jitter_delay;
    unsigned configured;
    const struct rptadv_iax2_async_descriptor_v1 *async;
    const void *jitter;
};

static int equal(struct rptadv_iax2_bytes_v1 value, const char *expected)
{
    return value.length == strlen(expected) && memcmp(value.data, expected, value.length) == 0;
}

static int32_t authorize(void *context, const struct rptadv_iax2_provider_incoming_v1 *metadata)
{
    struct incoming *state = context;
    if (!metadata || metadata->struct_size != sizeof(*metadata) || metadata->abi_version != 1 ||
        metadata->receipt.account_generation != 7 || metadata->receipt.call_generation == 0 ||
        metadata->receipt.local.port != state->port || metadata->receipt.remote.family != 4 || metadata->receipt.format != state->format ||
        !equal(metadata->account, "club-account") || !equal(metadata->local_binding, "operator-west")) return -1;
    ++state->authorized;
    return 0;
}

static int32_t accept_call(void *context, const struct rptadv_iax2_provider_incoming_v1 *metadata, void *peer)
{
    struct incoming *state = context;
    if (!metadata || !peer || state->peer || state->authorized != 1) return -1;
    if (!phone_jitter(state->async, peer, state->jitter, state->configured, &state->jitter_delay)) return -1;
    state->peer = peer;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 5) return 2;
    const int custom = argc == 5 && strcmp(argv[4], "configured") == 0;
    const int live = argc == 5 && strcmp(argv[4], "live") == 0;
    const int mixed = live || (argc == 5 && strcmp(argv[4], "mixed") == 0);
    if ((argc == 5 && !custom && !mixed) || (strcmp(argv[2], "ulaw") != 0 && strcmp(argv[2], "alaw") != 0)) return 2;
    unsigned profile = strcmp(argv[2], "alaw") == 0 ? 2 : 1;
    unsigned format = 1U << (profile + 1);
    const struct rptadv_iax2_client_descriptor_v2 *api = rptadv_iax2_client_descriptor_v2();
    const struct rptadv_iax2_server_descriptor_v2 *server = rptadv_iax2_server_descriptor_v2();
    const struct rptadv_iax2_async_descriptor_v1 *async = rptadv_iax2_async_descriptor_v1();
    void *catalog = catalog_open(api, profile), *listener = NULL, *runtime = NULL, *outgoing = NULL;
    void *jitter_library = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    const void *jitter = NULL;
    if (jitter_library) {
        const void *symbol = dlsym(jitter_library, "rptadv_jitter_adapter_descriptor_v1");
        const void *(*entry)(void) = NULL;
        if (symbol) { memcpy(&entry, &symbol, sizeof(entry)); jitter = entry(); }
    }
    struct incoming incoming = { .format = format, .async = async, .jitter = jitter, .configured = argc == 5 };
    int failed = 1;
    const char *stage = "descriptor/bind";
    uint16_t bound_port = 0;
    unsigned outgoing_delay = 0;
    size_t outgoing_samples = 0, incoming_samples = 0;
    if (!jitter || !catalog || api->struct_size < sizeof(*api) || !api->poll_timed || !api->send_prepared_audio_timed || !api->retire_egress || server->struct_size < sizeof(*server) || !server->configure_accounts || !server->register_account || !server->poll_accounts || !server->dial_provider_account) goto done;
    struct rptadv_iax2_provider_account_v1 account = {
        .struct_size = sizeof(account), .abi_version = 1, .generation = 7,
        .account = text("club-account"), .local_binding = text("operator-west"),
        .remote_address = text(argv[1]), .username = text("club-account"), .secret = text("fixture-only"), .authentication_timeout_ms = 3000,
    };
    struct rptadv_iax2_server_options_v2 options = {
        .struct_size = sizeof(options), .abi_version = 2, .bind_address = (const uint8_t *)"127.0.0.1:0", .bind_address_length = 11,
        .catalog = catalog, .accounts = &account, .account_count = 1,
    };
    if (server->bind(&options, &listener) != 0 || !listener || async->runtime_create(&runtime) != 0 || !runtime || async->server_enable(runtime, listener) != 0) goto done;
    struct rptadv_iax2_registration_options_v1 registration = {
        .struct_size = sizeof(registration), .abi_version = 1, .account = text("club-account"), .generation = 7, .refresh = 60, .timeout_ms = 3000,
    };
    struct rptadv_iax2_registration_result_v1 registered = { .struct_size = sizeof(registered) };
    stage = "register/refresh";
    for (unsigned i = 0; i < 2; ++i) {
        if (server->register_account(listener, &registration, &registered) != 0 || !registered.refresh || registered.apparent.family != 4 || !registered.local.port) goto done;
        if (bound_port && registered.local.port != bound_port) goto done;
        bound_port = registered.local.port;
        if (registered.apparent.port != bound_port || server->poll_accounts(listener, 0, NULL, NULL, NULL, NULL, NULL) < 0) goto done;
    }
    struct rptadv_iax2_provider_dial_options_v1 dial = {
        .struct_size = sizeof(dial), .abi_version = 1, .generation = 7,
        .account = text("club-account"), .destination = text("999"), .caller_number = text("KG0BP"), .caller_name = text("Fixture"), .context = text("phone-test"), .timeout_ms = 3000,
    };
    struct rptadv_iax2_provider_call_receipt_v1 receipt = { .struct_size = sizeof(receipt) };
    stage = "outgoing/echo";
    if (server->dial_provider_account(listener, &dial, &outgoing, &receipt) != 0 || !outgoing || receipt.local.port != bound_port || receipt.format != format) goto done;
    stage = "real phone jitter/outgoing echo";
    if (!phone_jitter(async, outgoing, jitter, custom, &outgoing_delay) || !(outgoing_samples = echo(api, outgoing, 65520, NULL, NULL))) goto done;
    struct rptadv_iax2_peer_observation_v1 parked = { .struct_size = sizeof(parked), .abi_version = 1 };
    if (mixed) {
        if (async->peer_observe(outgoing, &parked) != 0) goto done;
    } else {
        api->destroy(outgoing); outgoing = NULL;
    }
    if (server->poll_accounts(listener, 0, NULL, NULL, NULL, NULL, NULL) < 0) goto done;
    incoming.port = bound_port;
    stage = "incoming/echo";
    printf("{\"ready\":true,\"format\":%u,\"initial_jitter_samples\":%u,\"local_port\":%u,\"refresh\":%u,\"outgoing_echo_samples\":%zu}\n", format, outgoing_delay, bound_port, registered.refresh, outgoing_samples);
    fflush(stdout);
    uint64_t deadline = now_ms() + 5000;
    while (!incoming.peer && now_ms() < deadline) {
        if (server->poll_accounts(listener, (uint32_t)time(NULL), NULL, NULL, authorize, accept_call, &incoming) < 0) goto done;
        struct timespec wait = { .tv_nsec = 1000000 };
        nanosleep(&wait, NULL);
    }
    struct live_policy policy = { .async = async };
    if (!incoming.peer || incoming.authorized != 1 || !(incoming_samples = echo(api, incoming.peer, 0, live ? &policy : NULL, live ? runtime : NULL))) goto done;
    if (live) fprintf(stderr, "native live policy queued=%u delay_after=%u restore=1 attached=1 audio=%zu\n",
                      policy.queued, policy.after_delay, incoming_samples);
    if (mixed) {
        struct rptadv_iax2_peer_observation_v1 current = { .struct_size = sizeof(current), .abi_version = 1 };
        if (async->peer_observe(outgoing, &current) != 0 ||
            current.jitter_delay_samples != parked.jitter_delay_samples ||
            !same_queue(&parked, &current)) goto done;
        api->destroy(outgoing); outgoing = NULL;
    }
    api->destroy(incoming.peer); incoming.peer = NULL;
    if (server->poll_accounts(listener, 0, NULL, NULL, NULL, NULL, NULL) < 0) goto done;
    registration.release = 1;
    stage = "release";
    if (server->register_account(listener, &registration, &registered) != 0) goto done;
    if (server->poll_accounts(listener, 0, NULL, NULL, NULL, NULL, NULL) < 0) goto done;
    account.generation = registration.generation = 8;
    stage = "wrong registration secret";
    account.secret = text("wrong-fixture-secret"); registration.release = 0;
    if (server->configure_accounts(listener, &account, 1) != 0 || server->register_account(listener, &registration, &registered) != -4 || registered.refresh != 0) goto done;
    failed = 0;
done:
    if (outgoing) api->destroy(outgoing);
    if (incoming.peer) api->destroy(incoming.peer);
    if (listener) server->destroy(listener);
    if (runtime) async->runtime_destroy(runtime);
    if (catalog) api->close_catalog(catalog);
    if (jitter_library) dlclose(jitter_library);
    if (!failed) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(bound_port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        if (fd < 0 || bind(fd, (const struct sockaddr *)&local, sizeof(local)) != 0) failed = 1;
        if (fd >= 0) close(fd);
    }
    if (failed) fprintf(stderr, "provider listener fixture failed at %s: outgoing=%zu incoming=%zu authorized=%u port=%u\n", stage, outgoing_samples, incoming_samples, incoming.authorized, bound_port);
    else printf("{\"format\":%u,\"incoming_initial_jitter_samples\":%u,\"outgoing_echo_samples\":%zu,\"incoming_echo_samples\":%zu,\"released\":true,\"bad_secret_rejected\":true,\"port_rebound\":true}\n", format, incoming.jitter_delay, outgoing_samples, incoming_samples);
    return failed;
}
