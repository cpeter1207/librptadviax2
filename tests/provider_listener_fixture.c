/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "rptadv_iax2_client.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct rptadv_iax2_server_options_v2) == 64, "server options layout");
_Static_assert(sizeof(struct rptadv_iax2_server_descriptor_v2) == 88, "server tail layout");
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

static size_t echo(const struct rptadv_iax2_client_descriptor_v2 *api, void *peer, uint32_t timestamp_offset)
{
    float source[160], output[4096];
    uint8_t encoded[512], body[4096];
    for (size_t i = 0; i < 160; ++i) source[i] = 0.25f;
    size_t received = 0, qualified = 0, prepared_bytes = 0;
    uint32_t prepared_frames = 0, prepared_timestamp = 0;
    int prepared = 0;
    uint64_t tx_epoch = 0;
    if (api->retire_egress(peer, &tx_epoch) != 0 || !tx_epoch) return 0;
    struct rptadv_iax2_timed_send_v1 send_time = { .struct_size = sizeof(send_time), .abi_version = 1, .egress_epoch = tx_epoch };
    uint64_t acknowledged = 0, cursor = 0, epoch = 0;
    double energy = 0;
    uint64_t deadline = now_ms() + 4000;
    uint64_t next = now_ms();
    while (now_ms() < deadline) {
        if (!prepared && now_ms() >= next) {
            /* Native floor FIRST, then generation of this new test tone block.
             * The remaining500ms budget/deadline stays unchanged on WouldBlock. */
            uint32_t native = api->elapsed_ms(peer);
            if (native > UINT32_MAX - 500) return 0;
            send_time.deadline_ms = native + 500;
            prepared_timestamp = native + timestamp_offset;
            struct rptadv_codec_encode_result_v1 coded = { .struct_size = sizeof(coded) };
            if (api->prepare_audio(peer, source, 160, encoded, sizeof(encoded), 0, &coded) != 0 ||
                coded.consumed_frames != 160 || coded.encoded_bytes == 0) return 0;
            prepared_bytes = coded.encoded_bytes;
            prepared_frames = coded.packet_frames;
            prepared = 1;
        }
        if (prepared) {
            int sent = api->send_prepared_audio_timed(peer, encoded, prepared_bytes, prepared_frames, prepared_timestamp, &send_time);
            if (sent == 0) { prepared = 0; next += 20; }
            else if (sent != 1) return 0;
        }
        struct rptadv_iax2_timed_event_v1 timed = { .struct_size = sizeof(timed),
            .abi_version = 1, .host_clock_epoch = 1, .reference_now_ns = now_ns(),
            .acknowledged_media_epoch = acknowledged };
        if (api->poll_timed(peer, output, 4096, body, sizeof(body), &timed) != 0) return 0;
        if (timed.flags & RPTADV_IAX2_TIMED_DISCONTINUITY) {
            if (timed.event_kind == RPTADV_IAX2_EVENT_AUDIO || timed.event_kind == RPTADV_IAX2_EVENT_GAP) return 0;
            /* This fixture owns no retained downstream PCM/DSP/RF context. Its
             * old output is already consumed; acknowledge this actual target. */
            acknowledged = timed.media_epoch;
            cursor = 0;
            epoch = timed.media_epoch;
        }
        if (timed.event_kind == RPTADV_IAX2_EVENT_AUDIO || timed.event_kind == RPTADV_IAX2_EVENT_GAP) {
            if (timed.media_epoch != epoch || timed.source_start != cursor) return 0;
            cursor += timed.event_length;
        }
        if (timed.event_kind == RPTADV_IAX2_EVENT_AUDIO) {
            if (timed.flags & RPTADV_IAX2_TIMED_BIRTH) {
                if (timed.born_ns > timed.reference_now_ns - 5000000) return 0;
                qualified += timed.event_length;
            }
            received += timed.event_length;
            for (size_t i = 0; i < timed.event_length; ++i) energy += output[i] * output[i];
        }
        if (received >= 1600 && qualified >= 1600 && energy > 1) return received;
        struct timespec wait = { .tv_nsec = 1000000 };
        nanosleep(&wait, NULL);
    }
    return 0;
}

static int phone_jitter(const struct rptadv_iax2_async_descriptor_v1 *async, void *peer, const void *descriptor, unsigned *delay)
{
    struct rptadv_iax2_peer_observation_v1 observation = { .struct_size = sizeof(observation), .abi_version = 1 };
    if (async->peer_configure_jitter(peer, descriptor) != 0 || async->peer_observe(peer, &observation) != 0) return 0;
    *delay = observation.jitter_delay_samples;
    return *delay == 320;
}

struct incoming {
    void *peer;
    uint16_t port;
    unsigned authorized;
    unsigned format;
    unsigned jitter_delay;
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
    if (!phone_jitter(state->async, peer, state->jitter, &state->jitter_delay)) return -1;
    state->peer = peer;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[2], "ulaw") != 0 && strcmp(argv[2], "alaw") != 0)) return 2;
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
    struct incoming incoming = { .format = format, .async = async, .jitter = jitter };
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
    if (!phone_jitter(async, outgoing, jitter, &outgoing_delay) || !(outgoing_samples = echo(api, outgoing, 65520))) goto done;
    api->destroy(outgoing); outgoing = NULL;
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
    if (!incoming.peer || incoming.authorized != 1 || !(incoming_samples = echo(api, incoming.peer, 0))) goto done;
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
