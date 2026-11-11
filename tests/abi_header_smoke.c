/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "rptadv_iax2_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

_Static_assert(offsetof(struct rptadv_iax2_async_descriptor_v1, peer_configure_jitter) ==
    24 + 5 * sizeof(void (*)(void)), "async descriptor prefix changed");
_Static_assert(offsetof(struct rptadv_iax2_async_descriptor_v1, server_enable) ==
    24 + 6 * sizeof(void (*)(void)), "async descriptor tail order changed");
_Static_assert(offsetof(struct rptadv_iax2_async_descriptor_v1, peer_observe) ==
    24 + 7 * sizeof(void (*)(void)), "peer observation tail order changed");
_Static_assert(sizeof(struct rptadv_iax2_peer_observation_v1) == 144,
    "peer observation must match the product POD record");
_Static_assert(offsetof(struct rptadv_iax2_peer_observation_v1, egress_datagrams) == 112,
    "egress observation must preserve the original prefix");
_Static_assert(offsetof(struct rptadv_iax2_async_descriptor_v1, peer_wake) ==
    24 + 8 * sizeof(void (*)(void)), "wake tail must preserve the prefix");
_Static_assert(offsetof(struct rptadv_iax2_async_descriptor_v1, peer_set_deadline) ==
    24 + 9 * sizeof(void (*)(void)), "deadline tail order changed");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v2, prepare_audio) ==
    24 + 9 * sizeof(void (*)(void)), "prepared codec layout differs");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v2, elapsed_ms) ==
    24 + 12 * sizeof(void (*)(void)), "call clock tail order changed");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v2, dial_account) ==
    24 + 13 * sizeof(void (*)(void)), "provider dial tail must preserve prefix");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v2, poll_timed) ==
    136, "timed poll must preserve released136 prefix");
_Static_assert(sizeof(struct rptadv_iax2_timed_event_v1) == 72,
    "timed source record layout differs");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v2, send_prepared_audio_timed) == 144, "timed send tail order");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v2, retire_egress) == 152, "egress retirement tail order");
_Static_assert(sizeof(struct rptadv_iax2_timed_send_v1) == 24, "timed send record layout");

_Static_assert(offsetof(struct rptadv_iax2_server_descriptor_v2, prepare_configuration_batch) == 88,
    "prepared configuration must preserve released88 prefix");
_Static_assert(offsetof(struct rptadv_iax2_server_descriptor_v2, commit_configuration_batch) == 96,
    "configuration commit tail order");
_Static_assert(offsetof(struct rptadv_iax2_server_descriptor_v2, destroy_configuration_batch) == 104,
    "configuration destroy tail order");
_Static_assert(sizeof(struct rptadv_iax2_configuration_entry_v1) == 48,
    "configuration entry stride");

static void *open_catalog(void)
{
	const struct rptadv_iax2_client_descriptor_v2 *client = rptadv_iax2_client_descriptor_v2();
	const char *directory = getenv("RPTADV_CODEC_DIR");
	char path[4096];
	int length = snprintf(path, sizeof(path), "%s%slibrptadv_codec_g711.so.1",
		directory ? directory : "", directory ? "/" : "");
	if (length < 0 || (size_t)length >= sizeof(path))
		return NULL;
	struct rptadv_iax2_codec_selection_v2 selection = {
		.struct_size = sizeof(selection), .profile_id = 1, .provider_path = path,
	};
	void *catalog = NULL;
	if (!client || !client->open_catalog ||
		client->open_catalog(&selection, 1, &catalog) != 0)
		return NULL;
	return catalog;
}

static int server_lifecycle(void)
{
	const struct rptadv_iax2_server_descriptor_v2 *server =
		rptadv_iax2_server_descriptor_v2();
	static const uint8_t address[] = "127.0.0.1:0";
	static const uint8_t nodes[] = "123456";
	void *catalog = open_catalog();
	if (!catalog)
		return 1;
	struct rptadv_iax2_server_options_v2 options = {
		.struct_size = sizeof(options),
		.abi_version = RPTADV_IAX2_SERVER_ABI_VERSION,
		.bind_address = address,
		.bind_address_length = sizeof(address) - 1,
		.local_nodes = nodes,
		.local_nodes_length = sizeof(nodes) - 1,
		.catalog = catalog,
	};
	void *listener = NULL;
	if (server == NULL || server->struct_size != sizeof(*server) ||
		server->abi_version != 2 ||
		memcmp(server->capability, "rptadv.iaxsrv2\0\0", 16) != 0 ||
		server->bind == NULL || server->poll == NULL ||
		server->set_local_nodes == NULL || server->destroy == NULL ||
		server->bind(&options, &listener) != 0 || listener == NULL) {
		rptadv_iax2_client_descriptor_v2()->close_catalog(catalog);
		return 1;
	}
	rptadv_iax2_client_descriptor_v2()->close_catalog(catalog);
	int result = server->set_local_nodes(listener, nodes, sizeof(nodes) - 1) != 0 ||
		server->poll(listener, 0, NULL, NULL, NULL) != 0;
	const struct rptadv_iax2_async_descriptor_v1 *async = rptadv_iax2_async_descriptor_v1();
	void *runtime = NULL;
	if (async->runtime_create(&runtime) != 0 || !runtime) {
		server->destroy(listener);
		return 1;
	}
	result |= async->server_enable(runtime, listener) != 0;
	result |= async->server_enable(runtime, listener) != 0;
	async->runtime_destroy(runtime);
	server->destroy(listener);
	return result;
}

/* Independent provider fixture; all wire/media calls use the actual public header. */
static int provider_lifecycle(const char *address)
{
	const struct rptadv_iax2_client_descriptor_v2 *api = rptadv_iax2_client_descriptor_v2();
	void *catalog = open_catalog();
	void *peer = NULL;
	int failed = 1;
	size_t received = 0;
	static const uint8_t username[] = "club-account", destination[] = "999";
	static const uint8_t number[] = "KG0BP", name[] = "Radio club";
	static const uint8_t context[] = "phone-test", secret[] = "fixture-only";
	struct rptadv_iax2_account_dial_options_v1 options = {
		.struct_size = sizeof(options), .abi_version = 1,
		.remote_address = (const uint8_t *)address, .remote_address_length = strlen(address),
		.local_call_number = 1234,
		.username = username, .username_length = sizeof(username) - 1,
		.destination = destination, .destination_length = sizeof(destination) - 1,
		.caller_number = number, .caller_number_length = sizeof(number) - 1,
		.caller_name = name, .caller_name_length = sizeof(name) - 1,
		.context = context, .context_length = sizeof(context) - 1,
		.secret = secret, .secret_length = sizeof(secret) - 1,
		.timeout_ms = 3000, .catalog = catalog,
	};
	if (!catalog || api->dial_account(&options, &peer) != 0 || !peer ||
		api->sample_rate_hz(peer) != 8000)
		goto done;
	float source[160], output[4096];
	uint8_t encoded[512], text[4096];
	for (size_t sample = 0; sample < 160; sample++)
		source[sample] = 0.25f;
	for (uint32_t block = 0; block < 30; block++) {
		struct rptadv_codec_encode_result_v1 result = { .struct_size = sizeof(result) };
		if (api->prepare_audio(peer, source, 160, encoded, sizeof(encoded), 0, &result) != 0 ||
			!result.encoded_bytes || api->send_prepared_audio(peer, encoded,
			result.encoded_bytes, result.packet_frames, block * 20) != 0)
			goto done;
		for (size_t turn = 0; turn < 8; turn++) {
			uint32_t event = 0;
			size_t count = 0;
			if (api->poll(peer, output, 4096, text, sizeof(text), &event, &count) != 0)
				goto done;
			if (event == RPTADV_IAX2_EVENT_AUDIO)
				received += count;
			else if (event == RPTADV_IAX2_EVENT_NONE)
				break;
		}
		struct timespec pause = { .tv_nsec = 20000000 };
		nanosleep(&pause, NULL);
	}
	if (!received || api->hangup(peer) != 0)
		goto done;
	api->destroy(peer);
	peer = NULL;
	static const uint8_t incorrect[] = "wrong-fixture";
	options.secret = incorrect;
	options.secret_length = sizeof(incorrect) - 1;
	options.local_call_number++;
	if (api->dial_account(&options, &peer) != -4 || peer)
		goto done;
	printf("{\"echo_samples\":%zu,\"bad_password_rejected\":true}\n", received);
	failed = 0;
done:
	if (peer)
		api->destroy(peer);
	if (catalog)
		api->close_catalog(catalog);
	if (failed)
		fprintf(stderr, "provider interop failed; echo samples=%zu\n", received);
	return failed;
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--provider") == 0)
		return provider_lifecycle(argv[2]);
	if (argc != 1)
		return 1;
	const struct rptadv_iax2_async_descriptor_v1 *async = rptadv_iax2_async_descriptor_v1();
	void *runtime = NULL;
	void *registration = (void *)1;
	if (!async || async->abi_version != 1 || async->struct_size != sizeof(*async) ||
		!async->peer_wake || !async->peer_set_deadline ||
		async->runtime_create(&runtime) != 0 || !runtime ||
		async->peer_configure_jitter(NULL, NULL) != -1 ||
		async->server_enable(runtime, NULL) != -1 ||
		async->peer_attach(runtime, NULL, NULL, NULL, &registration) != -1 || registration)
		return 1;
	async->runtime_destroy(runtime);
	const struct rptadv_iax2_client_descriptor_v2 *descriptor =
		rptadv_iax2_client_descriptor_v2();
	struct rptadv_iax2_dial_options_v2 options = {
		.struct_size = sizeof(options),
		.abi_version = RPTADV_IAX2_CLIENT_ABI_VERSION,
	};
	void *peer = (void *)1;

	return descriptor != NULL && descriptor->struct_size == sizeof(*descriptor) &&
		   descriptor->abi_version == 2 &&
		   memcmp(descriptor->capability, "rptadv.iax2.v2\0\0", 16) == 0 &&
		   descriptor->prepare_audio != NULL && descriptor->send_prepared_audio != NULL &&
		   descriptor->open_catalog != NULL && descriptor->close_catalog != NULL &&
		   descriptor->reset_encoder != NULL &&
		   descriptor->elapsed_ms != NULL && descriptor->dial != NULL &&
		   descriptor->dial_account != NULL &&
		   descriptor->send_digit != NULL &&
		   descriptor->dial(&options, &peer) == -1 && peer == NULL &&
		   server_lifecycle() == 0
		? 0
		: 1;
}
