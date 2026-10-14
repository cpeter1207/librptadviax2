/* SPDX-License-Identifier: GPL-2.0-only */
#include "rptadv_iax2_client.h"
#include <string.h>

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
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v1, prepare_ulaw) ==
    24 + 8 * sizeof(void (*)(void)), "prepared codec tail must preserve the prefix");
_Static_assert(offsetof(struct rptadv_iax2_client_descriptor_v1, elapsed_ms) ==
    24 + 10 * sizeof(void (*)(void)), "call clock tail order changed");

static int server_lifecycle(void)
{
	const struct rptadv_iax2_server_descriptor_v1 *server =
		rptadv_iax2_server_descriptor_v1();
	static const uint8_t address[] = "127.0.0.1:0";
	static const uint8_t nodes[] = "123456";
	struct rptadv_iax2_server_options_v1 options = {
		.struct_size = sizeof(options),
		.abi_version = RPTADV_IAX2_SERVER_ABI_VERSION,
		.bind_address = address,
		.bind_address_length = sizeof(address) - 1,
		.local_nodes = nodes,
		.local_nodes_length = sizeof(nodes) - 1,
	};
	void *listener = NULL;
	if (server == NULL || server->struct_size != sizeof(*server) ||
		server->abi_version != 1 ||
		memcmp(server->capability, "rptadv.iaxsrv1\0\0", 16) != 0 ||
		server->bind == NULL || server->poll == NULL ||
		server->set_local_nodes == NULL || server->destroy == NULL ||
		server->bind(&options, &listener) != 0 || listener == NULL)
		return 1;
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

int main(void)
{
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
	const struct rptadv_iax2_client_descriptor_v1 *descriptor =
		rptadv_iax2_client_descriptor_v1();
	struct rptadv_iax2_dial_options_v1 options = {
		.struct_size = sizeof(options),
		.abi_version = RPTADV_IAX2_CLIENT_ABI_VERSION,
	};
	void *peer = (void *)1;

	return descriptor != NULL && descriptor->struct_size == sizeof(*descriptor) &&
		   descriptor->abi_version == 1 &&
		   memcmp(descriptor->capability, "rptadv.iax2.v1\0\0", 16) == 0 &&
		   descriptor->prepare_ulaw != NULL && descriptor->send_prepared_ulaw != NULL &&
		   descriptor->elapsed_ms != NULL && descriptor->dial != NULL &&
		   descriptor->send_digit != NULL &&
		   descriptor->dial(&options, &peer) == -1 && peer == NULL &&
		   server_lifecycle() == 0
		? 0
		: 1;
}
