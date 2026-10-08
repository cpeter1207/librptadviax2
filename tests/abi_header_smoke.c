/* SPDX-License-Identifier: GPL-2.0-only */
#include "rptadv_iax2_client.h"

int main(void)
{
	const struct rptadv_iax2_client_descriptor_v1 *descriptor =
		rptadv_iax2_client_descriptor_v1();
	struct rptadv_iax2_dial_options_v1 options = {
		.struct_size = sizeof(options),
		.abi_version = RPTADV_IAX2_CLIENT_ABI_VERSION,
	};
	void *peer = (void *)1;

	return descriptor != NULL && descriptor->dial != NULL &&
		   descriptor->send_digit != NULL &&
		   descriptor->dial(&options, &peer) == -1 && peer == NULL
		? 0
		: 1;
}
