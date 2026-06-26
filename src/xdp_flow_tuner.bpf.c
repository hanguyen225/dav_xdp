/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2026, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <bpftune/bpftune.bpf.h>
#include "xdp_flow_tuner.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP	6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP	17
#endif

/*
 * XDP-safe rate-limiting counter.  We cannot use the stock bpftune_sample()
 * macro because its early-exit "return 0" maps to XDP_ABORTED (packet drop).
 * Instead we track a per-BPF-program packet counter and skip the ring-buffer
 * output for packets that fall outside the sample window.
 *
 * Note: xdp_sample_count is a shared global (not per-CPU), so under heavy
 * multi-core load the effective sample rate may vary slightly.  For a
 * monitoring-only demo this is acceptable.
 */
unsigned int xdp_sample_count = 0;

SEC("xdp")
int xdp_monitor_flow(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	/* --- L2 boundary check --- */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* --- Rate limiting: only emit every bpftune_sample_rate packets ---
	 * Always return XDP_PASS so we never drop packets.
	 */
	{
		unsigned int rate = bpftune_sample_rate ? bpftune_sample_rate : 4;
		if ((xdp_sample_count++ % rate) != 0)
			return XDP_PASS;
	}

	/* --- L3 boundary check --- */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	struct bpftune_event event = {};
	event.tuner_id    = tuner_id;
	event.scenario_id = XDP_FLOW_SCENARIO_REPORT;

	struct xdp_flow_telemetry *tel =
		(struct xdp_flow_telemetry *)event.raw_data;

	tel->src_ip    = ip->saddr;
	tel->dst_ip    = ip->daddr;
	tel->protocol  = ip->protocol;
	tel->bytes     = (__u32)(data_end - data);
	tel->timestamp = bpf_ktime_get_ns();

	/* --- L4 port extraction for TCP and UDP --- */
	__u8 ihl = (ip->ihl & 0x0f) << 2;
	void *l4  = (void *)ip + ihl;

	if ((ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) &&
	    l4 + 4 <= data_end) {
		tel->src_port = bpf_ntohs(*(__u16 *)l4);
		tel->dst_port = bpf_ntohs(*(__u16 *)(l4 + 2));
	}

	bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);

	return XDP_PASS;
}
