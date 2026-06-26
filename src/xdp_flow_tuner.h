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

#ifndef __XDP_FLOW_TUNER_H
#define __XDP_FLOW_TUNER_H

#include <bpftune/bpftune.h>

enum {
	XDP_FLOW_SCENARIO_REPORT
};

/*
 * Per-packet telemetry sent from BPF to userspace via ring buffer.
 * Must fit within BPFTUNE_MAX_DATA (128 bytes).
 */
struct xdp_flow_telemetry {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;		/* IPPROTO_TCP=6, IPPROTO_UDP=17, etc. */
	__u8  _pad[3];
	__u32 bytes;		/* total packet bytes including all headers */
	__u64 timestamp;	/* bpf_ktime_get_ns() */
};

/*
 * Bitnetflow binary output format.
 * Written to /tmp/xdp_flow.bitnetflow as a stream of records, one per flow.
 * Magic: "BNFP" (0x424E4650).
 */
#define BITNETFLOW_MAGIC	0x424E4650U
#define BITNETFLOW_VERSION	1

struct bitnetflow_file_hdr {
	__u32 magic;
	__u16 version;
	__u16 record_size;	/* sizeof(struct bitnetflow_record) */
};

struct bitnetflow_record {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u8  _pad[3];
	__u64 packets;
	__u64 total_bytes;
	__u64 first_seen_ns;	/* nanoseconds from bpf_ktime_get_ns */
	__u64 last_seen_ns;
	double mean_iat_ms;
	double stddev_iat_ms;
};

#endif /* __XDP_FLOW_TUNER_H */
