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

#include <bpftune/libbpftune.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>

#include "xdp_flow_tuner.h"
#include "xdp_flow_tuner.skel.h"
#include "xdp_flow_tuner.skel.legacy.h"
#include "xdp_flow_tuner.skel.nobtf.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                        */
/* ------------------------------------------------------------------ */

#define FLOW_HASH_SIZE		1024
#define MAX_ATTACHED_INTERFACES	128

/* Path for the binary bitnetflow output file. */
#define BITNETFLOW_PATH		"/tmp/xdp_flow.bitnetflow"

/* ------------------------------------------------------------------ */
/* Attached interface tracking                                          */
/* ------------------------------------------------------------------ */

static int  attached_ifindexes[MAX_ATTACHED_INTERFACES];
static int  num_attached = 0;

/* ------------------------------------------------------------------ */
/* Flow statistics table                                                */
/* ------------------------------------------------------------------ */

struct flow_stats {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;

	__u64 packet_count;
	__u64 total_bytes;
	__u64 first_seen_ns;
	__u64 last_seen_ns;

	/* Welford online mean/variance for inter-arrival time (nanoseconds) */
	double mean_iat;
	double M2_iat;

	struct flow_stats *next;
};

static struct flow_stats *flow_table[FLOW_HASH_SIZE];

static unsigned int flow_hash(__u32 src_ip, __u32 dst_ip,
			      __u16 src_port, __u16 dst_port)
{
	return (src_ip ^ dst_ip ^ ((__u32)src_port << 16) ^ dst_port)
		% FLOW_HASH_SIZE;
}

static struct flow_stats *find_or_create_flow(__u32 src_ip, __u32 dst_ip,
					      __u16 src_port, __u16 dst_port,
					      __u8 protocol)
{
	unsigned int hash = flow_hash(src_ip, dst_ip, src_port, dst_port);
	struct flow_stats *s = flow_table[hash];

	while (s) {
		if (s->src_ip   == src_ip  && s->dst_ip   == dst_ip  &&
		    s->src_port == src_port && s->dst_port == dst_port &&
		    s->protocol == protocol)
			return s;
		s = s->next;
	}

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->src_ip   = src_ip;
	s->dst_ip   = dst_ip;
	s->src_port = src_port;
	s->dst_port = dst_port;
	s->protocol = protocol;
	s->next     = flow_table[hash];
	flow_table[hash] = s;
	return s;
}

static void free_flow_table(void)
{
	for (int i = 0; i < FLOW_HASH_SIZE; i++) {
		struct flow_stats *s = flow_table[i];
		while (s) {
			struct flow_stats *next = s->next;
			free(s);
			s = next;
		}
		flow_table[i] = NULL;
	}
}

/* ------------------------------------------------------------------ */
/* Bitnetflow binary file output                                        */
/* ------------------------------------------------------------------ */

static FILE *bnf_fp = NULL;

static void bitnetflow_open(void)
{
	struct bitnetflow_file_hdr hdr = {
		.magic       = BITNETFLOW_MAGIC,
		.version     = BITNETFLOW_VERSION,
		.record_size = sizeof(struct bitnetflow_record),
	};

	bnf_fp = fopen(BITNETFLOW_PATH, "wb");
	if (!bnf_fp) {
		bpftune_log(LOG_WARNING,
			    "xdp_flow: cannot open %s for writing: %s\n",
			    BITNETFLOW_PATH, strerror(errno));
		return;
	}
	fwrite(&hdr, sizeof(hdr), 1, bnf_fp);
	fflush(bnf_fp);
	bpftune_log(LOG_DEBUG,
		    "xdp_flow: writing bitnetflow records to %s\n",
		    BITNETFLOW_PATH);
}

static void bitnetflow_write(const struct flow_stats *s)
{
	if (!bnf_fp)
		return;

	double variance = s->packet_count > 2
		? s->M2_iat / (double)(s->packet_count - 2)
		: 0.0;

	struct bitnetflow_record rec = {
		.src_ip        = s->src_ip,
		.dst_ip        = s->dst_ip,
		.src_port      = s->src_port,
		.dst_port      = s->dst_port,
		.protocol      = s->protocol,
		.packets       = s->packet_count,
		.total_bytes   = s->total_bytes,
		.first_seen_ns = s->first_seen_ns,
		.last_seen_ns  = s->last_seen_ns,
		/* convert from ns to ms */
		.mean_iat_ms   = (double)(s->mean_iat   / 1e6),
		.stddev_iat_ms = (double)(sqrt(variance) / 1e6),
	};

	fwrite(&rec, sizeof(rec), 1, bnf_fp);
	fflush(bnf_fp);
}

static void bitnetflow_close(void)
{
	if (bnf_fp) {
		fclose(bnf_fp);
		bnf_fp = NULL;
	}
}

/* ------------------------------------------------------------------ */
/* Protocol name helper                                                 */
/* ------------------------------------------------------------------ */

static const char *proto_name(__u8 proto)
{
	switch (proto) {
	case 6:   return "TCP";
	case 17:  return "UDP";
	case 1:   return "ICMP";
	case 58:  return "ICMPv6";
	case 132: return "SCTP";
	default:  return "OTHER";
	}
}

/* ------------------------------------------------------------------ */
/* Docker / virtual-switch interface detection                          */
/* ------------------------------------------------------------------ */

/*
 * Returns true if the interface should be monitored as part of a Docker
 * virtual network switch:
 *
 *   docker0   - default Docker bridge
 *   br-*      - user-defined Docker bridge networks (docker network create)
 *   veth*     - veth pairs that connect containers to bridge
 *
 * Override with BPFTUNE_XDP_FLOW_IFACE env var to pin to a specific iface.
 */
static bool is_docker_iface(const char *name)
{
	return (strcmp(name, "docker0") == 0    ||
		strncmp(name, "br-",  3)  == 0  ||
		strncmp(name, "veth", 4)  == 0);
}

/* ------------------------------------------------------------------ */
/* Bpftune scenario table                                               */
/* ------------------------------------------------------------------ */

static struct bpftunable_scenario scenarios[] = {
	{ XDP_FLOW_SCENARIO_REPORT, "flow updated",
	  "network flow telemetry updated from Docker virtual switch" },
};

/* ------------------------------------------------------------------ */
/* init / fini                                                          */
/* ------------------------------------------------------------------ */

int init(struct bpftuner *tuner)
{
	struct if_nameindex *if_list = NULL;
	int err;

	err = bpftuner_bpf_open(xdp_flow, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_load(xdp_flow, tuner, NULL);
	if (err)
		return err;

	err = bpftune_cap_add();
	if (err) {
		bpftune_log(LOG_ERR,
			    "xdp_flow: cannot add capabilities: %s\n",
			    strerror(-err));
		return 1;
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(tuner->obj,
						 "xdp_monitor_flow");
	if (!prog) {
		bpftune_log(LOG_ERR,
			    "xdp_flow: could not find BPF program "
			    "'xdp_monitor_flow'\n");
		err = -EINVAL;
		goto out_caps;
	}

	int prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		bpftune_log(LOG_ERR, "xdp_flow: invalid program fd\n");
		err = -EINVAL;
		goto out_caps;
	}

	if_list = if_nameindex();
	if (!if_list) {
		bpftune_log(LOG_ERR,
			    "xdp_flow: failed to get network interfaces\n");
		err = -errno;
		goto out_caps;
	}

	const char *target_ifname = getenv("BPFTUNE_XDP_FLOW_IFACE");

	for (int i = 0; if_list[i].if_index != 0; i++) {
		const char *ifname = if_list[i].if_name;

		/* Skip loopback always */
		if (strcmp(ifname, "lo") == 0)
			continue;

		/* If a specific interface is requested, honour it;
		 * otherwise default to Docker virtual-switch interfaces. */
		if (target_ifname) {
			if (strcmp(ifname, target_ifname) != 0)
				continue;
		} else {
			if (!is_docker_iface(ifname))
				continue;
		}

		bpftune_log(LOG_DEBUG,
			    "xdp_flow: attaching XDP to interface %s "
			    "(index %d)\n",
			    ifname, if_list[i].if_index);

		int attach_err = bpf_xdp_attach(if_list[i].if_index,
						 prog_fd,
						 XDP_FLAGS_SKB_MODE, NULL);
		if (attach_err) {
			bpftune_log(LOG_ERR,
				    "xdp_flow: failed to attach XDP to %s: "
				    "%s\n",
				    ifname, strerror(-attach_err));
		} else {
			if (num_attached < MAX_ATTACHED_INTERFACES)
				attached_ifindexes[num_attached++] =
					if_list[i].if_index;
		}
	}
	if_freenameindex(if_list);
	if_list = NULL;

	if (num_attached == 0) {
		bpftune_log(LOG_WARNING,
			    "xdp_flow: no interfaces attached — "
			    "is Docker running? Try setting "
			    "BPFTUNE_XDP_FLOW_IFACE=<iface>\n");
	}

	bitnetflow_open();

	err = bpftuner_tunables_init(tuner, 0, NULL,
				     ARRAY_SIZE(scenarios), scenarios);
	goto out_caps;	/* always drop caps */

out_caps:
	bpftune_cap_drop();
	return err;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);

	if (bpftune_cap_add() == 0) {
		for (int i = 0; i < num_attached; i++) {
			bpftune_log(LOG_DEBUG,
				    "xdp_flow: detaching XDP from "
				    "interface index %d\n",
				    attached_ifindexes[i]);
			bpf_xdp_attach(attached_ifindexes[i], -1,
				       XDP_FLAGS_SKB_MODE, NULL);
		}
		bpftune_cap_drop();
	}
	num_attached = 0;

	bitnetflow_close();
	free_flow_table();
	bpftuner_bpf_fini(tuner);
}

/* ------------------------------------------------------------------ */
/* Event handler — aggregate telemetry → flow record → bitnetflow       */
/* ------------------------------------------------------------------ */

void event_handler(__attribute__((unused)) struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused)) void *ctx)
{
	if (event->scenario_id != XDP_FLOW_SCENARIO_REPORT)
		return;

	const struct xdp_flow_telemetry *tel =
		(const struct xdp_flow_telemetry *)event->raw_data;

	struct flow_stats *s = find_or_create_flow(tel->src_ip, tel->dst_ip,
						   tel->src_port, tel->dst_port,
						   tel->protocol);
	if (!s)
		return;

	/* --- Update flow counters --- */
	if (s->packet_count == 0) {
		s->packet_count  = 1;
		s->total_bytes   = tel->bytes;
		s->first_seen_ns = tel->timestamp;
		s->last_seen_ns  = tel->timestamp;
	} else {
		__u64 iat = tel->timestamp > s->last_seen_ns
			? tel->timestamp - s->last_seen_ns : 0;
		s->last_seen_ns = tel->timestamp;
		s->packet_count++;
		s->total_bytes += tel->bytes;

		/* Welford online mean/variance for IAT (ns) */
		if (s->packet_count == 2) {
			s->mean_iat = (double)iat;
			s->M2_iat   = 0.0;
		} else {
			double n     = (double)(s->packet_count - 1);
			double delta  = (double)iat - s->mean_iat;
			s->mean_iat  += delta / n;
			double delta2 = (double)iat - s->mean_iat;
			s->M2_iat    += delta * delta2;
		}
	}

	/* --- Emit bitnetflow binary record --- */
	bitnetflow_write(s);

	/* --- Pretty-print to stdout (live flow table) --- */
	char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
	struct in_addr sa = { .s_addr = tel->src_ip };
	struct in_addr da = { .s_addr = tel->dst_ip };
	inet_ntop(AF_INET, &sa, src_str, sizeof(src_str));
	inet_ntop(AF_INET, &da, dst_str, sizeof(dst_str));

	double variance   = s->packet_count > 2
		? s->M2_iat / (double)(s->packet_count - 2) : 0.0;
	double avg_bytes  = (double)s->total_bytes / (double)s->packet_count;
	double mean_iat_ms = s->mean_iat / 1e6;
	double jitter_ms   = sqrt(variance) / 1e6;

	fprintf(stdout,
		"[FLOW] %-6s  %-15s:%-5u  ->  %-15s:%-5u  "
		"pkts=%-8llu  bytes=%-10llu  avg_pkt=%-8.1f  "
		"iat=%-8.3fms  jitter=%-8.3fms\n",
		proto_name(s->protocol),
		src_str, (unsigned)s->src_port,
		dst_str, (unsigned)s->dst_port,
		(unsigned long long)s->packet_count,
		(unsigned long long)s->total_bytes,
		avg_bytes, mean_iat_ms, jitter_ms);
	fflush(stdout);
}
