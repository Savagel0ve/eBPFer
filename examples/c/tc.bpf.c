// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <linux/pkt_cls.h> 


#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);


	__u32 src_ip = __bpf_ntohl(l3->saddr);
    __u8 a = (src_ip >> 24) & 0xFF;
    __u8 b = (src_ip >> 16) & 0xFF;
    __u8 c = (src_ip >> 8) & 0xFF;
    __u8 d = src_ip & 0xFF;
    bpf_printk("Source IP: %d.%d.%d.%d", a, b, c, d);
	if(a == 127 && b == 0 && c == 0 && d == 1){
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
