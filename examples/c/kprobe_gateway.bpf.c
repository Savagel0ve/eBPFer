/*
统一 kprobe 入口与过滤链
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "kprobe_gateway.h"

char __license[] SEC("license") = "GPL";

enum {
	TAIL_CALL_SETUP = 0,
	TAIL_CALL_PROCESS = 1,
	TAIL_CALL_FILTER = 2,
	TAIL_CALL_ARGS = 3,
	TAIL_CALL_ACTIONS = 4,
	TAIL_CALL_SEND = 5,
	TAIL_CALL_PATH = 6,
};


// int generic_kprobe_setup_event(void *ctx);
// int generic_kprobe_process_event(void *ctx);
int generic_kprobe_process_filter(void *ctx);
// int generic_kprobe_filter_arg(void *ctx);
// int generic_kprobe_actions(void *ctx);
// int generic_kprobe_output(void *ctx);
// int generic_kprobe_path(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} kprobe_calls SEC(".maps") = {
	.values = {
		// [TAIL_CALL_SETUP] = (void *)&generic_kprobe_setup_event,
		// [TAIL_CALL_PROCESS] = (void *)&generic_kprobe_process_event,
		[0] = (void *)&generic_kprobe_process_filter,
		// [TAIL_CALL_ARGS] = (void *)&generic_kprobe_filter_arg,
		// [TAIL_CALL_ACTIONS] = (void *)&generic_kprobe_actions,
		// [TAIL_CALL_SEND] = (void *)&generic_kprobe_output,
// #ifndef __V61_BPF_PROG
// 		[TAIL_CALL_PATH] = (void *)&generic_kprobe_path,
// #endif
	},
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy);
} filter_map SEC(".maps");



SEC("kprobe")
int generic_kprobe_process_filter(void *ctx)
{	
	
    bpf_printk("process_filter_kprobe triggered:");
    return 0;

}



static inline __attribute__((always_inline)) int
generic_kprobe_start_process_filter(void *ctx){
    bpf_printk("start_process_filter_kprobe triggered:");
    bpf_tail_call(ctx, &kprobe_calls, 0);
    bpf_printk("tail call failed");
    return 0;
}



// 统一 kprobe 入口
SEC("kprobe")
int generic_kprobe_event(struct pt_regs *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("generic_kprobe triggered: pid=%llu,", pid);

    return generic_kprobe_start_process_filter(ctx);

}