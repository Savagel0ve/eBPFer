/*
统一 kprobe 入口与过滤链
 */

// #include <linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
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
int generic_kprobe_filter_arg(void *ctx);
int generic_kprobe_actions(void *ctx);
// int generic_kprobe_output(void *ctx);
// int generic_kprobe_path(void *ctx);

int generic_kprobe_override(struct pt_regs *ctx);

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
		[2] = (void *)&generic_kprobe_filter_arg,
		[1] = (void *)&generic_kprobe_actions,
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, int);
} override_tasks SEC(".maps");


static __inline int str_equals(const char *s1, const char *s2, int max_len) {
    int i = 0;
    for (; i < max_len; i++) {
        char c1 = s1[i];
        char c2 = s2[i];

        if (c1 != c2)
            return 0; // not equal

        if (c1 == '\0') // both strings ended
            return 1; // equal
    }
    return 1; // equal up to max_len
}


SEC("kprobe")
int generic_kprobe_actions(void *ctx){
	  
	bpf_printk("process_actions_kprobe triggered:");
	__u64 id = bpf_get_current_pid_tgid();
	int ret = -1;
	// bpf_send_signal(SIGKILL);
	bpf_map_update_elem(&override_tasks, &id, &ret, BPF_ANY);
	return 0;
}


SEC("kprobe")
int generic_kprobe_process_filter(void *ctx)
{	
	
    // bpf_printk("process_filter_kprobe triggered:");
	__u64 pid = bpf_get_current_pid_tgid() >> 32;
	struct policy *test = bpf_map_lookup_elem(&filter_map, &pid);
	if(test){
		char comm[TASK_COMM_LEN];
		// bpf_printk("current comm is %s", comm);
  		if(!bpf_get_current_comm(comm, TASK_COMM_LEN)){
			bpf_printk("current comm is %s %d", comm, sizeof(comm));
			if(str_equals(test->comm, comm, sizeof(comm))){
				bpf_printk("block current comm is %s", comm);
				bpf_tail_call(ctx, &kprobe_calls, 1);
			}
		}
	}
	bpf_tail_call(ctx, &kprobe_calls, 2);
    return 0;
}


SEC("kprobe")
int generic_kprobe_filter_arg(void *ctx){
	
	// bpf_printk("filter arg triggered");
	__u64 pid = bpf_get_current_pid_tgid() >> 32;
	struct policy *test = bpf_map_lookup_elem(&filter_map, &pid);
	const char filename[FILE_PATH_MAX_LEN] = {};
	

	struct pt_regs *new_ctx = PT_REGS_SYSCALL_REGS((struct pt_regs*)ctx);
	int len = bpf_probe_read_user_str((void *)filename, FILE_PATH_MAX_LEN, (const char *)PT_REGS_PARM2_CORE_SYSCALL(new_ctx));

	// bpf_printk("open file %x", &regs->si);
	if(test){
		//  bpf_printk("block file %s", filename, test->file_path);
		if(str_equals(test->file_path, filename,  sizeof(filename))){
			bpf_tail_call(ctx, &kprobe_calls, 1);
		}
	}
	return 0;
}


static inline __attribute__((always_inline)) int
generic_kprobe_start_process_filter(void *ctx){
    // bpf_printk("start_process_filter_kprobe triggered:");

    bpf_tail_call(ctx, &kprobe_calls, 0);
    bpf_printk("tail call failed");
    return 0;
}



// 统一 kprobe 入口
SEC("kprobe")
int generic_kprobe_event(struct pt_regs *ctx)
{
    
    return generic_kprobe_start_process_filter(ctx);

}

__attribute__((section(("kprobe")), used)) int
generic_kprobe_override(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__s32 *error;

	error = bpf_map_lookup_elem(&override_tasks, &id);
	if (!error)
		return 0;

	bpf_override_return(ctx, *error);
	// bpf_map_delete_elem(&override_tasks, &id);
	return 0;
}
