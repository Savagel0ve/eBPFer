#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "kprobe_gateway.h"
#include "kprobe_gateway.skel.h"


int test_policy(struct kprobe_gateway_bpf *skel){
    __u32 pid = 22077;
    // int ret = -1;
    struct policy test = {
        .kind = FILE_POLICY,
        .pid = 22077,
        .file_path = "1.txt",
        .comm = "python3",
    };
    int err = bpf_map__update_elem(skel->maps.filter_map, &pid, sizeof(__u32), &test, sizeof(struct policy), BPF_ANY);
    if (err < 0) {
        perror("map update failed");
        return -1;
    }

    // bpf_map__update_elem(skel->maps.override_tasks, &pid, sizeof(__u32), &ret, sizeof(int), BPF_ANY);

    return 0;

}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main() {
    struct kprobe_gateway_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // 1. 加载 skeleton
    skel = kprobe_gateway_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2. 附加主程序（kprobe 入口）
    err = kprobe_gateway_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    const char *kernel_func = "__x64_sys_openat";
    struct bpf_link* link = bpf_program__attach_kprobe(skel->progs.generic_kprobe_event,false, kernel_func);
	if (link == NULL) {
		fprintf(stderr, "Error:generic bpf_program__attach failed\n");
		return 1;
	}

    struct bpf_link* link1 = bpf_program__attach_kprobe(skel->progs.generic_kprobe_override,false, kernel_func);
	if (link1 == NULL) {
		fprintf(stderr, "Error: override bpf_program__attach failed\n");
		return 1;
	}


    // struct bpf_link* link = bpf_program__attach(skel->progs.generic_kprobe_event);
	// if (link == NULL) {
	// 	fprintf(stderr, "Error: bpf_program__attach failed\n");
	// 	return 1;
	// }
    
    test_policy(skel);

    printf("Tail call setup complete. Waiting for kprobe to trigger...\n");

    // 保持运行
    while (1) {
        sleep(1);
    }

cleanup:
    kprobe_gateway_bpf__destroy(skel);
    return err != 0;
}
