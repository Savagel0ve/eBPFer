#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include "kprobe_gateway.h"
#include "kprobe_gateway.skel.h"


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

    struct bpf_link* link = bpf_program__attach_kprobe(skel->progs.generic_kprobe_event,false,"security_file_open");
	if (link == NULL) {
		fprintf(stderr, "Error: bpf_program__attach failed\n");
		return 1;
	}

    // struct bpf_link* link = bpf_program__attach(skel->progs.generic_kprobe_event);
	// if (link == NULL) {
	// 	fprintf(stderr, "Error: bpf_program__attach failed\n");
	// 	return 1;
	// }
    

    printf("Tail call setup complete. Waiting for kprobe to trigger...\n");

    // 保持运行
    while (1) {
        sleep(1);
    }

cleanup:
    kprobe_gateway_bpf__destroy(skel);
    return err != 0;
}
