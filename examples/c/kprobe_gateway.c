#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "kprobe_gateway.skel.h"


struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	int map_prog_idx;
	struct bpf_program *prog;
};


static struct bpf_progs_desc progs[] = {
	{"generic_kprobe_event", BPF_PROG_TYPE_KPROBE, -1, NULL},
	{"generic_kprobe_process_filter", BPF_PROG_TYPE_KPROBE, 0, NULL},
};



int main() {
    struct kprobe_gateway_bpf *skel;
    int err;

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


    int map_fd  = bpf_map__fd(skel->maps.kprobe_calls);
    int prog_count = sizeof(progs) / sizeof(progs);
    for(int i = 0; i < prog_count; i++){
        progs[i].prog = bpf_object__find_program_by_name(skel->obj, progs[i].name);
        if (!progs[i].prog) {
			fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
			return 1;
		}
        bpf_program__set_type(progs[i].prog, progs[i].type);
    } 

    for(int i = 0; i < prog_count; i++){
        int prog_fd = bpf_program__fd(progs[i].prog);
        if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}
        if (progs[i].map_prog_idx != -1) {
			unsigned int map_prog_idx = progs[i].map_prog_idx;
			if (map_prog_idx < 0) {
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
				return 1;
			}
			err = bpf_map_update_elem(map_fd, &map_prog_idx, &prog_fd, 0);
			if (err) {
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				return 1;
			}
		}
    }

    struct bpf_link* link = bpf_program__attach_kprobe(skel->progs.generic_kprobe_event,false,"security_file_open");
	if (link == NULL) {
		fprintf(stderr, "Error: bpf_program__attach failed\n");
		return 1;
	}
    

    printf("Tail call setup complete. Waiting for kprobe to trigger...\n");

    // 保持运行
    while (1) {
        sleep(1);
    }

cleanup:
    kprobe_gateway_bpf__destroy(skel);
    return err != 0;
}
