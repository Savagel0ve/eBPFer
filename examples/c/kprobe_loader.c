//网关函数加载器
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

//加载统一网关函数
int kprobe_generic_loader(const char *kernel_func){
  
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link* link;
   
    int err;
    obj = bpf_object__open_file("kprobe_gateway.bpf.o", NULL);
    if (libbpf_get_error(obj)) { 
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    // 加载 eBPF 程序
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        return 1;
    }

    // 查找 eBPF 程序
    prog = bpf_object__find_program_by_name(obj, "generic_kprobe_event");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program: %s\n", strerror(errno));
        return 1;
    }

    // 设置 kprobe 目标函数
    link = bpf_program__attach_kprobe(prog, false, kernel_func);

    if (libbpf_get_error(link)) {
        int err = -libbpf_get_error(link); 
        fprintf(stderr,  "Failed to set kprobe for %s: %s\n", kernel_func, strerror(err));
        return 1;
    }
    
    bpf_object__close(obj);
    bpf_program__unload(prog);
    return 0;
}


// int main(int argc, char **argv)
// {
//     if (argc < 2) {
//         fprintf(stderr, "Usage: %s <kernel_function>\n", argv[0]);
//         return 1;
//     }

//     const char *kernel_func = argv[1]; 

    
//     char cmd[256];
//     snprintf(cmd, sizeof(cmd), "grep %s /proc/kallsyms", kernel_func);
//     if (system(cmd) != 0) {
//         fprintf(stderr, "Kernel function %s not found in /proc/kallsyms\n", kernel_func);
//         return 1;
//     }   



//     int err = kprobe_generic_loader(kernel_func);
//     if(!err){
//         printf("kprobe attached to %s, press Ctrl+C to exit\n", kernel_func);
//     } 
    

//     // 保持运行
//     while (1) {
//         sleep(1);
//     }

    
//     return 0;
// }