#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义 BPF 映射存储配置
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // 配置键，例如事件 ID
    __type(value, __u64); // 配置值，例如过滤参数
} config_map SEC(".maps");

// 统一 kprobe 入口
SEC("kprobe/generic_kprobe")
int generic_kprobe_event(struct pt_regs *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    char *arg0;

    // 读取第一个参数（示例：字符串指针）
    // bpf_core_read(&arg0, sizeof(arg0), (void *)PT_REGS_PARM1(ctx));

    // 检查配置映射
    // __u32 key = 0; // 示例键
    // __u64 *value = bpf_map_lookup_elem(&config_map, &key);
    // if (value) {
        bpf_printk("kprobe triggered: pid=%llu,", pid);
    // }

    return 0;
}

char _license[] SEC("license") = "GPL";