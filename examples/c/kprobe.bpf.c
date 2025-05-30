// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura 
* fileName:kprobe.bpf.c
* author: sleepalone
* vsersion: 1.0
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


//define maps
struct {
	__uint(type, BPF_MAP_TYPE_HASH); // use hash
	__uint(max_entries, 8192); // set max_entries is 8192
	__type(key, char[MAX_FILE_PATH]); // key is filepath  paresd from json file
	__type(value, u64); //value is flag parsed from json file
} file_maps SEC(".maps");


// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 8192);
// 	__type(key, char[100]);
// 	__type(value, u64);
// } test_maps SEC(".maps");




/*
 * Kprobe for unlink syscall
 * This function is called when a process attempts to delete a file.
 * It checks if the file is in the file_maps and if the process has permission to delete it.
 * If not, it blocks the deletion.
*/
SEC("kprobe/__x64_sys_unlink")
int BPF_KPROBE(__x64_sys_unlink, const char* pathname)
{
	pid_t pid;
	char filename[MAX_FILE_PATH] = {0};

	pid = bpf_get_current_pid_tgid() >> 32;
	
	struct pt_regs *new_ctx = PT_REGS_SYSCALL_REGS(ctx);
	int len = bpf_probe_read_user_str(filename, MAX_FILE_PATH, (const char *)PT_REGS_PARM1_CORE_SYSCALL(new_ctx));

	bpf_printk("KPROBE DELETE ENTRY pid = %d, filename = %s len=%d\n", pid, filename, len);

	u64 *flags = bpf_map_lookup_elem(&file_maps, &filename);
	if(flags && *flags >> 32 == pid){
		bpf_printk("PID MATCHED: %d\n", pid);
		if (*flags & DELETE)   { 
		bpf_printk("Blocked deletion of file: %s %d\n", filename, *flags) ;
		bpf_override_return(ctx, -1);
		return -1; 
		}
	}
	
	return 0; 
}


/*
 * Kprobe for unlinkat syscall
 * This function is called when a process attempts to delete a file.
 * It checks if the file is in the file_maps and if the process has permission to delete it.
 * If not, it blocks the deletion.
*/
SEC("kprobe/__x64_sys_unlinkat")
int BPF_KPROBE(__x64_sys_unlinkat, int dfd, const char* pathname, int flag)
{
	pid_t pid;
	char filename[MAX_FILE_PATH] = {0};

	pid = bpf_get_current_pid_tgid() >> 32;
	
	struct pt_regs *new_ctx = PT_REGS_SYSCALL_REGS(ctx);
	int len = bpf_probe_read_user_str(filename, MAX_FILE_PATH, (const char *)PT_REGS_PARM2_CORE_SYSCALL(new_ctx));

	bpf_printk("KPROBE DELETE ENTRY pid = %d, filename = %s len=%d\n", pid, filename, len);

	u64 *flags = bpf_map_lookup_elem(&file_maps, &filename);
	if(flags && *flags >> 32 == pid){
		bpf_printk("PID MATCHED: %d\n", pid);
		if (*flags & DELETE)   { 
		bpf_printk("Blocked deletion of file: %s %d\n", filename, *flags) ;
		bpf_override_return(ctx, -1);
		return -1; 
		}
	}
	
	return 0; 
}



/*
 * Kprobe for open syscall
 * This function is called when a process attempts to open a file.
 * It checks if the file is in the file_maps and if the process has permission to read or write it.
 * If not, it blocks the operation.
*/
SEC("kprobe/__x64_sys_open")
int BPF_KPROBE(__x64_sys_open, const char *filename, int flags, umode_t mode)
{
	pid_t pid;
	char file_name[MAX_FILE_PATH] = {0};

	pid = bpf_get_current_pid_tgid() >> 32;
	struct pt_regs *new_ctx = PT_REGS_SYSCALL_REGS(ctx);
	int len = bpf_probe_read_user_str(file_name, MAX_FILE_PATH, (const char *)PT_REGS_PARM2_CORE_SYSCALL(new_ctx));
	flags = PT_REGS_PARM3_CORE_SYSCALL(new_ctx);

	bpf_printk("KPROBE X64_OPEN ENTRY: pid = %d, filename = %s  flags = %d\n", pid, file_name, flags);

	u64 *json_flags = bpf_map_lookup_elem(&file_maps, &file_name);
	if (json_flags && *json_flags >> 32 == pid){ 
		if(*json_flags & READ){
			bpf_printk("Blocked read operation of file: %s %d\n", file_name, *json_flags) ;
			bpf_override_return(ctx, -1);
			return -1; 
		}
		if(*json_flags & WRITE){
			bpf_printk("Blocked write operation of file: %s %d\n", file_name, *json_flags) ;
			bpf_override_return(ctx, -1);
			return -1; 
		}
	}
	return 0;
}


/*
 * Kprobe for openat syscall
 * This function is called when a process attempts to open a file.
 * It checks if the file is in the file_maps and if the process has permission to read or write it.
 * If not, it blocks the operation.
*/
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(__x64_sys_openat, int dfd, const char *filename, int flags, umode_t mode){
	pid_t pid;
	char file_name[MAX_FILE_PATH] = {0};

	pid = bpf_get_current_pid_tgid() >> 32;


	struct pt_regs *new_ctx = PT_REGS_SYSCALL_REGS(ctx);
	int len = bpf_probe_read_user_str(file_name, MAX_FILE_PATH, (const char *)PT_REGS_PARM2_CORE_SYSCALL(new_ctx));
	flags = PT_REGS_PARM3_CORE_SYSCALL(new_ctx);

	bpf_printk("KPROBE X64_OPENAT ENTRY: pid = %d, filename = %s flags = %d\n", pid, file_name, flags);

	u64 *json_flags = bpf_map_lookup_elem(&file_maps, &file_name);
	if (json_flags && *json_flags >> 32  == pid){ 
		if( *json_flags & READ){
			bpf_printk("Blocked read operation of file: %s %d\n", file_name, *json_flags) ;
			bpf_override_return(ctx, -1);
			return -1; 
		}
		if( *json_flags & WRITE){
			bpf_printk("Blocked write operation of file: %s %d\n", file_name, *json_flags) ;
			bpf_override_return(ctx, -1);
			return -1; 
		}
	}


	return 0;
}


