// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook 
 * fileName:kprobe.c
 * author: sleepalone
 * vsersion: 1.0
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe.skel.h"
#include "cjson/cJSON.h"
#include "kprobe.h"
#include "zlog.h"
#include "kprobe_loader.h"


static zlog_category_t *zlog_cat = NULL;

/*
* Function to parse JSON file and extract file operations
* @param filename: Path to the JSON file
* @param file_ops: Pointer to the file_operations_t structure to fill
* @return: success, or error code
*/
int parseJson(char *filename, file_operations_t *file_ops){

    file_ops->op_count = 0;

    FILE *file = fopen(filename, "r");
    if(!file){
        perror("could not open file");
        zlog_error(zlog_cat, "Could not open file: %s [Error Code: %d]", strerror(errno), ERR_FILE_OPEN);
        return ERR_FILE_OPEN;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0 , SEEK_SET);

    char *buffer = (char *)malloc(file_size + 1);
    if(!buffer){
        perror("Could not allocate buffer");
        zlog_error(zlog_cat, "Could not allocate buffer: %s [Error Code: %d]", strerror(errno), ERR_MEMORY_ALLOC);
        fclose(file);
        return ERR_MEMORY_ALLOC;
    }
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    cJSON * json = cJSON_Parse(buffer);
    if(json == NULL){
        printf("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        zlog_error(zlog_cat, "Error parsing JSON: %s [Error Code: %d]", cJSON_GetErrorPtr(), ERR_JSON_PARSE);
        free(buffer);
        return ERR_JSON_PARSE;
    }

    cJSON *rule_id = cJSON_GetObjectItemCaseSensitive(json, "rule_id");
    if(rule_id && cJSON_IsString(rule_id)){
        printf("Rule ID: %s\n", rule_id->valuestring);
    }else{
        printf("rule_id NOT FOUND OR Invalid rule_id in JSON\n");
        zlog_error(zlog_cat, "rule_id NOT FOUND OR Invalid rule_id in JSON [Error Code: %d]", ERR_INVALID_RULE_ID);
        cJSON_Delete(json);
        free(buffer);
        return ERR_INVALID_RULE_ID;
    }

    zlog_info(zlog_cat, "Rule ID: %s", rule_id->valuestring);    

    cJSON *file_name_array = cJSON_GetObjectItem(json, "file_name");
    if (file_name_array &&  cJSON_IsArray(file_name_array)) {
        for(int i = 0; i < cJSON_GetArraySize(file_name_array); i++){
            cJSON *file_entry = cJSON_GetArrayItem(file_name_array, i);
            if (file_entry) {
                cJSON *file_path = cJSON_GetObjectItem(file_entry, "file_path");
                if (!file_path || !cJSON_IsString(file_path)) {
                    printf("Invalid file_path in JSON\n");
                    zlog_error(zlog_cat, "Invalid file_path in JSON [Error Code: %d]", ERR_INVALID_FILE_PATH);
                    cJSON_Delete(json);
                    free(buffer);
                    return ERR_INVALID_FILE_PATH;
                }
                zlog_info(zlog_cat, "File path: %s", file_path->valuestring);
                strncpy(file_ops->file_path, file_path->valuestring, MAX_FILE_PATH - 1);

                
                cJSON *disallowed_operations = cJSON_GetObjectItem(file_entry, "disallowed_operations");
                 if (disallowed_operations && cJSON_IsArray(disallowed_operations)) {
                    int size = cJSON_GetArraySize(disallowed_operations);
                    if(size > MAX_ENTRIES){
                        printf("Too many disallowed operations, max is %d, current is %d\n", MAX_ENTRIES, size);
                        zlog_error(zlog_cat, "Too many disallowed operations, max is %d, current is %d [Error Code: %d]", MAX_ENTRIES, size, ERR_TOO_MANY_OPS);
                        cJSON_Delete(json);
                        free(buffer);
                        return ERR_TOO_MANY_OPS;
                    }
                    for (int j = 0; j < size; j++) {
                        cJSON *operation = cJSON_GetArrayItem(disallowed_operations, j);
                        if (operation && cJSON_IsString(operation)) {
                            file_ops->op_count++;
                            strncpy(file_ops->disallowed_operations[j], operation->valuestring, MAX_OPERATION_LENGTH - 1);
                            printf("Disallowed operation: %s\n", file_ops->disallowed_operations[j]);
                            zlog_info(zlog_cat, "disallowed_operations[%d] = %s", j, file_ops->disallowed_operations[j]);
                        }
                    }
                }
            }
        }
        
    }

    // allowed_processes
    cJSON *allowed_processes = cJSON_GetObjectItem(json, "allowed_processes");
    if (!allowed_processes || !cJSON_IsString(allowed_processes)) {
        printf("allowed_processes NOT FOUND OR Invalid allowed_processes in JSON\n");
        zlog_error(zlog_cat, "allowed_processes NOT FOUND OR Invalid allowed_processes in JSON [Error Code: %d]", ERR_INVALID_PID);
        cJSON_Delete(json);
        free(buffer);
        return ERR_INVALID_PID;
    }
    zlog_info(zlog_cat, "allowed_processes: %s", allowed_processes->valuestring);
    char *endptr;
    long pid = strtol(allowed_processes->valuestring, &endptr, 10);
    if (*endptr != '\0') {
        printf("allowed_processes is not a valid number\n");
        zlog_error(zlog_cat, "allowed_processes is not a valid number [Error Code: %d]", ERR_INVALID_PID);
        cJSON_Delete(json);
        free(buffer);
        return ERR_INVALID_PID;
    }
    file_ops->pid = pid;
    zlog_info(zlog_cat, "allowed_processes pid: %ld", file_ops->pid);

    

    cJSON_Delete(json);
    free(buffer);

    return file_ops->op_count > 0 ? SUCCESS : SUCCESS_NO_OPS;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

/* 
 * Function to handle events
 * This function initializes zlog, parses the JSON file, and updates the BPF map with the disallowed operations.
 * @param skel: Pointer to the BPF skeleton
 * @return: success, or error code
*/
static int handle_event(struct kprobe_bpf *skel){
    int rc;
    
    rc = zlog_init("file_monitor.conf");

    if (rc) {
        printf("init failed\n");
        return ERR_ZLOG_INIT;
    }

    zlog_cat = zlog_get_category("my_cat");

    if (!zlog_cat) {
        printf("get cat fail\n");
        zlog_fini();
        return ERR_ZLOG_CATEGORY;
    }

    zlog_info(zlog_cat,"hello, file_monitor");
    
	

    file_operations_t file_ops = {0};
	rc = parseJson("file.json", &file_ops);
    if (rc < 0) {
        zlog_error(zlog_cat, "Failed to parse JSON: error code %d", rc);
        zlog_fini();
        return rc;
    }
    if (rc == SUCCESS_NO_OPS) {
        zlog_info(zlog_cat, "No disallowed operations found in file.json");
        zlog_fini();
        return SUCCESS_NO_OPS;
    }

	int64_t flags = 0; 
	for(int i = 0; i < file_ops.op_count; i++){
		char op[MAX_OPERATION_LENGTH];
		strncpy(op, file_ops.disallowed_operations[i], MAX_OPERATION_LENGTH - 1);
		printf("Disallowed operation: %s\n", op);
		if(strcmp(op, "delete") == 0){
			flags |= DELETE;
            printf("SET DELETE FLAG\n");
            zlog_info(zlog_cat, "SET DELETE FLAG");
		}
        if(strcmp(op, "read") == 0){
            flags |= READ;
            printf("SET READ FLAG\n");
            zlog_info(zlog_cat, "SET READ FLAG");
        }
        if(strcmp(op, "write") == 0){
            flags |= WRITE;
            printf("SET WRITE FLAG\n");
            zlog_info(zlog_cat, "SET WRITE FLAG");
        }
	}
    // fill pid as high 32 bits,fill flags as low 32 bits
    flags = flags | file_ops.pid << 32;
    printf("flags:%lx\n",flags);
    zlog_info(zlog_cat, "flags: %lx", flags);

	rc = bpf_map__update_elem(skel->maps.file_maps, &file_ops.file_path, MAX_FILE_PATH, &flags, sizeof(int64_t), BPF_ANY);
    if (rc < 0) {
        zlog_error(zlog_cat, "Failed to update BPF map: %s [Error Code: %d]", strerror(-rc), ERR_BPF_MAP_UPDATE);
        zlog_fini();
        return ERR_BPF_MAP_UPDATE;
    }

    //store map in /sys/fs/bpf/file_maps
    // int err = bpf_map__pin(skel->maps.file_maps, "/sys/fs/bpf/file_maps");
    // if (err) {
    //     zlog_error(zlog_cat, "Failed to pin map: %s [Error Code: %d]", strerror(-err), ERR_BPF_MAP_PIN);
    //     // fprintf(stderr, "Failed to pin map: %s\n", strerror(-err));
    //     zlog_fini();
    //     return ERR_BPF_MAP_PIN;
    // }

    zlog_fini();
    return SUCCESS;
}



int main(int argc, char **argv)
{
	struct kprobe_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}


	/* Attach tracepoint handler */
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");


	err = handle_event(skel);
    if (err < 0) {
        zlog_error(zlog_cat, "handle_event failed: error code %d", err);
        goto cleanup;
    }

    const char *kernel_func = "__x64_sys_open";
    err = kprobe_generic_loader(kernel_func);
    if(!err){
        printf("kprobe attached to %s, press Ctrl+C to exit\n", kernel_func);
    }

	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	kprobe_bpf__destroy(skel);
	return -err;
}
