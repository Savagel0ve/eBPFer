#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "cjson/cJSON.h"
#include<string.h>
#include <unistd.h>


// Definitions from process_monitor.c
#define MAX_ENTRIES 128
#define MAX_FILE_PATH_LENGTH 256
#define MAX_OPERATION_LENGTH 16

// Definitions from process_monitor.c
typedef struct {
    int pid;
    char process_operate[MAX_ENTRIES][MAX_OPERATION_LENGTH];
    int op_count;
} process_operations_t;


// Definitions from process_monitor.c
process_operations_t parseJson(char *filename){

    process_operations_t proc_ops =  {0}; // add initialization
    proc_ops.op_count = 0;

    FILE *file = fopen(filename, "r");
    if(!file){
        perror("could not open file");
        return proc_ops;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0 , SEEK_SET);

    char *buffer = (char *)malloc(file_size + 1);
    if(!buffer){
        perror("Could not allocate buffer");
        fclose(file);
        return proc_ops;
    }
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if(bytes_read != file_size){
        perror("Failed to read file completely");
        free(buffer);
        fclose(file);
        return proc_ops;
    }

    buffer[file_size] = '\0';
    fclose(file);

    cJSON * json = cJSON_Parse(buffer);
    if(json == NULL){
        printf("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        cJSON_Delete(json);
        free(buffer);
        return proc_ops;
    }

    cJSON *pid = cJSON_GetObjectItemCaseSensitive(json, "pid");
    if(pid && cJSON_IsString(pid)){
        long val = strtol(pid->valuestring, NULL, 10);
        printf("PID: %ld\n", val);
        proc_ops.pid = val;
    }else{
        printf("PID NOT FOUND OR Invalid PID in JSON");
        cJSON_Delete(json);
        free(buffer);
        return proc_ops;
    }


    cJSON *process_operate = cJSON_GetObjectItemCaseSensitive(json, "process_operations");
    if (process_operate &&  cJSON_IsArray(process_operate)) {
        int size = cJSON_GetArraySize(process_operate);
        if(size > MAX_ENTRIES){
            printf("Too many entries in process_operations, max is %d, current is %d\n", MAX_ENTRIES,size);
            cJSON_Delete(json);
            free(buffer);
            return proc_ops;
        }
        for (int i = 0; i < size; i++) {
            cJSON *operation_item = cJSON_GetArrayItem(process_operate, i);
                if (operation_item) {
                cJSON *allowed_operations = cJSON_GetObjectItem(operation_item, "allowed_operations");
                if (allowed_operations && cJSON_IsString(allowed_operations)) {
                    printf("允许的操作: %s\n", allowed_operations->valuestring);
                    proc_ops.op_count++;
                    strncpy(proc_ops.process_operate[i], allowed_operations->valuestring, MAX_OPERATION_LENGTH - 1);
                }
            }
        }
    }


    cJSON_Delete(json);
    free(buffer);

    return proc_ops;

}

// set TEST_SIZES 
#define TEST_SIZES 5
// set MAX_TEST_OPERATIONS
#define MAX_TEST_OPERATIONS 1000


/* 
 * Function to generate a test JSON file with a given number of operations
 * @param filename: Name of the file to create
 * @param num_operations: Number of operations to include in the JSON
 * @param pid: Process ID to include in the JSON
 */
void generate_test_json(const char* filename, int num_operations, int pid) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "pid", "12345");
    
    cJSON *ops = cJSON_CreateArray();
    char operation[32];
    
    for (int i = 0; i < num_operations; i++) {
        cJSON *op = cJSON_CreateObject();
        snprintf(operation, sizeof(operation), "%s%d", 
                (i % 4 == 0) ? "kill" : "operation", i);
        cJSON_AddStringToObject(op, "allowed_operations", operation);
        cJSON_AddItemToArray(ops, op);
    }
    
    cJSON_AddItemToObject(root, "process_operations", ops);
    
    FILE *fp = fopen(filename, "w");
    if (fp) {
        char *json_str = cJSON_Print(root);
        fprintf(fp, "%s", json_str);
        free(json_str);
        fclose(fp);
    }
    
    cJSON_Delete(root);
}

/* 
 * Function to get the current time in seconds
 * @return: Current time in seconds
 */
double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

/*
 * Function to get the current memory usage of the process
 * @return: Memory usage in KB
 */
long get_memory_usage() {
#ifdef __linux__
    FILE *fp = fopen("/proc/self/statm", "r");
    if (!fp) {
        perror("Failed to open /proc/self/statm");
        return 0;
    }
    long size, resident, shared, text, lib, data, dt;
    if (fscanf(fp, "%ld %ld %ld %ld %ld %ld %ld", 
               &size, &resident, &shared, &text, &lib, &data, &dt) != 7) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return resident * (sysconf(_SC_PAGESIZE) / 1024); // Page size to KB
#elif __APPLE__
    struct task_basic_info info;
    mach_msg_type_number_t size = TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &size) != KERN_SUCCESS) {
        return 0;
    }
    return info.resident_size / 1024; // Bytes to KB
#else
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss; // Fallback to ru_maxrss
#endif
}

/*
 * Function to run performance tests
 * @return: void
 */
void run_performance_test() {
    int test_sizes[TEST_SIZES] = {10, 100, 500, 1000, 5000};
    char filename[] = "test.json";
    
    printf("Performance Test Results:\n");
    printf("------------------------\n");
    printf("Size\tTime(s)\tPeak Memory(KB)\tOperations Parsed\n");
    
    for (int i = 0; i < TEST_SIZES; i++) {
        int num_ops = test_sizes[i];
        
        // Generate test file
        generate_test_json(filename, num_ops, 12345);
        
        // Record start time
        double start_time = get_time();
        
        // Track peak memory usage
        long peak_memory = 0;
        
        // Run parseJson and monitor memory
        process_operations_t result = parseJson(filename);
        
        // Check memory after parsing
        long current_memory = get_memory_usage();
        if (current_memory > peak_memory) {
            peak_memory = current_memory;
        }
        
        // Record end time
        double end_time = get_time();
        
        // Output results
        printf("%d\t%.4f\t%ld\t%d\n", 
               num_ops,
               end_time - start_time,
               peak_memory,
               result.op_count);
        
        // Cleanup
        remove(filename);
    }
}

int main() {
    srand(time(NULL));
    run_performance_test();
    return 0;
}