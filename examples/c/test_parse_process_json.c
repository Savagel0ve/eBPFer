/*
 * fileName:test_parse_process_json.c
 * author: sleepalone
 * vsersion: 1.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cjson/cJSON.h"  // Assuming cJSON.h is in a subdirectory

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

// Helper function to create test JSON files
void create_test_json(const char *filename, const char *content) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "%s", content);
        fclose(fp);
    } else {
        perror("Failed to create test JSON file");
    }
}

// Test cases
// Function to test parsing an empty JSON file
void test_parse_json_empty() {
    create_test_json("test_empty.json", "{}");
    
    process_operations_t result = parseJson("test_empty.json");
    
    printf("Test Empty JSON:\n");
    printf("Expected pid: 0, Got: %d\n", result.pid);
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    int passed = (result.pid == 0 && result.op_count == 0);
    printf("%s\n\n", passed ? "✓ Test passed" : "✗ Test failed");
    
    remove("test_empty.json");
}

// Function to test parsing an invalid JSON file
void test_parse_json_invalid_file() {
    process_operations_t result = parseJson("nonexistent.json");
    
    printf("Test Invalid File:\n");
    printf("Expected pid: 0, Got: %d\n", result.pid);
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    int passed = (result.pid == 0 && result.op_count == 0);
    printf("%s\n\n", passed ? "✓ Test passed" : "✗ Test failed");
}

// Function to test parsing a valid JSON file
void test_parse_json_valid() {
    create_test_json("test_valid.json",
        "{\n"
        "  \"pid\": \"1234\",\n"
        "  \"process_operations\": [\n"
        "    {\"allowed_operations\": \"read\"},\n"
        "    {\"allowed_operations\": \"write\"}\n"
        "  ]\n"
        "}"
    );
    
    process_operations_t result = parseJson("test_valid.json");
    
    printf("Test Valid JSON:\n");
    printf("Expected pid: 1234, Got: %d\n", result.pid);
    printf("Expected op_count: 2, Got: %d\n", result.op_count);
    printf("Expected process_operate[0]: 'read', Got: '%s'\n", result.process_operate[0]);
    printf("Expected process_operate[1]: 'write', Got: '%s'\n", result.process_operate[1]);
    
    int passed = (result.pid == 1234 &&
                  result.op_count == 2 &&
                  strcmp(result.process_operate[0], "read") == 0 &&
                  strcmp(result.process_operate[1], "write") == 0);
    printf("%s\n\n", passed ? "✓ Test passed" : "✗ Test failed");
    
    remove("test_valid.json");
}

// Function to test parsing a JSON file with too many operations
void test_parse_json_too_many_entries() {
    FILE *fp = fopen("test_too_many.json", "w");
    if (fp) {
        fprintf(fp, "{\n  \"pid\": \"5678\",\n  \"process_operations\": [\n");
        for (int i = 0; i < MAX_ENTRIES + 1; i++) {
            fprintf(fp, "    {\"allowed_operations\": \"op%d\"}%s\n", i, i < MAX_ENTRIES ? "," : "");
        }
        fprintf(fp, "  ]\n}");
        fclose(fp);
    }
    
    process_operations_t result = parseJson("test_too_many.json");
    
    printf("Test Too Many Entries:\n");
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    int passed = (result.op_count == 0);
    printf("%s\n\n", passed ? "✓ Test passed" : "✗ Test failed");
    
    remove("test_too_many.json");
}

// Function to test parsing a malformed JSON file
void test_parse_json_malformed() {
    create_test_json("test_malformed.json", "{ \"pid\": \"1234\", \"process_operations\": [ { \"allowed_operations\": ");
    
    process_operations_t result = parseJson("test_malformed.json");
    
    printf("Test Malformed JSON:\n");
    printf("Expected pid: 0, Got: %d\n", result.pid);
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    int passed = (result.pid == 0 && result.op_count == 0);
    printf("%s\n\n", passed ? "✓ Test passed" : "✗ Test failed");
    
    remove("test_malformed.json");
}

// Function to test parsing a JSON file with an invalid PID
void test_parse_json_invalid_pid() {
    create_test_json("test_invalid_pid.json",
        "{\n"
        "  \"pid\": \"abc\",\n"
        "  \"process_operations\": [\n"
        "    {\"allowed_operations\": \"read\"}\n"
        "  ]\n"
        "}"
    );
    
    process_operations_t result = parseJson("test_invalid_pid.json");
    
    printf("Test Invalid PID:\n");
    printf("Expected pid: 0, Got: %d\n", result.pid);
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    int passed = (result.pid == 0 && result.op_count == 0);
    printf("%s\n\n", passed ? "✓ Test passed" : "✗ Test failed");
    
    remove("test_invalid_pid.json");
}

int main() {
    printf("Running parseJson Unit Tests...\n\n");
    
    test_parse_json_empty();
    test_parse_json_invalid_file();
    test_parse_json_valid();
    test_parse_json_too_many_entries();
    test_parse_json_malformed();

    
    return 0;
}