/*
 * fileName:process_monitor.c
 * author: sleepalone
 * vsersion: 1.0
*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<cjson/cJSON.h>
#include <signal.h>

// set MAX_ENTRIES
#define MAX_ENTRIES 128
// set MAX_FILE_PATH_LENGTH
#define MAX_FILE_PATH_LENGTH 256
// set MAX_OPERATION_LENGTH
#define MAX_OPERATION_LENGTH 16


typedef struct {
    int pid; // pid from json file
    char process_operate[MAX_ENTRIES][MAX_OPERATION_LENGTH]; // process_operations from json file
    int op_count; // sum of process_operations
} process_operations_t;

/*
 * Function to parse JSON file and extract process operations
 * @param filename: Path to the JSON file
 * @return: process_operations_t structure containing parsed data
 */
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

int main(){
    process_operations_t proc_ops = parseJson("process.json");
    if(proc_ops.op_count == 0){
        printf("No disallowed operations found in process.json\n");
        return 0;
    }
    printf("PID: %d\n", proc_ops.pid);
    for(int i = 0; i < proc_ops.op_count; i++){
        char op[MAX_OPERATION_LENGTH];
        strncpy(op, proc_ops.process_operate[i], MAX_OPERATION_LENGTH - 1);
        printf("Disallowed operation: %s\n", op);
        if(!strcmp(op,"kill")){
            printf("KILL THE PROCESS\n");
            kill(proc_ops.pid,SIGKILL);
        }
    }
    return 0;
}
