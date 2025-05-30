#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<cjson/cJSON.h>

#include "ReadJson.h"

file_operations_t parseJson(char *filename){

    file_operations_t file_ops;
    file_ops.op_count = 0;

    FILE *file = fopen(filename, "r");
    if(!file){
        perror("could not open file");
        return file_ops;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0 , SEEK_SET);

    char *buffer = (char *)malloc(file_size + 1);
    if(!buffer){
        perror("Could not allocate buffer");
        fclose(file);
        return file_ops;
    }
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    cJSON * json = cJSON_Parse(buffer);
    if(json == NULL){
        printf("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        free(buffer);
        return file_ops;
    }

    cJSON *rule_id = cJSON_GetObjectItemCaseSensitive(json, "rule_id");
    if(cJSON_IsString(rule_id) && (rule_id->valuestring != NULL)){
        printf("Rule ID: %s\n", rule_id->valuestring);
    }

    cJSON* file_path_json = cJSON_GetObjectItemCaseSensitive(json, "file_path");
    if(cJSON_IsString(file_path_json) && (file_path_json->valuestring != NULL)){
        printf("File Path: %s\n", file_path_json->valuestring);
        strncpy(file_ops.file_path, file_path_json->valuestring, MAX_FILE_PATH_LENGTH - 1);
    }


    cJSON *disallowed_operations = cJSON_GetObjectItemCaseSensitive(json, "disallowed_operations");
    if (cJSON_IsArray(disallowed_operations)) {
        for (int i = 0; i < cJSON_GetArraySize(disallowed_operations); i++) {
            cJSON *operation = cJSON_GetArrayItem(disallowed_operations, i);
            if (cJSON_IsString(operation) && (operation->valuestring != NULL)) {
                file_ops.op_count++;
                strncpy(file_ops.disallowed_operations[i], operation->valuestring, MAX_OPERATION_LENGTH - 1);
                printf("disallowed_operations[%d] = %s\n", i, file_ops.disallowed_operations[i]);
            }
        }
    }


    cJSON_Delete(json);
    free(buffer);

    return file_ops;

}

int main(){
    
    parseJson("test.json");

    return 0;
}