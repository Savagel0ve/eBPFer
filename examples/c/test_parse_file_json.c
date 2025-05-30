/*
 * fileName:test_parse_file_json.c
 * author: sleepalone
 * vsersion: 1.0
*/

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include "cjson/cJSON.h"
#include "kprobe.h"
#include <stdlib.h>


/* 
 * Function to parse JSON file and extract file operations
 * @param filename: Path to the JSON file
 * @return: file_operations_t structure containing parsed data
 */
file_operations_t parseJson(char *filename){

    file_operations_t file_ops = {0};
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
    if(rule_id && cJSON_IsString(rule_id)){
        printf("Rule ID: %s\n", rule_id->valuestring);
    }else{
        printf("rule_id NOT FOUND OR Invalid rule_id in JSON\n");
        cJSON_Delete(json);
        free(buffer);
        return file_ops;
    }

    

    cJSON *file_name_array = cJSON_GetObjectItem(json, "file_name");
    if (file_name_array &&  cJSON_IsArray(file_name_array)) {
        for(int i = 0; i < cJSON_GetArraySize(file_name_array); i++){
            cJSON *file_entry = cJSON_GetArrayItem(file_name_array, i);
            if (file_entry) {
                cJSON *file_path = cJSON_GetObjectItem(file_entry, "file_path");
                if (file_path &&  cJSON_IsString(file_path)) {
                    printf("文件路径: %s\n", file_path->valuestring);
                    strncpy(file_ops.file_path, file_path->valuestring, MAX_FILE_PATH - 1);
                }

        
                cJSON *disallowed_operations = cJSON_GetObjectItem(file_entry, "disallowed_operations");
                 if (disallowed_operations && cJSON_IsArray(disallowed_operations)) {
                    int size = cJSON_GetArraySize(disallowed_operations);
                    if(size > MAX_ENTRIES){
                        printf("Too many disallowed operations, max is %d, current is %d\n", MAX_ENTRIES, size);
                        cJSON_Delete(json);
                        free(buffer);
                        return file_ops;
                    }
                    for (int i = 0; i < cJSON_GetArraySize(disallowed_operations); i++) {
                        cJSON *operation = cJSON_GetArrayItem(disallowed_operations, i);
                        if (operation && cJSON_IsString(operation)) {
                            file_ops.op_count++;
                            strncpy(file_ops.disallowed_operations[i], operation->valuestring, MAX_OPERATION_LENGTH - 1);
                            printf("disallowed_operations[%d] = %s\n", i, file_ops.disallowed_operations[i]);
                        }
                    }
                }
            }
        }
        
    }


    cJSON_Delete(json);
    free(buffer);

    return file_ops;

}

/* 
 * Function to test parsing an empty JSON file
 * @return: void
 */
void test_parse_empty_file() {
    // Create a temporary empty JSON file
    FILE* fp = fopen("test_empty.json", "w");
    fprintf(fp, "{}");
    fclose(fp);

    file_operations_t result = parseJson("test_empty.json");
    
    printf("Test Empty File:\n");
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    printf("Expected file_path: '', Got: '%s'\n", result.file_path);
    
    if (result.op_count == 0 && strlen(result.file_path) == 0) {
        printf("✓ Test passed\n\n");
    } else {
        printf("✗ Test failed\n\n");
    }
    
    remove("test_empty.json");
}

/*
 * Function to test parsing an invalid JSON file
 * @return: void
 */
void test_parse_invalid_file() {
    file_operations_t result = parseJson("nonexistent.json");
    
    printf("Test Invalid File:\n");
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    printf("Expected file_path: '', Got: '%s'\n", result.file_path);
    
    if (result.op_count == 0 && strlen(result.file_path) == 0) {
        printf("✓ Test passed\n\n");
    } else {
        printf("✗ Test failed\n\n");
    }
}

/*
 * Function to test parsing a valid JSON file
 * @return: void
 */
void test_parse_valid_json() {
    // Create a temporary valid JSON file
    FILE* fp = fopen("test_valid.json", "w");
    fprintf(fp, "{\n"
           "  \"rule_id\": \"test123\",\n"
           "  \"file_name\": [\n"
           "    {\n"
           "      \"file_path\": \"/test/path/file.txt\",\n"
           "      \"disallowed_operations\": [\"read\", \"write\"]\n"
           "    }\n"
           "  ]\n"
           "}");
    fclose(fp);

    file_operations_t result = parseJson("test_valid.json");
    
    printf("Test Valid JSON:\n");
    printf("Expected op_count: 2, Got: %d\n", result.op_count);
    printf("Expected file_path: '/test/path/file.txt', Got: '%s'\n", result.file_path);
    printf("Expected operation[0]: 'read', Got: '%s'\n", result.disallowed_operations[0]);
    printf("Expected operation[1]: 'write', Got: '%s'\n", result.disallowed_operations[1]);
    
    int passed = (result.op_count == 2 &&
                  strcmp(result.file_path, "/test/path/file.txt") == 0 &&
                  strcmp(result.disallowed_operations[0], "read") == 0 &&
                  strcmp(result.disallowed_operations[1], "write") == 0);
                  
    printf("%s Test %s\n\n", passed ? "✓" : "✗", passed ? "passed" : "failed");
    
    remove("test_valid.json");
}

/*
 * Function to test parsing a JSON file with too many operations
 * @return: void
 */
void test_parse_too_many_operations() {
    // Create JSON with more than MAX_ENTRIES operations
    FILE* fp = fopen("test_too_many.json", "w");
    fprintf(fp, "{\n"
           "  \"rule_id\": \"test123\",\n"
           "  \"file_name\": [\n"
           "    {\n"
           "      \"file_path\": \"/test/path\",\n"
           "      \"disallowed_operations\": [");
    for (int i = 0; i < MAX_ENTRIES + 1; i++) {
        fprintf(fp, "\"op%d\"%s", i, i < MAX_ENTRIES ? "," : "");
    }
    fprintf(fp, "]\n    }\n  ]\n}");
    fclose(fp);

    file_operations_t result = parseJson("test_too_many.json");
    
    printf("Test Too Many Operations:\n");
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    if (result.op_count == 0) {
        printf("✓ Test passed\n\n");
    } else {
        printf("✗ Test failed\n\n");
    }
    
    remove("test_too_many.json");
}

/*
 * Function to test parsing a malformed JSON file
 * @return: void
 */
void test_parse_malformed_json() {
    // Create a malformed JSON file
    FILE* fp = fopen("test_malformed.json", "w");
    fprintf(fp, "{ \"rule_id\": \"test123\", \"file_name\": [ { \"file_path\": ");
    fclose(fp);

    file_operations_t result = parseJson("test_malformed.json");
    
    printf("Test Malformed JSON:\n");
    printf("Expected op_count: 0, Got: %d\n", result.op_count);
    
    if (result.op_count == 0) {
        printf("✓ Test passed\n\n");
    } else {
        printf("✗ Test failed\n\n");
    }
    
    remove("test_malformed.json");
}

int main() {
    printf("Running Unit Tests...\n\n");
    
    test_parse_empty_file();
    test_parse_invalid_file();
    test_parse_valid_json();
    test_parse_too_many_operations();
    test_parse_malformed_json();
    
    return 0;
}