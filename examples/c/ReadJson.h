#define MAX_ENTRIES 128
#define MAX_FILE_PATH_LENGTH 256
#define MAX_OPERATION_LENGTH 16


typedef struct {
    char file_path[MAX_FILE_PATH_LENGTH];
    char disallowed_operations[MAX_ENTRIES][MAX_OPERATION_LENGTH];
    int op_count;
} file_operations_t;


file_operations_t parseJson(char *filename);