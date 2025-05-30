/*
 * fileName:kprobe.h
 * author: sleepalone
 * vsersion: 1.0
*/

// set file operation flag(read,write,delete)
#define READ 1
#define WRITE 2
#define DELETE 4

// set MAX_FILE_PATH
#define MAX_FILE_PATH 256

//set MAX_ENTRIES
#define MAX_ENTRIES 128

//set MAX_OPERATION_LENGTH
#define MAX_OPERATION_LENGTH 16

//define file_operations_t
typedef struct {
    char file_path[MAX_FILE_PATH]; // file_path in json file
    char disallowed_operations[MAX_ENTRIES][MAX_OPERATION_LENGTH]; // disallowed_operations in json file
    int op_count; // sum of disallowed_operations
    long pid; // pid in json file
} file_operations_t;


// success
#define SUCCESS 0
// success pares but no operation
#define SUCCESS_NO_OPS 1

// error codes
// could not open file
#define ERR_FILE_OPEN -1 
// memory allocation error
#define ERR_MEMORY_ALLOC -2
// json parse error
#define ERR_JSON_PARSE -3
// invalid rule id
#define ERR_INVALID_RULE_ID -4
// invalid file path
#define ERR_INVALID_FILE_PATH -5
// too many operations
#define ERR_TOO_MANY_OPS -6
// invalid PID
#define ERR_INVALID_PID -7
// zlog initialization error
#define ERR_ZLOG_INIT -8
// zlog category error
#define ERR_ZLOG_CATEGORY -9
// bpf open error
#define ERR_BPF_OPEN -10
// bpf attach error
#define ERR_BPF_ATTACH -11
// signal handler error
#define ERR_SIGNAL_HANDLER -12
// bpf map update error
#define ERR_BPF_MAP_UPDATE -13
// bpf map pin error
#define ERR_BPF_MAP_PIN -14