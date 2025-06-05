#include <unistd.h>

#define BINARY_PATH_MAX_LEN 256
#define FILE_PATH_MAX_LEN 256


enum{
    FILE_POLICY = 1,
    PROCEE_POLICY = 2,
    NETWORK_POLICY = 3,
};


struct policy {
    __u8 kind;
    __u32 pid;
    char binary[BINARY_PATH_MAX_LEN];
    char file_path[FILE_PATH_MAX_LEN];
};


