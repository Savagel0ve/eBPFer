
#define BINARY_PATH_MAX_LEN 256
#define FILE_PATH_MAX_LEN 256


enum{
    FILE_POLICY = 1,
    PROCEE_POLICY = 2,
    NETWORK_POLICY = 3,
};


struct policy {
    int kind;
    int pid;
    char comm[BINARY_PATH_MAX_LEN];
    char file_path[FILE_PATH_MAX_LEN];
};


