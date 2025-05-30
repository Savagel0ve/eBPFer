#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <limits.h>

int main() {
    int fan_fd; // fanotify 文件描述符
    char buf[4096]; // 事件缓冲区
    ssize_t len;

    // 1. 初始化 fanotify
    fan_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_PRE_CONTENT, O_RDONLY);
    if (fan_fd < 0) {
        perror("fanotify_init failed");
        exit(EXIT_FAILURE);
    }

    // 2. 标记监控路径（这里监控 /tmp 挂载点）
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_PERM, AT_FDCWD, "/tmp") < 0) {
        perror("fanotify_mark failed");
        close(fan_fd);
        exit(EXIT_FAILURE);
    }

    printf("开始监控 /tmp 下文件的打开操作...\n");

    // 3. 主循环：读取和处理事件
    while (1) {
        len = read(fan_fd, buf, sizeof(buf));
        if (len < 0 && errno != EAGAIN) {
            perror("read failed");
            close(fan_fd);
            exit(EXIT_FAILURE);
        }
        if (len <= 0) {
            continue; // 无事件，继续等待
        }

        // 处理每个事件
        struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->mask & FAN_OPEN_PERM) {
                // 获取被访问文件的路径
                char proc_path[32];
                char path[PATH_MAX];
                sprintf(proc_path, "/proc/self/fd/%d", metadata->fd);
                ssize_t path_len = readlink(proc_path, path, sizeof(path) - 1);
                if (path_len < 0) {
                    perror("readlink failed");
                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }
                path[path_len] = '\0';

                // 检查文件名是否包含 "secret"
                struct fanotify_response response;
                response.fd = metadata->fd;
                if (strstr(path, "secret")) {
                    printf("拒绝访问: %s\n", path);
                    response.response = FAN_DENY; // 拒绝访问
                } else {
                    // printf("允许访问: %s\n", path);
                    response.response = FAN_ALLOW; // 允许访问
                }

                // 写入响应
                if (write(fan_fd, &response, sizeof(response)) < 0) {
                    perror("write response failed");
                }
            }

            // 关闭事件中的文件描述符并移动到下一个事件
            close(metadata->fd);
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }

    // 清理（理论上不会到达这里，因为是无限循环）
    close(fan_fd);
    return 0;
}



//to do
block n




  