#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/types.h>

#define SHM_NAME "/my_shared_memory"
#define SHM_SIZE 1024  // 共享内存大小

// 全局标志用于安全退出
volatile sig_atomic_t exit_flag = 0;

// 处理 SIGINT 信号的函数
void handle_sigint(int sig) {
    exit_flag = 1;  // 设置退出标志
}

// futex 等待函数
int futex_wait(atomic_int *futexp, int expected) {
    return syscall(SYS_futex, futexp, FUTEX_WAIT, expected, NULL, NULL, 0);
}

// futex 唤醒函数
int futex_wake(atomic_int *futexp, int num_wake) {
    return syscall(SYS_futex, futexp, FUTEX_WAKE, num_wake, NULL, NULL, 0);
}

int main() {
    int shm_fd;
    void *shm_ptr;

    // 设置信号处理函数
    signal(SIGINT, handle_sigint);

    // 删除旧的共享内存
    shm_unlink(SHM_NAME);

    // 创建共享内存
    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open failed");
        exit(EXIT_FAILURE);
    }

    // 设置共享内存大小
    if (ftruncate(shm_fd, SHM_SIZE) == -1) {
        perror("ftruncate failed");
        close(shm_fd);
        shm_unlink(SHM_NAME);
        exit(EXIT_FAILURE);
    }

    // 映射共享内存
    shm_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap failed");
        close(shm_fd);
        shm_unlink(SHM_NAME);
        exit(EXIT_FAILURE);
    }

    // 初始化 futex 变量
    atomic_int *futex = (atomic_int *)shm_ptr;
    *futex = 0;

    char *data_ptr = (char *)(shm_ptr + sizeof(atomic_int));  // 数据存储区在 futex 之后

    // 主循环，等待从 eBPF 程序写入数据
    while (!exit_flag) {
        // 等待 futex 变量被 eBPF 程序设置为 1
        while (atomic_load(futex) != 1) {
            futex_wait(futex, 0);
        }

        // 读取并打印共享内存中的数据
        printf("Shared Memory Content: %s\n", data_ptr);

        // 重置 futex 变量为 0，并唤醒可能在等待的进程
        atomic_store(futex, 0);
        futex_wake(futex, 1);

        sleep(1);  // 防止 CPU 占用过高
    }

    // 清理资源
    if (munmap(shm_ptr, SHM_SIZE) == -1) {
        perror("munmap failed");
    }

    if (shm_unlink(SHM_NAME) == -1) {
        perror("shm_unlink failed");
    }

    return 0;
}
