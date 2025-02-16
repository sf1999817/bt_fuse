#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include "error_inject_syscall.skel.h"
#include "error_inject_syscall.h"
#include <time.h>

#define SHM_NAME "/my_shared_memory"
#define SHM_SIZE 1024  // 共享内存大小
#define BUFFER_SIZE 1024

static void *shm_ptr;
static pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = false;

static void sig_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        exiting = true;
        printf("Signal received: %d. Exiting...\n", sig);
    }
}

// 定义 libbpf 的打印回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

typedef struct {
    atomic_int futex;  // 用于同步的 futex 变量
    char buffer[BUFFER_SIZE];
    atomic_size_t write_index;
    atomic_size_t read_index;
} shared_memory_t;

void *map_shared_memory() {
    int shm_fd;
    shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) {
        warn("shm_open failed: %s\n", strerror(errno));
        return NULL;
    }

    void *shm_ptr = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        close(shm_fd);
        return NULL;
    }
    close(shm_fd);

    return shm_ptr;
}

void unmap_shared_memory(void *shm_ptr) {
    if (munmap(shm_ptr, SHM_SIZE) == -1) {
        perror("munmap");
    }
}

int futex_wait(atomic_int *futexp, int expected, const struct timespec *timeout) {
    return syscall(SYS_futex, futexp, FUTEX_WAIT, expected, timeout, NULL, 0);
}

int futex_wake(atomic_int *futexp, int num_wake) {
    return syscall(SYS_futex, futexp, FUTEX_WAKE, num_wake, NULL, NULL, 0);
}

void write_data_to_queue(shared_memory_t *shm_ptr, const char *data, size_t size) {
    size_t write_index = atomic_load(&shm_ptr->write_index);
    size_t current_read_index = atomic_load(&shm_ptr->read_index);
    size_t next_write_index = (write_index + size) % BUFFER_SIZE;

    if (next_write_index == current_read_index) {
        fprintf(stderr, "Error: Buffer is full, cannot write data.\n");
        return;
    }

    size_t first_part_size = BUFFER_SIZE - write_index;

    if (size <= first_part_size) {
        memcpy(&shm_ptr->buffer[write_index], data, size);
    } else {
        memcpy(&shm_ptr->buffer[write_index], data, first_part_size);
        memcpy(&shm_ptr->buffer[0], data + first_part_size, size - first_part_size);
    }
    atomic_store(&shm_ptr->write_index, next_write_index);

    // 输出写入的数据和索引位置进行调试
    fprintf(stderr, "Data written to shared memory at index %zu: %s\n", write_index, data);

    // 设置 futex 变量为 1，通知 FUSE 文件系统有新数据
    atomic_store(&shm_ptr->futex, 1);
    futex_wake(&shm_ptr->futex, 1);  // 唤醒等待的 FUSE 进程
}

static int read_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;

     printf("Event Pathname: %s, command: %s\n", e->pathname,e->command);

    // 获取共享内存的指针
    shared_memory_t *shared_mem = (shared_memory_t *)shm_ptr;

    // 将事件数据写入共享内存队列
    write_data_to_queue(shared_mem, (const char *)e, sizeof(struct event));

    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct error_inject_syscall_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    shm_ptr = map_shared_memory();
    if (!shm_ptr) {
        fprintf(stderr, "Failed to map shared memory\n");
        return 1;
    }

    skel = error_inject_syscall_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        unmap_shared_memory(shm_ptr);
        return 1;
    }

    err = error_inject_syscall_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        error_inject_syscall_bpf__destroy(skel);
        unmap_shared_memory(shm_ptr);
        return 1;
    }

    err = error_inject_syscall_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        error_inject_syscall_bpf__destroy(skel);
        unmap_shared_memory(shm_ptr);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), read_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        error_inject_syscall_bpf__destroy(skel);
        unmap_shared_memory(shm_ptr);
        return 1;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // // 退出清理
    // exiting = true;
    // pthread_join(data_thread, NULL);

cleanup:
    ring_buffer__free(rb);
    error_inject_syscall_bpf__destroy(skel);
    unmap_shared_memory(shm_ptr);
    return err < 0 ? -err : 0;
}
