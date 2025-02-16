/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "error_inject_syscall.h"

#define MAX_PATH_LEN 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(char[MAX_PATH_LEN]));
    __uint(max_entries, 1024);
} pathname_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    char pathname[MAX_PATH_LEN];
    u64 addr = ctx->args[1]; // pathname 地址
    u32 pid = bpf_get_current_pid_tgid(); // 使用 PID 作为 map 键
    int path_len;

    // 读取路径字符串
    path_len = bpf_probe_read_user_str(pathname, sizeof(pathname) - 1, (void *) addr);
    if (path_len < 0) {
        bpf_printk("Failed to read pathname string\n");
        return 0;  // 读取失败，退出
    }

    // 确保路径字符串以 NULL 结尾
    pathname[sizeof(pathname) - 1] = '\0';

    // 过滤掉以 "/usr" 开头的路径
    if (path_len >= 4 && pathname[0] == '/' && pathname[1] == 'u' && pathname[2] == 's' && pathname[3] == 'r') {
        // bpf_printk("Filtered Pathname: %s\n", pathname);  // 调试信息
        return 0;  // 路径以 "/usr" 开头，过滤掉
    }

    // 将 pathname 存储到 map 中
    bpf_map_update_elem(&pathname_map, &pid, pathname, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("3456\n");
    struct event *e;
    u32 pid = bpf_get_current_pid_tgid();
    char *pathname;

    // 从 map 中获取 pathname
    pathname = bpf_map_lookup_elem(&pathname_map, &pid);
    if (!pathname) {
        bpf_printk("Failed to get pathname from map\n");
        return 0;
    }

    // 过滤掉以 "/usr" 开头的路径
    if (pathname[0] == '/' && pathname[1] == 'u' && pathname[2] == 's' && pathname[3] == 'r') {
        // bpf_printk("Filtered Pathname: %s\n", pathname);  // 调试信息
        return 0;  // 路径以 "/usr" 开头，过滤掉
    }

    // 预留 ring buffer 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed to reserve space in ring buffer\n");
        return 0;  // 预留空间失败，退出
    }

    // 设置命令名为 "cat"
    __builtin_memcpy(e->command, "cat", 4); // 包括终止的 null 字符
    __builtin_memcpy(e->pathname, pathname, sizeof(e->pathname)); // 复制 pathname

    bpf_printk("command: %s, pathname: %s\n", e->command, e->pathname);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(e, 0);

    bpf_override_return(ctx,-1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    char comm[TASK_COMM_LEN];
    int fd = ctx->args[0];
    char *buf = (char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    // 获取当前进程的命令名
    bpf_get_current_comm(&comm, sizeof(comm));

    // 确保 count 不超出缓冲区限制
    if (count > MAX_DATA_LEN) {
        count = MAX_DATA_LEN;
    }

    // 获取文件路径
    u32 pid = bpf_get_current_pid_tgid();
    // char *pathname = bpf_map_lookup_elem(&pathname_map, &pid);
    char *pathname = bpf_map_lookup_elem(&pathname_map, &fd);
    if (!pathname) {
        bpf_printk("No pathname found for PID: %u\n", pid);
        return 0;
    }

    // 过滤掉以 "/usr" 开头的路径
    if (pathname[0] == '/' && pathname[1] == 'u' && pathname[2] == 's' && pathname[3] == 'r') {
        bpf_printk("Ignoring write syscall to path: %s\n", pathname);
        return 0;  // 路径以 "/usr" 开头，过滤掉
    }

    // 预留 ring buffer 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed to reserve space in ring buffer\n");
        return 0;
    }

    // 读取写入的数据
    if (bpf_probe_read(e->data, count, buf) < 0) {
        bpf_printk("Failed to read data from buffer\n");
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->size = count;
    __builtin_memcpy(e->command, comm, sizeof(e->command));
    __builtin_memcpy(e->pathname, pathname, sizeof(e->pathname));

    bpf_printk("Captured Data: %s\n", e->data);
    bpf_printk("Command: %s\n", e->command);
    bpf_printk("Size: %zu\n", e->size);
    bpf_printk("File: %s\n", e->pathname);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_mkdir(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    char pathname[256];
    u64 addr = ctx->args[0];  // pathname
    int mode = ctx->args[1];  // mode

    // Reserve sample from BPF ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed to reserve space in ring buffer\n");
        return 0;
    }

    // Read pathname string
    if (bpf_probe_read_user_str(pathname, sizeof(pathname), (void *)addr) < 0) {
        bpf_ringbuf_discard(e, 0);
        bpf_printk("Failed to read pathname string\n");
        return 0;
    }

    // Copy pathname and mode to event
    __builtin_memcpy(e->pathname, pathname, sizeof(e->pathname));
	e->mode = mode;

    // 将命令名 "mkdir" 复制到事件的 command 字段
    __builtin_memcpy(e->command, "mkdir", 6);  // 包括终止 null 字符

    // Print pathname and mode
      // 打印 pathname 和 mode
    bpf_printk("mkdir called with pathname: %s, mode: %o, command: %s\n", e->pathname, e->mode, e->command);

    // Submit the event
    bpf_ringbuf_submit(e, 0);

	bpf_override_return(ctx,-1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";