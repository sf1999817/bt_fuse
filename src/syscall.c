// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "syscall.skel.h"
#include <inttypes.h>
#include <linux/fs.h>

#define path_size 256

struct event {
	int pid_;
	char path_name_[path_size];
	int n_;
};

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle(void *ctx, void *data, size_t data_sz)
{
	struct event *e = (struct event *)data;
	char *filename = strrchr(e->path_name_, '/');
	++filename;

	/// printf("PID: %d, filename:%s\n", e->pid_, e->path_name_);

	char fd_path[path_size];
	char actual_path[path_size];
	int i = 0;
	for (; i < e->n_; ++i) {
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", e->pid_,
			 i);
		ssize_t len =
			readlink(fd_path, actual_path, sizeof(actual_path) - 1);
		if (len != -1) {
			actual_path[len] = '\0';
			// printf("Resolved Filename: %s\n", actual_path);
			int result = strcmp(e->path_name_, actual_path);
			if (result == 0) {
				printf("get     ,   filename:%s    ,  fd:%d\n",
				       e->path_name_, i);
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct syscall_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = syscall_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = syscall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	int attach = syscall_bpf__attach(skel);
	if (attach) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.rb), handle, NULL,
		NULL); // 创建一个环形缓冲区，并设置好缓冲区的回调函数
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);

		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	syscall_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
