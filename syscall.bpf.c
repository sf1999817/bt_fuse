#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define path_size 256

struct event {
	int pid_;
	char path_name_[path_size];
	int n_;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps"); // 环形缓冲区


SEC("tracepoint/syscalls/sys_enter_openat")
int do_syscall_trace(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	char filename[path_size];
	struct task_struct *task = (struct task_struct *)bpf_get_current_task(),
			   *real_parent;
	if (task == NULL) {
		bpf_printk("task\n");
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	int pid = bpf_get_current_pid_tgid() >> 32, tgid;

	int ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_probe_read_str(e->path_name_, sizeof(e->path_name_),
			   (void *)(ctx->args[1]));

	bpf_printk("path name: %s,pid:%d,ppid:%d\n", e->path_name_, pid, ppid);

	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (fdt == NULL) {
		bpf_printk("fdt\n");
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	unsigned int i = 0, count = 0, n = BPF_CORE_READ(fdt, max_fds);
	bpf_printk("n:%d\n", n);

	e->n_ = n;
	e->pid_ = pid;

	// struct file **fd = BPF_CORE_READ(fdt, fd); // 文件描述符表
	// struct file *file;
	// bpf_probe_read_kernel(&file, sizeof(file), &fd[11]); // 拿到文件指针
	// if (file) {
	// 	char path_name[path_size];
	// 	struct dentry *dp = BPF_CORE_READ(file, f_path.dentry);
	// 	bpf_probe_read_str(path_name, sizeof(path_name),
	// 			   BPF_CORE_READ(dp, d_name.name));
	// 	if (path_name != NULL) {
	// 		bpf_printk("filename: %s\n", path_name);
	// 	}
	// }

	// for (; count < 50 || i < n; ++i, ++count) {
	// 	bpf_probe_read_kernel(&file, sizeof(file), &fd[i]);
	// 	if (file) {
	// 		char path_name[path_size];
	// 		struct dentry *dp = BPF_CORE_READ(file, f_path.dentry);
	// 		bpf_probe_read_str(path_name, sizeof(path_name),
	// 				   BPF_CORE_READ(dp, d_name.name));
	// 		if (path_name != NULL) {
	// 			bpf_printk("filename: %s\n", path_name);
	// 			if (bpf_strcmp(path_name, filename) == 0) {
	// 				bpf_printk("get\n");
	// 				break;
	// 			}
	// 		}
	// 	}
	// }

	bpf_ringbuf_submit(e, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
