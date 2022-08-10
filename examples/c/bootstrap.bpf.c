// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int _NR_openat = 0;
unsigned long init_ns = 0;
typedef struct file_name {
    char filename[MAX_PATH_NAME_SIZE];
} filename_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, filename_t);
} open_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

static int __getcommlen(char *str)
{
	for(int commlen = 0; commlen < TASK_COMM_LEN; commlen++)
	{
		if(str[commlen] == 0)
		{
			return commlen;
		}
	}
	return -1;
}
/*
 * 比较传入的两个命令是否相同
 * 相同返回 0，不同返回1
 */
static int __commcmp(char *comm1,char *comm2)
{
	for(int i = 0 ;i < TASK_COMM_LEN; i++)
	{
		if(comm1[i] == comm2[i])
		{
			if(comm1[i] == 0)
			{
				return 0;
			}
		}
		else 
		{
			return 1;
		}
	}
	return 1;
}
// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
// {
// 	struct task_struct *task;
// 	unsigned fname_off;
// 	struct event *e;
// 	pid_t pid;
// 	u64 ts;

// 	/* remember time exec() was executed for this PID */
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	ts = bpf_ktime_get_ns();
// 	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

// 	/* don't emit exec events when minimum duration is specified */
// 	if (min_duration_ns)
// 		return 0;

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->event_type = EVENT_TYPE_EXEC;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));

// 	fname_off = ctx->__data_loc_filename & 0xFFFF;
// 	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

// 	/* successfully submit it to user-space for post-processing */
// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }

// SEC("tp/sched/sched_process_exit")
// int handle_exit(struct trace_event_raw_sched_process_template* ctx)
// {
// 	struct task_struct *task;
// 	struct event *e;
// 	pid_t pid, tid;
// 	u64 id, ts, *start_ts, duration_ns = 0;
	

// 	/* get PID and TID of exiting thread/process */
// 	id = bpf_get_current_pid_tgid();
// 	pid = id >> 32;
// 	tid = (u32)id;

// 	/* ignore thread exits */
// 	if (pid != tid)
// 		return 0;

// 	/* if we recorded start of the process, calculate lifetime duration */
// 	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
// 	if (start_ts)
// 		duration_ns = bpf_ktime_get_ns() - *start_ts;
// 	else if (min_duration_ns)
// 		return 0;
// 	bpf_map_delete_elem(&exec_start, &pid);

// 	/* if process didn't live long enough, return early */
// 	if (min_duration_ns && duration_ns < min_duration_ns)
// 		return 0;

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->event_type = EVENT_TYPE_EXIT;
// 	e->duration_ns = duration_ns;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));

// 	/* send data to user-space for post-processing */
// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }
SEC("raw_tp/sys_enter")
int handle_open(struct bpf_raw_tracepoint_args *ctx)
{
	pid_t pid;
	filename_t pathname = {0};
	filename_t *pathdebug;
	struct task_struct *task;
	char comm[16];
	int result;
	char debugstr[128];
	unsigned long syscall_id = ctx->args[1];
	unsigned long pid_ns;
	
	bpf_get_current_comm(comm, sizeof(comm));
 	result = __commcmp(comm,"bootstrap");
	task = (struct task_struct *)bpf_get_current_task();
	/*筛选主机端*/
	pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
	if(pid_ns != init_ns)
	{
		return 0;
	}
	//筛选openat
	if(syscall_id != _NR_openat || result == 0)
		return 0;
	struct pt_regs *regs;
	regs = (struct pt_regs *) ctx->args[0];

	char *pathname_ptr = (char *) PT_REGS_PARM2_CORE(regs);
	bpf_core_read_user_str(pathname.filename, sizeof(pathname.filename), pathname_ptr);
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&open_map, &pid, &pathname, BPF_ANY);

	//bpf_printk("syscall %d %s debug:%s\n", syscall_id,pathname.filename,pathdebug->filename);

	return 0;
}
SEC("raw_tp/sys_exit")
int handle_open_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task;
	pid_t pid;
	unsigned long syscall_id;
	struct event *e;
	filename_t *name;
	char comm[16];
	int result;
	struct pt_regs *regs;
	regs = (struct pt_regs *) ctx->args[0];

	/* 筛选openat*/
	bpf_probe_read_kernel(&syscall_id, sizeof(syscall_id), &(regs->orig_ax));
	if(syscall_id != _NR_openat)
		return 0;
	/* 筛选comm ,筛掉自己open的东西*/
	bpf_get_current_comm(comm, sizeof(comm));
 	result = __commcmp(comm,"bootstrap");
	if(result == 0)
	{
		//bpf_printk("cmp result %d",result);
		return 0;
	}
	
	/**/
	pid = bpf_get_current_pid_tgid() >> 32;
	name = (filename_t *)bpf_map_lookup_elem(&open_map, &pid);
	if(name == NULL)	
	{
		return 0;
	}

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	
	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();
	//bpf_printk("PID %d result %d", syscall_id,result);

	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)(name->filename)); 
	//bpf_core_read_user_str(e->filename, sizeof(e->filename), (void *)(name->filename));

	e->event_type = EVENT_TYPE_OPEN;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;


	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
		
}
// SEC("tp/syscalls/sys_enter_openat")
// int handle_tpopen(struct trace_event_openat* ctx)
// {
// 	struct event *e;
// 	struct task_struct *task;
// 	pid_t pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->event_type = EVENT_TYPE_OPEN;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));
// 	bpf_core_read_user_str(e->filename, sizeof(e->filename), (void *)(ctx->filename));
// 	bpf_ringbuf_submit(e, 0);
	
// 	return 0;
// }