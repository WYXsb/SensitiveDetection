// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_openat")
int handle_tp(struct bpf_raw_tracepoint_args *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	unsigned long syscall_id = ctx->args[1];
	// if (pid != my_pid)
	// 	return 0;

	bpf_printk("PID %d\n", syscall_id);

	return 0;
}
