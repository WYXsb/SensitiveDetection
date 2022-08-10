/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define EVENT_TYPE_EXEC 0
#define EVENT_TYPE_EXIT 1
#define EVENT_TYPE_OPEN 2
#define MAX_PATH_NAME_SIZE 254
struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	int event_type;
};

#endif /* __BOOTSTRAP_H */
