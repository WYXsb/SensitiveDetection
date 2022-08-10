// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"
#include "hash1.1.h"
#include "main.h"


static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}


static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}
int isaDir(char *buff)
{
    struct stat st;
    stat(buff,&st);
    if (S_ISDIR(st.st_mode))
    {
        //printf("is a dir\n");
        return 1;
    }
    else{
        return 0;
    }
}
int getAbspath(char *rootpath,char *path,char *pid)
{
    int pathlen;
    char cwd[1024];
    char linkpath[1024];
    char Relativepath[1024]={0};
    if (path[0] == '/')
    {
        //printf("%s\n", path);
		sprintf(rootpath, "%s", path);
        return isaDir(path);
    } 
    else if (path[0] == '.' && path[1] == '/')
    {
        pathlen = strlen(path);
        for (int i = 0; i < pathlen; i++)
        {
            Relativepath[i] = path[i+1];
        }
        sprintf(cwd, "/proc/%s/cwd", pid);
        readlink(cwd, linkpath, 1024 - 1);
        sprintf(rootpath, "%s%s", linkpath,Relativepath);
		//printf("rootpath:%s\nrelvpath:%s\n",linkpath,Relativepath);
        return isaDir(rootpath);

    }
    else
    {
        sprintf(cwd, "/proc/%s/cwd", pid);
        readlink(cwd, linkpath, 1024 - 1);
        sprintf(rootpath, "%s/%s", linkpath,path);
        //printf("rootpath:%s\nrelvpath:%s\n",linkpath,path);
        return isaDir(rootpath);
    }
	
}
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	char rootpath[256]={0};
	unsigned int sha1state[5];
	time_t t;
	char strpid[16];
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->event_type == EVENT_TYPE_EXIT) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]",
		       ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else if(e->event_type == EVENT_TYPE_EXEC){
		printf("%-8s %-5s %-16s %-7d %-7d %s\n",
		       ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
	}else if (e->event_type == EVENT_TYPE_OPEN)
	{
		
		if(e->pid && e->exit_code != -1 && e->filename[0]!=0)
		{
			if(!strcmp(e->comm,"git"))
				return 0;
			// printf("%-8s %-5s %-16s %-7d %-7d %s\n",
		    //      ts, "OPEN", e->comm, e->pid, e->ppid, e->filename);
			sprintf(strpid,"%d",e->pid);
			//detect(e->filename,strpid);
			int ret = getAbspath(rootpath,e->filename,strpid);
			if(strncmp("/tmp",rootpath,4))
				return 0;
			
			switch (ret)
			{
			case 1:
				/* code */
				break;
			case 0:
				detect(rootpath,strpid);
				//printf("SHA1:%08x%08x%08x%08x%08x \n", sha1state[0], sha1state[1], sha1state[2], sha1state[3], sha1state[4]);
			default:
				break;
			}
			
		}

	}
	return 0;
}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;
	unsigned long * systable_p;
	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
	skel->bss->_NR_openat = __NR_openat;
	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */ 
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
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
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
