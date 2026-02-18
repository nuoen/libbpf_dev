#ifndef LIBBPFSTRACE_H
#define LIBBPFSTRACE_H

#define TASK_COMM_LEN 16

struct syscall_event {
    int tgid;
    int pid;
    int syscall_id;
    unsigned long long args[6];
    char comm[TASK_COMM_LEN];
};

#endif
