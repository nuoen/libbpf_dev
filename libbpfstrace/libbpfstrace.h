#ifndef LIBBPFSTRACE_H
#define LIBBPFSTRACE_H

#define TASK_COMM_LEN 16
#define SYSCALL_STR_LEN 256

struct syscall_event {
    int tgid;
    int pid;
    int syscall_id;
    long long ret;
    unsigned long long args[6];
    char comm[TASK_COMM_LEN];
    char str[SYSCALL_STR_LEN];
    unsigned int str_len;
    unsigned short sa_family;
    unsigned short sa_port;
    unsigned int sa_addr4;
    unsigned char sa_addr6[16];
    unsigned int sa_scope_id;
    unsigned char sa_valid;
};

#endif
