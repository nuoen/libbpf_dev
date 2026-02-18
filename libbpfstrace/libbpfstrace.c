#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "libbpfstrace.h"
#include "libbpfstrace.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int signo)
{
    (void)signo;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static const char *futex_op_name(unsigned long long op)
{
    switch (op & 0x7f) {
    case 0:
        return "FUTEX_WAIT";
    case 1:
        return "FUTEX_WAKE";
    case 2:
        return "FUTEX_FD";
    case 3:
        return "FUTEX_REQUEUE";
    case 4:
        return "FUTEX_CMP_REQUEUE";
    case 5:
        return "FUTEX_WAKE_OP";
    case 6:
        return "FUTEX_LOCK_PI";
    case 7:
        return "FUTEX_UNLOCK_PI";
    case 8:
        return "FUTEX_TRYLOCK_PI";
    case 9:
        return "FUTEX_WAIT_BITSET";
    case 10:
        return "FUTEX_WAKE_BITSET";
    case 11:
        return "FUTEX_WAIT_REQUEUE_PI";
    case 12:
        return "FUTEX_CMP_REQUEUE_PI";
    case 13:
        return "FUTEX_LOCK_PI2";
    default:
        return "FUTEX_UNKNOWN";
    }
}

static void format_openat_flags(unsigned long long flags, char *buf, size_t sz)
{
    size_t off = 0;
    unsigned long long access = flags & O_ACCMODE;

    if (access == O_RDONLY)
        off += snprintf(buf + off, sz - off, "O_RDONLY");
    else if (access == O_WRONLY)
        off += snprintf(buf + off, sz - off, "O_WRONLY");
    else if (access == O_RDWR)
        off += snprintf(buf + off, sz - off, "O_RDWR");
    else
        off += snprintf(buf + off, sz - off, "0x%llx", access);

#define APPEND_FLAG(f) \
    do { \
        if ((flags) & (f)) \
            off += snprintf(buf + off, sz - off, "|%s", #f); \
    } while (0)
    APPEND_FLAG(O_CREAT);
    APPEND_FLAG(O_EXCL);
    APPEND_FLAG(O_NOCTTY);
    APPEND_FLAG(O_TRUNC);
    APPEND_FLAG(O_APPEND);
    APPEND_FLAG(O_NONBLOCK);
    APPEND_FLAG(O_DSYNC);
    APPEND_FLAG(O_SYNC);
    APPEND_FLAG(O_CLOEXEC);
    APPEND_FLAG(O_DIRECTORY);
    APPEND_FLAG(O_NOFOLLOW);
#undef APPEND_FLAG
}

static const char *syscall_name(int nr)
{
    switch (nr) {
#define __SYSCALL(n, call) case n: return #call;
#define __SC_COMP(n, call, compat_call) __SYSCALL(n, call)
#define __SC_3264(n, call32, call64) __SYSCALL(n, call64)
#define __SC_COMP_3264(n, call32, call64, compat_call) __SYSCALL(n, call64)
#include "../akita-include/kernel-headers/include/uapi/asm-generic/unistd.h"
#undef __SC_COMP_3264
#undef __SC_3264
#undef __SC_COMP
#undef __SYSCALL
    default:
        return "unknown";
    }
}

static void format_syscall_args(const struct syscall_event *e, const char *name, char *out,
                                size_t out_sz)
{
    switch (e->syscall_id) {
    case __NR_read:
        snprintf(out, out_sz, "%s(fd=%llu, buf=%#llx, count=%llu)",
                 name, e->args[0], e->args[1], e->args[2]);
        break;
    case __NR_write:
        snprintf(out, out_sz, "%s(fd=%llu, buf=%#llx, count=%llu)",
                 name, e->args[0], e->args[1], e->args[2]);
        break;
    case __NR_ioctl:
        snprintf(out, out_sz, "%s(fd=%llu, cmd=%#llx, arg=%#llx)",
                 name, e->args[0], e->args[1], e->args[2]);
        break;
    case __NR_futex:
        snprintf(out, out_sz,
                 "%s(uaddr=%#llx, op=%s(%#llx), val=%llu, timeout/uaddr2=%#llx, val3=%#llx)",
                 name, e->args[0], futex_op_name(e->args[1]), e->args[1], e->args[2], e->args[3],
                 e->args[4]);
        break;
    case __NR_openat: {
        char flagbuf[256];
        format_openat_flags(e->args[2], flagbuf, sizeof(flagbuf));
        snprintf(out, out_sz,
                 "%s(dfd=%lld, pathname=%#llx, flags=%s, mode=%#llo)",
                 name, (long long)e->args[0], e->args[1], flagbuf, e->args[3]);
        break;
    }
    case __NR_epoll_pwait:
        snprintf(out, out_sz,
                 "%s(epfd=%llu, events=%#llx, maxevents=%llu, timeout=%lld, sigmask=%#llx, sigsetsize=%llu)",
                 name, e->args[0], e->args[1], e->args[2], (long long)e->args[3], e->args[4],
                 e->args[5]);
        break;
    default:
        snprintf(out, out_sz, "%s(%#llx, %#llx, %#llx, %#llx, %#llx, %#llx)",
                 name, e->args[0], e->args[1], e->args[2], e->args[3], e->args[4], e->args[5]);
        break;
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct syscall_event *e = data;
    const char *name;
    char callbuf[512];

    (void)ctx;
    if (data_sz < sizeof(*e))
        return 0;

    name = syscall_name(e->syscall_id);

    if (strncmp(name, "sys_", 4) == 0)
        name += 4;

    format_syscall_args(e, name, callbuf, sizeof(callbuf));
    printf("pid=%d tid=%d comm=%s %s [id=%d]\n",
           e->tgid, e->pid, e->comm, callbuf, e->syscall_id);
    return 0;
}

static int parse_pid(const char *s, int *pid)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v <= 0 || v > 0x7fffffff)
        return -1;
    *pid = (int)v;
    return 0;
}

static int read_proc_comm(int pid, char *buf, size_t buf_sz)
{
    char path[64];
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (!fgets(buf, (int)buf_sz, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

static int read_proc_cmdline(int pid, char *buf, size_t buf_sz)
{
    char path[64];
    FILE *fp;
    size_t n;

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    n = fread(buf, 1, buf_sz - 1, fp);
    fclose(fp);
    if (n == 0)
        return -1;

    buf[n] = '\0';
    return 0;
}

static int process_name_match(const char *target, const char *name)
{
    size_t len = strlen(target);

    if (strcmp(target, name) == 0)
        return 1;
    if (strncmp(target, name, len) == 0 && name[len] == ':')
        return 1;
    return 0;
}

static int find_pid_by_name(const char *name, int *pid)
{
    DIR *dir;
    struct dirent *de;
    char *end = NULL;
    char comm[256];
    char cmdline[512];

    dir = opendir("/proc");
    if (!dir)
        return -1;

    while ((de = readdir(dir)) != NULL) {
        long v;

        errno = 0;
        v = strtol(de->d_name, &end, 10);
        if (errno || end == de->d_name || *end != '\0' || v <= 0 || v > 0x7fffffff)
            continue;

        if (read_proc_cmdline((int)v, cmdline, sizeof(cmdline)) == 0 &&
            process_name_match(name, cmdline)) {
            *pid = (int)v;
            closedir(dir);
            return 0;
        }

        if (read_proc_comm((int)v, comm, sizeof(comm)) == 0 &&
            process_name_match(name, comm)) {
            *pid = (int)v;
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;
}

int main(int argc, char **argv)
{
    struct libbpfstrace_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int target_pid = 0;
    int err;
    int is_pid = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid|process_name>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (parse_pid(argv[1], &target_pid) == 0) {
        is_pid = 1;
    } else {
        printf("waiting for process name '%s' ...\n", argv[1]);
        while (!exiting) {
            if (find_pid_by_name(argv[1], &target_pid) == 0)
                break;
            sleep(1);
        }
        if (exiting || target_pid <= 0) {
            fprintf(stderr, "interrupted before process '%s' started\n", argv[1]);
            return 1;
        }
        printf("found process '%s' with pid=%d\n", argv[1], target_pid);
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = libbpfstrace_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open skeleton\n");
        return 1;
    }

    skel->rodata->target_tgid = target_pid;

    err = libbpfstrace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = libbpfstrace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    if (is_pid)
        printf("libbpfstrace started, tracing pid=%d\n", target_pid);
    else
        printf("libbpfstrace started, tracing process '%s' pid=%d\n", argv[1], target_pid);

    while (!exiting) {
        err = ring_buffer__poll(rb, 200);
        if (err == -EINTR)
            continue;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    libbpfstrace_bpf__destroy(skel);
    return err != 0;
}
