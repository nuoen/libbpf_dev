#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "libbpfstrace.h"
#include "libbpfstrace.skel.h"

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_connect
#define __NR_connect 203
#endif
#ifndef __NR_bind
#define __NR_bind 200
#endif
#ifndef __NR_sendto
#define __NR_sendto 206
#endif
#ifndef __NR_execve
#define __NR_execve 221
#endif

static volatile sig_atomic_t exiting;

/* 信号处理：收到 Ctrl-C(SIGINT) 或 SIGTERM 后，让主循环退出 */
static void sig_handler(int signo)
{
    (void)signo;
    exiting = 1;
}

/* libbpf 日志回调：屏蔽 DEBUG，其他级别输出到 stderr */
static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static const char *errno_name(int err)
{
    /* 将常见 errno 数值映射为名字，便于输出更像 strace */
    switch (err) {
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case ESRCH: return "ESRCH";
    case EINTR: return "EINTR";
    case EIO: return "EIO";
    case ENXIO: return "ENXIO";
    case E2BIG: return "E2BIG";
    case ENOEXEC: return "ENOEXEC";
    case EBADF: return "EBADF";
    case ECHILD: return "ECHILD";
    case EAGAIN: return "EAGAIN";
    case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES";
    case EFAULT: return "EFAULT";
    case EBUSY: return "EBUSY";
    case EEXIST: return "EEXIST";
    case ENODEV: return "ENODEV";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EINVAL: return "EINVAL";
    case ENFILE: return "ENFILE";
    case EMFILE: return "EMFILE";
    case ENOTTY: return "ENOTTY";
    case ETXTBSY: return "ETXTBSY";
    case EFBIG: return "EFBIG";
    case ENOSPC: return "ENOSPC";
    case ESPIPE: return "ESPIPE";
    case EROFS: return "EROFS";
    case EMLINK: return "EMLINK";
    case EPIPE: return "EPIPE";
    case EDOM: return "EDOM";
    case ERANGE: return "ERANGE";
    case ENOSYS: return "ENOSYS";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ETIMEDOUT: return "ETIMEDOUT";
    default: return "ERR";
    }
}

static const char *futex_op_name(unsigned long long op)
{
    /* futex op 低 7 bit 是基础操作码，其他 bit 往往是修饰标志 */
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

static void format_sockaddr(const struct syscall_event *e, char *buf, size_t sz)
{
    /* BPF 侧只在 connect/bind/sendto 时尽量抓 sockaddr，失败则输出 NULL/简化信息 */
    if (!e->sa_valid) {
        snprintf(buf, sz, "NULL");
        return;
    }

    if (e->sa_family == AF_INET) {
        struct in_addr a4;
        char ip[INET_ADDRSTRLEN];

        a4.s_addr = e->sa_addr4;
        if (!inet_ntop(AF_INET, &a4, ip, sizeof(ip))) {
            snprintf(buf, sz, "{sa_family=AF_INET, sin_port=%u, sin_addr=?}",
                     ntohs(e->sa_port));
            return;
        }
        snprintf(buf, sz, "{sa_family=AF_INET, sin_port=%u, sin_addr=\"%s\"}",
                 ntohs(e->sa_port), ip);
        return;
    }

    if (e->sa_family == AF_INET6) {
        struct in6_addr a6;
        char ip[INET6_ADDRSTRLEN];

        memcpy(&a6, e->sa_addr6, sizeof(a6));
        if (!inet_ntop(AF_INET6, &a6, ip, sizeof(ip))) {
            snprintf(buf, sz, "{sa_family=AF_INET6, sin6_port=%u, sin6_addr=?}",
                     ntohs(e->sa_port));
            return;
        }
        snprintf(buf, sz,
                 "{sa_family=AF_INET6, sin6_port=%u, sin6_addr=\"%s\", sin6_scope_id=%u}",
                 ntohs(e->sa_port), ip, e->sa_scope_id);
        return;
    }

    snprintf(buf, sz, "{sa_family=%u}", e->sa_family);
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

static const char *arg_string(const struct syscall_event *e)
{
    /* 仅当 BPF 侧成功抓到用户态字符串时返回 */
    if (e->str_len > 0 && e->str_len <= SYSCALL_STR_LEN)
        return e->str;
    return NULL;
}

static const char *syscall_name(int nr)
{
    /* 通过内核 uapi 的 syscall 表宏，构造 syscall nr -> 名称映射 */
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
    const char *s;

    /*
     * 将原始 args[] 格式化成人类可读文本。
     * 未单独适配的 syscall 走 default，打印 6 个原始参数。
     */
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
        s = arg_string(e);
        if (s) {
            snprintf(out, out_sz,
                     "%s(dfd=%lld, pathname=\"%s\", flags=%s, mode=%#llo)",
                     name, (long long)e->args[0], s, flagbuf, e->args[3]);
        } else {
            snprintf(out, out_sz,
                     "%s(dfd=%lld, pathname=%#llx, flags=%s, mode=%#llo)",
                     name, (long long)e->args[0], e->args[1], flagbuf, e->args[3]);
        }
        break;
    }
    case __NR_openat2: {
        s = arg_string(e);
        if (s) {
            snprintf(out, out_sz,
                     "%s(dfd=%lld, pathname=\"%s\", how=%#llx, size=%llu)",
                     name, (long long)e->args[0], s, e->args[2], e->args[3]);
        } else {
            snprintf(out, out_sz,
                     "%s(dfd=%lld, pathname=%#llx, how=%#llx, size=%llu)",
                     name, (long long)e->args[0], e->args[1], e->args[2], e->args[3]);
        }
        break;
    }
    case __NR_execve:
        s = arg_string(e);
        if (s) {
            snprintf(out, out_sz, "%s(filename=\"%s\", argv=%#llx, envp=%#llx)",
                     name, s, e->args[1], e->args[2]);
        } else {
            snprintf(out, out_sz, "%s(filename=%#llx, argv=%#llx, envp=%#llx)",
                     name, e->args[0], e->args[1], e->args[2]);
        }
        break;
    case __NR_connect:
    case __NR_bind:
    case __NR_sendto: {
        char addrbuf[192];
        format_sockaddr(e, addrbuf, sizeof(addrbuf));
        if (e->syscall_id == __NR_sendto) {
            snprintf(out, out_sz,
                     "%s(sockfd=%llu, buf=%#llx, len=%llu, flags=%#llx, dest_addr=%s, addrlen=%llu)",
                     name, e->args[0], e->args[1], e->args[2], e->args[3], addrbuf, e->args[5]);
        } else {
            snprintf(out, out_sz,
                     "%s(sockfd=%llu, addr=%s, addrlen=%llu)",
                     name, e->args[0], addrbuf, e->args[2]);
        }
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
    char retbuf[128];

    /* 内核与用户态结构体不一致时直接丢弃，避免越界读取 */
    (void)ctx;
    if (data_sz < sizeof(*e))
        return 0;

    name = syscall_name(e->syscall_id);

    if (strncmp(name, "sys_", 4) == 0)
        name += 4;

    format_syscall_args(e, name, callbuf, sizeof(callbuf));
    /* 将负返回值按 -errno 解释成错误码与错误字符串 */
    if (e->ret < 0) {
        int err = (int)-e->ret;
        snprintf(retbuf, sizeof(retbuf), "-1 %s (%s)", errno_name(err), strerror(err));
    } else {
        snprintf(retbuf, sizeof(retbuf), "%lld", e->ret);
    }

    printf("pid=%d tid=%d comm=%s %s = %s [id=%d]\n",
           e->tgid, e->pid, e->comm, callbuf, retbuf, e->syscall_id);
    return 0;
}

static int parse_pid(const char *s, int *pid)
{
    char *end = NULL;
    long v;

    /* 只接受正整数且在 int32 范围内的 pid 输入 */
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

    /* /proc/<pid>/comm 通常是进程名（线程组名） */
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

    /* /proc/<pid>/cmdline 以 '\0' 分隔参数，首段一般是可执行文件路径/名字 */
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

    /* 兼容 Android 风格的 "name:suffix"（例如多进程/子进程后缀） */
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

    /* 轮询 /proc，优先用 cmdline 匹配，失败再退回 comm 匹配 */
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

    /*
     * 用法：
     *   libbpfstrace <pid|process_name>
     * 传 pid：立即附着。
     * 传进程名：循环扫描 /proc，直到目标出现。
     */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid|process_name>\n", argv[0]);
        return 1;
    }

    /* 安装退出信号，保证 poll 循环可被中断并清理资源 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 参数是数字则按 pid；否则按进程名等待目标启动 */
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

    /* 初始化 libbpf 行为与日志 */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* 打开 BPF skeleton（还未 load/attach） */
    skel = libbpfstrace_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open skeleton\n");
        return 1;
    }

    /* 向 BPF rodata 写入过滤 pid，仅跟踪这个 tgid */
    skel->rodata->target_tgid = target_pid;

    /* 校验并加载 BPF 程序与 map 到内核 */
    err = libbpfstrace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* 将 raw_tracepoint 程序挂到 sys_enter/sys_exit */
    err = libbpfstrace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* 订阅 BPF ringbuf，内核事件到达后回调 handle_event */
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

    /* 主循环：poll ringbuf，不断消费内核上报的 syscall_event */
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
    /* 统一释放用户态资源 */
    ring_buffer__free(rb);
    libbpfstrace_bpf__destroy(skel);
    return err != 0;
}
