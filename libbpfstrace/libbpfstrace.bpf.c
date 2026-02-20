#include "vmlinux.h"
#include "libbpfstrace.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* BPF 程序许可证声明，内核要求必须存在 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 用户态会在 load 前写入目标 tgid，0 表示不过滤（跟踪所有进程） */
const volatile int target_tgid = 0;

/* arm64 syscall numbers */
#define NR_OPENAT 56
#define NR_READ 63
#define NR_WRITE 64
#define NR_IOCTL 29
#define NR_EPOLL_PWAIT 22
#define NR_FUTEX 98
#define NR_CONNECT 203
#define NR_BIND 200
#define NR_SENDTO 206
#define NR_RECVFROM 207
#define NR_EXECVE 221
#define NR_OPENAT2 437

#define AF_INET_VAL 2
#define AF_INET6_VAL 10

/*
 * 进入 syscall 时的临时状态：
 * 1) 保存 syscall 号与 6 个参数；
 * 2) 尝试抓取 pathname/filename 字符串；
 * 3) 对网络类 syscall 抓取 sockaddr 的关键字段；
 * 4) 该结构先放 inflight map，等 sys_exit 时再拼成完整事件。
 */
struct enter_state {
    int syscall_id;
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* 按 pid_tgid 关联 enter/exit 两个阶段的数据 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct enter_state);
} inflight SEC(".maps");

static __always_inline void maybe_capture_string(struct enter_state *s)
{
    const char *p = NULL;
    int n;

    /* 仅对包含用户态字符串指针的 syscall 做抓取 */
    if (s->syscall_id == NR_OPENAT || s->syscall_id == NR_OPENAT2)
        p = (const char *)s->args[1];
    else if (s->syscall_id == NR_EXECVE)
        p = (const char *)s->args[0];

    if (!p)
        return;

    /* 从用户内存读取 C 字符串，包含 '\0' 在返回长度中 */
    n = bpf_probe_read_user_str(s->str, sizeof(s->str), p);
    if (n > 0)
        s->str_len = (unsigned int)n;
}

static __always_inline void maybe_capture_sockaddr(struct enter_state *s)
{
    void *uaddr;
    unsigned long long len;
    unsigned short family;

    /* 仅处理会传入目的/本地地址的网络 syscall */
    if (s->syscall_id != NR_CONNECT && s->syscall_id != NR_BIND && s->syscall_id != NR_SENDTO)
        return;

    uaddr = (void *)s->args[1];
    if (!uaddr)
        return;

    /* sendto 的 sockaddr 长度参数位置与 connect/bind 不同 */
    if (s->syscall_id == NR_SENDTO)
        len = s->args[5];
    else
        len = s->args[2];

    if (len < sizeof(family))
        return;

    /* 先读取 family 再按 AF_INET/AF_INET6 分支解析 */
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return;

    s->sa_family = family;

    if (family == AF_INET_VAL && len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in in4 = {};

        /* 读取 IPv4 地址结构，按原样保存网络字节序字段 */
        if (bpf_probe_read_user(&in4, sizeof(in4), uaddr) < 0)
            return;

        s->sa_port = in4.sin_port;
        s->sa_addr4 = in4.sin_addr.s_addr;
        s->sa_valid = 1;
        return;
    }

    if (family == AF_INET6_VAL && len >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 in6 = {};

        /* 读取 IPv6 地址结构并复制 16 字节地址 */
        if (bpf_probe_read_user(&in6, sizeof(in6), uaddr) < 0)
            return;

        s->sa_port = in6.sin6_port;
        __builtin_memcpy(s->sa_addr6, &in6.sin6_addr, sizeof(s->sa_addr6));
        s->sa_scope_id = in6.sin6_scope_id;
        s->sa_valid = 1;
    }
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct enter_state s = {};
    struct pt_regs *regs;
    u64 id;
    int tgid;

    regs = (struct pt_regs *)ctx->args[0];

    /* id 高 32 位是 tgid，低 32 位是 pid(tid) */
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    /* 按用户态配置进行进程过滤 */
    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    /* raw_tracepoint/sys_enter: args[1] 是 syscall 号 */
    s.syscall_id = (int)ctx->args[1];

    /* 从寄存器取出最多 6 个 syscall 参数 */
    s.args[0] = PT_REGS_PARM1_CORE(regs);
    s.args[1] = PT_REGS_PARM2_CORE(regs);
    s.args[2] = PT_REGS_PARM3_CORE(regs);
    s.args[3] = PT_REGS_PARM4_CORE(regs);
    s.args[4] = PT_REGS_PARM5_CORE(regs);
    s.args[5] = BPF_CORE_READ(regs, regs[5]);
    bpf_get_current_comm(&s.comm, sizeof(s.comm));

    maybe_capture_string(&s);
    maybe_capture_sockaddr(&s);

    /* 先缓存 enter 状态，供 sys_exit 阶段补齐返回值 */
    bpf_map_update_elem(&inflight, &id, &s, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct syscall_event *e;
    struct enter_state *s;
    u64 id;
    int tgid;

    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    /* exit 侧同样做过滤，避免无关线程触发 map 访问 */
    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    /* 取回 enter 阶段缓存；没有就直接返回 */
    s = bpf_map_lookup_elem(&inflight, &id);
    if (!s)
        return 0;

    /* 在 ringbuf 中申请输出事件空间 */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        /* ringbuf 满时丢弃该条，并清理 inflight 防止泄露 */
        bpf_map_delete_elem(&inflight, &id);
        return 0;
    }

    /* sys_exit 的 args[1] 是 syscall 返回值（负值表示 -errno） */
    e->tgid = tgid;
    e->pid = (int)id;
    e->syscall_id = s->syscall_id;
    e->ret = (long long)ctx->args[1];

    /* 复制 enter 阶段记录下来的参数与扩展字段 */
    e->args[0] = s->args[0];
    e->args[1] = s->args[1];
    e->args[2] = s->args[2];
    e->args[3] = s->args[3];
    e->args[4] = s->args[4];
    e->args[5] = s->args[5];

    __builtin_memcpy(e->comm, s->comm, sizeof(e->comm));
    __builtin_memcpy(e->str, s->str, sizeof(e->str));
    e->str_len = s->str_len;

    e->sa_family = s->sa_family;
    e->sa_port = s->sa_port;
    e->sa_addr4 = s->sa_addr4;
    __builtin_memcpy(e->sa_addr6, s->sa_addr6, sizeof(e->sa_addr6));
    e->sa_scope_id = s->sa_scope_id;
    e->sa_valid = s->sa_valid;

    /* 提交到用户态并删除 inflight 临时状态 */
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
