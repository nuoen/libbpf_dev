#include "vmlinux.h"
#include "libbpfstrace.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

    if (s->syscall_id == NR_OPENAT || s->syscall_id == NR_OPENAT2)
        p = (const char *)s->args[1];
    else if (s->syscall_id == NR_EXECVE)
        p = (const char *)s->args[0];

    if (!p)
        return;

    n = bpf_probe_read_user_str(s->str, sizeof(s->str), p);
    if (n > 0)
        s->str_len = (unsigned int)n;
}

static __always_inline void maybe_capture_sockaddr(struct enter_state *s)
{
    void *uaddr;
    unsigned long long len;
    unsigned short family;

    if (s->syscall_id != NR_CONNECT && s->syscall_id != NR_BIND && s->syscall_id != NR_SENDTO)
        return;

    uaddr = (void *)s->args[1];
    if (!uaddr)
        return;

    if (s->syscall_id == NR_SENDTO)
        len = s->args[5];
    else
        len = s->args[2];

    if (len < sizeof(family))
        return;

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return;

    s->sa_family = family;

    if (family == AF_INET_VAL && len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in in4 = {};

        if (bpf_probe_read_user(&in4, sizeof(in4), uaddr) < 0)
            return;

        s->sa_port = in4.sin_port;
        s->sa_addr4 = in4.sin_addr.s_addr;
        s->sa_valid = 1;
        return;
    }

    if (family == AF_INET6_VAL && len >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 in6 = {};

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

    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    s.syscall_id = (int)ctx->args[1];
    s.args[0] = PT_REGS_PARM1_CORE(regs);
    s.args[1] = PT_REGS_PARM2_CORE(regs);
    s.args[2] = PT_REGS_PARM3_CORE(regs);
    s.args[3] = PT_REGS_PARM4_CORE(regs);
    s.args[4] = PT_REGS_PARM5_CORE(regs);
    s.args[5] = BPF_CORE_READ(regs, regs[5]);
    bpf_get_current_comm(&s.comm, sizeof(s.comm));

    maybe_capture_string(&s);
    maybe_capture_sockaddr(&s);

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

    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    s = bpf_map_lookup_elem(&inflight, &id);
    if (!s)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&inflight, &id);
        return 0;
    }

    e->tgid = tgid;
    e->pid = (int)id;
    e->syscall_id = s->syscall_id;
    e->ret = (long long)ctx->args[1];

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

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&inflight, &id);
    return 0;
}
