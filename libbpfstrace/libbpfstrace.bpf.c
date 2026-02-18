#include "vmlinux.h"
#include "libbpfstrace.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int target_tgid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *e;
    u64 id;
    int tgid;

    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->tgid = tgid;
    e->pid = (int)id;
    e->syscall_id = (int)ctx->id;

    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
