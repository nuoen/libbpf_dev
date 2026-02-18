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

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct syscall_event *e;
    struct pt_regs *regs;
    u64 id;
    long syscall_id;
    int tgid;

    regs = (struct pt_regs *)ctx->args[0];
    syscall_id = (long)ctx->args[1];

    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->tgid = tgid;
    e->pid = (int)id;
    e->syscall_id = (int)syscall_id;

    e->args[0] = PT_REGS_PARM1_CORE(regs);
    e->args[1] = PT_REGS_PARM2_CORE(regs);
    e->args[2] = PT_REGS_PARM3_CORE(regs);
    e->args[3] = PT_REGS_PARM4_CORE(regs);
    e->args[4] = PT_REGS_PARM5_CORE(regs);
    e->args[5] = PT_REGS_PARM6_CORE(regs);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
