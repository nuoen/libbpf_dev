#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct syscall_event *e = data;

    (void)ctx;
    if (data_sz < sizeof(*e))
        return 0;

    printf("pid=%d tid=%d comm=%s syscall=%d(0x%x) args=[0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx]\n",
           e->tgid, e->pid, e->comm,
           e->syscall_id, e->syscall_id,
           e->args[0], e->args[1], e->args[2],
           e->args[3], e->args[4], e->args[5]);
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

int main(int argc, char **argv)
{
    struct libbpfstrace_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int target_pid = 0;
    int err;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [pid]\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        if (parse_pid(argv[1], &target_pid) < 0) {
            fprintf(stderr, "invalid pid: %s\n", argv[1]);
            return 1;
        }
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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (target_pid)
        printf("libbpfstrace started, filtering pid=%d\n", target_pid);
    else
        printf("libbpfstrace started, tracing all processes\n");

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
