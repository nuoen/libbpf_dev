#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "libbpfapp.skel.h"

static int libbpf_print(enum libbpf_print_level level, const char *fmt,
                        va_list args)
{
    return vfprintf(stderr, fmt, args);
}

int main(void)
{
    struct libbpfapp_bpf *skel = NULL;
    int err;
    pid_t pid;
    unsigned index =0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print);

    skel = libbpfapp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }

    /* ensure BPF program only handle write() syscall from our process*/
    pid = getpid();
    err = bpf_map__update_elem(skel->maps.my_pid_map,&index, sizeof(index),&pid,sizeof(pid_t),BPF_ANY);
    if(err<0){
        fprintf(stderr,"Error updating map with pid: %s\n",strerror(err));
        goto cleanup;
    }



    err = libbpfapp_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started!\n");
    system("cat /sys/kernel/tracing/trace_pipe");

cleanup:
    libbpfapp_bpf__destroy(skel);
    return -err;
}
