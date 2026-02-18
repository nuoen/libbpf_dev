#include <signal.h>
#include <stdio.h>
#include "libbpfso.h"
#include "bpf/libbpf.h"
#include <sys/resource.h>
#include <errno.h>
#include <libbpfso.skel.h>
static volatile int exiting =0;

static char* libdl_path = "/system/lib64/libdl.so";

static void sig_handler(int sig){
    exiting =1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
                        va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static int handle_event(void *ctx, void *data,size_t size){
    const struct event *e=data;
    printf("dlopen_ext called by pid %d (%s), filename: %s\n",
           e->pid, e->comm, e->filename);
    return 0;
}



int main(int argc,char **argv){
    struct libbpfso_bpf * skel =NULL;
    struct ring_buffer *rb=NULL;
    struct bpf_link *link =NULL;
    struct rlimit rl ={
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    if(setrlimit(RLIMIT_MEMLOCK,&rl)){
        perror("setrlimit");
        return 1;
    }

    skel = libbpfso_bpf__open_and_load();
    if(!skel){
        fprintf(stderr,"failed to open and load skeleton\n");
        return 1;
    }
    struct bpf_program *prog = skel->progs.handle_andrid_dlopen_ext;
    /*
    •	bpf_program__attach_uprobe(...)：把 prog 挂到一个用户态函数入口（uprobe）
	•	参数解释：
	1.	prog：你要执行的 BPF 程序
	2.	false：表示 uprobe（函数入口）
	•	如果传 true：就是 uretprobe（函数返回时触发）
	3.	pid = -1：对所有进程生效（全局 hook）
	•	如果你只想 hook 某个 pid，就填具体 pid
	4.	lib_path：目标 ELF 文件路径（这里是 libdl.so）
	5.	func_offset = 0：表示你不提供偏移，让 libbpf 用“符号解析”方式找到函数位置
    */
    struct bpf_uprobe_opts opts = {
        .sz = sizeof(struct bpf_uprobe_opts),
        .func_name ="android_dlopen_ext",
        .retprobe = false,
    };
    link = bpf_program__attach_uprobe_opts(prog,-1,libdl_path,0,&opts);
    if(!link){
        err = -errno;
        fprintf(stderr, "failed to attach uprobe: %s\n", strerror(errno));
        goto cleanup;
    }
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,NULL,NULL);
    if(!rb){
        fprintf(stderr,"failed to create ring buffer\n");
        goto cleanup;
    }
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("Started uprobe on %s:android_dlopen_ext, Ctrl+C to exit\n", libdl_path);
    while(!exiting){
        err = ring_buffer__poll(rb,100);
        if(err==-EINTR){
            continue;
        }
        if (err < 0) {
        fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
         break;
        }
    }
cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (link)
        bpf_link__destroy(link);
    if (skel)
        libbpfso_bpf__destroy(skel);
    return err != 0;
}