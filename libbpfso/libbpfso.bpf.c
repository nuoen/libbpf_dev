#include "vmlinux.h"
#include "libbpfso.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
  __uint(type,BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,1<<24);

} events SEC(".maps");

/*
[用户态 Java]
System.loadLibrary("foo")
  ↳ Runtime.loadLibrary0()
    ↳ Runtime.nativeLoad()
      ↳ NativeLoader::LoadNativeLibrary(...)
        ↳ android_dlopen_ext(...)

[用户态 C/C++ in linker64]
android_dlopen_ext(...)
  ↳ open_library...(内部逻辑)
    ↳ openat(AT_FDCWD, "/data/app/.../libfoo.so", O_RDONLY|O_CLOEXEC)

[用户态 libc 封装]
openat(...)
  ↳ __sys_openat(...)
    ↳ syscall(SYS_openat) / svc #0

[内核态]
el0_svc → do_el0_svc → __arm64_sys_openat()
  ↳ trace_sys_enter(openat, ...)   // ★ 你的 BPF tracepoint 在这里运行
  ↳ do_sys_openat2(...)
  ↳ path_lookupat / VFS / dentry / inode...
  ↳ fd = alloc_fd(...)
  ↳ 返回用户态
*/
SEC("uprobe/android_dlopen_ext")
int BPF_KPROBE(handle_andrid_dlopen_ext,const char *filename){
    struct event *e;
    u64 id;
    int ret;
    if(!filename)
      return 0;
    e = bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e){
      return 0;
    }
    /**
    高 32 位：tgid（进程 pid）
    低 32 位：pid（线程 tid）
    */
    id = bpf_get_current_pid_tgid();
    e->pid = id >>32;
    bpf_get_current_comm(&e->comm,sizeof(e->comm));

    //初始化 filename 缓冲区
    __builtin_memset(e->filename,0,sizeof(e->filename));

    //从用户态读取字符串参数
    ret = bpf_probe_read_user_str(e->filename,sizeof(e->filename),filename);
    //读取失败的兜底处理
    if(ret<0){
      __builtin_memcpy(e->filename,"<failed>",8);
    }
    bpf_ringbuf_submit(e,0);
    return 0;
  }