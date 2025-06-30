#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 7813 * 4096); // 32MiB 
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} tracked_pids SEC(".maps");


// ------------ NON RESIDENT ROUTINES ------------------

SEC("tracepoint/syscalls/sys_exit_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32* tracked = bpf_map_lookup_elem(&tracked_pids, &pid);


    if(!tracked) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->addr = ctx->args[0];
    e->timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(e->syscall_name, "mmap", 5);

    bpf_printk("pid=%d, addr=0x%llx\n", pid, ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
