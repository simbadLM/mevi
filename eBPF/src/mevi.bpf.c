#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common.h"

struct mremap_tmp {
    __u64 old_addr;
    __u64 old_length;
    __u64 new_length;
};

struct tmp_data {
    __u64 mmap_length;
    __u64 old_brk;
    struct mremap_tmp mremap_tmp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, struct tmp_data);
    __uint(max_entries, 1024);
} tmp_data_map SEC(".maps"); // Store temporary length of memory region from mmap_enter->arg[1]

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, __u64);
    __uint(max_entries, 1024);
} mmap_length_map SEC(".maps"); // Store temporary length of memory region from mmap_enter->arg[1]

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, __u64);
    __uint(max_entries, 1024);
} brk_map SEC(".maps"); // Store old brk @ to calculate delta

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, struct mremap_tmp);
    __uint(max_entries, 1024);
} mremap_tmp_map SEC(".maps"); // Store temporary data from mremap_enter()

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); 
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} tracked_pids SEC(".maps");

// ------------ NON RESIDENT ROUTINES ------------------------/

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u64 length = ctx->args[1];

    struct tmp_data *old_tmp    = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    struct tmp_data new_tmp     = {};

    if(old_tmp) {
        new_tmp = *old_tmp;      
    }

    new_tmp.mmap_length = ctx->args[1];

    bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int handle_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u64 *length = bpf_map_lookup_elem(&mmap_length_map, &pid_tgid);
    if (!length) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = ctx->ret;
    e->length               = *length;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MMAP;

    bpf_printk("mmap => pid_tgid=%d, addr=0x%llx\n", pid_tgid, ctx->ret);
    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&mmap_length_map, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int handle_enter_mremap(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;

    struct mremap_tmp m = {
        .old_addr   = ctx->args[0],
        .old_length = ctx->args[1],
        .new_length = ctx->args[2]
    };

    bpf_map_update_elem(&mremap_tmp_map, &pid_tgid, &m, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mremap")
int handle_exit_mremap(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct mremap_tmp *tmp = bpf_map_lookup_elem(&mremap_tmp_map, &pid_tgid);
    if (!tmp) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = tmp->old_addr;
    e->new_addr             = ctx->ret;
    e->length               = tmp->old_length;
    e->new_length           = tmp->new_length;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MREMAP;

    bpf_printk("mremap => pid_tgid=%d, old_addr=0x%llx -> new_addr=0x%llx, new_len=%llu\n",
            pid_tgid, tmp->old_addr, ctx->ret, tmp->new_length);

    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&mremap_tmp_map, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int handle_madvise(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = ctx->args[0];
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MADVISE;

    bpf_printk("madvise => pid_tgid=%d, addr=0x%llx\n", pid_tgid, ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ---------------------------------------------------------------/


// ------------ RESIDENT ROUTINES --------------------------------/

SEC("tracepoint/exceptions/page_fault_user") // Only available on x86_x64 & aarch64 for kernel version > 2025 march
int handle_page_fault_user_exception(struct trace_event_raw_exception_page_fault_user *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;

    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u64 addr; 
    const int OFFSET = 8;
    bpf_probe_read_kernel(&addr, sizeof(addr), (void *)ctx + OFFSET); 
    // Non-described in BTF, need to use "sudo cat /sys/kernel/debug/tracing/events/exceptions/page_fault_user/format"
    // command to obtain the correct offset  

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_RESIDENT;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = addr;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MMAP;


    bpf_printk("page_fault_user => pid_tgid=%d, addr=0x%llx\n", pid_tgid, addr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ---------------------------------------------------------------/

// ------------ DESALLOCATED ROUTINES --------------------------------/
SEC("tracepoint/syscalls/sys_enter_munmap")
int handle_munmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_UNTRACKED;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = ctx->args[0];
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MUNMAP;

    bpf_printk("munmap => pid_tgid=%d, addr=0x%llx\n", pid_tgid, ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ---------------------------------------------------------------/

// ------------ PROCESSES EVOLUTION --------------------------------/

SEC("tracepoint/sched/sched_process_fork")
int handle_proc_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);

    if(!value || *value == DEAD) return 0;

    __u32 child_pid_tgid = ctx->child_pid | ctx->child_pid; 

    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &value+1, BPF_ANY); // Store the process order

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->proc_info.pid_tgid        = child_pid_tgid;
    e->proc_info.state           = ALIVE;
    e->proc_info.parent_pid_tgid = parent_pid_tgid;
    e->timestamp                 = bpf_ktime_get_ns();
    e->memory_change_kind        = MEMORY_CHANGE_KIND_NEW_CHILD_PROC;


    bpf_ringbuf_submit(e, 0);
    bpf_printk("Tracking a new process child pid_tgid %d from parent pid_tgid %d\n", child_pid_tgid, parent_pid_tgid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_proc_exit(struct trace_event_raw_sched_process_exit *ctx) {
    __u64 pid_tgid;
    // Non-described in BTF, need to use "sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exit/format"
    // command to obtain the correct offset  
    const int OFFSET = 24;
    bpf_core_read(&pid_tgid, sizeof(pid_tgid), (void *)ctx + OFFSET);

    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u8 dead = DEAD; // No other choice than to create temporary variable 
    bpf_map_update_elem(&tracked_pids, &pid_tgid, &dead, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = DEAD;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_EXIT;

    bpf_ringbuf_submit(e, 0);

    bpf_printk("exit=> exiting the pid_tgid %d\n", pid_tgid);
    return 0;
}
// ---------------------------------------------------------------/

// ------------ HEAP --------------------------------/

int handle_brk(__u32 i_pid, __u8 *i_tracked_pids, __u64 i_brk_addr, __u64 *i_old_addr, __u64 i_delta) {
     struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;

        e->memory_state            = MEMORY_STATE_NOT_RESIDENT;
        e->proc_info.pid_tgid        = i_pid;
        e->proc_info.state      = ALIVE;
        e->addr                 = i_brk_addr;
        e->length               = i_delta;
        e->timestamp            = bpf_ktime_get_ns();
        e->memory_change_kind   = MEMORY_CHANGE_KIND_BRK;


        bpf_printk("brk => pid_tgid=%d, addr=0x%llx, delta=%d\n", i_pid, i_brk_addr, i_delta);
        bpf_ringbuf_submit(e, 0);
        
        bpf_map_update_elem(&brk_map, &i_pid, &i_brk_addr, BPF_ANY); // Update brk @ in the map
}

SEC("tracepoint/syscalls/sys_exit_brk")
int handle_exit_brk(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u64 brk_addr = ctx->ret;
    __u64 *old_addr = bpf_map_lookup_elem(&brk_map, &pid_tgid);

    if (!old_addr) {
        __u64 const NO_DELTA = 0;
        handle_brk(pid_tgid, tracked, brk_addr, NULL, NO_DELTA);
        return 0;
    } else handle_brk(pid_tgid, tracked, brk_addr, old_addr, (*old_addr - brk_addr));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";