#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common.h"

#ifndef CLONE_VM
#define CLONE_VM        0x00000100
#endif

#ifndef CLONE_THREAD
#define CLONE_THREAD    0x00010000
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, struct tmp_data);
    __uint(max_entries, 1024);
} tmp_data_map SEC(".maps"); // Store temporary data between enter & exit + last brk @

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

    struct tmp_data *old_tmp    = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if (!old_tmp) return 0;
    struct tmp_data new_tmp     = *old_tmp;      

    new_tmp.mmap_length = ctx->args[1];

    bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int handle_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if (!tmp) return 0;

    __u64 *length = &tmp->mmap_length;
    if (!length) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = ctx->ret;
    e->length               = *length;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MMAP;

    bpf_printk("mmap => pid_tgid=%d, addr=0x%llx\n, length=%d", pid_tgid, ctx->ret, *length);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int handle_enter_mremap(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if(!tmp) return 0; 

    struct tmp_data new_tmp = *tmp;

    struct mremap_tmp m = {
        .old_addr   = ctx->args[0],
        .old_length = ctx->args[1],
        .new_length = ctx->args[2]
    };

    new_tmp.mremap_tmp = m;

    bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mremap")
int handle_exit_mremap(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if (!tmp) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = tmp->mremap_tmp.old_addr;
    e->new_addr             = ctx->ret;
    e->length               = tmp->mremap_tmp.old_length;
    e->new_length           = tmp->mremap_tmp.new_length;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_MREMAP;

    bpf_printk("mremap => pid_tgid=%d, old_addr=0x%llx -> new_addr=0x%llx, new_len=%llu\n",
            pid_tgid, tmp->mremap_tmp.old_addr, ctx->ret, tmp->mremap_tmp.new_length);

    bpf_ringbuf_submit(e, 0);    
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
    e->proc_info.pid_tgid   = pid_tgid;
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
    e->proc_info.pid_tgid   = pid_tgid;
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

/* SEC("tracepoint/sched/sched_process_fork")
int handle_proc_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    __u64 child_pid_tgid = ((__u64)ctx->child_pid << 32) | ctx->child_pid;

    if(!value || *value == DEAD) return 0;

    __u8 order = *value+1;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->proc_info.pid_tgid        = child_pid_tgid;
    e->proc_info.state           = ALIVE;
    e->proc_info.parent_pid_tgid = parent_pid_tgid;
    e->timestamp                 = bpf_ktime_get_ns();
    e->memory_change_kind        = MEMORY_CHANGE_KIND_NEW_CHILD_PROC;

    bpf_ringbuf_submit(e, 0);
    bpf_printk("Clone_exit => tracking new thread child_pid_tgid=%d (order=%d), from parent=%d\n", child_pid_tgid, order, parent_pid_tgid);
    
    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &order, BPF_ANY); // Store the process order

    return 0;
} */

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    if (!tracked || *tracked == DEAD) return 0;

    __u64 flags = ctx->args[0];
    
    if (!(flags & CLONE_VM) || !(flags & CLONE_THREAD)) return 0; // If child doesn't share memory let's get out of here

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &parent_pid_tgid);
    if(!tmp) return 0; 

    struct tmp_data new_tmp = *tmp;

    new_tmp.clone_flags = flags;
    bpf_map_update_elem(&tmp_data_map, &parent_pid_tgid, &new_tmp, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int handle_enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    if (!tracked || *tracked == DEAD) return 0;

    __u64 flags;
    struct clone_args {
        __u64 userland_flags;
        // No need for other fields, struct is mandatory to access data
    };
    struct clone_args args = {};
    bpf_probe_read_user(&args, sizeof(args), (void *)ctx->args[0]);
    flags = args.userland_flags;
    
    if (!(flags & CLONE_VM) || !(flags & CLONE_THREAD)) return 0; // If child doesn't share memory let's get out of here

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &parent_pid_tgid);
    if(!tmp) return 0; 

    struct tmp_data new_tmp = *tmp;

    new_tmp.clone_flags = flags;
    bpf_map_update_elem(&tmp_data_map, &parent_pid_tgid, &new_tmp, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int handle_exit_clone(struct trace_event_raw_sys_exit *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    __u8* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    if (!value || *value == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &parent_pid_tgid);
    if (!tmp) return 0;

    if (!(tmp->clone_flags & CLONE_VM) || !(tmp->clone_flags & CLONE_THREAD)) return 0;

    __u32 child_pid = ctx->ret;
    __u64 child_pid_tgid = ((__u64)child_pid << 32) | child_pid;
    __u8 order = *value+1;

    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &order, BPF_ANY);

    const char *flag_str = "UNKNOWN";
    if (tmp->clone_flags & CLONE_THREAD) flag_str = "thread(CLONE_THREAD)";
    else if (tmp->clone_flags & CLONE_VM) flag_str = "process(CLONE_VM)";

    bpf_printk("Clone_exit => tracking new %s : child_pid_tgid=%d (order=%d), from parent=%d\n",flag_str, child_pid_tgid, order, parent_pid_tgid);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int handle_exit_clone(struct trace_event_raw_sys_exit *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    __u8* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    if (!value || *value == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &parent_pid_tgid);
    if (!tmp) return 0;

    if (!(tmp->clone_flags & CLONE_VM) || !(tmp->clone_flags & CLONE_THREAD)) return 0;

    __u32 child_pid = ctx->ret;
    __u64 child_pid_tgid = ((__u64)child_pid << 32) | child_pid;
    __u8 order = *value+1;

    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &order, BPF_ANY);

    const char *flag_str = "UNKNOWN";
    if (tmp->clone_flags & CLONE_THREAD) flag_str = "thread(CLONE_THREAD)";
    else if (tmp->clone_flags & CLONE_VM) flag_str = "process(CLONE_VM)";

    bpf_printk("Clone3_exit => tracking new %s : child_pid_tgid=%d (order=%d), from parent=%d\n",flag_str, child_pid_tgid, order, parent_pid_tgid);

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

SEC("tracepoint/syscalls/sys_exit_brk")
int handle_exit_brk(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u8* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);
    __u64 delta = 0;

    if(!tracked || *tracked == DEAD) return 0;

    struct tmp_data new_tmp = {};
    struct tmp_data *old_tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);

    if (!old_tmp) return 0; 

    new_tmp = *old_tmp;

    __u64 brk_addr  = ctx->ret;
    __u64 *old_addr = &old_tmp->old_brk;

    if (*old_addr != 0) delta = (*old_addr - brk_addr);
    
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->memory_state         = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->addr                 = brk_addr;
    e->length               = delta;
    e->timestamp            = bpf_ktime_get_ns();
    e->memory_change_kind   = MEMORY_CHANGE_KIND_BRK;
    
    bpf_printk("brk => pid_tgid=%d, addr=0x%llx, delta=%d\n", pid_tgid, brk_addr, delta);
    bpf_ringbuf_submit(e, 0);
    
    new_tmp.old_brk = brk_addr; // Update brk @ in the map
    bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";