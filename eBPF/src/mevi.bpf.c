#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common.h"

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif

#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif

#ifndef MADV_DONTNEED
#define MADV_DONTNEED 4//-> grep MADV_DONTNEED /usr/include/bits/mman-linux.h
#endif

#define SIZE_32MiB 335544320

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); 
    __type(value, struct tmp_data);
    __uint(max_entries, 1024);
} tmp_data_map SEC(".maps"); // Store temporary data between enter & exit + last brk @

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SIZE_32MiB); 
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
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

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
 
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;


    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if (!tmp) return 0;

    __u64 *length = &tmp->mmap_length;
    if (!length) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    struct memory_change l_memory_change = {};

    e->change.state             = MEMORY_STATE_NOT_RESIDENT;
    e->proc_info.pid_tgid       = pid_tgid;
    e->proc_info.state          = ALIVE;
    e->change.map.range.addr    = ctx->ret;
    e->change.map.range.length  = *length;
    e->timestamp                = bpf_ktime_get_ns();
    e->change.kind              = MEMORY_CHANGE_KIND_MAP;

    bpf_printk("mmap => pid_tgid=%llu, addr=0x%llx, length=%d\n", pid_tgid, ctx->ret, *length);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int handle_enter_mremap(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

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
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if (!tmp) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->proc_info.pid_tgid           = pid_tgid;
    e->proc_info.state              = ALIVE;
    e->change.remap.old_range.addr        = tmp->mremap_tmp.old_addr;
    e->change.remap.old_range.length       = tmp->mremap_tmp.old_length;
    e->change.remap.new_range.addr        = ctx->ret;
    e->change.remap.new_range.length       = tmp->mremap_tmp.new_length;
    e->timestamp                    = bpf_ktime_get_ns();
    e->change.kind                  = MEMORY_CHANGE_KIND_REMAP;

    bpf_printk("mremap => pid_tgid=%llu, old_range=%d -> new_range=0x%d\n",
            pid_tgid, tmp->mremap_tmp.old_length, tmp->mremap_tmp.new_length);
    bpf_ringbuf_submit(e, 0);    
    return 0;
}

// ---------------------------------------------------------------/


// ------------ RESIDENT ROUTINES --------------------------------/

SEC("tracepoint/exceptions/page_fault_user") // Only available on x86_x64 & aarch64 for kernel version > 2025 march
int handle_page_fault_user_exception(struct trace_event_raw_exception_page_fault_user *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;

    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u64 addr; 
    const int OFFSET = 8;
    bpf_probe_read_kernel(&addr, sizeof(addr), (void *)ctx + OFFSET); 
    // Non-described in BTF, need to use "sudo cat /sys/kernel/debug/tracing/events/exceptions/page_fault_user/format"
    // command to obtain the correct offset  

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->change.state         = MEMORY_STATE_RESIDENT;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->change.page_out.range.addr = addr;
    e->timestamp            = bpf_ktime_get_ns();
    e->change.kind   = MEMORY_CHANGE_KIND_PAGE_OUT;


    bpf_printk("page_fault_user => pid_tgid=%llu, addr=0x%llx\n", pid_tgid, addr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ---------------------------------------------------------------/

// ------------ DESALLOCATED ROUTINES --------------------------------/
SEC("tracepoint/syscalls/sys_enter_munmap")
int handle_munmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->change.state  = MEMORY_STATE_UNTRACKED;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->change.unmap.range.addr = ctx->args[0];
    e->change.unmap.range.length = ctx->args[1];
    e->timestamp            = bpf_ktime_get_ns();
    e->change.kind   = MEMORY_CHANGE_KIND_UNMAP;

    bpf_printk("munmap => pid_tgid=%llu, addr=0x%llx, new length=%d\n", pid_tgid, ctx->args[0], ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int handle_madvise(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD || ctx->args[2] != MADV_DONTNEED) return 0;
  
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->change.state  = MEMORY_STATE_UNTRACKED;
    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->change.unmap.range.addr    = ctx->args[0]; // Similar to unmap
    e->change.unmap.range.length = ctx->args[1];
    e->timestamp            = bpf_ktime_get_ns();
    e->change.kind   = MEMORY_CHANGE_KIND_UNMAP;

    bpf_printk("madvise => pid_tgid=%llu, addr=0x%llx\n", pid_tgid, ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ---------------------------------------------------------------/

// ------------ PROCESSES EVOLUTION --------------------------------/

/* SEC("tracepoint/sched/sched_process_fork")
int handle_proc_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid() ;
    __u64* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
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
    bpf_printk("Clone_exit => tracking new thread child_pid_tgid=%llu (order=%d), from parent=%d\n", child_pid_tgid, order, parent_pid_tgid);
    
    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &order, BPF_ANY); // Store the process order

    return 0;
} */

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
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
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
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
    __u64* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    if (!value || *value == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &parent_pid_tgid);
    if (!tmp) return 0;

    if (!(tmp->clone_flags & CLONE_VM) || !(tmp->clone_flags & CLONE_THREAD)) return 0;

    __u32 child_pid = ctx->ret;
    if(child_pid <= 0) return 0; //Error 
    __u64 child_pid_tgid = ((__u64)child_pid << 32) | child_pid;
    __u8 order = *value+1;

    struct tmp_data child_tmp_data = *tmp;

    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &order, BPF_ANY);
    bpf_map_update_elem(&tmp_data_map, &child_pid_tgid, &child_tmp_data, BPF_ANY);

    const char *flag_str = "UNKNOWN";
    if (tmp->clone_flags & CLONE_THREAD) flag_str = "thread(CLONE_THREAD)";
    else if (tmp->clone_flags & CLONE_VM) flag_str = "process(CLONE_VM)";

    bpf_printk("Clone_exit => tracking new %s : child_pid_tgid=%llu (order=%d), from parent=%d\n",flag_str, child_pid_tgid, order, parent_pid_tgid);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int handle_exit_clone3(struct trace_event_raw_sys_exit *ctx) {
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    __u64* value = bpf_map_lookup_elem(&tracked_pids, &parent_pid_tgid);
    if (!value || *value == DEAD) return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &parent_pid_tgid);
    if (!tmp) return 0;

    if (!(tmp->clone_flags & CLONE_VM) || !(tmp->clone_flags & CLONE_THREAD)) return 0;

    __u32 child_pid = ctx->ret;
    if(child_pid <= 0) return 0; //Error 
    __u64 child_pid_tgid = ((__u64)child_pid << 32) | child_pid;
    __u8 order = *value;

    struct tmp_data child_tmp_data = *tmp;

    bpf_map_update_elem(&tracked_pids, &child_pid_tgid, &order, BPF_ANY);
    bpf_map_update_elem(&tmp_data_map, &child_pid_tgid, &child_tmp_data, BPF_ANY);

    const char *flag_str = "UNKNOWN";
    if (child_pid_tgid != parent_pid_tgid) {
        order = *value+1;
        flag_str = "process";
    } else {
        flag_str = "thread";
    }
    bpf_printk("Clone3_exit => tracking new %s : child_pid_tgid=%llu (order=%d), from parent=%d\n",flag_str, child_pid_tgid, order, parent_pid_tgid);

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_proc_exit(struct trace_event_raw_sched_process_exit *ctx) {
    __u64 pid_tgid;
    // Non-described in BTF, need to use "sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exit/format"
    // command to obtain the correct offset  
    const int OFFSET = 24;
    bpf_core_read(&pid_tgid, sizeof(pid_tgid), (void *)ctx + OFFSET);

    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u8 dead = DEAD;
    bpf_map_update_elem(&tracked_pids, &pid_tgid, &dead, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->change.state = MEMORY_STATE_UNTRACKED;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state           = DEAD;
    e->timestamp                 = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    bpf_printk("exit=> exiting the pid_tgid %d\n", pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u8 dead = DEAD;
    bpf_map_update_elem(&tracked_pids, &pid_tgid, &dead, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->change.state = MEMORY_STATE_UNTRACKED;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state           = DEAD;
    e->timestamp                 = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    bpf_printk("execve=> delete mapping for the pid_tgid %d\n", pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_at(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    __u8 dead = DEAD;
    bpf_map_update_elem(&tracked_pids, &pid_tgid, &dead, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->change.state = MEMORY_STATE_UNTRACKED;
    e->proc_info.pid_tgid        = pid_tgid;
    e->proc_info.state           = DEAD;
    e->timestamp                 = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    bpf_printk("execveat=> delete mapping for the pid_tgid %d\n", pid_tgid);
    return 0;
}
// ---------------------------------------------------------------/

// ------------ HEAP --------------------------------/
SEC("tracepoint/syscalls/sys_enter_brk")
int handle_enter_brk(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if (!tracked || *tracked == DEAD)
        return 0;

    struct tmp_data *tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);
    if (!tmp)
        return 0;

    struct tmp_data new_tmp = *tmp;

    new_tmp.brk_arg0 = ctx->args[0];
    bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_brk")
int handle_exit_brk(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() ;
    __u64* tracked = bpf_map_lookup_elem(&tracked_pids, &pid_tgid);

    if(!tracked || *tracked == DEAD) return 0;

    struct tmp_data new_tmp = {};
    struct tmp_data *old_tmp = bpf_map_lookup_elem(&tmp_data_map, &pid_tgid);

    if (!old_tmp) return 0; 

    new_tmp = *old_tmp;

    __u64 brk_addr  = ctx->ret;
    __u64 *old_addr = &old_tmp->old_brk;

    if (new_tmp.start_brk == 0 && new_tmp.brk_arg0 == 0) {
        new_tmp.start_brk = brk_addr;
        new_tmp.old_brk = brk_addr;
        bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);
        bpf_printk("init start_brk=0x%llx for pid_tgid=%llu\n", brk_addr, pid_tgid);
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    __u64 old_range, new_range;
    enum heap_state heap_change;

    old_range = *old_addr - new_tmp.start_brk;
    new_range = brk_addr - new_tmp.start_brk;
    
    if      (*old_addr != 0 && new_range == 0)          heap_change = HEAP_STATE_ALL_DATA_REMOVED;
    else if (*old_addr == 0 || old_range < new_range)   heap_change = HEAP_STATE_INCREASE;
    else if (old_range > new_range)                     heap_change = HEAP_STATE_DECREASE;

    e->proc_info.pid_tgid   = pid_tgid;
    e->proc_info.state      = ALIVE;
    e->timestamp            = bpf_ktime_get_ns();
    switch (heap_change) {
        case HEAP_STATE_ALL_DATA_REMOVED : 
            e->change.state      = MEMORY_STATE_UNTRACKED;
            e->change.kind       = MEMORY_CHANGE_KIND_UNMAP;
            break;
        
        case HEAP_STATE_INCREASE :
            e->change.state      = MEMORY_STATE_NOT_RESIDENT;
            e->change.kind       = MEMORY_CHANGE_KIND_MAP;
            e->change.map.range.addr    = brk_addr;
            e->change.map.range.length  = new_range;
            break;
        
        case HEAP_STATE_DECREASE : 
            e->change.state      = MEMORY_STATE_UNKNOWN; //To be or not to be resident...
            e->change.kind       = MEMORY_CHANGE_KIND_UNMAP;
            e->change.unmap.range.addr  = brk_addr;
            e->change.unmap.range.length= new_range;
            break;
    }

    bpf_printk("brk => pid_tgid=%llu, addr=0x%llx, range=%d\n", pid_tgid, brk_addr, new_range);
    bpf_ringbuf_submit(e, 0);
    
    new_tmp.old_brk = brk_addr; // Update brk @ in the map
    bpf_map_update_elem(&tmp_data_map, &pid_tgid, &new_tmp, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";