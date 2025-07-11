#pragma once

#define DEAD  0
#define ALIVE 1

enum heap_state {
    HEAP_STATE_DECREASE = 1,
    HEAP_STATE_INCREASE = 2,
    HEAP_STATE_ALL_DATA_REMOVED = 3
};

enum memory_state {
    MEMORY_STATE_RESIDENT = 1,
    MEMORY_STATE_NOT_RESIDENT = 2,
    MEMORY_STATE_UNTRACKED = 3,
    MEMORY_STATE_UNKNOWKN = 4
};

struct proc_info {
    __u64 pid_tgid;
    __u8  state;
    __u64 parent_pid_tgid;
};

struct memory_range {
    __u64 addr;
    __u64 length;
};

enum memory_change_kind {
    MEMORY_CHANGE_KIND_MAP = 1,
    MEMORY_CHANGE_KIND_REMAP = 2,
    MEMORY_CHANGE_KIND_UNMAP = 3,
    MEMORY_CHANGE_KIND_PAGE_OUT = 4,
};

struct memory_change {
    enum memory_change_kind kind;
    enum memory_state state;
    union {
        struct {
            struct memory_range range;
        } map;
        struct {
            struct memory_range old_range;
            struct memory_range new_range;
        } remap;
        struct {
            struct memory_range range;
        } unmap;
        struct {
            struct memory_range range;
        } page_out;
    };
};

struct event {
    struct proc_info proc_info;
    __u64 timestamp;
    struct memory_change change;
};

struct mremap_tmp {
    __u64 old_addr;
    __u64 old_length;
    __u64 new_length;
};

struct tmp_data {
    __u64 mmap_length;
    __u64 old_brk;
    __u64 start_brk;
    __u64 clone_flags;
    struct mremap_tmp mremap_tmp;
};

