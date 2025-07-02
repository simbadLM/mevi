#pragma once

#define DEAD  0
#define ALIVE 1

enum memory_state {
    MEMORY_STATE_RESIDENT = 1,
    MEMORY_STATE_NOT_RESIDENT = 2,
    MEMORY_STATE_UNTRACKED = 3,
};

enum memory_change_kind {
    MEMORY_CHANGE_KIND_MAP = 1,
    MEMORY_CHANGE_KIND_REMAP = 2,
    MEMORY_CHANGE_KIND_UNMAP = 3,
    MEMORY_CHANGE_KIND_PAGE_OUT = 4,
};

struct proc_info {
    __u32 pid;
    __u8  state;
    __u32 parent_pid;
};

struct event {
    enum memory_state mem_state;
    struct proc_info proc_info;
    __u64 addr;
    __u64 new_addr;
    __u64 length;
    __u64 new_length;
    __u64 timestamp;
    char hooked_event_name[25];
};

