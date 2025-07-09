#pragma once

#define DEAD  0
#define ALIVE 1

enum memory_state {
    MEMORY_STATE_RESIDENT = 1,
    MEMORY_STATE_NOT_RESIDENT = 2,
    MEMORY_STATE_UNTRACKED = 3
};

enum memory_change_kind {
    MEMORY_CHANGE_KIND_MMAP = 1,
    MEMORY_CHANGE_KIND_MREMAP = 2,
    MEMORY_CHANGE_KIND_MADVISE = 3,
    MEMORY_CHANGE_KIND_MUNMAP = 4,
    MEMORY_CHANGE_KIND_PAGE_FAULT_USER = 5,
    MEMORY_CHANGE_KIND_NEW_CHILD_PROC = 6,
    MEMORY_CHANGE_KIND_EXIT = 7,
    MEMORY_CHANGE_KIND_BRK = 8
};

struct proc_info {
    __u64 pid_tgid;
    __u8  state;
    __u64 parent_pid_tgid;
};

struct event {
    enum memory_state memory_state;
    struct proc_info proc_info;
    __u64 addr;
    __u64 new_addr;
    __u64 length;
    __u64 new_length;
    __u64 timestamp;
    enum memory_change_kind memory_change_kind;
};

struct mremap_tmp {
    __u64 old_addr;
    __u64 old_length;
    __u64 new_length;
};

struct tmp_data {
    __u64 mmap_length;
    __u64 old_brk;
    __u64 clone_flags;
    struct mremap_tmp mremap_tmp;
};

