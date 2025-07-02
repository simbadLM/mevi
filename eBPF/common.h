#pragma once

#define DEAD  0
#define ALIVE 1

struct proc_info {
    __u32 pid;
    __u8  state;
    __u32 parent_pid;
};

struct event {
    struct proc_info proc_info;
    __u64 addr;
    __u64 timestamp;
    char hooked_event_name[25];
};

