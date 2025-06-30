#ifndef __COMMON_H__
#define __COMMON_H__

struct event {
    __u32 pid; 
    __u64 addr;
    __u64 timestamp;
    char syscall_name[10];
};

#endif