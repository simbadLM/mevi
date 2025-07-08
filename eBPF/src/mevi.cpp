#include <iostream>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../mevi.skel.h"

#include "../common.h"

static volatile bool running = true;

//TO-DO : determine heap first @ to calculate its size (brk - @heap start)

void handle_sigint(int) {
    running = false;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    int pid = std::atoi(argv[1]);
    if (pid <= 0) {
        std::cerr << "Invalid PID" << std::endl;
        return 1;
    }

    struct mevi_bpf* skel = mevi_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Error while loading BPF" << std::endl;
        return 1;
    }

    int map_fd = bpf_map__fd(skel->maps.tracked_pids);
    __u64 key = static_cast<__u64>(pid);
    __u8 value = ALIVE;

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Error while adding PID to the map" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    }

    int tmp_map_fd = bpf_map__fd(skel->maps.tmp_data_map);
    struct tmp_data initial = {
        .mmap_length    = 0,
        .old_brk        = 0,
        .mremap_tmp     = {
            .old_addr       = 0,
            .old_length     = 0,
            .new_length     = 0
        },
    };

    if (bpf_map_update_elem(tmp_map_fd, &key, &initial, BPF_ANY) != 0) {
        std::cerr << "Error while initializing tmp_data_map" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    }

    if (mevi_bpf__attach(skel) != 0) {
        std::cerr << "Failed to attach BPF program" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    } else std::cout << "Tracking PID " << pid << ". Press Ctrl+C to stop." << std::endl;

    std::signal(SIGINT, handle_sigint);
    while (running) {
        sleep(1);
    }

    mevi_bpf__destroy(skel);
    return 0;
}
