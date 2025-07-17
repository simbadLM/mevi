#include <iostream>
#include <fstream>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <vector>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <type_traits>

#include "../mevi.skel.h"
#include "../common.h"

static volatile bool running = true;

void handle_sigint(int) { running = false; }

#define MAX_STAT_LINE 4096
#define TARGET_FIELD 45

template<typename T>
void write_json_kv(std::ostream &os, const char *k, const T &v) {
    os << '"' << k << "\":";
    if constexpr (std::is_same_v<T, const char*> || std::is_same_v<T, char*> || std::is_same_v<T, std::string>)
        os << '"' << v << '"';
    else
        os << v;
}

// Serialize struct memory_range
void serialize_memory_range(std::ostream &os, const memory_range &mr) {
    os << "{\"addr\":" << mr.addr << ",\"length\":" << mr.length << "}";
}

// Serialize struct proc_info
void serialize_proc_info(std::ostream &os, const proc_info &p) {
    os << "\"proc_info\":{";
    write_json_kv(os, "pid_tgid", p.pid_tgid); os << ",";
    write_json_kv(os, "state", static_cast<int>(p.state)); os << ",";
    write_json_kv(os, "parent_pid_tgid", p.parent_pid_tgid);
    os << "}";
}

// Serialize struct memory_change
void serialize_memory_change(std::ostream &os, const memory_change &m) {
    os << "\"change\":{";
    write_json_kv(os, "kind", m.kind); os << ",";
    write_json_kv(os, "state", static_cast<int>(m.state));
    switch (m.kind) {
        case MEMORY_CHANGE_KIND_MAP:
            os << ",\"map\":";
            serialize_memory_range(os, m.map.range);
            break;
        case MEMORY_CHANGE_KIND_REMAP:
            os << ",\"remap\":{\"old_range\":";
            serialize_memory_range(os, m.remap.old_range);
            os << ",\"new_range\":";
            serialize_memory_range(os, m.remap.new_range);
            os << "}";
            break;
        case MEMORY_CHANGE_KIND_UNMAP:
            os << ",\"unmap\":";
            serialize_memory_range(os, m.unmap.range);
            break;
        case MEMORY_CHANGE_KIND_PAGE_OUT:
            os << ",\"page_out\":";
            serialize_memory_range(os, m.page_out.range);
            break;
        default:
            os << ",\"unk\":null";
    }
    os << "}";
}

// Serialize event
void serialize_event_json(std::ostream &os, const event &ev) {
    os << "{";
    serialize_proc_info(os, ev.proc_info); os << ",";
    write_json_kv(os, "timestamp", ev.timestamp); os << ",";
    serialize_memory_change(os, ev.change);
    os << "}";
}

// Rb callback
static std::ofstream logfile;

static int handle_event(void *, void *data, size_t) {
    const event* ev = static_cast<const event*>(data);
    serialize_event_json(logfile, *ev);
    logfile << std::endl;
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program> [args...]" << std::endl;
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "Fork failed" << std::endl;
        return 1;
    }

    if (pid == 0) {
        std::vector<char*> args;
        for (int i = 1; i < argc; i++) args.push_back(argv[i]);
        args.push_back(nullptr);
        execvp(args[0], args.data());
        perror("execvp failed");
        return 1;
    }

    struct mevi_bpf* skel = mevi_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Error while loading BPF" << std::endl;
        return 1;
    }

    int map_fd = bpf_map__fd(skel->maps.tracked_pids);
    __u64 root_pid_tgid = ((__u64)pid << 32) | pid;
    __u8 value = ALIVE;

    if (bpf_map_update_elem(map_fd, &root_pid_tgid, &value, BPF_ANY) != 0) {
        std::cerr << "Error while adding PID to the map" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    }

    int tmp_map_fd = bpf_map__fd(skel->maps.tmp_data_map);
    struct tmp_data tmp_init = {
        .mmap_length    = 0,
        .old_brk        = 0,
        .start_brk      = 0,
        .mremap_tmp     = {
            .old_addr   = 0,
            .old_length = 0,
            .new_length = 0
        },
    };

    if (bpf_map_update_elem(tmp_map_fd, &root_pid_tgid, &tmp_init, BPF_ANY) != 0) {
        std::cerr << "Error while initializing tmp_data_map" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    }

    if (mevi_bpf__attach(skel) != 0) {
        std::cerr << "Failed to attach BPF program" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    } else {
        std::cout << "Tracking PID " << pid << ". Press Ctrl+C to stop." << std::endl;
    }

    logfile.open("mevi_log.json", std::ios::out | std::ios::trunc);
    if (!logfile) {
        std::cerr << "Cannot open log file" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.rb),
        handle_event,
        nullptr, nullptr
    );
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        mevi_bpf__destroy(skel);
        return 1;
    }

    std::signal(SIGINT, handle_sigint);

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    logfile.close();
    mevi_bpf__destroy(skel);
    return 0;
}
