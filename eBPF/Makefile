CFLAGS += $(shell pkg-config --cflags libbpf)
LDFLAGS += $(shell pkg-config --libs libbpf)

.PHONY: all
all: mevi

.PHONY: clean
clean:
	rm -f vmlinux.h
	rm -rf mevi.bpf.o
	rm -rf mevi
	rm -rf .cache/
	rm -f compile_commands.json mevi_log.json

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

mevi.bpf.o: src/mevi.bpf.c vmlinux.h
	clang -O2 -g --target=bpf $< -c -o $@

mevi.skel.h: mevi.bpf.o
	bpftool gen skeleton $< > $@

mevi: src/mevi.cpp mevi.skel.h
	c++ $(CFLAGS) -g $^ -o $@ $(LDFLAGS)
