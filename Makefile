BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -gdwarf-4 -target bpf -D__TARGET_ARCH_x86

# Try pkg-config; if missing, fall back to common include/lib paths
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null)

JSONC_CFLAGS  := $(shell pkg-config --cflags json-c 2>/dev/null || echo "-I/usr/include/json-c")
JSONC_LIBS    := $(shell pkg-config --libs   json-c 2>/dev/null || echo "-ljson-c")

CFLAGS := -O2 -Wall $(LIBBPF_CFLAGS) $(JSONC_CFLAGS)
LIBS   := $(LIBBPF_LIBS) $(JSONC_LIBS) -lelf -lz -ldl -pthread

all: vmlinux.h policy_kern.bpf.o policy_uprobes.bpf.o policy_loader

vmlinux.h:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found (need BTF-enabled kernel)"; exit 1; \
	fi
	@which bpftool >/dev/null 2>&1 || (echo "bpftool not found. sudo apt install bpftool"; exit 1)
	@echo "[*] Generating vmlinux.h from kernel BTF ..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

policy_kern.bpf.o: policy_kern.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

policy_uprobes.bpf.o: policy_uprobes.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

policy_loader: policy_loader.c
	cc $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f policy_kern.bpf.o policy_uprobes.bpf.o policy_loader vmlinux.h

.PHONY: all clean
