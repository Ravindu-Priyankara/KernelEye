# Makefile for KernelEye eBPF programs

CLANG = clang
BPF_FLAGS = -O2 -g -target bpf -D__KERNEL__ -D__BPF_TRACING__ -I./common -I./helpers -I./maps -I/usr/include -I/usr/include/bpf

PROBES_DIR = ./probes
BUILD_DIR = ./build
COMMON_DIR = ./common

# Find all .bpf.c files
BPF_SRCS := $(wildcard $(PROBES_DIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))

# Default target
all: $(COMMON_DIR)/vmlinux.h $(BPF_OBJS)

# Generate vmlinux.h if missing or outdated
$(COMMON_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h..."
	sudo bpftool btf dump file /sys/kernel/debug/tracing/vmlinux format c > $@

# Compile BPF programs
$(BUILD_DIR)/%.bpf.o: $(PROBES_DIR)/%.bpf.c $(COMMON_DIR)/vmlinux.h
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)/*.bpf.o
	rm -f $(COMMON_DIR)/vmlinux.h

.PHONY: all clean