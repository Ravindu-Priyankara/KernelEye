# Makefile for KernelEye eBPF programs

CLANG = clang
BPFTOOL = bpftool

BPF_FLAGS = -O2 -g -target bpf -D__KERNEL__ -D__BPF_TRACING__ \
	-I./common -I./helpers -I./maps -I/usr/include -I/usr/include/bpf

PROBES_DIR = ./probes
BUILD_DIR = ./build
COMMON_DIR = ./common

# Find all .bpf.c files
BPF_SRCS := $(wildcard $(PROBES_DIR)/*.bpf.c)

# Object files
BPF_OBJS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))

# Skeleton headers
BPF_SKELS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.skel.h,$(BPF_SRCS))

# Default target
all: $(COMMON_DIR)/vmlinux.h $(BPF_SKELS)

# Generate vmlinux.h
$(COMMON_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h..."
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF programs
$(BUILD_DIR)/%.bpf.o: $(PROBES_DIR)/%.bpf.c $(COMMON_DIR)/vmlinux.h
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

# Generate skeleton
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	@echo "Generating skeleton $@"
	$(BPFTOOL) gen skeleton $< > $@

# Clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(COMMON_DIR)/vmlinux.h

.PHONY: all clean