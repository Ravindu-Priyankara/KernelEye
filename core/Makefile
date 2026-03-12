# ===============================
# KernelEye Makefile
# ===============================

CLANG = clang
CC = gcc
BPFTOOL = bpftool

CORE_DIR = .
BUILD_DIR = ./build

# ===============================
# BPF CONFIG
# ===============================

BPF_FLAGS = -O2 -g -target bpf -D__KERNEL__ -D__BPF_TRACING__ \
	-I./common -I./helpers -I./maps -I/usr/include -I/usr/include/bpf

PROBES_DIR = ./probes
COMMON_DIR = ./common

BPF_SRCS := $(wildcard $(PROBES_DIR)/*.bpf.c)

BPF_OBJS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))

BPF_SKELS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.skel.h,$(BPF_SRCS))

# ===============================
# USERSPACE CONFIG
# ===============================

CFLAGS = -Wall -Wextra -g \
	-I./common -I./helpers -I./events -I./detections -I./policies -I./responses -I./loader -I./maps -I./build

USER_SRCS := \
	main.c \
	events/event_handler.c \
	loader/load_connect.c \
	loader/load_execve.c \
	detections/detection_engine.c \
	detections/detection_registry.c \
	detections/reverse_shell/reverse_shell_detector.c \
	detections/rules/exec_rules.c \
	policies/evaluate_policy.c \
	responses/response_engine.c \
	responses/response_registry.c \
	responses/alert_response.c \
	responses/block_response.c \
	responses/allow_response.c

USER_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(USER_SRCS))

# ===============================
# DEFAULT TARGET
# ===============================

all: $(COMMON_DIR)/vmlinux.h $(BPF_SKELS) kerneleye

# ===============================
# vmlinux.h generation
# ===============================

$(COMMON_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h..."
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# ===============================
# BPF compile
# ===============================

$(BUILD_DIR)/%.bpf.o: $(PROBES_DIR)/%.bpf.c $(COMMON_DIR)/vmlinux.h
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

# ===============================
# Skeleton generation
# ===============================

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	@echo "Generating skeleton $@"
	$(BPFTOOL) gen skeleton $< > $@

# ===============================
# Userspace object build
# ===============================

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# ===============================
# Link final binary
# ===============================

kerneleye: $(USER_OBJS)
	$(CC) $(USER_OBJS) -lbpf -lelf -o $(BUILD_DIR)/kerneleye

# ===============================
# Clean
# ===============================

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(COMMON_DIR)/vmlinux.h

.PHONY: all clean