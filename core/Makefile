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

DEBUG ?= 0   # 0 = no debug, 1 = debug

BPF_FLAGS = -O2 -g -target bpf -D__KERNEL__ -D__BPF_TRACING__ \
	-I./common -I./helpers -I./maps -I/usr/include -I/usr/include/bpf

ifeq ($(DEBUG),1)
BPF_FLAGS += -DDEBUG_MODE
endif

PROBES_DIR = ./probes
COMMON_DIR = ./common

# old 
# BPF_SRCS := $(wildcard $(PROBES_DIR)/*.bpf.c) 
#BPF_OBJS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))
#BPF_SKELS := $(patsubst $(PROBES_DIR)/%.bpf.c,$(BUILD_DIR)/%.skel.h,$(BPF_SRCS))

BPF_DIR = ./bpf
BPF_SRC = $(BPF_DIR)/kerneleye.bpf.c

BPF_OBJ = $(BUILD_DIR)/kerneleye.bpf.o
BPF_SKEL = $(BUILD_DIR)/kerneleye.skel.h


# ===============================
# USERSPACE CONFIG
# ===============================

CFLAGS = -Wall -Wextra -g \
	-I./common -I./helpers -I./events -I./detections -I./policies -I./responses -I./loader -I./maps -I./ui -I./build

USER_SRCS := \
	main.c \
	events/event_handler.c \
	loader/load_kerneleye.c \
	detections/detection_engine.c \
	detections/detection_registry.c \
	detections/reverse_shell/reverse_shell_detector.c \
	detections/rules/exec_rules.c \
	policies/evaluate_policy.c \
	responses/response_engine.c \
	responses/response_registry.c \
	responses/alert_response.c \
	responses/block_response.c \
	responses/allow_response.c \
	ui/banner/banner.c \
	ui/display/display.c

USER_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(USER_SRCS))

# ===============================
# DEFAULT TARGET
# ===============================

#old
#all: $(COMMON_DIR)/vmlinux.h $(BPF_SKELS) kerneleye

all: $(COMMON_DIR)/vmlinux.h $(BPF_SKEL) kerneleye

# ===============================
# vmlinux.h generation
# ===============================

$(COMMON_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h..."
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# ===============================
# BPF compile
# ===============================

# old
#$(BUILD_DIR)/%.bpf.o: $(PROBES_DIR)/%.bpf.c $(COMMON_DIR)/vmlinux.h
#	@mkdir -p $(BUILD_DIR)
#	$(CLANG) $(BPF_FLAGS) -c $< -o $@

$(BPF_OBJ): $(BPF_SRC) $(COMMON_DIR)/vmlinux.h
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

# ===============================
# Skeleton generation
# ===============================

# old
#$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
#	@echo "Generating skeleton $@"
#	$(BPFTOOL) gen skeleton $< > $@

$(BPF_SKEL): $(BPF_OBJ)
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