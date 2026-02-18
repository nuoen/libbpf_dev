# // SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# /* Copyright (c) 2023-2024 fei_cong(https://github.com/feicong/ebpf-course) */

# ================== 目标平台选择 ==================
# TARGET=android : 交叉编译到 aarch64-linux-android (arm64)
# TARGET=linux   : 编译成本机 x86_64 Linux 可执行文件
TARGET ?= android

# 通用 SDK_DIR（Android 要用，Linux 目前只用 VMLINUX 时可选）
SDK_DIR  ?= ./ebpf-android-sdk

# ================== 基础工具链配置 ==================
ifeq ($(TARGET),android)

ARCH       := arm64
NDK_HOME  ?= $(HOME)/android-ndk

LLVM_STRIP := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
CLANG      := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang
CC         := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang

LIBBPF_OBJ := $(abspath $(SDK_DIR)/lib/$(ARCH)/libbpf.a)
BPFTOOL    := $(abspath $(SDK_DIR)/bpftool/x86/bpftool)
VMLINUX    := $(SDK_DIR)/vmlinux/$(ARCH)/vmlinux.h

# Android 链接参数
ALL_LDFLAGS := $(LDFLAGS) -L$(SDK_DIR)/lib/$(ARCH)
LIBBPF_LIBS := -static -L$(SDK_DIR)/libbpf/lib/$(ARCH)/ -lbpf -lelf -lz

# BPF 程序里的 arch 宏（libbpf 约定）
BPF_ARCH   := arm64

else ifeq ($(TARGET),linux)

# 本机 Linux：用户态程序是 x86_64
ARCH       := x86_64

# 使用系统的 clang / cc / llvm-strip（需要在 PATH 里面）
LLVM_STRIP ?= llvm-strip
CLANG      ?= clang
CC         ?= cc

# Linux 下不再用 Android SDK 里的 libbpf.a，改用系统 libbpf
LIBBPF_OBJ :=
BPFTOOL    ?= bpftool

# vmlinux.h 的路径（你自己生成好的）
VMLINUX    ?= /home/mi/vmlinux.h

# 通过 pkg-config 获取 libbpf 编译 / 链接参数（没装 libbpf-dev 时会为空）
CFLAGS      += $(shell pkg-config --cflags libbpf 2>/dev/null)
ALL_LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libbpf 2>/dev/null)
# 保险再补一遍
LIBBPF_LIBS := -lbpf -lelf -lz

# x86_64 对应的 BPF arch 宏写成 x86
BPF_ARCH   := x86

else
$(error Unsupported TARGET=$(TARGET), only 'android' or 'linux' are supported)
endif

# CFLAGS：通用基础参数（两个分支都生效）
CFLAGS += -g -Wall

# ================== 项目列表 ==================
PROJECTS := libbpfapp libbpfso

# 默认 APP（直接 make 时构建谁）
APP ?= libbpfapp

# 控制构建阶段：0 = 默认编到二进制，1 = 只编到 skeleton
SKELETON_ONLY ?= 0

# ================== 针对当前 APP 的派生变量（递归 make 时重算） ==================
APP_DIR  := $(APP)
OUT_DIR  := $(APP_DIR)/out

BPF_C    := $(APP_DIR)/$(APP).bpf.c
USER_C   := $(APP_DIR)/$(APP).c

BPF_O    := $(OUT_DIR)/$(APP).bpf.o
SKEL_H   := $(OUT_DIR)/$(APP).skel.h
USER_O   := $(OUT_DIR)/$(APP).o
BIN      := $(OUT_DIR)/$(APP)

ifeq ($(TARGET),linux)
# /usr/include 里有 bpf/bpf_helpers.h，包含 <bpf/bpf_helpers.h> 时需要 -I/usr/include
INCLUDES := -I$(OUT_DIR) -I$(dir $(VMLINUX)) -I/usr/include
else
INCLUDES := -I$(OUT_DIR) -I$(SDK_DIR)/include -I$(dir $(VMLINUX))
endif

# clang bpf sys headers
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# 用于生成 compile_commands.json 的工具
BEAR ?= bear

# ================== 顶层目标 ==================
.PHONY: all
all: $(APP)

# make libbpfapp / make libbpfapp2 / ...
.PHONY: $(PROJECTS)
$(PROJECTS):
	@if command -v $(BEAR) >/dev/null 2>&1; then \
		echo "  COMPDB   compile_commands.json (APP=$@)"; \
		$(BEAR) --output compile_commands.json -- $(MAKE) APP=$@ __build_one; \
	else \
		echo "  BUILD    $@ (no bear, no compile_commands.json)"; \
		$(MAKE) APP=$@ __build_one; \
	fi

# 实际构建某个 APP 的内部目标（在递归 make 中调用）
.PHONY: __build_one
ifeq ($(SKELETON_ONLY),1)
__build_one: $(SKEL_H)
else
__build_one: $(BIN)
endif

# ================== 清理 ==================
.PHONY: clean
clean:
	@echo "  CLEAN    out/ & compile_commands.json"
	@rm -f compile_commands.json
	@for p in $(PROJECTS); do rm -rf $$p/out; done

# ================== 目录和工具 ==================
$(OUT_DIR):
	@echo "  MKDIR    $(OUT_DIR)"
	@mkdir -p $(OUT_DIR)

$(BPFTOOL):
	@echo "  BPFTOOL  $(BPFTOOL)"
	@true

# ================== 编译规则（针对当前 APP） ==================
# 1. BPF 对象：APP/APP.bpf.c -> APP/out/APP.bpf.o
$(BPF_O): $(BPF_C) $(VMLINUX) | $(OUT_DIR)
	@echo "  BPF      $@ (TARGET=$(TARGET), ARCH=$(ARCH), BPF_ARCH=$(BPF_ARCH))"
	@$(CLANG) $(CFLAGS) -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $@
	@$(LLVM_STRIP) -g $@

# 2. skeleton：APP/out/APP.bpf.o -> APP/out/APP.skel.h
$(SKEL_H): $(BPF_O) | $(OUT_DIR) $(BPFTOOL)
	@echo "  GEN-SKEL $@"
	@$(BPFTOOL) gen skeleton $< > $@

# 3. 用户态：APP/APP.c -> APP/out/APP.o
$(USER_O): $(USER_C) $(SKEL_H) | $(OUT_DIR)
	@echo "  CC       $@"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 4. 最终二进制：APP/out/APP
$(BIN): $(USER_O) $(LIBBPF_OBJ) | $(OUT_DIR)
	@echo "  BINARY   $@ (TARGET=$(TARGET), ARCH=$(ARCH))"
	@$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) $(LIBBPF_LIBS) -o $@
	@$(LLVM_STRIP) -g $@

.DELETE_ON_ERROR:
.SECONDARY: