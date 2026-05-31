# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# myfirewall：使用系统自带的 clang、bpftool、libbpf（通过 PATH / pkg-config 解析）。

ROOT      := $(abspath .)
SRC_DIR   := $(ROOT)/src
OUT       := $(SRC_DIR)/.output

CLANG     ?= clang
BPFTOOL   ?= bpftool

BPF_C     := $(SRC_DIR)/firewall.bpf.c
USER_C    := $(SRC_DIR)/firewall.c
USER_HDR  := $(SRC_DIR)/firewall.h

BPF_OBJ   := $(OUT)/firewall.bpf.o
SKEL_HDR  := $(OUT)/firewall.skel.h
APP       := $(OUT)/firewall

# 与 bpftool gen skeleton … name firewall_bpf 一致，对应 struct firewall_bpf / firewall_bpf__open 等。
SKEL_NAME := firewall_bpf

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' \
	-e 's/ppc64le/powerpc/' -e 's/mips.*/mips/' -e 's/riscv64/riscv/' \
	-e 's/loongarch64/loongarch/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null)
ifeq ($(strip $(LIBBPF_LIBS)),)
LIBBPF_CFLAGS := -I/usr/include
LIBBPF_LIBS   := -lbpf -lelf -lz
endif

BPF_INCLUDES := -I$(ROOT) $(LIBBPF_CFLAGS)

BPF_CFLAGS := -target bpf \
	-D__FIREWALL_BPF__ \
	-D__TARGET_ARCH_$(ARCH) \
	-O2 -g \
	-Wall -Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option

USER_CFLAGS := -O2 -g -Wall $(LIBBPF_CFLAGS) -I$(SRC_DIR) -I$(OUT)

.PHONY: all clean check-deps

all: $(APP)

check-deps:
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "未找到 $(CLANG)"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "未找到 $(BPFTOOL)，请安装 bpftool"; exit 1; }
	@echo "使用: $$(command -v $(CLANG))"; echo "使用: $$(command -v $(BPFTOOL))"

$(OUT):
	mkdir -p "$(OUT)"

$(BPF_OBJ): $(BPF_C) $(USER_HDR) $(ROOT)/vmlinux.h | $(OUT) check-deps
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c "$(BPF_C)" -o "$@"

$(SKEL_HDR): $(BPF_OBJ) | check-deps
	$(BPFTOOL) gen skeleton "$<" name $(SKEL_NAME) > "$@"

$(APP): $(USER_C) $(USER_HDR) $(SKEL_HDR) | $(OUT)
	$(CC) $(USER_CFLAGS) $(CFLAGS) -o "$@" "$(USER_C)" $(LDFLAGS) $(LIBBPF_LIBS)

clean:
	rm -rf "$(OUT)"
