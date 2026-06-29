#	Tempesta xFW eBPF programs build
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
OBJ_DIR = BUILD
OBJECTS := $(patsubst %.c, $(OBJ_DIR)/%.o, $(wildcard *.c))
DEPS = $(OBJECTS:.o=.d)

# For detached build
BUILD_LIBDIR ?= BUILD

# Installation bpf path
BPFDIR := $(LIBDIR)/bpf

# Override optimization level to -O2 to avoid "BPF stack limit exceeded" errors
BPF_CFLAGS := $(filter-out -O%,$(CFLAGS)) -O2
BPF_CFLAGS += -MMD -MP -Wno-option-ignored -target bpf -g -fno-stack-protector
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu/ -I../BUILD/

ifneq ($(filter-out 0,$(DEBUG)),)
	BPF_CFLAGS += -DXFW_DEBUG=1
endif

.PHONY: build bpf install clean test

build: bpf

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(BPF_CFLAGS) $(INCLUDES) -I$(OBJ_DIR) -o "$@" -c $<
	@mkdir -p $(BUILD_LIBDIR)/bpf/
	@cp $@ $(BUILD_LIBDIR)/bpf/

bpf: $(OBJECTS)

clean: FORCE
	@rm -rf $(OBJ_DIR)

install:
	@echo "Installing BPF objects to $(BPFDIR)"
	install -d $(BPFDIR)
	install -m 644 $(BUILD_LIBDIR)/bpf/*.o $(BPFDIR)

-include $(DEPS)

test:

FORCE:
