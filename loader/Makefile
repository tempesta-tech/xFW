#
# Tempesta xFW BPF loader
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

OBJ_DIR = BUILD

OBJECTS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(wildcard *.c))

DEPS = $(OBJECTS:.o=.d)

CFLAGS += -DXFW_LIB_DIR=\"$(PREFIX)/lib\"
LDFLAGS += -lbpf -lelf -lz

INCLUDES += -I$(BUILD_INCLUDE)

.PHONY: build install clean test

build: $(OBJ_DIR)/xfw_bpf_loader

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/xfw_bpf_loader: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@mkdir -p $(BUILD_BINDIR)
	@cp $@ $(BUILD_BINDIR)

install:
	@echo "Installing executable to $(BINDIR)"
	install -d $(BINDIR)
	install -m 755 $(BUILD_BINDIR)/xfw_bpf_loader $(BINDIR)

clean:
	rm -rf $(OBJ_DIR)

-include $(DEPS)

test:

FORCE:
