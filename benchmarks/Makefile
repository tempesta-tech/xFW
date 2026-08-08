#
# Tempesta xFW benchmarks
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
#

OBJ_DIR := BUILD
TARGET  := $(OBJ_DIR)/benchmark

SOURCES := $(wildcard *.cc)
OBJECTS := $(patsubst %.cc,$(OBJ_DIR)/%.o,$(SOURCES))
DEPS    := $(OBJECTS:.o=.d)

CPPFLAGS += -I../..

.PHONY: build benchmark clean install

build: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS) -lbenchmark

$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

clean: FORCE
	rm -rf $(OBJ_DIR)

install:

-include $(DEPS)

benchmark:
	@echo $(BUILD_DIR)
	$(TARGET)

test:

FORCE:
