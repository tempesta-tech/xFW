#
# Tempesta xFW eBPF tests
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
#

OBJ_DIR := BUILD
TARGET  := $(OBJ_DIR)/utest

GTEST_DIR := /usr/src/gtest
GTEST_SRC := $(GTEST_DIR)/src/gtest-all.cc
GTEST_OBJ := $(OBJ_DIR)/gtest-all.o

SOURCES := $(wildcard *.cc)
OBJECTS := $(patsubst %.cc,$(OBJ_DIR)/%.o,$(SOURCES))
DEPS    := $(OBJECTS:.o=.d)

CPPFLAGS += -I/usr/include/gtest
CPPFLAGS += -I$(GTEST_DIR)
CPPFLAGS += -I..
CPPFLAGS += -I../..

.PHONY: build test clean install

build: $(TARGET)

$(TARGET): $(OBJECTS) $(GTEST_OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS) -lxxhash

$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(GTEST_OBJ): $(GTEST_SRC)
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

clean: FORCE
	rm -rf $(OBJ_DIR)

install:

-include $(DEPS)

test:
	@echo $(BUILD_DIR)
	$(TARGET)

FORCE :
