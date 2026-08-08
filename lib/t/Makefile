#	Tempesta Management CLI tool
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

OBJ_DIR = BUILD
TARGET:= $(OBJ_DIR)/utest

# GoogleTest source directory (you might need to manually compile gtest-all.cc)
GTEST_DIR = /usr/src/gtest
# GoogleTest source files (you need to compile this from source)
GTEST_SRC = $(GTEST_DIR)/src/gtest-all.cc
# GoogleTest object files (after compiling gtest-all.cc)
GTEST_OBJ = $(OBJ_DIR)/gtest-all.o
# GoogleTest libraries (installed system-wide)
GTEST_LIBS = -lgtest -lgtest_main

# Project object files
OBJECTS = $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard *.cc))
DEPS = $(OBJECTS:.o=.d)

# Additional flags for linker and compiler
LDFLAGS	+=  -L/$(BUILD_LIBDIR)
CXXFLAGS += -I/usr/include/gtest -pthread
INCLUDES += -I$(BUILD_INCLUDE)

.PHONY: build install clean test

# Main target for building the test binary
build: $(TARGET)

# Build the test binary and link with GoogleTest
$(TARGET): $(OBJECTS) $(GTEST_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) -lgrpc++ -ltfwcli -lproto $(GTEST_LIBS) -Wl,-rpath,'$$ORIGIN/../../../BUILD/lib'

# Build object files from source files
$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

# Compile the GoogleTest source file into an object
$(GTEST_OBJ):
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -I$(GTEST_DIR) -c $(GTEST_SRC) -o $@

clean: FORCE
	@rm -rf $(OBJ_DIR)

install:

-include $(DEPS)

# You can call utest with "-v" or "--verbose" to get all debug output.
test:
	@echo $(BUILD_DIR)
	@$(TARGET)

FORCE:
