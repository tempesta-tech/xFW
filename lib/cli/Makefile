#	Tempesta Management CLI library
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
OBJ_DIR = BUILD
OBJECTS = $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard *.cc))
DEPS = $(OBJECTS:.o=.d)
CXXFLAGS += -fPIC
INCLUDES += -I$(BUILD_INCLUDE)

.PHONY: build install clean test

build: $(OBJ_DIR)/libtfwcli.so

$(OBJ_DIR)/libtfwcli.so: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ $(LDFLAGS)
	@mkdir -p $(BUILD_LIBDIR)
	@cp $@ $(BUILD_LIBDIR)

$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

clean: FORCE
	@rm -rf $(OBJ_DIR)

install:
	@echo "Installing shared library to $(LIBDIR)"
	install -d $(LIBDIR)
	install -m 755 $(BUILD_LIBDIR)/libtfwcli.so $(LIBDIR)

-include $(DEPS)

test:

FORCE :

