#	Tempesta Management CLI tool
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
OBJ_DIR = BUILD
OBJECTS = $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard *.cc))
DEPS = $(OBJECTS:.o=.d)
LDFLAGS	+= -L/$(BUILD_LIBDIR)

.PHONY: build tfw install clean test

build: $(OBJ_DIR)/tfw

$(OBJ_DIR)/tfw: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) -lproto -ltfwcli -Wl,-rpath,'$$ORIGIN/../lib:$$ORIGIN/../../BUILD/lib'
	@mkdir -p $(BUILD_BINDIR)
	@cp $@ $(BUILD_BINDIR)

$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

clean: FORCE
	@rm -rf $(OBJ_DIR)

install:
	@echo "Installing executable to $(BINDIR)"
	install -d $(BINDIR)
	install -m 755 $(BUILD_BINDIR)/tfw $(BINDIR)

-include $(DEPS)

test:

FORCE:

