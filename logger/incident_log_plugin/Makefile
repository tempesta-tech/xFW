#	Tempesta escudo plugins
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
OBJ_DIR = BUILD

CLICKHOUSE_DIR := ../../fw/logger/clickhouse
CLICKHOUSE_LIB := tfw_clickhouse.a

PLUGIN_LIB := incident_log.so

OBJECTS = $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard *.cc))
DEPS = $(OBJECTS:.o=.d)

CXXFLAGS += $(shell pkgconf --cflags spdlog)
CXXFLAGS += -DSPDLOG_COMPILED_LIB

LDFLAGS += $(shell pkgconf --libs spdlog)
LDFLAGS += -rdynamic -ldl -lbpf
LDFLAGS	+= -L/$(BUILD_LIBDIR)

INCLUDES += -I $(abspath $(CLICKHOUSE_DIR)/clickhouse-cpp)
INCLUDES += -I $(abspath $(CLICKHOUSE_DIR)/clickhouse-cpp/contrib/absl)
INCLUDES += -I$(BUILD_INCLUDE)

CXXFLAGS += -fPIC
CXXFLAGS += $(INCLUDES)
.PHONY: build install clean test

build: $(OBJ_DIR)/$(PLUGIN_LIB)

# We don't want to worry about compatibility, so just link ClickHouse statically.
# But we need to pass CXXFLAGS to build clickhouse with our building flags.
$(OBJ_DIR)/$(CLICKHOUSE_LIB):
	$(MAKE) -C $(CLICKHOUSE_DIR) TARGET_DIR=$(abspath $(OBJ_DIR)) CXXFLAGS="$(CXXFLAGS)" -j$(shell nproc)

$(OBJ_DIR)/$(PLUGIN_LIB): $(OBJ_DIR)/$(CLICKHOUSE_LIB) $(OBJECTS)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -shared -o $@ $^ \
		-Wl,--whole-archive,$(OBJ_DIR)/$(CLICKHOUSE_LIB),--no-whole-archive $(LDFLAGS)
	@mkdir -p $(BUILD_LIBDIR)
	@cp $@ $(BUILD_LIBDIR)

$(OBJ_DIR)/%.o: %.cc $(OBJ_DIR)/$(CLICKHOUSE_LIB)
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

clean: FORCE
	@rm -rf $(OBJ_DIR)
	$(MAKE) -C $(CLICKHOUSE_DIR) clean TARGET_DIR=$(abspath $(OBJ_DIR))

install:
	@echo "Installing shared library to $(LIBDIR)"
	install -d $(LIBDIR)
	install -m 755 $(BUILD_LIBDIR)/$(PLUGIN_LIB) $(LIBDIR)

-include $(DEPS)

test:

FORCE :
