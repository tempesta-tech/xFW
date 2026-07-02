#	Tempesta Escudo Management Daemon
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

OBJ_DIR = BUILD
OBJECTS = $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard bpf_uapi/*.cc))
OBJECTS += $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard *.cc))
OBJECTS += $(patsubst %.cc, $(OBJ_DIR)/%.o, $(wildcard xfw/*.cc))
# pidfile.{cc,hh} are inside tempesta fw (see vpath below)
OBJECTS += $(OBJ_DIR)/pidfile.o
DEPS = $(OBJECTS:.o=.d)
LDFLAGS	+= -L$(BUILD_LIBDIR) -lspdlog -lmaxminddb -lbpf
#we still build libtus from sources, because Tempesta uses another compiler fot it
INCLUDES += -I$(BUILD_INCLUDE) -I../fw/libtus

vpath %.cc . bpf_uapi ../fw/libtus

.PHONY: build tfw_mgr install clean test

build: $(OBJ_DIR)/tfw_mgr

$(OBJ_DIR)/%.o: %.cc
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/tfw_mgr: $(OBJECTS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(INCLUDES) -lgrpc -lgrpc++ -lproto -Wl,-rpath,'$$ORIGIN/../lib:$$ORIGIN/../../BUILD/lib'
	@mkdir -p $(BUILD_SBINDIR)
	@cp $@ $(BUILD_SBINDIR)

clean: FORCE
	@rm -rf $(OBJ_DIR)

install:
	@echo "Installing executable to $(SBINDIR)"
	install -d $(SBINDIR)
	install -m 755 $(BUILD_SBINDIR)/tfw_mgr $(SBINDIR)

-include $(DEPS)

test:

FORCE:
