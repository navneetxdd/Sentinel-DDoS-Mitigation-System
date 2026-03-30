# Sentinel DDoS Core - Root Makefile (Tier-1 stack)
#
# Single 'make' builds libs + pipeline binary. sentinel_core/ is headers-only (no build).
# proxy/ is optional (build XDP object via make kernel).

CC       ?= gcc
CFLAGS   := -Wall -Wextra -Werror -O3 -march=native -std=c11 -I. -I./sentinel_core -D_FORTIFY_SOURCE=2 -fstack-protector-strong -DSENTINEL_LINUX_RUNTIME=1
LDFLAGS  :=
LDLIBS   := -lm -lcurl -lpthread -lssl -lcrypto -latomic -lpcap -lrt

PREFIX   ?= /usr/local

FE_DIR    := l1_native
DE_DIR    := ml_engine
SDN_DIR   := sdncontrol
FEEDBACK_DIR := feedback
WS_DIR    := websocket
PROXY_DIR := proxy

FE_LIB   := $(FE_DIR)/libfeatureextractor.a
DE_LIB   := $(DE_DIR)/libdecisionengine.a
SDN_LIB  := $(SDN_DIR)/libsdncontrolplane.a
FB_LIB   := $(FEEDBACK_DIR)/libfeedback.a
WS_LIB   := $(WS_DIR)/libwebsocket.a
ALL_LIBS := $(FE_LIB) $(DE_LIB) $(SDN_LIB) $(FB_LIB) $(WS_LIB)

PIPELINE := sentinel_pipeline

.PHONY: all libs build_fe build_de build_sdn build_fb build_ws pipeline kernel loader benchmark clean install test help

all: libs pipeline

help:
	@echo "Sentinel DDoS Core - Build System"
	@echo ""
	@echo "  make              Build all components + pipeline binary"
	@echo "  make libs         Build only the static libraries"
	@echo "  make pipeline     Build the pipeline daemon"
	@echo "  make kernel       Build the XDP eBPF object (proxy/sentinel_xdp.o)"
	@echo "  make loader       Alias of 'make kernel'"
	@echo "  make benchmark    Run benchmark harness (sudo required)"
	@echo "  make feedback     Build the feedback library"
	@echo "  make clean        Remove all build artifacts"
	@echo "  make install      Install pipeline to $(PREFIX)/bin"
	@echo "  make test         Run sanity checks"

# ---- libraries ----

libs: build_fe build_de build_sdn build_fb build_ws

build_fe:
	$(MAKE) -C $(FE_DIR)

build_de:
	$(MAKE) -C $(DE_DIR)

build_sdn:
	$(MAKE) -C $(SDN_DIR)

build_fb:
	$(MAKE) -C $(FEEDBACK_DIR)

build_ws:
	$(MAKE) -C $(WS_DIR)

# ---- pipeline binary (requires all libs; sentinel_core/ is -I only). Use -MMD for .h deps. ----

pipeline: $(PIPELINE)

PIPELINE_OBJ := sentinel_pipeline.o
PIPELINE_D   := sentinel_pipeline.d
-include $(PIPELINE_D)

$(PIPELINE_OBJ): sentinel_pipeline.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ sentinel_pipeline.c

$(PIPELINE): $(PIPELINE_OBJ) libs
	$(CC) $(LDFLAGS) -o $@ $(PIPELINE_OBJ) $(ALL_LIBS) $(LDLIBS)

# ---- kernel module ----

kernel:
	$(MAKE) -C $(PROXY_DIR)

# ---- userspace loader ----

loader:
	$(MAKE) kernel

# ---- benchmark ----

benchmark:
	bash benchmarks/run_mininet_benchmark.sh

# ---- feedback ----

feedback:
	$(MAKE) -C $(FEEDBACK_DIR)

# ---- clean ----

clean:
	$(MAKE) -C $(FE_DIR) clean
	$(MAKE) -C $(DE_DIR) clean
	$(MAKE) -C $(SDN_DIR) clean
	$(MAKE) -C $(FEEDBACK_DIR) clean
	$(MAKE) -C $(WS_DIR) clean
	-$(MAKE) -C $(PROXY_DIR) clean 2>/dev/null
	rm -f $(PIPELINE) $(PIPELINE_OBJ) $(PIPELINE_D) $(TEST_EXE) test_ml_threshold

# ---- install ----

install: $(PIPELINE)
	install -d $(PREFIX)/bin
	install -m 755 $(PIPELINE) $(PREFIX)/bin/

# ---- test ----
TEST_EXE := tests/integration_test
TEST_SRC := tests/integration_test.c

$(TEST_EXE): $(TEST_SRC) libs
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(ALL_LIBS) $(LDLIBS)

test: $(PIPELINE) $(TEST_EXE)
	@echo "=== Sanity checks ==="
	@echo -n "Pipeline binary... "
	@test -f $(PIPELINE) && echo "OK" || (echo "FAIL"; exit 1)
	@echo -n "Libraries... "
	@test -f $(FE_LIB) && test -f $(DE_LIB) && test -f $(SDN_LIB) && test -f $(FB_LIB) && test -f $(WS_LIB) && echo "OK" || (echo "FAIL"; exit 1)
	@echo "=== Integration Tests ==="
	@./$(TEST_EXE)
	@echo "=== Done ==="
