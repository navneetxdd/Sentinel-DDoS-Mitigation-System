#
# Sentinel DDoS Core - XDP & TC eBPF Makefile
#
# Builds the eBPF kernel programs:
#   sentinel_xdp.o - XDP for AF_XDP zero-copy
#   sentinel_tc.o  - TC clsact fallback when AF_XDP unavailable
#

BPF_XDP_TARGET := sentinel_xdp.o
BPF_TC_TARGET  := sentinel_tc.o

CC := clang-18

# Basic BPF compilation flags
BPF_CFLAGS := -target bpf
BPF_CFLAGS += -Wall -Wextra -O2 -g
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu

all: $(BPF_XDP_TARGET) $(BPF_TC_TARGET)

$(BPF_XDP_TARGET): sentinel_xdp.c
	@echo "Building XDP eBPF program..."
	$(CC) $(BPF_CFLAGS) -c $< -o $@
	@echo "XDP BPF object built: $@"

$(BPF_TC_TARGET): sentinel_tc.c
	@echo "Building TC clsact eBPF program..."
	$(CC) $(BPF_CFLAGS) -c $< -o $@
	@echo "TC BPF object built: $@"

clean:
	@echo "Cleaning BPF artifacts..."
	rm -f $(BPF_XDP_TARGET) $(BPF_TC_TARGET)
	@echo "Clean complete"

.PHONY: all clean
