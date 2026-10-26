# Builds CO-RE eBPF objects for ebpf_exporter straight into the Helm chart.
# Needs: clang >= 14, llvm-strip, and a checkout of cloudflare/ebpf_exporter
# (for vmlinux.h, maps.bpf.h, bits.bpf.h and libbpf headers).
#
#   git clone --branch v2.5.1 https://github.com/cloudflare/ebpf_exporter.git
#   make -C ebpf_exporter libbpf.a
#   make EBPF_EXPORTER=$PWD/ebpf_exporter
#
# The exporter configs (*.yaml) for each program live next to the objects in the chart.

EBPF_EXPORTER ?= ../../ebpf_exporter
OUT ?= ../charts/ebpf-pod-metrics/files/programs
ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
CC := clang

CLANG_BPF_SYS_INCLUDES = $(shell $(CC) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

CFLAGS := -mcpu=v3 -g -O2 -Wall -Werror -D__TARGET_ARCH_$(ARCH) \
	-I. -I$(EBPF_EXPORTER)/examples -I$(EBPF_EXPORTER)/include/$(ARCH) \
	-I$(EBPF_EXPORTER)/libbpf/dest/usr/include $(CLANG_BPF_SYS_INCLUDES)

SRC := $(wildcard *.bpf.c)
OBJ := $(patsubst %.bpf.c,$(OUT)/%.bpf.o,$(SRC))

.PHONY: build clean
build: $(OBJ)

$(OUT)/%.bpf.o: %.bpf.c pod.bpf.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -target bpf -c $< -o $@
	llvm-strip -g $@   # drop DWARF, keep .BTF/.BTF.ext for CO-RE

clean:
	rm -f $(OBJ)
