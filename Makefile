# Tools
CLANG ?= clang
BPFTOOL ?= bpftool

# Git version info (build fails if not available)
GIT_REV := $(shell git rev-parse --short HEAD)
GIT_DATE := $(shell git log -1 --format=%cI)
ifeq ($(GIT_REV),)
    $(error GIT_REV is not set - not in a git repository?)
endif
ifeq ($(GIT_DATE),)
    $(error GIT_DATE is not set - not in a git repository?)
endif

# Output executable name
APP = sigsegv_monitor
SAMPLE = sample_segfault
LINES2FILE = lines2file

# Source files
BPF_SRC = sigsegv-monitor.bpf.c
USER_SRC = sigsegv-monitor.c

# Generated files
BPF_OBJ = $(BPF_SRC:.c=.o)
SKEL_OBJ = $(BPF_SRC:.bpf.c=.skel.h)
VMLINUX = vmlinux.h

# Compiler flags
# -g: Debug info (required for BTF)
# -O2: Optimization (required for BPF)
CFLAGS := -g -O2 -Wall -DGIT_REV=\"$(GIT_REV)\" -DGIT_DATE=\"$(GIT_DATE)\"
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

# Libs to link
LIBS := -lbpf -lelf -lz

.PHONY: all clean sample test

all: $(APP) $(SAMPLE) $(LINES2FILE)

sample: $(SAMPLE)

test: $(SAMPLE)
	sudo python3 verify_monitor.py
	python3 test_lines2file.py

.DELETE_ON_ERROR:

$(VMLINUX):
	@echo "  GEN     $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	@echo "  BPF     $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_OBJ): $(BPF_OBJ)
	@echo "  GEN-SKEL $@"
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(USER_SRC) $(SKEL_OBJ)
	@echo "  CC      $@"
	$(CLANG) $(CFLAGS) $(USER_SRC) $(LIBS) -o $@

$(SAMPLE): sample_segfault.c
	@echo "  CC      $@"
	$(CLANG) -g -O0 -Wall $< -o $@

$(LINES2FILE): lines2file.c
	@echo "  CC      $@"
	$(CLANG) -Wall -Wextra -pedantic -std=c99 -O2 -o $@ $<

clean:
	@echo "  CLEAN"
	rm -f $(APP) $(BPF_OBJ) $(SKEL_OBJ) $(VMLINUX) $(SAMPLE) $(LINES2FILE)
