# Tools
CLANG ?= clang
BPFTOOL ?= bpftool

# Output executable name
APP = sigsegv_monitor

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
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

# Libs to link
LIBS := -lbpf -lelf -lz

.PHONY: all clean

all: $(APP)

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

clean:
	@echo "  CLEAN"
	rm -f $(APP) $(BPF_OBJ) $(SKEL_OBJ) $(VMLINUX)
