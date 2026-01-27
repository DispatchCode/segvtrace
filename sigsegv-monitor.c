#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <bpf/libbpf.h>
#include "sigsegv-monitor.skel.h"

// TODO: how to do this properly?
#include <linux/types.h>
typedef __u32 u32;
typedef __u64 u64;
#include "sigsegv-monitor.h"

#define MAX_LBR_ENTRIES 32

#define for_each(i, cond) for(int (i)=0; (i) < cond; (i)++)
#define for_each_cpu(cpu) for_each(cpu, get_nprocs_conf())

static volatile sig_atomic_t running = 1;

// perf_event_open fd for every CPUs
static int *cpus_fd;

// TODO: do we need this to enable LBR? We take the samples from within the eBPF program...
void setup_global_lbr() {
    int num_cpus = get_nprocs_conf();
    printf("[*] Activating LBR hardware on %d CPUs...\n", num_cpus);

    cpus_fd = malloc(sizeof(int) * num_cpus);
    if (!cpus_fd) {
        fprintf(stderr, "Unable to allocate memory for %d CPUs. Abort.", num_cpus);
        return;
    }

    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
    pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    for_each_cpu(cpu) {
        //                                          pid     group_fs, flags
        int fd = syscall(__NR_perf_event_open, &pe, -1, cpu, -1, 0);

        if (fd < 0) {
            fprintf(stderr, "Failed to enable LBR on CPU %d (Root required?)\n", cpu);
            continue;
        }

        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        cpus_fd[cpu] = fd;
    }
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event_t *e = data;

    printf("\n------------ SIGSEGV Detected ----------------\n");
    printf("CPU: %d | PID: %d | COMM: %s\n", cpu, e->pid, e->comm);

    printf("\n--- Registers ---\n");
    printf("RAX: 0x%016llx  RBX: 0x%016llx\n", e->regs.rax, e->regs.rbx);
    printf("RCX: 0x%016llx  RDX: 0x%016llx\n", e->regs.rcx, e->regs.rdx);
    printf("RSI: 0x%016llx  RDI: 0x%016llx\n", e->regs.rsi, e->regs.rdi);
    printf("RBP: 0x%016llx  RSP: 0x%016llx\n", e->regs.rbp, e->regs.rsp);
    printf("R8 : 0x%016llx  R9 : 0x%016llx\n", e->regs.r8,  e->regs.r9);
    printf("R10: 0x%016llx  R11: 0x%016llx\n", e->regs.r10, e->regs.r11);
    printf("R12: 0x%016llx  R13: 0x%016llx\n", e->regs.r12, e->regs.r13);
    printf("R14: 0x%016llx  R15: 0x%016llx\n", e->regs.r14, e->regs.r15);

    printf("\nRIP: 0x%016llx  FLG: 0x%016llx\n", e->regs.rip, e->regs.flags);
    printf("CR2: 0x%016llx ", e->regs.cr2);

     if (e->regs.cr2_fault != -1)
       printf("#PF CR2: %016llx", e->regs.cr2_fault);

    printf("\n\n--- LBR Branch Record (Last %d Jumps) ---\n", e->lbr_count);
    // e->lbr_count it is enough in theory, the other check is just
    // to enforce the limit
    for_each(i, e->lbr_count && i < MAX_LBR_ENTRIES) {
        // Skip empty entries
        if (e->lbr[i].from == 0 && e->lbr[i].to == 0) continue;

        printf("#%-2d: 0x%llx  ->  0x%llx\n",
            i,
            (unsigned long long)e->lbr[i].from,
            (unsigned long long)e->lbr[i].to);
    }
    printf("--------------------------------------------\n");
}

void sigint_handler(int dummy) {
    running = 0;
}

void clean() {
    if (!cpus_fd) return;

    for_each_cpu(cpu) {
       ioctl(cpus_fd[cpu], PERF_EVENT_IOC_DISABLE, 0);
    }

    free(cpus_fd);
}

int main() {
    struct sigsegv_monitor_bpf *skel;
    struct perf_buffer *pb = NULL;

    // Stop running if CTRL+C is entered
    signal(SIGINT, sigint_handler);

    // Enable LBR: seems it is working that way...
    setup_global_lbr();

    skel = sigsegv_monitor_bpf__open();
    if (!skel) return 1;

    if (sigsegv_monitor_bpf__load(skel)) return 1;
    if (sigsegv_monitor_bpf__attach(skel)) return 1;

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) return 1;

    fprintf(stderr, "[*] Monitoring for SIGSEGV... (Ctrl+C to stop)\n");

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    fprintf(stderr, "\b\b[*] Exiting the program...\n");

    clean();

    return 0;
}
