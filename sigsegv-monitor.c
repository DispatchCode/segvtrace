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
    fprintf(stderr, "[*] Activating LBR hardware on %d CPUs...\n", num_cpus);

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
    pe.sample_period = ((uint64_t)1) << 62; // newer kernels don't activate LBR if this is zero

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

    printf("{\"cpu\":%d,", cpu);
    printf("\"tai\":%llu,", e->tai);
    printf("\"process\":{\"rootns_pid\":%d,\"ns_pid\":%d,\"comm\":\"%s\"},", e->tgid, e->pidns_tgid, e->tgleader_comm);
    printf("\"thread\":{\"rootns_tid\":%d,\"ns_tid\":%d,\"comm\":\"%s\"},", e->pid, e->pidns_pid, e->comm);
    printf("\"si_code\":%d,", e->si_code);
    printf("\"registers\":{");
    printf("\"rax\":\"0x%016llx\",", e->regs.rax);
    printf("\"rbx\":\"0x%016llx\",", e->regs.rbx);
    printf("\"rcx\":\"0x%016llx\",", e->regs.rcx);
    printf("\"rdx\":\"0x%016llx\",", e->regs.rdx);
    printf("\"rsi\":\"0x%016llx\",", e->regs.rsi);
    printf("\"rdi\":\"0x%016llx\",", e->regs.rdi);
    printf("\"rbp\":\"0x%016llx\",", e->regs.rbp);
    printf("\"rsp\":\"0x%016llx\",", e->regs.rsp);
    printf("\"r8\":\"0x%016llx\",", e->regs.r8);
    printf("\"r9\":\"0x%016llx\",", e->regs.r9);
    printf("\"r10\":\"0x%016llx\",", e->regs.r10);
    printf("\"r11\":\"0x%016llx\",", e->regs.r11);
    printf("\"r12\":\"0x%016llx\",", e->regs.r12);
    printf("\"r13\":\"0x%016llx\",", e->regs.r13);
    printf("\"r14\":\"0x%016llx\",", e->regs.r14);
    printf("\"r15\":\"0x%016llx\",", e->regs.r15);
    printf("\"rip\":\"0x%016llx\",", e->regs.rip);
    printf("\"flags\":\"0x%016llx\",", e->regs.flags);
    printf("\"trapno\":\"0x%016llx\",", e->regs.trapno);
    printf("\"err\":\"0x%016llx\",", e->regs.err);
    printf("\"cr2\":\"0x%016llx\",", e->regs.cr2);
    if (e->regs.cr2_fault != (u64)-1)
        printf("\"cr2_fault\":\"0x%016llx\"", e->regs.cr2_fault);
    else
        printf("\"cr2_fault\":null");
    printf("},");

    printf("\"lbr\":[");
    int lbr_limit = (e->lbr_count < MAX_LBR_ENTRIES) ? e->lbr_count : MAX_LBR_ENTRIES;
    for_each(i, lbr_limit) {
        if (i > 0) printf(",");
        if (e->lbr[i].from == 0 && e->lbr[i].to == 0)
            printf("null");
        else
            printf("{\"from\":\"0x%llx\",\"to\":\"0x%llx\"}",
                (unsigned long long)e->lbr[i].from,
                (unsigned long long)e->lbr[i].to);
    }
    printf("]}\n");
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
