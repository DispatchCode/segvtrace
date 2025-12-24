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

#define MAX_LBR_ENTRIES 32
#define LOG_FILE_NAME   "sigsegv-events.log"

#define for_each(i, cond) for(int (i)=0; (i) < cond; (i)++)
#define for_each_cpu(cpu) for_each(cpu, get_nprocs_conf())

static volatile sig_atomic_t running = 1;

// perf_event_open fd for every CPUs
static int *cpus_fd;

struct user_regs_t {
    unsigned long long rip;
    unsigned long long rsp;
    unsigned long long rax;
    unsigned long long rbx;
    unsigned long long rcx;
    unsigned long long rdx;
    unsigned long long rsi;
    unsigned long long rdi;
    unsigned long long rbp;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long r10;
    unsigned long long r11;
    unsigned long long r12;
    unsigned long long r13;
    unsigned long long r14;
    unsigned long long r15;
    unsigned long long flags;
    unsigned long long cr2;
    unsigned long long cr2_fault;
};

struct event_t {
    unsigned int pid;
    char comm[16];
    unsigned int lbr_count;
    struct user_regs_t regs;
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];
};

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

    int cpu;

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

#define LOG(fmt, ...) { \
    printf(fmt, ##__VA_ARGS__); \
    fprintf(fp, fmt, ##__VA_ARGS__); \
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event_t *e = data;
    FILE *fp = fopen(LOG_FILE_NAME,"a");

    LOG("\n------------ SIGSEGV Detected ----------------\n");
    LOG("CPU: %d | PID: %d | COMM: %s\n", cpu, e->pid, e->comm);

    LOG("\n--- Registers ---\n");
    LOG("RAX: 0x%016llx  RBX: 0x%016llx\n", e->regs.rax, e->regs.rbx);
    LOG("RCX: 0x%016llx  RDX: 0x%016llx\n", e->regs.rcx, e->regs.rdx);
    LOG("RSI: 0x%016llx  RDI: 0x%016llx\n", e->regs.rsi, e->regs.rdi);
    LOG("RBP: 0x%016llx  RSP: 0x%016llx\n", e->regs.rbp, e->regs.rsp);
    LOG("R8 : 0x%016llx  R9 : 0x%016llx\n", e->regs.r8,  e->regs.r9);
    LOG("R10: 0x%016llx  R11: 0x%016llx\n", e->regs.r10, e->regs.r11);
    LOG("R12: 0x%016llx  R13: 0x%016llx\n", e->regs.r12, e->regs.r13);
    LOG("R14: 0x%016llx  R15: 0x%016llx\n", e->regs.r14, e->regs.r15);

    LOG("\nRIP: 0x%016llx  FLG: 0x%016llx\n", e->regs.rip, e->regs.flags);
    LOG("CR2: 0x%016llx, #PF CR2: %016llx\n", e->regs.cr2, e->regs.cr2_fault);
 
    LOG("\n--- LBR Branch History (Last %d Jumps) ---\n", e->lbr_count);
    // e->lbr_count it is enough in theory, the other check is just
    // to enforce the limit
    int i;
    for_each(i, e->lbr_count && i < MAX_LBR_ENTRIES) {
        // Skip empty entries
        if (e->lbr[i].from == 0 && e->lbr[i].to == 0) continue;

        LOG("#%-2d: 0x%llx  ->  0x%llx\n",
            i,
            (unsigned long long)e->lbr[i].from,
            (unsigned long long)e->lbr[i].to);
    }
    LOG("--------------------------------------------\n");

    fclose(fp);
}

void sigint_handler(int dummy) {
    running = 0;
}

void clean() {
    if (!cpus_fd) return;

    int cpu;

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
    
    printf("[*] Monitoring for SIGSEGV... (Ctrl+C to stop)\n");

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    printf("\b\b[*] Exiting the program...\n");

    clean();

    return 0;
}
