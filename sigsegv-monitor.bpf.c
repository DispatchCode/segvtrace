#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "sigsegv-monitor.h"

// By default is commented: a lot of #PF events are hit
// so enable only if it is acceptable.
// #define TRACE_PF_CR2

// if /sys/kernel/tracing/trace_on  is set to 1,
//   cat /sys/kernel/tracing/trace
// will show the bpf_printk() output

#ifdef TRACE_PF_CR2
struct trace_event_raw_page_fault_user {
    struct trace_entry ent;
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
    char __data[0];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} tgid_cr2 SEC(".maps");
#endif

// Output map (for user space)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// event_t is too big for the eBPF stack.
// This map store only 1 entry and it is per-cpu
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} heap SEC(".maps");

SEC("tracepoint/signal/signal_generate")
int trace_sigsegv(struct trace_event_raw_signal_generate *ctx) {
    struct task_struct *task = NULL;
    struct pt_regs *regs = NULL;
    struct event_t *event;
    u32 key = 0;

    if (ctx->sig != 11)
        return 0;

    event = bpf_map_lookup_elem(&heap, &key);
    if (!event)
        return 0; // Should never happen

    task = bpf_get_current_task_btf();
    event->pid = task->pid;
    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), &task->comm);

    regs = (struct pt_regs *)bpf_task_pt_regs(task);

    if (regs) {
        event->regs.rip = BPF_CORE_READ(regs, ip);
        event->regs.rsp = BPF_CORE_READ(regs, sp);
        event->regs.rax = BPF_CORE_READ(regs, ax);
        event->regs.rbx = BPF_CORE_READ(regs, bx);
        event->regs.rcx = BPF_CORE_READ(regs, cx);
        event->regs.rdx = BPF_CORE_READ(regs, dx);
        event->regs.rsi = BPF_CORE_READ(regs, si);
        event->regs.rdi = BPF_CORE_READ(regs, di);
        event->regs.rbp = BPF_CORE_READ(regs, bp);
        event->regs.r8  = BPF_CORE_READ(regs, r8);
        event->regs.r9  = BPF_CORE_READ(regs, r9);
        event->regs.r10 = BPF_CORE_READ(regs, r10);
        event->regs.r11 = BPF_CORE_READ(regs, r11);
        event->regs.r12 = BPF_CORE_READ(regs, r12);
        event->regs.r13 = BPF_CORE_READ(regs, r13);
        event->regs.r14 = BPF_CORE_READ(regs, r14);
        event->regs.r15 = BPF_CORE_READ(regs, r15);
        event->regs.flags = BPF_CORE_READ(regs, flags);

        event->regs.cr2 = BPF_CORE_READ(task, thread.cr2);
        event->regs.cr2_fault = -1;

        #ifdef TRACE_PF_CR2
        u32 tgid = task->tgid;
        u64 *cr2 = bpf_map_lookup_elem(&tgid_cr2, &tgid);

        if (cr2) {
            event->regs.cr2_fault = *cr2;
            bpf_map_delete_elem(&tgid_cr2, &tgid);
        }
        #endif
    }

    // TODO: shouldn't this be at the top of the function?
    long ret = bpf_get_branch_snapshot(&event->lbr, sizeof(event->lbr), 0);
    if (ret > 0) {
        event->lbr_count = ret / sizeof(struct perf_branch_entry);
    } else {
        // on VMs, LBR might not be available
        event->lbr_count = 0;
    }
    // BPF_F_CURRENT_CPU -> "index of current core should be used"
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

#ifdef TRACE_PF_CR2
SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault(struct trace_event_raw_page_fault_user *ctx) {
    u64 cr2;
    u32 tgid;

    cr2  = ctx->address;
    tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&tgid_cr2, &tgid, &cr2, BPF_ANY);

    return 0;
}
#endif

char LICENSE[] SEC("license") = "GPL";
