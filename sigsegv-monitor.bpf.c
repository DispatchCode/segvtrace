#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "sigsegv-monitor.h"

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

struct cr2_stat {
    u64 cr2;
    u64 err;
    u64 tai;
};

struct cr2_stats {
    struct cr2_stat stat[MAX_USER_PF_ENTRIES];
    u64 head;
    u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct cr2_stats);
} tgid_cr2 SEC(".maps");

inline void cr2stats_init(struct cr2_stats* stats) {
    stats->head = 0;
    stats->count = 0;
}

inline void cr2stats_push(struct cr2_stats* stats, struct cr2_stat* value) {
    if (stats->head < MAX_USER_PF_ENTRIES) {
        stats->stat[stats->head] = *value;

        if (++stats->head == MAX_USER_PF_ENTRIES) {
            stats->head = 0;
        }

        if (stats->count < MAX_USER_PF_ENTRIES) {
            ++stats->count;
        }
    }
}

// The `index` parameter here is not an index in the array, but an index in the ring buffer,
// i.e. passing an index 0 would return the oldest element in the ring buffer.
inline struct cr2_stat* cr2stats_get(struct cr2_stats* stats, u32 index) {
    if (stats->count == MAX_USER_PF_ENTRIES) {
        index += stats->head;
        if (index >= MAX_USER_PF_ENTRIES) {
            index -= MAX_USER_PF_ENTRIES;
        }
    }

    if (index < MAX_USER_PF_ENTRIES) {
        return stats->stat + index;
    }

    return NULL;
}
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

inline void split_2u32(u64 in, u32* lower, u32* upper)
{
    *lower = (u32)in;
    *upper = (u32)(in >> 32);
}

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

    event->si_code = ctx->code;
    event->tai = bpf_ktime_get_tai_ns();

    split_2u32(bpf_get_current_pid_tgid(), &event->pid, &event->tgid);

    task = bpf_get_current_task_btf();
    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), &task->comm);
    bpf_probe_read_kernel_str(&event->tgleader_comm, sizeof(event->tgleader_comm), &task->group_leader->comm);
    // TODO: can the acquisition of pidns_tgid, pidns_pid be made more robust / simplified?
    {
        struct pid const* thread_pid = task->thread_pid;
        unsigned int const level = thread_pid->level;
        // thread_pid->numbers is a size-one flexible array member (type numbers[1])
        // => cannot perform bounds-check against BTF information
        // => need bpf_probe_read_kernel to read from indices potentially > 1
        struct upid const* upid_inv = &thread_pid->numbers[level];
        event->pidns_pid = BPF_CORE_READ(upid_inv, nr); // we already have implicit CO-RE, but we need the probe function call
    }
    {
        struct pid const* tgid_pid = task->signal->pids[PIDTYPE_TGID];
        unsigned int const level = tgid_pid->level;
        struct upid const* tgid_upid_inv = &tgid_pid->numbers[level];
        // TODO: doesn't this return the pid in the NS of the tg leader, instead of the pid in the NS of the current thread?
        // TODO: don't we need RCU here?
        event->pidns_tgid = BPF_CORE_READ(tgid_upid_inv, nr);
    }

    event->regs.trapno = task->thread.trap_nr;
    event->regs.err = task->thread.error_code;

    // TODO: how are these regs acquired?
    regs = (struct pt_regs *)bpf_task_pt_regs(task);

    if (regs) {
        event->regs.rip = regs->ip;
        event->regs.rsp = regs->sp;
        event->regs.rax = regs->ax;
        event->regs.rbx = regs->bx;
        event->regs.rcx = regs->cx;
        event->regs.rdx = regs->dx;
        event->regs.rsi = regs->si;
        event->regs.rdi = regs->di;
        event->regs.rbp = regs->bp;
        event->regs.r8  = regs->r8;
        event->regs.r9  = regs->r9;
        event->regs.r10 = regs->r10;
        event->regs.r11 = regs->r11;
        event->regs.r12 = regs->r12;
        event->regs.r13 = regs->r13;
        event->regs.r14 = regs->r14;
        event->regs.r15 = regs->r15;
        event->regs.flags = regs->flags;

        event->regs.cr2 = task->thread.cr2;
    }

    event->pf_count = 0;
    #ifdef TRACE_PF_CR2
    u32 tgid = task->tgid;
    struct cr2_stats *cr2stats = bpf_map_lookup_elem(&tgid_cr2, &tgid);

    if (cr2stats) {
        for (u32 i = 0; i < cr2stats->count && i < MAX_USER_PF_ENTRIES; i++) {
            struct cr2_stat* stat = cr2stats_get(cr2stats, i);
            if (stat) {
                event->pf[i].cr2 = stat->cr2;
                event->pf[i].err = stat->err;
                event->pf[i].tai = stat->tai;

                ++event->pf_count;
            }
        }

        bpf_map_delete_elem(&tgid_cr2, &tgid);
    }
    #endif

    // TODO: when is this snapshot taken? or does the CPU not do LBR in the kernel?
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
    struct cr2_stat stat;
    u32 tgid;

    stat.cr2 = ctx->address;
    stat.err = ctx->error_code;
    stat.tai = bpf_ktime_get_tai_ns();
    tgid = bpf_get_current_pid_tgid() >> 32;

    struct cr2_stats *cr2stats = bpf_map_lookup_elem(&tgid_cr2, &tgid);
    if (cr2stats) {
        cr2stats_push(cr2stats, &stat);
    } else {
        struct cr2_stats new_stats;
        cr2stats_init(&new_stats);
        cr2stats_push(&new_stats, &stat);

        bpf_map_update_elem(&tgid_cr2, &tgid, &new_stats, BPF_ANY);
    }

    return 0;
}
#endif

char LICENSE[] SEC("license") = "GPL";
