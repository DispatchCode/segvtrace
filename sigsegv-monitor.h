#pragma once


#define MAX_LBR_ENTRIES 32

struct user_regs_t {
    u64 rip;
    u64 rsp;
    u64 rax;
    u64 rbx;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 flags;
    u64 trapno;
    u64 err;
    u64 cr2;
    u64 cr2_fault;
};

struct event_t {
    u32 tgid; // the PROCESS id!
    char tgleader_comm[16]; // the PROCESS name
    u32 pid; // the THREAD id!
    char comm[16]; // the THREAD name
    u32 lbr_count;
    struct user_regs_t regs;
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];
};
