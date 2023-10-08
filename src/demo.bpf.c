#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";




SEC("raw_tracepoint/sys_enter")
int handle_syscalls(struct bpf_raw_tracepoint_args *ctx){

    unsigned long syscall_id = ctx->args[1]; 
    volatile struct user_pt_regs *regs;
    regs = (struct user_pt_regs*)ctx->args[0];

    unsigned long syscall_no;
    bpf_probe_read_kernel(&syscall_no, sizeof(syscall_no), regs->regs + 8 );

    
    bpf_printk("syscall %d is issued. syscallno is %d\n", syscall_id, syscall_no);
    
    return 0;
}