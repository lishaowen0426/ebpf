#include "vmlinux.h"
#include <linux/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const u32 UserID = 1000;
const u32 RootID = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, __NR_syscalls);
    __type(key, u32);
    __type(value, unsigned long);
} user_syscall_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, __NR_syscalls);
    __type(key, u32);
    __type(value, unsigned long);
} root_syscall_counts SEC(".maps");


SEC("raw_tracepoint/sys_exit")
int handle_syscalls(struct bpf_raw_tracepoint_args *ctx){

    u32 nr_syscall = (u32)ctx->args[1]; 
    unsigned long init_val = 1;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    //volatile struct user_pt_regs *regs;
    //regs = (struct user_pt_regs*)ctx->args[0];

    unsigned long *count = NULL;
    void* map;
    if (uid == UserID){
        map = &user_syscall_counts;
    }else if (uid == RootID){
        map = &root_syscall_counts;
    }

    if (map){
        count = bpf_map_lookup_elem(&user_syscall_counts, &nr_syscall);
        if(count != NULL){
            *count += 1;
        }else{
            bpf_map_update_elem(&user_syscall_counts, &nr_syscall, &init_val, BPF_NOEXIST);
        }
    }


    
    return 0;
}