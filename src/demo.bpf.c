#include "vmlinux.h"
#include "ebpf_def.h"
#include <linux/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2 );
    __type(key, u32);
    __type(value, unsigned long);
} syscall_counts SEC(".maps");



SEC("raw_tracepoint/sys_exit")
int handle_syscalls(struct bpf_raw_tracepoint_args *ctx){

    u32 nr_syscall = (u32)ctx->args[1]; 
    unsigned long init_val = 1;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    //volatile struct user_pt_regs *regs;
    //regs = (struct user_pt_regs*)ctx->args[0];

    unsigned long *count = NULL;
    void* map = &syscall_counts;
    
    if (uid == UserID || uid == RootID){
        if (map){
            count = bpf_map_lookup_elem(map, &uid);
            if(count != NULL){
                *count += 1;
            }else{
                bpf_map_update_elem(map, &uid , &init_val, BPF_NOEXIST);
            }
        }
    }

    
    return 0;
}