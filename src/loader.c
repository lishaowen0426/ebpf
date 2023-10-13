#include "ebpf_def.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

static const char *default_filename = "demo.bpf.o";


static void display_map(int map_fd){
   unsigned long val;
   int err;

    err = bpf_map_lookup_elem(map_fd, &UserID, &val);
    if(err < 0){
        fprintf(stderr,"no value associated with id %d, error: %s\n", UserID, strerror(errno));
    }else{
        printf(
            "ID = %d, syscalls: %ld\n",UserID, val
        );
    }
    err = bpf_map_lookup_elem(map_fd, &RootID, &val);
    if(err < 0){
        fprintf(stderr,"no value associated with id %d, error: %s\n", RootID, strerror(errno));
    }else{
        printf(
            "ID = %d, syscalls: %ld\n",RootID, val
        );
    }
    
}

static int load_and_attach(const char* filename){
    struct bpf_object* obj = NULL;
    struct bpf_link* link = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map* map = NULL;
    int map_fd;

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Open bpf object file failed: %s\n", strerror(errno));
        obj = NULL;
        goto cleanup;
    }

    if(bpf_object__load(obj)){
        fprintf(stderr, "Load bpf object file failed: %s\n", strerror(errno));
        goto cleanup;
    }

    

    bpf_object__for_each_program(prog, obj){
        printf("Program name: %s\n", bpf_program__name(prog));
        link = bpf_program__attach(prog);
        if(libbpf_get_error(link)){
            fprintf(stderr, "bpf_program__attach failed: %s\n", strerror(errno));
            link = NULL;
            goto cleanup;
        }
    }



    map = bpf_object__find_map_by_name(obj, "syscall_counts");
    if(!map){
        fprintf(stderr, "bpf_object__find_map_by_name failed: %s\n", strerror(errno));
        goto cleanup;
    }

    map_fd = bpf_map__fd(map);
    if(map_fd < 0){
        fprintf(stderr, "bpf_map__fd failed: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("syscall_counts map id: %d\n", map_fd );

    int count = 0;
    sleep(1);
    while(count < 10){
        display_map(map_fd);
        sleep(1);
        count += 1;
    }




cleanup:
    if(link)
        bpf_link__destroy(link);
        
    if(obj)
        bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv){

    load_and_attach(default_filename);
}