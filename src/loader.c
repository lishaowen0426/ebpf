#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

static const char *default_filename = "demo.bpf.o";

static int load_and_attach(const char* filename){
    struct bpf_object* obj = NULL;
    struct bpf_link* link = NULL;
    struct bpf_program *prog = NULL;
    int user_map_fd, root_map_fd;

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

    user_map_fd = bpf_object__find_map_fd_by_name(obj, "user_syscall_counts");
    root_map_fd = bpf_object__find_map_fd_by_name(obj, "root_syscall_counts");
    if(user_map_fd < 0 || root_map_fd < 0){
        fprintf(stderr, "Find a map in bpf object file failed: %s\n", strerror(errno));
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

    printf("user_syscall_counts and root_syscall_counts map id: %d %d\n", user_map_fd, root_map_fd);

    sleep(10);



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