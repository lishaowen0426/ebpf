#include "demo.skel.h"
#include <string.h>
#include <unistd.h>

int main(){

    struct demo_bpf *skel;
    int err;
    skel = demo_bpf__open_and_load();

    err = demo_bpf__attach(skel);
    if(err){
        fprintf(stderr, "demo_bpf__attach faiiled: %s\n", strerror(err));
        return EXIT_FAILURE;
    }

    sleep(10);

    demo_bpf__destroy(skel);
    return EXIT_FAILURE;


}