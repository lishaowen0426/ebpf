vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

docker-build:
    docker build --rm -f docker/Dockerfile -t ebpf:latest .

docker-run:
    @docker run --cap-add=CAP_BPF --cap-add=CAP_IPC_LOCK --cap-add=CAP_SYS_ADMIN --ulimit=memlock=-1  \
    -it --rm \
    --mount type=bind,source="$(pwd)/src/.output/",target=/app,readonly \
    ebpf bash

oci-image img:
    skopeo copy docker-daemon:{{img}}:latest oci:docker/images/oci-images/{{img}}:latest

bundle img:
    sudo umoci unpack --image docker/images/oci-images/{{img}} docker/images/fs-bundle/{{img}}-bundle
