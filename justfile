vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

docker-build:
    docker build --rm -f docker/Dockerfile -t ebpf:latest .

docker-run:
    docker run -it --rm ebpf bash
