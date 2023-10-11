FROM debian

RUN apt update
RUN apt install -y libelf-dev


COPY src/.output/demo.bpf.o /
COPY src/.output/loader /

