ROOT := $(shell pwd)
OUTPUT := $(ROOT)/.output
CLANG := clang-17
CC := gcc
LLVM_STRIP := llvm-strip-17
LIBBPF_SRC := $(abspath ../lib/libbpf/src)
LIBBPF_OBJ := $(OUTPUT)/libbpf.a
BPFTOOL := bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := $(abspath ../vmlinux.h)

INCLUDES := -I$(OUTPUT) -I../lib/libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = demo

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')


ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@


# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) 
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(OUTPUT)/build DESTDIR=$(OUTPUT)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Generate vmlinux
$(VMLINUX): 
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) 
	$(call msg,BPF,$@)
	$(Q)$(CLANG)  -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%.bpf.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)




# Build loader
loader: loader.c $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,LOADER,$@)
	$(Q)$(CC) $(CFLAGS) $< $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -L$(dir $(LIBBPF_OBJ)) -lbpf  -lelf -lz -o $(OUTPUT)/$@


clean:
	$(call msg, CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)