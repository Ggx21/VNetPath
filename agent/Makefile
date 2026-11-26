CC ?= cc
CLANG ?= clang
PKG_CONFIG ?= pkg-config
BPF_TARGET ?= bpf
MULTIARCH ?= $(shell $(CC) -dumpmachine)
USER_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf json-c)
USER_LIBS := $(shell $(PKG_CONFIG) --libs libbpf json-c)
BPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)

.PHONY: all
all: vnetpath-agent trace.bpf.o

vnetpath-agent: agent.c trace.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -O2 -g -Wall -Wextra $(USER_CFLAGS) -o $@ agent.c $(LDFLAGS) $(USER_LIBS)

trace.bpf.o: trace.bpf.c trace.h
	$(CLANG) -target $(BPF_TARGET) -O2 -g -Wall -I/usr/include/$(MULTIARCH) $(BPF_CFLAGS) -c $< -o $@
