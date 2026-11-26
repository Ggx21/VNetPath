CC ?= cc
CLANG ?= clang
PKG_CONFIG ?= pkg-config
BPF_TARGET ?= bpf
MULTIARCH ?= $(shell $(CC) -dumpmachine)
USER_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf json-c)
USER_LIBS := $(shell $(PKG_CONFIG) --libs libbpf json-c)
BPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)

.PHONY: all check-drop
all: vnetpath-agent trace.bpf.o vnetpath-drop-agent drop.bpf.o

vnetpath-agent: agent.c trace.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -O2 -g -Wall -Wextra $(USER_CFLAGS) -o $@ agent.c $(LDFLAGS) $(USER_LIBS)

trace.bpf.o: trace.bpf.c trace.h
	$(CLANG) -target $(BPF_TARGET) -O2 -g -Wall -I/usr/include/$(MULTIARCH) $(BPF_CFLAGS) -c $< -o $@

vnetpath-drop-agent: drop.c drop.h trace.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -O2 -g -Wall -Wextra $(USER_CFLAGS) -o $@ drop.c $(LDFLAGS) $(USER_LIBS)

drop.bpf.o: drop.bpf.c drop.h trace.h
	$(CLANG) -target $(BPF_TARGET) -O2 -g -Wall -I/usr/include/$(MULTIARCH) $(BPF_CFLAGS) -c $< -o $@

check-drop: drop_test
	./drop_test

drop_test: drop_test.c drop.h trace.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -O2 -Wall -Wextra -o $@ drop_test.c
