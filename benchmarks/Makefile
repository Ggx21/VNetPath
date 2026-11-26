CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

.PHONY: all
all: http_rtt echo_rtt

http_rtt echo_rtt: %: %.c bench_common.h probe_mark.h ../agent/trace.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -static $(LDFLAGS) -o $@ $<
