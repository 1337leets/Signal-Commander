CC     := gcc
CFLAGS := -Wall -Wextra -O2
BINS   := signal_commander trace tcptrace udptrace dnsq

.PHONY: all clean setcap

all: $(BINS)

signal_commander: signal_commander.c
	$(CC) $(CFLAGS) $< -o $@ -lncurses

trace: trace.c
	$(CC) $(CFLAGS) $< -o $@

tcptrace: tcptrace.c
	$(CC) $(CFLAGS) $< -o $@

udptrace: udptrace.c
	$(CC) $(CFLAGS) $< -o $@

dnsq: dnsq.c
	$(CC) $(CFLAGS) $< -o $@

setcap: $(BINS)
	sudo setcap cap_net_raw+ep ./signal_commander
	sudo setcap cap_net_raw+ep ./trace
	sudo setcap cap_net_raw+ep ./tcptrace
	sudo setcap cap_net_raw+ep ./udptrace

clean:
	rm -f $(BINS)
