CC     := gcc
CFLAGS := -Wall -Wextra -O2
BINS   := signal_commander trace tcptrace

.PHONY: all clean setcap

all: $(BINS)

signal_commander: signal_commander.c
	$(CC) $(CFLAGS) $< -o $@ -lncurses

trace: trace.c
	$(CC) $(CFLAGS) $< -o $@

tcptrace: tcptrace.c
	$(CC) $(CFLAGS) $< -o $@

setcap: $(BINS)
	sudo setcap cap_net_raw+ep ./signal_commander
	sudo setcap cap_net_raw+ep ./trace
	sudo setcap cap_net_raw+ep ./tcptrace

clean:
	rm -f $(BINS)
