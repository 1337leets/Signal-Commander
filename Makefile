CC     := gcc
CFLAGS := -Wall -Wextra -O2
BINS   := signal_commander trace

.PHONY: all clean setcap

all: $(BINS)

signal_commander: signal_commander.c
	$(CC) $(CFLAGS) $< -o $@ -lncurses

trace: trace.c
	$(CC) $(CFLAGS) $< -o $@

setcap: $(BINS)
	sudo setcap cap_net_raw+ep ./signal_commander
	sudo setcap cap_net_raw+ep ./trace

clean:
	rm -f $(BINS)
