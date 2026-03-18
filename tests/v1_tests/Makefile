# tests/Makefile
CC=gcc
CFLAGS=-Wall -O2

TARGETS=revsh_fast revsh_slow revsh_partial revsh_evasion

all: $(TARGETS)

revsh_fast: revsh_fast.c
	$(CC) $(CFLAGS) $< -o $@

revsh_slow: revsh_slow.c
	$(CC) $(CFLAGS) $< -o $@

revsh_partial: revsh_partial.c
	$(CC) $(CFLAGS) $< -o $@

revsh_evasion: revsh_evasion.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)