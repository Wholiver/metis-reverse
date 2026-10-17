CC ?= clang
CFLAGS ?= -Wall -Wextra

all: demo_target demo_target_debug

demo_target: main.c
	$(CC) $(CFLAGS) -O2 -s -o demo_target main.c
	strip -x demo_target 2>/dev/null || true

demo_target_debug: main.c
	$(CC) $(CFLAGS) -O0 -g -o demo_target_debug main.c

clean:
	rm -f demo_target demo_target_debug
	rm -rf demo_target_debug.dSYM

.PHONY: all clean
