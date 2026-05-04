CC ?= cc
CFLAGS ?= -O3 -fPIC -Wall -Wextra
SHARED_FLAGS = -shared

libaes_v2.so: aes_v2.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $<

clean:
	rm -f libaes_v2.so

.PHONY: clean
