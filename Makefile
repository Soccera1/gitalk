CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 $(shell pkg-config --cflags libgit2 gpgme)
LDLIBS ?= $(shell pkg-config --libs libgit2 gpgme)

all: gitalk-client gitalk-server

gitalk-client: client.c main.c
	$(CC) $(CFLAGS) -o $@ client.c $(LDLIBS)

gitalk-server: server.c main.c
	$(CC) $(CFLAGS) -o $@ server.c $(LDLIBS)

clean:
	rm -f gitalk-client gitalk-server

.PHONY: all clean
