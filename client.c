#define _POSIX_C_SOURCE 200809L
#define GITALK_NO_STANDALONE_MAIN

#include "main.c"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static int send_ping(const char *user, const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *it;
    int fd = -1, rc = -1;
    char line[256], reply[256];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "resolve %s:%s: %s\n", host, port, gai_strerror(gai));
        return -1;
    }

    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    if (fd < 0) {
        perror("connect");
        goto done;
    }

    snprintf(line, sizeof(line), "PING %s\n", user);
    if (send(fd, line, strlen(line), 0) < 0) goto done;
    ssize_t n = recv(fd, reply, sizeof(reply) - 1, 0);
    if (n < 0) goto done;
    reply[n] = '\0';
    fputs(reply, stdout);
    rc = 0;

done:
    if (fd >= 0) close(fd);
    freeaddrinfo(res);
    return rc;
}

static int ping_loop(const char *user, const char *host, const char *port, long interval_ms) {
    struct timespec delay;
    if (interval_ms < 10) interval_ms = 10;
    delay.tv_sec = interval_ms / 1000;
    delay.tv_nsec = (interval_ms % 1000) * 1000000L;
    for (;;) {
        if (send_ping(user, host, port) < 0) fprintf(stderr, "ping failed\n");
        nanosleep(&delay, NULL);
    }
    return 0;
}

static void client_usage(FILE *f) {
    fprintf(f,
            "usage:\n"
            "  gitalk-client init USER\n"
            "  gitalk-client send SENDER RECIPIENT MESSAGE\n"
            "  gitalk-client list VIEWER\n"
            "  gitalk-client verify USER\n"
            "  gitalk-client resolve-conflicts\n"
            "  gitalk-client ping USER HOST PORT\n"
            "  gitalk-client ping-loop USER HOST PORT [INTERVAL_MS]\n");
}

int main(int argc, char **argv) {
    int rc = -1;
    if (argc < 2) {
        client_usage(stderr);
        return 2;
    }

    git_libgit2_init();
    if (strcmp(argv[1], "init") == 0 && argc == 3) rc = cmd_init(argv[2]);
    else if (strcmp(argv[1], "send") == 0 && argc == 5) rc = cmd_send(argv[2], argv[3], argv[4]);
    else if (strcmp(argv[1], "list") == 0 && argc == 3) rc = for_each_meta(list_one, argv[2]);
    else if (strcmp(argv[1], "verify") == 0 && argc == 3) rc = for_each_meta(user_one, argv[2]);
    else if (strcmp(argv[1], "resolve-conflicts") == 0 && argc == 2) rc = cmd_resolve_conflicts();
    else if (strcmp(argv[1], "ping") == 0 && argc == 5) rc = send_ping(argv[2], argv[3], argv[4]);
    else if (strcmp(argv[1], "ping-loop") == 0 && (argc == 5 || argc == 6)) {
        long ms = argc == 6 ? strtol(argv[5], NULL, 10) : 250;
        rc = ping_loop(argv[2], argv[3], argv[4], ms);
    } else {
        client_usage(stderr);
        git_libgit2_shutdown();
        return 2;
    }

    git_libgit2_shutdown();
    return rc == 0 ? 0 : 1;
}
