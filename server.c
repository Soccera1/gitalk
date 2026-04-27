#define _POSIX_C_SOURCE 200809L
#define GITALK_NO_STANDALONE_MAIN

#include "main.c"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static int record_ping(const char *user) {
    char safe[128], path[MAX_PATH], body[256];
    sanitize(user, safe, sizeof(safe));
    if (mkdir_p("pings") < 0) return -1;
    if (snprintf(path, sizeof(path), "pings/%s.ping", safe) >= (int)sizeof(path)) return -1;
    snprintf(body, sizeof(body), "user=%s\nlast_seen=%lld\n", user, (long long)time(NULL));
    return write_file(path, body);
}

static int handle_client(int fd, const char *server_name) {
    char buf[256], user[128];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';
    if (sscanf(buf, "PING %127s", user) != 1) {
        send(fd, "ERR expected PING user\n", 23, 0);
        return -1;
    }

    if (record_ping(user) < 0) {
        send(fd, "ERR ping record failed\n", 23, 0);
        return -1;
    }
    (void)for_each_meta(server_one, (void *)server_name);
    send(fd, "OK\n", 3, 0);
    return 0;
}

static int serve(const char *server_name, const char *port) {
    struct addrinfo hints, *res = NULL, *it;
    int listen_fd = -1, yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int gai = getaddrinfo(NULL, port, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "resolve listen port %s: %s\n", port, gai_strerror(gai));
        return -1;
    }

    for (it = res; it; it = it->ai_next) {
        listen_fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (listen_fd < 0) continue;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(listen_fd, it->ai_addr, it->ai_addrlen) == 0 && listen(listen_fd, 64) == 0) break;
        close(listen_fd);
        listen_fd = -1;
    }
    freeaddrinfo(res);
    if (listen_fd < 0) {
        perror("listen");
        return -1;
    }

    printf("gitalk-server listening on %s\n", port);
    fflush(stdout);
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) continue;
        handle_client(fd, server_name);
        close(fd);
    }
}

static void server_usage(FILE *f) {
    fprintf(f,
            "usage:\n"
            "  gitalk-server init SERVER\n"
            "  gitalk-server serve SERVER PORT\n"
            "  gitalk-server verify SERVER\n"
            "  gitalk-server resolve-conflicts\n"
            "  gitalk-server force-theirs USER\n"
            "  gitalk-server grant-force-theirs USER\n"
            "  gitalk-server pings\n");
}

static int print_ping_one(const char *path) {
    FILE *f = fopen(path, "rb");
    char line[MAX_LINE];
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) fputs(line, stdout);
    fclose(f);
    return 0;
}

static int list_pings(void) {
    DIR *d = opendir("pings");
    struct dirent *ent;
    if (!d) return -1;
    while ((ent = readdir(d))) {
        char path[MAX_PATH];
        size_t n = strlen(ent->d_name);
        if (n < 6 || strcmp(ent->d_name + n - 5, ".ping") != 0) continue;
        if (snprintf(path, sizeof(path), "pings/%s", ent->d_name) >= (int)sizeof(path)) continue;
        print_ping_one(path);
    }
    closedir(d);
    return 0;
}

int main(int argc, char **argv) {
    int rc = -1;
    if (argc < 2) {
        server_usage(stderr);
        return 2;
    }

    git_libgit2_init();
    if (strcmp(argv[1], "init") == 0 && argc == 3) rc = cmd_init(argv[2]);
    else if (strcmp(argv[1], "serve") == 0 && argc == 4) rc = serve(argv[2], argv[3]);
    else if (strcmp(argv[1], "verify") == 0 && argc == 3) rc = for_each_meta(server_one, argv[2]);
    else if (strcmp(argv[1], "resolve-conflicts") == 0 && argc == 2) rc = cmd_resolve_conflicts();
    else if (strcmp(argv[1], "force-theirs") == 0 && argc == 3) rc = cmd_force_theirs(argv[2]);
    else if (strcmp(argv[1], "grant-force-theirs") == 0 && argc == 3) rc = cmd_grant_force_theirs(argv[2]);
    else if (strcmp(argv[1], "pings") == 0 && argc == 2) rc = list_pings();
    else {
        server_usage(stderr);
        git_libgit2_shutdown();
        return 2;
    }

    git_libgit2_shutdown();
    return rc == 0 ? 0 : 1;
}
