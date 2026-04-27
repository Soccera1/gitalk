#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <git2.h>
#include <gpgme.h>

#define MAX_LINE 4096
#define MAX_PATH 1024
#define HASH_HEX 65

#if defined(__GNUC__) || defined(__clang__)
#define GITALK_UNUSED __attribute__((unused))
#else
#define GITALK_UNUSED
#endif

typedef struct {
    char id[192];
    char sender[128];
    char recipient[128];
    char hash[HASH_HEX];
    char commit[128];
    char message_path[MAX_PATH];
    char meta_path[MAX_PATH];
} MessageMeta;

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} Sha256;

static const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t ep0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t ep1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static void sha256_transform(Sha256 *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | data[j + 3];
    for (; i < 64; ++i)
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + ep1(e) + ch(e, f, g) + k256[i] + m[i];
        t2 = ep0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256 *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(Sha256 *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static int hash_file(const char *path, char out[HASH_HEX]) {
    FILE *f = fopen(path, "rb");
    uint8_t buf[8192], digest[32];
    Sha256 ctx;
    size_t n;

    if (!f) return -1;
    sha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) sha256_update(&ctx, buf, n);
    if (ferror(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    sha256_final(&ctx, digest);
    for (int i = 0; i < 32; ++i) sprintf(out + (i * 2), "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

static int mkdir_p(const char *path) {
    char tmp[MAX_PATH];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) && errno != EEXIST) return -1;
    return 0;
}

static int mkdir_parent(const char *path) {
    char tmp[MAX_PATH];
    char *slash;
    if (strlen(path) >= sizeof(tmp)) return -1;
    strcpy(tmp, path);
    slash = strrchr(tmp, '/');
    if (!slash) return 0;
    *slash = '\0';
    return mkdir_p(tmp);
}

static void sanitize(const char *in, char *out, size_t out_len) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_len; ++i) {
        unsigned char c = (unsigned char)in[i];
        out[j++] = (char)(isalnum(c) || c == '-' || c == '_' ? c : '_');
    }
    out[j] = '\0';
}

static int write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fputs(body, f) == EOF) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

static int write_bytes_file(const char *path, const void *data, size_t len) {
    FILE *f;
    if (mkdir_parent(path) < 0) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

static void print_git_error(const char *what) {
    const git_error *e = git_error_last();
    fprintf(stderr, "%s: %s\n", what, e && e->message ? e->message : "unknown libgit2 error");
}

static int open_repo(git_repository **repo) {
    if (git_repository_open_ext(repo, ".", 0, NULL) < 0) {
        print_git_error("open repository");
        return -1;
    }
    return 0;
}

static int default_signature(git_signature **sig, git_repository *repo) {
    if (git_signature_default(sig, repo) == 0) return 0;
    if (git_signature_now(sig, "gitalk", "gitalk@example.invalid") == 0) return 0;
    print_git_error("create signature");
    return -1;
}

static int sign_commit_buffer(const char *commit_buf, char **signature_out) {
    gpgme_ctx_t ctx = NULL;
    gpgme_data_t plain = NULL, sig = NULL;
    gpgme_error_t err;
    char *buf = NULL;
    size_t cap = 0, len = 0;

    *signature_out = NULL;
    gpgme_check_version(NULL);
    err = gpgme_new(&ctx);
    if (err) goto fail;
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_armor(ctx, 1);
    err = gpgme_data_new_from_mem(&plain, commit_buf, strlen(commit_buf), 0);
    if (err) goto fail;
    err = gpgme_data_new(&sig);
    if (err) goto fail;
    err = gpgme_op_sign(ctx, plain, sig, GPGME_SIG_MODE_DETACH);
    if (err) goto fail;
    if (gpgme_data_seek(sig, 0, SEEK_SET) < 0) goto fail;

    for (;;) {
        char tmp[1024];
        ssize_t n = gpgme_data_read(sig, tmp, sizeof(tmp));
        if (n < 0) goto fail;
        if (n == 0) break;
        if (len + (size_t)n + 1 > cap) {
            size_t next = cap ? cap * 2 : 2048;
            while (next < len + (size_t)n + 1) next *= 2;
            char *grown = realloc(buf, next);
            if (!grown) goto fail;
            buf = grown;
            cap = next;
        }
        memcpy(buf + len, tmp, (size_t)n);
        len += (size_t)n;
    }
    if (!buf) goto fail;
    buf[len] = '\0';
    *signature_out = buf;
    gpgme_data_release(plain);
    gpgme_data_release(sig);
    gpgme_release(ctx);
    return 0;

fail:
    fprintf(stderr, "GPG signing failed; configure a usable OpenPGP secret key\n");
    free(buf);
    if (plain) gpgme_data_release(plain);
    if (sig) gpgme_data_release(sig);
    if (ctx) gpgme_release(ctx);
    return -1;
}

static int git_add_commit_paths(const char **paths, size_t path_count, const char *subject, char out_oid[128]) {
    git_repository *repo = NULL;
    git_index *index = NULL;
    git_tree *tree = NULL;
    git_commit *parent = NULL;
    git_signature *author = NULL, *committer = NULL;
    git_reference *head = NULL, *updated = NULL;
    git_buf commit_buf = GIT_BUF_INIT;
    git_oid tree_oid, commit_oid, parent_oid;
    const git_commit *parents[1];
    char *gpgsig = NULL;
    int rc = -1;

    if (open_repo(&repo) < 0) goto done;
    if (git_repository_index(&index, repo) < 0) { print_git_error("open index"); goto done; }
    for (size_t i = 0; i < path_count; ++i) {
        if (git_index_add_bypath(index, paths[i]) < 0) { print_git_error("add path"); goto done; }
    }
    if (git_index_write(index) < 0) { print_git_error("write index"); goto done; }
    if (git_index_write_tree(&tree_oid, index) < 0) { print_git_error("write tree"); goto done; }
    if (git_tree_lookup(&tree, repo, &tree_oid) < 0) { print_git_error("lookup tree"); goto done; }
    if (default_signature(&author, repo) < 0 || default_signature(&committer, repo) < 0) goto done;

    size_t parent_count = 0;
    if (git_reference_name_to_id(&parent_oid, repo, "HEAD") == 0 &&
        git_commit_lookup(&parent, repo, &parent_oid) == 0) {
        parents[0] = parent;
        parent_count = 1;
    }

    if (git_commit_create_buffer(&commit_buf, repo, author, committer, "UTF-8", subject, tree, parent_count, parents) < 0) {
        print_git_error("create commit buffer");
        goto done;
    }
    if (sign_commit_buffer(commit_buf.ptr, &gpgsig) < 0) goto done;
    if (git_commit_create_with_signature(&commit_oid, repo, commit_buf.ptr, gpgsig, "gpgsig") < 0) {
        print_git_error("create signed commit");
        goto done;
    }
    const char *head_name = "refs/heads/master";
    if (git_repository_head(&head, repo) == 0 && git_reference_is_branch(head))
        head_name = git_reference_name(head);
    if (git_reference_create(&updated, repo, head_name, &commit_oid, 1, subject) < 0) {
        print_git_error("update branch");
        goto done;
    }
    if (git_repository_set_head(repo, head_name) < 0) {
        print_git_error("set HEAD");
        goto done;
    }
    if (out_oid) git_oid_tostr(out_oid, 128, &commit_oid);
    rc = 0;

done:
    free(gpgsig);
    git_buf_dispose(&commit_buf);
    git_signature_free(author);
    git_signature_free(committer);
    git_reference_free(head);
    git_reference_free(updated);
    git_commit_free(parent);
    git_tree_free(tree);
    git_index_free(index);
    git_repository_free(repo);
    return rc;
}

static int git_add_commit_one(const char *path, const char *subject) {
    const char *paths[1] = { path };
    return git_add_commit_paths(paths, 1, subject, NULL);
}

static int force_permission_path(const char *user, char path[MAX_PATH]);
static int has_force_permission(const char *user);
static int claim_force_priority(const char *user);

static int blob_bytes(git_repository *repo, const git_index_entry *entry, const void **data, size_t *len, git_blob **blob_out) {
    git_blob *blob = NULL;
    if (!entry) {
        *data = NULL;
        *len = 0;
        *blob_out = NULL;
        return 0;
    }
    if (git_blob_lookup(&blob, repo, &entry->id) < 0) {
        print_git_error("lookup conflict blob");
        return -1;
    }
    *data = git_blob_rawcontent(blob);
    *len = git_blob_rawsize(blob);
    *blob_out = blob;
    return 0;
}

static int same_bytes(const void *a, size_t a_len, const void *b, size_t b_len) {
    return a_len == b_len && (a_len == 0 || memcmp(a, b, a_len) == 0);
}

static int resolve_conflict_choice(git_repository *repo, git_index *index, const char *path, const git_index_entry *entry) {
    const void *data;
    size_t len;
    git_blob *blob = NULL;
    int rc = -1;
    if (!entry) {
        unlink(path);
        if (git_index_conflict_remove(index, path) < 0) {
            print_git_error("remove conflict");
            return -1;
        }
        if (git_index_remove_bypath(index, path) < 0) {
            print_git_error("stage deletion");
            return -1;
        }
        return 0;
    }
    if (blob_bytes(repo, entry, &data, &len, &blob) < 0) return -1;
    if (write_bytes_file(path, data, len) < 0) {
        perror("write resolved file");
        goto done;
    }
    if (git_index_conflict_remove(index, path) < 0) {
        print_git_error("remove conflict");
        goto done;
    }
    if (git_index_add_bypath(index, path) < 0) {
        print_git_error("stage resolved file");
        goto done;
    }
    rc = 0;
done:
    git_blob_free(blob);
    return rc;
}

static int resolve_git_conflicts(int force_theirs) {
    git_repository *repo = NULL;
    git_index *index = NULL;
    git_index_conflict_iterator *it = NULL;
    const git_index_entry *ancestor, *ours, *theirs;
    int conflicts = 0, resolved = 0, unresolved = 0, rc = -1;

    if (open_repo(&repo) < 0) goto done;
    if (git_repository_index(&index, repo) < 0) { print_git_error("open index"); goto done; }
    if (!git_index_has_conflicts(index)) {
        printf("no merge conflicts\n");
        rc = 0;
        goto done;
    }
    if (git_index_conflict_iterator_new(&it, index) < 0) {
        print_git_error("iterate conflicts");
        goto done;
    }

    while (git_index_conflict_next(&ancestor, &ours, &theirs, it) == 0) {
        const git_index_entry *choice = NULL;
        int has_choice = 0;
        char path[MAX_PATH];
        const char *entry_path = theirs ? theirs->path : (ours ? ours->path : (ancestor ? ancestor->path : "(unknown)"));
        const void *a_data = NULL, *o_data = NULL, *t_data = NULL;
        size_t a_len = 0, o_len = 0, t_len = 0;
        git_blob *a_blob = NULL, *o_blob = NULL, *t_blob = NULL;
        conflicts++;
        if (strlen(entry_path) >= sizeof(path)) {
            unresolved++;
            continue;
        }
        strcpy(path, entry_path);

        if (blob_bytes(repo, ancestor, &a_data, &a_len, &a_blob) < 0 ||
            blob_bytes(repo, ours, &o_data, &o_len, &o_blob) < 0 ||
            blob_bytes(repo, theirs, &t_data, &t_len, &t_blob) < 0) {
            unresolved++;
            goto release_blobs;
        }

        if (force_theirs) { choice = theirs; has_choice = 1; }
        else if (ours && theirs && same_bytes(o_data, o_len, t_data, t_len)) { choice = ours; has_choice = 1; }
        else if (ancestor && ours && theirs && same_bytes(o_data, o_len, a_data, a_len)) { choice = theirs; has_choice = 1; }
        else if (ancestor && ours && theirs && same_bytes(t_data, t_len, a_data, a_len)) { choice = ours; has_choice = 1; }
        else if (ancestor && ours && !theirs && same_bytes(o_data, o_len, a_data, a_len)) { choice = NULL; has_choice = 1; }
        else if (ancestor && !ours && theirs && same_bytes(t_data, t_len, a_data, a_len)) { choice = NULL; has_choice = 1; }

        if (has_choice && resolve_conflict_choice(repo, index, path, choice) == 0) {
            printf("resolved %s using %s\n", path, choice == theirs ? "theirs" : "ours");
            resolved++;
        } else {
            fprintf(stderr, "unresolved conflict: %s\n", path);
            unresolved++;
        }

release_blobs:
        git_blob_free(a_blob);
        git_blob_free(o_blob);
        git_blob_free(t_blob);
    }

    if (git_index_write(index) < 0) {
        print_git_error("write index");
        goto done;
    }
    printf("conflicts=%d resolved=%d unresolved=%d\n", conflicts, resolved, unresolved);
    rc = unresolved == 0 ? 0 : -1;

done:
    git_index_conflict_iterator_free(it);
    git_index_free(index);
    git_repository_free(repo);
    return rc;
}

static int GITALK_UNUSED cmd_resolve_conflicts(void) {
    return resolve_git_conflicts(0);
}

static int GITALK_UNUSED cmd_force_theirs(const char *user) {
    if (!has_force_permission(user)) {
        fprintf(stderr, "%s does not have force-theirs permission\n", user);
        return -1;
    }
    if (claim_force_priority(user) < 0) return -1;
    return resolve_git_conflicts(1);
}

static int GITALK_UNUSED cmd_grant_force_theirs(const char *user) {
    char path[MAX_PATH], body[256], subject[256];
    if (mkdir_p("permissions/force-theirs") < 0) return -1;
    if (force_permission_path(user, path) < 0) return -1;
    snprintf(body, sizeof(body), "user=%s\npermission=force-theirs\n", user);
    if (write_file(path, body) < 0) return -1;
    snprintf(subject, sizeof(subject), "gitalk grant force-theirs to %s", user);
    return git_add_commit_one(path, subject);
}

static int parse_meta(const char *path, MessageMeta *m) {
    FILE *f = fopen(path, "rb");
    char line[MAX_LINE];
    memset(m, 0, sizeof(*m));
    snprintf(m->meta_path, sizeof(m->meta_path), "%s", path);
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        eq[strcspn(eq, "\r\n")] = '\0';
        if (strcmp(line, "id") == 0) strncpy(m->id, eq, sizeof(m->id) - 1);
        else if (strcmp(line, "sender") == 0) strncpy(m->sender, eq, sizeof(m->sender) - 1);
        else if (strcmp(line, "recipient") == 0) strncpy(m->recipient, eq, sizeof(m->recipient) - 1);
        else if (strcmp(line, "plaintext_sha256") == 0) strncpy(m->hash, eq, sizeof(m->hash) - 1);
        else if (strcmp(line, "commit") == 0) strncpy(m->commit, eq, sizeof(m->commit) - 1);
        else if (strcmp(line, "message_path") == 0) strncpy(m->message_path, eq, sizeof(m->message_path) - 1);
    }
    fclose(f);
    return m->id[0] && m->sender[0] && m->hash[0] && m->message_path[0] ? 0 : -1;
}

static int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int force_permission_path(const char *user, char path[MAX_PATH]) {
    char safe_user[128];
    sanitize(user, safe_user, sizeof(safe_user));
    return snprintf(path, MAX_PATH, "permissions/force-theirs/%s.perm", safe_user) < MAX_PATH ? 0 : -1;
}

static int has_force_permission(const char *user) {
    char path[MAX_PATH];
    if (force_permission_path(user, path) < 0) return 0;
    return path_exists(path);
}

static int claim_force_priority(const char *user) {
    char safe_user[128], body[256];
    int fd;
    sanitize(user, safe_user, sizeof(safe_user));
    if (mkdir_p("permissions/force-theirs") < 0) return -1;
    fd = open("permissions/force-theirs/priority.claim", O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno == EEXIST) fprintf(stderr, "force priority already claimed\n");
        else perror("claim force priority");
        return -1;
    }
    snprintf(body, sizeof(body), "user=%s\nclaimed_at=%lld\n", user, (long long)time(NULL));
    if (write(fd, body, strlen(body)) != (ssize_t)strlen(body)) {
        close(fd);
        return -1;
    }
    close(fd);
    printf("force priority claimed by %s\n", safe_user);
    return 0;
}

static int attestation_exists(const char *commit, const char *role, const char *actor) {
    char safe_actor[128], path[MAX_PATH];
    sanitize(actor, safe_actor, sizeof(safe_actor));
    if (snprintf(path, sizeof(path), "attestations/%s/%s-%s.att", commit, role, safe_actor) >= (int)sizeof(path))
        return 0;
    return path_exists(path);
}

static int server_attestation_exists(const char *commit) {
    char dir[MAX_PATH];
    DIR *d;
    struct dirent *ent;
    if (snprintf(dir, sizeof(dir), "attestations/%s", commit) >= (int)sizeof(dir)) return 0;
    d = opendir(dir);
    if (!d) return 0;
    while ((ent = readdir(d))) {
        if (strncmp(ent->d_name, "server-", 7) == 0 && strstr(ent->d_name, ".att")) {
            closedir(d);
            return 1;
        }
    }
    closedir(d);
    return 0;
}

static const char *status_for(const MessageMeta *m, const char *viewer) {
    char current[HASH_HEX];
    if (hash_file(m->message_path, current) < 0 || strcmp(current, m->hash) != 0) return "tampered";
    if (strcmp(m->sender, viewer) == 0) return "verified";
    if (!server_attestation_exists(m->commit)) return "unverified";
    if (!attestation_exists(m->commit, "user", m->sender)) return "unverified";
    return "verified";
}

static int attest(const MessageMeta *m, const char *role, const char *actor) {
    char current[HASH_HEX], safe_actor[128], dir[MAX_PATH], path[MAX_PATH], body[1024], subject[256];
    if (hash_file(m->message_path, current) < 0) return -1;
    if (strcmp(current, m->hash) != 0) {
        fprintf(stderr, "%s is tampered; refusing to co-sign\n", m->id);
        return -1;
    }
    sanitize(actor, safe_actor, sizeof(safe_actor));
    if (snprintf(dir, sizeof(dir), "attestations/%s", m->commit) >= (int)sizeof(dir)) return -1;
    if (mkdir_p(dir) < 0) return -1;
    if (snprintf(path, sizeof(path), "%s/%s-%s.att", dir, role, safe_actor) >= (int)sizeof(path)) return -1;
    snprintf(body, sizeof(body),
             "commit=%s\nmessage_id=%s\nrole=%s\nactor=%s\nplaintext_sha256=%s\n",
             m->commit, m->id, role, actor, m->hash);
    if (write_file(path, body) < 0) return -1;
    snprintf(subject, sizeof(subject), "gitalk %s attests %s", actor, m->id);
    return git_add_commit_one(path, subject);
}

static int for_each_meta(int (*fn)(const char *, const MessageMeta *, void *), void *arg) {
    DIR *d = opendir("meta");
    struct dirent *ent;
    int failures = 0;
    if (!d) return -1;
    while ((ent = readdir(d))) {
        char path[MAX_PATH];
        MessageMeta m;
        size_t n = strlen(ent->d_name);
        if (n < 6 || strcmp(ent->d_name + n - 5, ".meta") != 0) continue;
        if (snprintf(path, sizeof(path), "meta/%s", ent->d_name) >= (int)sizeof(path)) {
            failures++;
            continue;
        }
        if (parse_meta(path, &m) == 0 && fn(path, &m, arg) < 0) failures++;
    }
    closedir(d);
    return failures == 0 ? 0 : -1;
}

static int cmd_init(const char *user) {
    (void)user;
    git_repository *repo = NULL;
    if (!path_exists(".git")) {
        if (git_repository_init(&repo, ".", 0) < 0) {
            print_git_error("initialize repository");
            return -1;
        }
        git_repository_free(repo);
    }
    if (mkdir_p("messages") < 0 || mkdir_p("meta") < 0 || mkdir_p("attestations") < 0 ||
        mkdir_p("permissions/force-theirs") < 0) return -1;
    if (!path_exists(".gitalk")) {
        if (write_file(".gitalk", "version=1\n") < 0) return -1;
        int rc = git_add_commit_one(".gitalk", "gitalk initialize repository");
        return rc;
    }
    return 0;
}

static int GITALK_UNUSED cmd_send(const char *sender, const char *recipient, const char *text) {
    char safe_sender[128], id[192], msg_path[MAX_PATH], meta_path[MAX_PATH], hash[HASH_HEX], body[MAX_LINE], commit[128], subject[256];
    time_t now = time(NULL);
    sanitize(sender, safe_sender, sizeof(safe_sender));
    snprintf(id, sizeof(id), "%lld-%s", (long long)now, safe_sender);
    snprintf(msg_path, sizeof(msg_path), "messages/%s.txt", id);
    snprintf(meta_path, sizeof(meta_path), "meta/%s.meta", id);
    if (mkdir_p("messages") < 0 || mkdir_p("meta") < 0) return -1;
    snprintf(body, sizeof(body), "from: %s\nto: %s\n\n%s\n", sender, recipient, text);
    if (write_file(msg_path, body) < 0 || hash_file(msg_path, hash) < 0) return -1;
    snprintf(body, sizeof(body),
             "id=%s\nsender=%s\nrecipient=%s\nmessage_path=%s\nplaintext_sha256=%s\ncommit=PENDING\n",
             id, sender, recipient, msg_path, hash);
    if (write_file(meta_path, body) < 0) return -1;
    snprintf(subject, sizeof(subject), "gitalk message %s from %s", id, sender);
    const char *paths[2] = { msg_path, meta_path };
    if (git_add_commit_paths(paths, 2, subject, commit) < 0) return -1;
    snprintf(body, sizeof(body),
             "id=%s\nsender=%s\nrecipient=%s\nmessage_path=%s\nplaintext_sha256=%s\ncommit=%s\n",
             id, sender, recipient, msg_path, hash, commit);
    if (write_file(meta_path, body) < 0) return -1;
    return git_add_commit_one(meta_path, "gitalk record message commit id");
}

static int GITALK_UNUSED list_one(const char *path, const MessageMeta *m, void *arg) {
    const char *viewer = arg;
    (void)path;
    printf("%s [%s] %s -> %s %s\n", m->id, status_for(m, viewer), m->sender, m->recipient, m->message_path);
    return 0;
}

static int GITALK_UNUSED server_one(const char *path, const MessageMeta *m, void *arg) {
    const char *server = arg;
    (void)path;
    if (server_attestation_exists(m->commit)) return 0;
    return attest(m, "server", server);
}

static int GITALK_UNUSED user_one(const char *path, const MessageMeta *m, void *arg) {
    const char *user = arg;
    (void)path;
    if (strcmp(m->sender, user) != 0) return 0;
    if (attestation_exists(m->commit, "user", user)) return 0;
    return attest(m, "user", user);
}

#ifndef GITALK_NO_STANDALONE_MAIN
static void usage(FILE *f) {
    fprintf(f,
            "usage:\n"
            "  gitalk init USER\n"
            "  gitalk send SENDER RECIPIENT MESSAGE\n"
            "  gitalk list VIEWER\n"
            "  gitalk resolve-conflicts\n"
            "  gitalk force-theirs USER\n"
            "  gitalk grant-force-theirs USER\n"
            "  gitalk server-verify SERVER\n"
            "  gitalk user-verify USER\n");
}

int main(int argc, char **argv) {
    int rc;
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    git_libgit2_init();
    if (strcmp(argv[1], "init") == 0 && argc == 3) rc = cmd_init(argv[2]);
    else if (strcmp(argv[1], "send") == 0 && argc == 5) rc = cmd_send(argv[2], argv[3], argv[4]);
    else if (strcmp(argv[1], "list") == 0 && argc == 3) rc = for_each_meta(list_one, argv[2]);
    else if (strcmp(argv[1], "resolve-conflicts") == 0 && argc == 2) rc = cmd_resolve_conflicts();
    else if (strcmp(argv[1], "force-theirs") == 0 && argc == 3) rc = cmd_force_theirs(argv[2]);
    else if (strcmp(argv[1], "grant-force-theirs") == 0 && argc == 3) rc = cmd_grant_force_theirs(argv[2]);
    else if (strcmp(argv[1], "server-verify") == 0 && argc == 3) rc = for_each_meta(server_one, argv[2]);
    else if (strcmp(argv[1], "user-verify") == 0 && argc == 3) rc = for_each_meta(user_one, argv[2]);
    else {
        usage(stderr);
        git_libgit2_shutdown();
        return 2;
    }
    git_libgit2_shutdown();
    return rc == 0 ? 0 : 1;
}
#endif
