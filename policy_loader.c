// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <json-c/json.h>

#ifndef CGROUP_DEFAULT
#define CGROUP_DEFAULT "/sys/fs/cgroup"
#endif

/* -------------------- pin helpers -------------------- */
static int pin_map_or_err(int fd, const char *path) {
    if (bpf_obj_pin(fd, path) && errno != EEXIST) {
        fprintf(stderr, "pin map %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int try_pin_link(struct bpf_link *link, const char *pinpath, int *kept_foreground) {
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", pinpath);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; mkdir(dir, 0755); }

    int rc = bpf_link__pin(link, pinpath);
    if (rc) {
        fprintf(stderr, "WARN: pin %s denied (%s); keeping FD alive in foreground.\n",
                pinpath, strerror(-rc));
        if (kept_foreground) *kept_foreground = 1;
    }
    return 0;
}

static int open_cgroup(const char *path) {
    return open(path, O_RDONLY | O_CLOEXEC);
}

/* -------------------- diagnostics -------------------- */
static void dump_maps(const char *title, struct bpf_object *obj) {
    fprintf(stderr, "%s maps:\n", title);
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        const char *nm = bpf_map__name(m);
        int fd = bpf_map__fd(m);
        fprintf(stderr, "  - name=%s fd=%d\n", nm ? nm : "(null)", fd);
    }
}

static int get_map_fd_any(struct bpf_object *obj_core, struct bpf_object *obj_up, const char *name) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj_core, name);
    if (m) return bpf_map__fd(m);
    m = bpf_object__find_map_by_name(obj_up, name);
    if (m) return bpf_map__fd(m);
    return -1;
}

/* -------------------- small put helpers -------------------- */
static int put_comm(int map, const char *comm){
    __u32 k=0; char v[16]={0}; size_t L=strlen(comm); if (L>15) L=15; memcpy(v,comm,L);
    return bpf_map_update_elem(map,&k,v,BPF_ANY);
}
static int put_toggle(int map, __u8 v){ __u32 k=0; return bpf_map_update_elem(map,&k,&v,BPF_ANY); }
static int put_prefix(int map, const char *s){
    __u32 k=0; char v[256]={0}; size_t L=strlen(s); if (L>=sizeof(v)) L=sizeof(v)-1; memcpy(v,s,L);
    return bpf_map_update_elem(map,&k,v,BPF_ANY);
}
struct token_key { char s[16]; };
static int put_bad_token(int map, const char *tok){
    struct token_key key = {0}; size_t L=strlen(tok); if (L>15) L=15;
    for (size_t i=0;i<L;i++){ char c=tok[i]; if (c>='a'&&c<='z') c-=32; key.s[i]=c; }
    __u8 one=1; return bpf_map_update_elem(map,&key,&one,BPF_ANY);
}

/* -------------------- DNS + allowlist loader -------------------- */
static int resolve_and_load_ips(json_object *jarr, int map4, int map6, int *out_v4, int *out_v6)
{
    int v4 = 0, v6 = 0;
    if (!jarr || !json_object_is_type(jarr, json_type_array)) {
        if (out_v4) *out_v4 = 0;
        if (out_v6) *out_v6 = 0;
        return 0;
    }
    size_t n = json_object_array_length(jarr);
    for (size_t i=0;i<n;i++){
        const char *host = json_object_get_string(json_object_array_get_idx(jarr,i));
        if (!host) continue;

        struct addrinfo hints = {0}, *res=NULL;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int rc = getaddrinfo(host, NULL, &hints, &res);
        if (rc != 0) {
            fprintf(stderr,"getaddrinfo(%s): %s\n", host, gai_strerror(rc));
            continue;
        }
        for (struct addrinfo *ai=res; ai; ai=ai->ai_next){
            if (ai->ai_family==AF_INET){
                __u32 ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr; __u8 one=1;
                if (bpf_map_update_elem(map4,&ip,&one,BPF_ANY)==0) v4++;
            } else if (ai->ai_family==AF_INET6){
                struct in6_addr ip6 = ((struct sockaddr_in6*)ai->ai_addr)->sin6_addr; __u8 one=1;
                if (bpf_map_update_elem(map6,&ip6,&one,BPF_ANY)==0) v6++;
            }
        }
        freeaddrinfo(res);
    }
    if (out_v4) *out_v4 = v4;
    if (out_v6) *out_v6 = v6;
    return 0;
}

/* -------------------- (NEW) robust libc resolver + uprobe attach -------------------- */
static const char *locate_libc(void)
{
    /* quick common locations */
    const char *cands[] = {
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        NULL
    };
    for (int i=0; cands[i]; i++) {
        if (access(cands[i], R_OK)==0) return cands[i];
    }
    /* fallback: parse ldd output of curl */
    FILE *fp = popen("ldd /usr/bin/curl | awk '/libc\\.so\\.6/ {print $3; exit}'", "r");
    static char buf[512];
    if (fp && fgets(buf, sizeof(buf), fp)) {
        size_t L = strlen(buf);
        if (L && buf[L-1]=='\n') buf[L-1] = '\0';
        pclose(fp);
        if (access(buf, R_OK)==0) return strdup(buf);
    }
    if (fp) pclose(fp);
    return NULL;
}

static int attach_uprobes_explicit(struct bpf_object *obj_up, int *keep_foreground)
{
    struct bpf_program *p_getenv  = bpf_object__find_program_by_name(obj_up, "enter_getenv");
    struct bpf_program *p_sgetenv = bpf_object__find_program_by_name(obj_up, "enter_secure_getenv");
    if (!p_getenv || !p_sgetenv) {
        fprintf(stderr, "find uprobes failed (enter_getenv / enter_secure_getenv)\n");
        return -1;
    }

    const char *libc_path = locate_libc();
    if (!libc_path) {
        fprintf(stderr, "cannot locate libc for uprobes\n");
        return -1;
    }
    fprintf(stderr, "attaching uprobes to libc: %s\n", libc_path);

#if defined(LIBBPF_OPTS)
    LIBBPF_OPTS(bpf_uprobe_opts, opts,
        .retprobe = false  /* entry probe */
    );
    struct bpf_link *l  = bpf_program__attach_uprobe_opts(p_getenv,  -1, libc_path, 0, &opts);
    if (libbpf_get_error(l)) {
        fprintf(stderr, "attach uprobe getenv via _opts failed: %ld\n", libbpf_get_error(l));
        return -1;
    }
    if (bpf_link__pin(l, "/sys/fs/bpf/curl_sandbox/links/uprobe_getenv") && errno != EEXIST) {
        fprintf(stderr, "WARN: pin uprobe_getenv denied (%s); keeping FD alive in foreground.\n", strerror(errno));
        if (keep_foreground) *keep_foreground = 1;
    }

    struct bpf_link *l2 = bpf_program__attach_uprobe_opts(p_sgetenv, -1, libc_path, 0, &opts);
    if (libbpf_get_error(l2)) {
        fprintf(stderr, "attach uprobe secure_getenv via _opts failed: %ld\n", libbpf_get_error(l2));
        return -1;
    }
    if (bpf_link__pin(l2, "/sys/fs/bpf/curl_sandbox/links/uprobe_secure_getenv") && errno != EEXIST) {
        fprintf(stderr, "WARN: pin uprobe_secure_getenv denied (%s); keeping FD alive in foreground.\n", strerror(errno));
        if (keep_foreground) *keep_foreground = 1;
    }
#else
    /* fallback for older libbpf without *_opts */
    struct bpf_link *l  = bpf_program__attach(p_getenv);
    if (libbpf_get_error(l)) { fprintf(stderr, "attach uprobe getenv failed\n"); return -1; }
    if (bpf_link__pin(l, "/sys/fs/bpf/curl_sandbox/links/uprobe_getenv") && errno != EEXIST) {
        fprintf(stderr, "WARN: pin uprobe_getenv denied (%s); keeping FD alive in foreground.\n", strerror(errno));
        if (keep_foreground) *keep_foreground = 1;
    }

    struct bpf_link *l2 = bpf_program__attach(p_sgetenv);
    if (libbpf_get_error(l2)) { fprintf(stderr, "attach uprobe secure_getenv failed\n"); return -1; }
    if (bpf_link__pin(l2, "/sys/fs/bpf/curl_sandbox/links/uprobe_secure_getenv") && errno != EEXIST) {
        fprintf(stderr, "WARN: pin uprobe_secure_getenv denied (%s); keeping FD alive in foreground.\n", strerror(errno));
        if (keep_foreground) *keep_foreground = 1;
    }
#endif
    return 0;
}

/* ===================================================== */

int main(int argc, char **argv)
{
    const char *json_path   = (argc>1) ? argv[1] : "policy.json";
    const char *cgroup_path = (argc>2 && argv[2][0] != '-') ? argv[2] : CGROUP_DEFAULT;
    int foreground = 0;
    for (int i=1;i<argc;i++){
        if (strcmp(argv[i], "--foreground")==0) foreground = 1;
    }

    /* ---- read JSON ---- */
    FILE *fp = fopen(json_path,"r"); if (!fp){ perror("fopen policy.json"); return 1; }
    fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
    char *buf = calloc(1, sz+1);
    if (fread(buf,1,sz,fp) != (size_t)sz) { fprintf(stderr,"short read\n"); }
    fclose(fp);

    json_object *root = json_tokener_parse(buf);
    if (!root){ fprintf(stderr,"Invalid JSON\n"); return 1; }

    json_object *j_cmd=NULL, *j_ver=NULL, *j_net=NULL, *j_fs=NULL, *j_sec=NULL;
    json_object_object_get_ex(root, "policy_version", &j_ver);
    json_object_object_get_ex(root, "command", &j_cmd);
    json_object_object_get_ex(root, "network_policies", &j_net);
    json_object_object_get_ex(root, "filesystem_policies", &j_fs);
    json_object_object_get_ex(root, "security_policies", &j_sec);

    const char *cmd = j_cmd ? json_object_get_string(j_cmd) : "curl";
    json_object *j_allowed_domains=NULL, *j_allowed_dirs=NULL, *j_blocked_env=NULL;
    if (j_net) json_object_object_get_ex(j_net, "allowed_domains", &j_allowed_domains);
    if (j_fs)  json_object_object_get_ex(j_fs, "allowed_write_dirs", &j_allowed_dirs);
    if (j_sec) json_object_object_get_ex(j_sec, "blocked_environment", &j_blocked_env);

    /* ---- open/load BPF objs from CWD ---- */
    struct bpf_object *obj_core=NULL, *obj_up=NULL;

    obj_core = bpf_object__open_file("policy_kern.bpf.o", NULL);
    if (libbpf_get_error(obj_core)) { fprintf(stderr,"open core obj failed\n"); return 1; }
    if (bpf_object__load(obj_core))  { fprintf(stderr,"load core obj failed: %d\n", -errno); return 1; }

    obj_up = bpf_object__open_file("policy_uprobes.bpf.o", NULL);
    if (libbpf_get_error(obj_up)) { fprintf(stderr,"open uprobes obj failed\n"); return 1; }
    if (bpf_object__load(obj_up))  { fprintf(stderr,"load uprobes obj failed: %d\n", -errno); return 1; }

    /* ---- map FDs (try core else uprobes) ---- */
    int map_comm_core   = get_map_fd_any(obj_core, obj_up, "target_comm_map");
    int map_net         = get_map_fd_any(obj_core, obj_up, "net_enforce");
    int map_fs          = get_map_fd_any(obj_core, obj_up, "fs_enforce");
    int map_ipv4        = get_map_fd_any(obj_core, obj_up, "ipv4_allow");
    int map_ipv6        = get_map_fd_any(obj_core, obj_up, "ipv6_allow");
    int map_prefix      = get_map_fd_any(obj_core, obj_up, "allowed_write_prefix");
    int map_scratch     = get_map_fd_any(obj_core, obj_up, "scratch_buf");
    int map_bad_core    = get_map_fd_any(obj_core, obj_up, "bad_env_tokens");

    if (map_comm_core<0 || map_net<0 || map_fs<0 || map_ipv4<0 || map_ipv6<0 || map_prefix<0 || map_scratch<0 || map_bad_core<0) {
        fprintf(stderr, "map lookup failed (core/uprobes). Dumping available maps for debugging...\n");
        dump_maps("CORE", obj_core);
        dump_maps("UPROBES", obj_up);
        return 1;
    }

    /* Also try separate copies in uprobes (populate both if present) */
    int up_map_bad  = get_map_fd_any(obj_up, obj_core, "bad_env_tokens");
    int up_map_comm = get_map_fd_any(obj_up, obj_core, "target_comm_map");

    /* ---- populate ---- */
    put_comm(map_comm_core, cmd);
    if (up_map_comm >= 0) put_comm(up_map_comm, cmd);

    put_toggle(map_net, 1);
    put_toggle(map_fs, 1);

    /* normalize the allowed prefix: exactly one trailing '/' */
    const char *prefix = "/tmp/curl_downloads/";
    if (j_allowed_dirs && json_object_is_type(j_allowed_dirs, json_type_array) &&
        json_object_array_length(j_allowed_dirs)>0) {
        prefix = json_object_get_string(json_object_array_get_idx(j_allowed_dirs,0));
    }
    {
        static char norm[256];
        size_t Lp = strlen(prefix);
        if (Lp > 0 && prefix[Lp-1] == '/') {
            strncpy(norm, prefix, sizeof(norm));
            norm[sizeof(norm)-1] = '\0';
        } else {
            snprintf(norm, sizeof(norm), "%s/", prefix);
        }
        put_prefix(map_prefix, norm);
    }

    int v4=0, v6=0;
    resolve_and_load_ips(j_allowed_domains, map_ipv4, map_ipv6, &v4, &v6);

    if (j_blocked_env && json_object_is_type(j_blocked_env, json_type_array)){
        size_t n = json_object_array_length(j_blocked_env);
        for (size_t i=0;i<n;i++){
            const char *t = json_object_get_string(json_object_array_get_idx(j_blocked_env,i));
            if (t && *t){
                put_bad_token(map_bad_core, t);
                if (up_map_bad >= 0) put_bad_token(up_map_bad, t);
            }
        }
    } else {
        const char *defs[] = {"PASSWORD","KEY","SECRET"};
        for (int i=0;i<3;i++){
            put_bad_token(map_bad_core, defs[i]);
            if (up_map_bad >= 0) put_bad_token(up_map_bad, defs[i]);
        }
    }

    /* ---- pin maps ---- */
    mkdir("/sys/fs/bpf/curl_sandbox", 0755);
    pin_map_or_err(map_comm_core, "/sys/fs/bpf/curl_sandbox/target_comm_map");
    pin_map_or_err(map_net,       "/sys/fs/bpf/curl_sandbox/net_enforce");
    pin_map_or_err(map_fs,        "/sys/fs/bpf/curl_sandbox/fs_enforce");
    pin_map_or_err(map_ipv4,      "/sys/fs/bpf/curl_sandbox/ipv4_allow");
    pin_map_or_err(map_ipv6,      "/sys/fs/bpf/curl_sandbox/ipv6_allow");
    pin_map_or_err(map_prefix,    "/sys/fs/bpf/curl_sandbox/allowed_write_prefix");
    pin_map_or_err(map_scratch,   "/sys/fs/bpf/curl_sandbox/scratch_buf");
    pin_map_or_err(map_bad_core,  "/sys/fs/bpf/curl_sandbox/bad_env_tokens");

    /* ---- attach (cgroup + LSM) ---- */
    int cgfd = open_cgroup(cgroup_path);
    if (cgfd < 0) { perror("open cgroup"); return 1; }

    struct bpf_program *prog;
    struct bpf_link *link_c4=NULL, *link_c6=NULL, *link_fopen=NULL, *link_fperm=NULL;
    int keep_foreground = foreground ? 1 : 0;

    bpf_object__for_each_program(prog, obj_core) {
        const char *sec = bpf_program__section_name(prog);
        if (strstr(sec, "cgroup/connect4")) {
            link_c4 = bpf_program__attach_cgroup(prog, cgfd);
            if (libbpf_get_error(link_c4)) { fprintf(stderr,"attach connect4 failed\n"); return 1; }
            try_pin_link(link_c4, "/sys/fs/bpf/curl_sandbox/links/cgroup_connect4", &keep_foreground);
        } else if (strstr(sec, "cgroup/connect6")) {
            if (v6 > 0) {
                link_c6 = bpf_program__attach_cgroup(prog, cgfd);
                if (libbpf_get_error(link_c6)) { fprintf(stderr,"attach connect6 failed\n"); return 1; }
                try_pin_link(link_c6, "/sys/fs/bpf/curl_sandbox/links/cgroup_connect6", &keep_foreground);
            } else {
                fprintf(stderr, "NOTE: skipping connect6 (IPv6 allow-list is empty)\n");
            }
        } else if (strstr(sec, "lsm.s/file_open")) {
            link_fopen = bpf_program__attach(prog);
            if (libbpf_get_error(link_fopen)) { fprintf(stderr,"attach file_open failed\n"); return 1; }
            try_pin_link(link_fopen, "/sys/fs/bpf/curl_sandbox/links/lsm.s_file_open", &keep_foreground);
        } else if (strstr(sec, "lsm/file_permission")) {
            link_fperm = bpf_program__attach(prog);
            if (libbpf_get_error(link_fperm)) { fprintf(stderr,"attach file_permission failed\n"); return 1; }
            try_pin_link(link_fperm, "/sys/fs/bpf/curl_sandbox/links/lsm_file_permission", &keep_foreground);
        }
    }

    /* ---- (NEW) attach getenv/secure_getenv uprobes once ---- */
    if (attach_uprobes_explicit(obj_up, &keep_foreground) != 0) {
        fprintf(stderr, "uprobe attach failed\n");
        return 1;
    }

    /* ---- Summary ---- */
    fprintf(stdout,
        "Loaded OK.\n"
        "Allow-list counts: IPv4=%d IPv6=%d\n"
        "Attached to cgroup: %s\n", v4, v6, cgroup_path);

    if (keep_foreground) {
        fprintf(stdout, "Policy loaded. Running in foreground to keep links alive (pin not permitted or forced).\n");
        fprintf(stdout, "Maps at /sys/fs/bpf/curl_sandbox ; links pinned where permitted.\n");
        fflush(stdout);
        pause();
    } else {
        fprintf(stdout, "Policy loaded. Links pinned. You may exit.\n");
    }

    return 0;
}
