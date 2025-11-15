// SPDX-License-Identifier: GPL-2.0
// Kernel eBPF: NET-001 (socket/connect), FS-001 (open/write)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ---- Portable constants (avoid kernel header deps that break CO-RE) ---- */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef EPERM
#define EPERM 1
#endif
/* MAY_WRITE from <linux/fs.h> == 0x2 */
#ifndef __MAY_WRITE
#define __MAY_WRITE 2
#endif

/* we use numeric fallbacks for O_* in helpers */

/* ========== Maps ========== */

// command filter (comm)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[16]);
} target_comm_map SEC(".maps");

// toggles
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} net_enforce SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} fs_enforce SEC(".maps");

// IPv4/IPv6 allow-lists
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);    // network-order IPv4
    __type(value, __u8);
} ipv4_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct in6_addr);
    __type(value, __u8);
} ipv6_allow SEC(".maps");

// write-allowed prefix
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);
} allowed_write_prefix SEC(".maps");

// scratch for d_path
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[4096]);
} scratch_buf SEC(".maps");

// files allowed to write (key = struct file* as u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} write_ok_files SEC(".maps");

/* ========== Helpers ========== */

static __always_inline bool is_target_proc(void) {
    char comm[16] = {};
    __u32 k = 0;
    char *want = bpf_map_lookup_elem(&target_comm_map, &k);
    if (!want) return false;
    bpf_get_current_comm(&comm, sizeof(comm));
#pragma clang loop unroll(full)
    for (int i=0;i<16;i++){
        if (want[i] == '\0') return true;
        if (want[i] != comm[i]) return false;
    }
    return true;
}

static __always_inline bool write_like_open(__u32 flags) {
    /* acc = flags & 3 (O_ACCMODE) ; 1=WRONLY 2=RDWR */
    __u32 acc = flags & 3;
    if (acc == 1 || acc == 2) return true; /* WRONLY/RDWR */
    /* common write-like extras: O_TRUNC(01000), O_APPEND(02000), O_CREAT(0100) */
    if (flags & 01000) return true;
    if (flags & 02000) return true;
    if (flags & 0100)  return true;
    return false;
}

static __always_inline int has_allowed_prefix(const char *buf, const char *prefix) {
#pragma clang loop unroll(disable)
    for (int i=0;i<256;i++){
        char a = prefix[i];
        char b = buf[i];
        if (a == '\0') return 1;
        if (a != b) return 0;
    }
    return 1;
}

/* ========== NET-001: cgroup/connectX (HTTP/S only + allowlist) ========== */

/* ---- NET-001 (allow loopback DNS; enforce allowlist on 80/443) ---- */

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
    __u32 k = 0;
    __u8 *enf = bpf_map_lookup_elem(&net_enforce, &k);
    if (!enf || *enf == 0)
        return 1;

    if (!is_target_proc())
        return 1;

    __u16 dport = bpf_ntohs(ctx->user_port);
    __u32 dip   = ctx->user_ip4;           /* network byte-order */

    /* EXCEPTION: allow local stub resolver DNS: 127.0.0.53 (and 127.0.0.1) on :53 */
    if (dport == 53) {
        if (dip == bpf_htonl(0x7f000035) /* 127.0.0.53 */ ||
            dip == bpf_htonl(0x7f000001) /* 127.0.0.1  */) {
            return 1;  /* allow DNS to systemd-resolved */
        }
    }

    /* Enforce: only HTTP(S) */
    if (!(dport == 80 || dport == 443))
        return 0;

    /* Enforce: destination IP must be allow-listed */
    __u8 *ok = bpf_map_lookup_elem(&ipv4_allow, &dip);
    return ok && *ok ? 1 : 0;
}

SEC("cgroup/connect6")
int cg_connect6(struct bpf_sock_addr *ctx)
{
    __u32 k = 0;
    __u8 *enf = bpf_map_lookup_elem(&net_enforce, &k);
    if (!enf || *enf == 0)
        return 1;

    if (!is_target_proc())
        return 1;

    __u16 dport = bpf_ntohs(ctx->user_port);

    /* EXCEPTION: allow local stub resolver DNS: ::1 on :53 */
    if (dport == 53) {
        /* ctx->user_ip6 equals ::1 ? */
        bool is_loopback_v6 = true;
        struct in6_addr ip6 = {};
        bpf_core_read(&ip6, sizeof(ip6), &ctx->user_ip6);
        /* ::1 is 15 zero bytes followed by 0x01 */
        for (int i = 0; i < 15; i++) {
            if (((const __u8 *)&ip6)[i] != 0) { is_loopback_v6 = false; break; }
        }
        if (is_loopback_v6 && ((const __u8 *)&ip6)[15] == 1)
            return 1;  /* allow DNS to ::1 */
    }

    /* Enforce: only HTTP(S) */
    if (!(dport == 80 || dport == 443))
        return 0;

    /* Enforce: destination IP must be allow-listed */
    struct in6_addr ip6_key = {};
    bpf_core_read(&ip6_key, sizeof(ip6_key), &ctx->user_ip6);
    __u8 *ok = bpf_map_lookup_elem(&ipv6_allow, &ip6_key);
    return ok && *ok ? 1 : 0;
}




/* ========== FS-001: open gating + write() enforcement ========== */

/* Sleepable file_open to check path; if allowed, mark file* as write-ok */
SEC("lsm.s/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
    __u32 k = 0;
    __u8 *enf = bpf_map_lookup_elem(&fs_enforce, &k);
    if (!enf || *enf == 0)
        return 0;

    if (!is_target_proc())
        return 0;

    __u32 flags = 0;
    bpf_core_read(&flags, sizeof(flags), &file->f_flags);

    if (!write_like_open(flags))
        return 0;

    char *buf = bpf_map_lookup_elem(&scratch_buf, &k);
    char *prefix = bpf_map_lookup_elem(&allowed_write_prefix, &k);
    if (!buf || !prefix)
        return -EPERM;

    long n = bpf_d_path((struct path *)&file->f_path, buf, 4096);
    if (n < 0)
        return -EPERM;

    if (!has_allowed_prefix(buf, prefix))
        return -EPERM;

    /* mark this file* as OK to write later */
    __u64 fkey = (unsigned long)file;
    __u8 one = 1;
    bpf_map_update_elem(&write_ok_files, &fkey, &one, BPF_ANY);
    return 0;
}

/* Non-sleepable: enforce write() by checking MAY_WRITE and our allow-list */
SEC("lsm/file_permission")
int BPF_PROG(enforce_file_permission, struct file *file, int mask)
{
    __u32 k = 0;
    __u8 *enf = bpf_map_lookup_elem(&fs_enforce, &k);
    if (!enf || *enf == 0) return 0;
    if (!is_target_proc()) return 0;

    // Only care if this is a write attempt
    if (!(mask & __MAY_WRITE)) return 0;

    // Only enforce on regular files; let TTYs, pipes, sockets, etc. pass
    // (S_IFMT = 00170000, S_IFREG = 0100000)
    #ifndef S_IFMT
    #define S_IFMT  00170000
    #endif
    #ifndef S_IFREG
    #define S_IFREG 0100000
    #endif

    umode_t mode = 0;
    struct inode *inode = NULL;

    // Prefer f_inode; CO-RE safe
    bpf_core_read(&inode, sizeof(inode), &file->f_inode);
    if (inode)
        bpf_core_read(&mode, sizeof(mode), &inode->i_mode);

    if ((mode & S_IFMT) != S_IFREG)
        return 0;  // don’t enforce on non-regular files (e.g., stdout)

    // For regular files, require prior allow-listing by file_open
    __u64 key = (unsigned long)file;
    __u8 *ok = bpf_map_lookup_elem(&write_ok_files, &key);
    return ok ? 0 : -EPERM;
}



