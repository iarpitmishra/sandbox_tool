// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef SIGKILL
#define SIGKILL 9
#endif

/* ---- shared maps (same names as in core obj; loader populates both) ---- */
struct token_key { char s[16]; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct token_key);
    __type(value, __u8);
} bad_env_tokens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[16]);
} target_comm_map SEC(".maps");

/* ---- helpers ---- */
static __always_inline bool is_target_proc(void) {
    char comm[16] = {};
    __u32 k = 0;
    char *want = bpf_map_lookup_elem(&target_comm_map, &k);
    if (!want) return false;
    bpf_get_current_comm(&comm, sizeof(comm));
    #pragma clang loop unroll(full)
    for (int i=0;i<16;i++){
        if (want[i]=='\0') return true;
        if (want[i]!=comm[i]) return false;
    }
    return true;
}

static __always_inline int name_has_bad_token(const char *name)
{
    char tmp[64] = {};
    if (bpf_probe_read_user_str(tmp, sizeof(tmp), name) < 0) return 0;

    #pragma clang loop unroll(disable)
    for (int off=0; off<48 && tmp[off]; off++){
        struct token_key tk = {};
        #pragma clang loop unroll(disable)
        for (int j=0; j<16 && tmp[off+j]; j++){
            char c = tmp[off+j];
            if (c>='a' && c<='z') c = c - 32;  /* uppercase */
            tk.s[j] = c;
        }
        __u8 *match = bpf_map_lookup_elem(&bad_env_tokens, &tk);
        if (match) return 1;
    }
    return 0;
}

/* ---- path-agnostic uprobes; real libc path is chosen by the loader ---- */
SEC("uprobe/getenv")
int BPF_PROG(enter_getenv, const char *name)
{
    if (!is_target_proc()) return 0;
    if (name_has_bad_token(name)) bpf_send_signal(SIGKILL);
    return 0;
}

SEC("uprobe/secure_getenv")
int BPF_PROG(enter_secure_getenv, const char *name)
{
    if (!is_target_proc()) return 0;
    if (name_has_bad_token(name)) bpf_send_signal(SIGKILL);
    return 0;
}
