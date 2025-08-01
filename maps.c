//go:build ignore
#include "vmlinux.h" 
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} percpu_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} lru_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} percpu_lru_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} array_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 10);
} percpu_array_map SEC(".maps");

struct lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} lpm_trie_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, u32);
    __uint(max_entries, 10);
} queue_map SEC(".maps");
