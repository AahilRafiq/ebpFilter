//go:build ignore

#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>

SEC("xdp")
int xdp_netblocker_func(struct xdp_md *ctx) {
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual MIT/GPL";