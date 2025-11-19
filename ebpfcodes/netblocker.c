//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "net_parsers.h"

__u64 parse_eth(void *data, void *data_end);
__u64 parse_ip(void *data, void *data_end, __u64 offset);
__u64 parse_udp(void *data, void *data_end, __u64 offset);

SEC("tcx/action")
int sockfilter_netblocker_func(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u64 offset = 0;

    offset = parse_eth(data, data_end);
    
    offset = parse_ip(data, data_end, offset);
    if(offset == -1) return TCX_NEXT;

    offset = parse_udp(data, data_end, offset);
    if(offset == -1) return TCX_NEXT;

    bpf_printk("DNS Packet detected\n");

    return TCX_NEXT;
}

char _license[] SEC("license") = "Dual MIT/GPL";

