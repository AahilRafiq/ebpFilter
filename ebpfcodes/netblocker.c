//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "net_parsers.h"
#include <stdbool.h>

__u64 parse_eth(void *data, void *data_end);
__u64 parse_ip(void *data, void *data_end, __u64 offset);
__u64 parse_udp(void *data, void *data_end, __u64 offset);

struct dns_hdr{
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 256);
    __type(value, int);
    __uint(max_entries, 200); // adjust later
} blockeddns SEC(".maps");

SEC("tcx/action")
int sockfilter_netblocker_func(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u64 offset = 0;
    
    offset = parse_eth_and_ip(data, data_end);
    if(offset == -1) return TCX_NEXT;
    
    offset = parse_udp(data, data_end, offset);
    if(offset == -1) return TCX_NEXT;

    struct dns_hdr *dnsh = (struct dns_hdr*)(data + offset);
    if((void *)dnsh + sizeof(struct dns_hdr) > data_end) {
        return TCX_NEXT;
    }
    __u16 num_queries = ntohs(dnsh->qdcount);
    offset += sizeof(struct dns_hdr);

    char query[256] = {0};
    char *dns_data = (char*)(data + offset);
    int idx=0;
    while(idx < 256 && (void*)dns_data + idx < data_end) {
        if(dns_data[idx] == 0) break;

        query[idx] = (char)dns_data[idx];
        idx++;
    }

    void *val = bpf_map_lookup_elem(&blockeddns, (void*)query);
    if(val != NULL) {
        bpf_printk("Dropping %s", query);
        return TCX_DROP;
    }

    return TCX_NEXT;
}

char _license[] SEC("license") = "Dual MIT/GPL";

