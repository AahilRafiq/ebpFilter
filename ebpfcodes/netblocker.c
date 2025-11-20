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

int __strcmp(const char *s1, const char *s2, int len) {
    int index = 0;
    while(index < len && s1[index] != '\0') {
        if(s1[index] != s2[index]) {
            return -1;
        }
        index++;
    }
    return 0;
}

SEC("tcx/action")
int sockfilter_netblocker_func(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u64 offset = 0;
    
    offset = parse_eth(data, data_end);
    if(offset == -1) {
        bpf_printk("returning here");
        return TCX_NEXT;
    }
    offset = parse_ip(data, data_end, offset);
    if(offset == -1) return TCX_NEXT;
    offset = parse_udp(data, data_end, offset);
    if(offset == -1) return TCX_NEXT;

    struct dns_hdr *dnsh = (struct dns_hdr*)(data + offset);
    if((void *)dnsh + sizeof(struct dns_hdr) > data_end) {
        return TCX_NEXT;
    }
    __u16 num_queries = ntohs(dnsh->qdcount);
    offset += sizeof(struct dns_hdr);

    char *query = (char*)(data + offset);
    char dexample[] = "_youtube_com";
    dexample[0] = 7;
    dexample[8] = 3;
    if((void*)query + 13 > data_end) {
        return TCX_NEXT;
    }
    if(__strcmp(query, dexample, 13) == 0) {
        bpf_printk("dropping %s",dexample);
        return TCX_DROP;
    }

    return TCX_NEXT;
}

char _license[] SEC("license") = "Dual MIT/GPL";

