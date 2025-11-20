//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "net_parsers.h"
#include <stdbool.h>
#include <string.h>

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

    char buffer[256];
    while(true) {
        __u8 label_len;
        if(bpf_skb_load_bytes(skb, offset, &label_len, 1) < 0) {
            return TCX_NEXT;
        }
        offset += 1;
        
        if(label_len == 0) {
            break;
        }
        
        if(bpf_skb_load_bytes(skb, offset, (void*)buffer, label_len) < 0) {
            return TCX_NEXT;
        }

        buffer[label_len] = '\0';
        bpf_printk("%s",buffer);
        if(strcmp(buffer, "leetcode") == 0) {
            bpf_printk("DROPPING");
            return TCX_DROP;
        }

        offset += label_len;
        break;
    }

    return TCX_NEXT;
}
/*
for each dns
    read octet
    while octet is not 0x00
        str word = copy from ptr to ptr+octet_val
        move ptr to octet_val+1
*/

char _license[] SEC("license") = "Dual MIT/GPL";

