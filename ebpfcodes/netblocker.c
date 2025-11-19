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

    while(true) {
        void *ptr = data + offset;
        if(ptr + 1 > data_end) {
            break;
        }
        __u8 wordlen = *(__u8*)ptr;
        ptr += 1;

        if(ptr + wordlen > data_end) {
            break;
        }
        
        const char* byte_ptr = (const char*)ptr;
        if((void*)byte_ptr + wordlen > data_end) {
            return TCX_NEXT;
        }

        char word[256];
        for(__u8 i=0; i<wordlen; i++) {
            if ((void *)byte_ptr + i + 1 > data_end)
                return TCX_NEXT;
            word[i] = byte_ptr[i];
        }
        word[wordlen] = '\0';
        bpf_printk("%s",word);
        if(strcmp(word, "neetcode") == 0) {
            bpf_printk("Dropping LEETCODE");
            return 2;
        }

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

