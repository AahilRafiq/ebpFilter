//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
// #include <linux/in.h>
#include <linux/if_vlan.h>
#include <arpa/inet.h>

/*
 * Copied from - https://docs.huihoo.com/doxygen/linux/kernel/3.7/linux_2if__vlan_8h_source.html
 *  struct vlan_hdr - vlan header
 *  @h_vlan_TCI: priority and VLAN ID
 *  @h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};

__u64 parse_eth(void *data, void *data_end);
__u64 parse_ip(void *data, void *data_end, __u64 offset);

SEC("tcx/action")
int sockfilter_netblocker_func(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u64 offset = 0;

    offset = parse_eth(data, data_end);
    if(offset == -1) return TCX_NEXT;
    
    offset = parse_ip(data, data_end, offset);
    if(offset == -1) return TCX_NEXT;


    return TCX_NEXT;
}

char _license[] SEC("license") = "Dual MIT/GPL";

/******* Helper functions ********/
__u64 parse_eth(void *data, void *data_end) {
    struct ethhdr *eth = data;
    __u64 offset = sizeof(*eth);

    if((void*)data + sizeof(*eth) > data_end) {
        return -1;
    }
    __u16 ethtype = eth->h_proto;

    // handle VLAN tagged packet
    if(ntohs(ethtype) == ETH_P_8021Q || ntohs(ethtype) == ETH_P_8021AD) {
        struct vlan_hdr *vlan_hdr = data + offset;
        offset += sizeof(*vlan_hdr);
        if ((void *)vlan_hdr + sizeof(*vlan_hdr) > data_end) {
            return XDP_ABORTED;
        }
        ethtype = vlan_hdr->h_vlan_encapsulated_proto;
    }

    // Only handling IPV4
    if(ntohs(ethtype) != ETH_P_IP) {
        return -1;
    }

    return offset;
}

__u64 parse_ip(void *data, void *data_end, __u64 offset) {
    struct iphdr *iph = data + offset;
    if ((void *)iph + sizeof(*iph) > data_end) {
        return -1;
    }
    if(iph->protocol != IPPROTO_UDP) {
        return -1;
    }
    offset += sizeof(iph);
    // bpf_printk("%u.%u.%u.%u\n", (iph->saddr >> 24) & 0xFF, (iph->saddr >> 16) & 0xFF, (iph->saddr >> 8) & 0xFF, iph->saddr & 0xFF);
    return offset;
}