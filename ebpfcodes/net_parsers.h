#ifndef NET_PARSERS_H
#define NET_PARSERS_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
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

__u64 parse_eth(void *data, void *data_end) {
    struct ethhdr *eth = (struct ethhdr*)data;
    __u64 offset = sizeof(*eth);

    if((void*)data + sizeof(struct ethhdr) > data_end) {
        return -1;
    }
    __u16 ethtype = eth->h_proto;

    // Todo: is this really needed?
    // handle VLAN tagged packet
    if(ntohs(ethtype) == ETH_P_8021Q || ntohs(ethtype) == ETH_P_8021AD) {
        struct vlan_hdr *vlanh = (struct vlan_hdr*)(data + offset);
        offset += sizeof(*vlanh);
        if ((void *)vlanh + sizeof(struct vlan_hdr) > data_end) {
            return XDP_ABORTED;
        }
        ethtype = vlanh->h_vlan_encapsulated_proto;
    }

    // Only handling IPV4
    if(ntohs(ethtype) != ETH_P_IP) {
        return -1;
    }

    return offset;
}

__u64 parse_ip(void *data, void *data_end, __u64 offset) {
    struct iphdr *iph = (struct iphdr*)(data + offset);
    if ((void *)iph + sizeof(struct iphdr) > data_end) {
        return -1;
    }
    if(iph->protocol != IPPROTO_UDP) {
        return -1;
    }
    offset += sizeof(*iph);
    // bpf_printk("%u.%u.%u.%u\n", (iph->saddr >> 24) & 0xFF, (iph->saddr >> 16) & 0xFF, (iph->saddr >> 8) & 0xFF, iph->saddr & 0xFF);
    return offset;
}

__u64 parse_udp(void *data, void *data_end, __u64 offset) {
    struct udphdr *udph = (struct udphdr*)(data + offset);
    if((void *)udph + sizeof(struct udphdr) > data_end) {
        return -1;
    }
    __u16 src_port = ntohs(udph->source);
    __u16 dest_port = ntohs(udph->dest);
    if(dest_port != 53) {
        return -1;
    }
    offset += sizeof(*udph);
    return offset;
}

#endif