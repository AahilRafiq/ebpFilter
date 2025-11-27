#ifndef NET_PARSERS_H
#define NET_PARSERS_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <linux/ipv6.h>

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

__u64 parse_ipv6(void *data, void *data_end, __u64 offset) {
    struct ipv6hdr *iph = (struct ipv6hdr*)(data + offset);
    if ((void *)iph + sizeof(struct ipv6hdr) > data_end) {
        return -1;
    }
    if(iph->nexthdr != IPPROTO_UDP) {
        return -1;
    }
    offset += sizeof(*iph);
    return offset;
}

__u64 parse_eth_and_ip(void *data, void *data_end) {
    struct ethhdr *eth = (struct ethhdr*)data;
    __u64 offset = sizeof(*eth);

    if((void*)data + sizeof(struct ethhdr) > data_end) {
        return -1;
    }
    __u16 ethtype = eth->h_proto;

    // IPv4
    if(ntohs(ethtype) == ETH_P_IP) {
        offset = parse_ip(data, data_end, offset);
        if(offset == -1) return -1;
    }

    //IPv6
    if(ntohs(ethtype) == ETH_P_IPV6) {
        offset = parse_ipv6(data, data_end, offset);
        if(offset == -1) return -1;
    }

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