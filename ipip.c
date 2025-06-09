#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

#define AF_INET 2

#define IPV4_VERSION 4
#define IPV4_IHL_NO_OPTIONS 5
#define DEFAULT_TTL 64

#ifndef DEST_SUBNET_ADDR
#define DEST_SUBNET_ADDR 0xc0a80100
#endif
#ifndef DEST_SUBNET_MASK
#define DEST_SUBNET_MASK 0xffffff00
#endif

#ifndef TRANSPORT_LOCAL_ADDR
#define TRANSPORT_LOCAL_ADDR 0x0a000002
#endif
#ifndef TRANSPORT_REMOTE_ADDR
#define TRANSPORT_REMOTE_ADDR 0x0a000001
#endif

#ifndef TRANSPORT_NIC_INDEX
#define TRANSPORT_NIC_INDEX 5
#endif

#ifndef TUNNEL_NIC_INDEX
#define TUNNEL_NIC_INDEX 6
#endif

static __u16 calc_ipv4_checksum(struct iphdr *ip) {
    ip->check = 0;
    __u32 csum = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(struct iphdr), 0);
    return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void fill_outer_ip(struct iphdr *outer_ip,
                                          struct iphdr *inner_ip) {
    outer_ip->version = IPV4_VERSION;
    outer_ip->ihl = IPV4_IHL_NO_OPTIONS;
    outer_ip->tos = 0;
    outer_ip->tot_len =
        bpf_htons(bpf_ntohs(inner_ip->tot_len) + sizeof(struct iphdr));
    outer_ip->id = 0;
    outer_ip->frag_off = 0;
    outer_ip->ttl = DEFAULT_TTL;
    outer_ip->protocol = IPPROTO_IPIP;
    outer_ip->saddr = bpf_htonl(TRANSPORT_LOCAL_ADDR);
    outer_ip->daddr = bpf_htonl(TRANSPORT_REMOTE_ADDR);
    outer_ip->check = calc_ipv4_checksum(outer_ip);
}

static __always_inline void init_fib_params(struct bpf_fib_lookup *fib_params,
                                            struct __sk_buff *skb,
                                            struct iphdr *iph, int ifindex) {
    __builtin_memset(fib_params, 0, sizeof(*fib_params));
    fib_params->family = AF_INET;
    fib_params->ipv4_src = iph->saddr;
    fib_params->ipv4_dst = iph->daddr;
    fib_params->ifindex = ifindex;
}

static __always_inline int validate_l2(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    return eth->h_proto == bpf_htons(ETH_P_IP);
}

static __always_inline int validate_ip_header(struct iphdr *ip,
                                              void *data_end) {
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        return 0;
    return 1;
}

static __always_inline int is_dest_subnet(struct iphdr *ip) {
    return (ip->daddr & bpf_htonl(DEST_SUBNET_MASK)) ==
           bpf_htonl(DEST_SUBNET_ADDR);
}

static int fib_lookup_and_forward(struct __sk_buff *skb, struct ethhdr *eth,
                                  struct iphdr *iph, int ifindex) {
    struct bpf_fib_lookup fib_params;
    int ret;

    init_fib_params(&fib_params, skb, iph, ifindex);

    ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);

    switch (ret) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        return bpf_redirect(ifindex,
                            ifindex == TUNNEL_NIC_INDEX ? BPF_F_INGRESS : 0);

    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        bpf_printk("FIB lookup failed (%d), dropping packet", ret);
        return TC_ACT_SHOT;

    case BPF_FIB_LKUP_RET_NOT_FWDED:
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
        bpf_printk("FIB lookup failed (%d), passing to kernel", ret);
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

static int encap(struct __sk_buff *skb) {
    int ret;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *outer_ip, *inner_ip;

    ret = bpf_skb_adjust_room(skb, sizeof(struct iphdr), BPF_ADJ_ROOM_MAC,
                              BPF_F_ADJ_ROOM_ENCAP_L3_IPV4);
    if (ret < 0) {
        bpf_printk("bpf_skb_adjust_room failed. ret = %d", ret);
        return TC_ACT_OK;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;

    inner_ip = (void *)(outer_ip + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_OK;

    fill_outer_ip(outer_ip, inner_ip);

    return fib_lookup_and_forward(skb, eth, outer_ip, TRANSPORT_NIC_INDEX);
}

SEC("tc/encap")
int tc_encap(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    if (!validate_l2(data, data_end))
        return TC_ACT_OK;

    ip = (void *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;

    if (is_dest_subnet(ip))
        return encap(skb);

    return TC_ACT_OK;
}

static int decap(struct __sk_buff *skb) {
    int ret;
    void *data, *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;

    ret = bpf_skb_adjust_room(skb, (__s32)(-sizeof(struct iphdr)),
                              BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
    if (ret < 0) {
        bpf_printk("bpf_skb_adjust_room failed. ret = %d", ret);
        return TC_ACT_OK;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    eth->h_proto = bpf_htons(ETH_P_IP);
    return fib_lookup_and_forward(skb, eth, ip, TUNNEL_NIC_INDEX);
}

SEC("tc/decap")
int tc_decap(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *outer_ip;

    if (!validate_l2(data, data_end))
        return TC_ACT_OK;

    outer_ip = (void *)(eth + 1);
    if (!validate_ip_header(outer_ip, data_end))
        return TC_ACT_OK;

    if (outer_ip->protocol == IPPROTO_IPIP)
        return decap(skb);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
