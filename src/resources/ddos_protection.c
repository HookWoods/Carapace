#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define INITIAL_THRESHOLD 100
#define SUSPICIOUS_THRESHOLD 1000

struct ip_stats {
    __u32 packet_count;
    __u32 byte_count;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);    // source IP
    __type(value, struct ip_stats);
} ip_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);    // IP address
    __type(value, __u8);   // 1 if blacklisted
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if ((void*)iph + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    // Check blacklist first
    __u8 *blacklisted = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blacklisted && *blacklisted == 1)
        return XDP_DROP;

    // Update IP stats
    struct ip_stats *stats, new_stats = {0};
    stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    if (!stats) {
        stats = &new_stats;
    }

    stats->packet_count++;
    stats->byte_count += (data_end - data);
    stats->last_seen = bpf_ktime_get_ns();


    bpf_map_update_elem(&ip_stats_map, &src_ip, stats, BPF_ANY);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";