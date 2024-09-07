use crate::ip_stats::IpStats;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TrafficTier {
    HTTPS,
    HTTP,
    TCP,
    UDP,
    ICMP,
    Other,
}

pub fn determine_traffic_tier(stats: &IpStats) -> TrafficTier {
    if stats.https_count > 0 {
        TrafficTier::HTTPS
    } else if stats.http_count > 0 {
        TrafficTier::HTTP
    } else if stats.tcp_count > stats.udp_count && stats.tcp_count > stats.icmp_count {
        TrafficTier::TCP
    } else if stats.udp_count > stats.tcp_count && stats.udp_count > stats.icmp_count {
        TrafficTier::UDP
    } else if stats.icmp_count > 0 {
        TrafficTier::ICMP
    } else {
        TrafficTier::Other
    }
}