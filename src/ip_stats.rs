#[derive(Clone)]
#[repr(C)]
pub struct IpStats {
    pub packet_count: u32,
    pub byte_count: u32,
    pub last_seen: u64,
    pub tcp_count: u32,
    pub udp_count: u32,
    pub icmp_count: u32,
    pub http_count: u32,
    pub https_count: u32,
    pub decay_factor: f32,
}