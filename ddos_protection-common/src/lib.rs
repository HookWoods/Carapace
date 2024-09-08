#![no_std]
extern crate alloc;

#[derive(Clone, Copy, Default)]
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
    pub last_port: u16,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct RateLimitInfo {
    pub last_seen: u64,
    pub tokens: u32,
    pub rate: u32,
    pub burst: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpStats {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitInfo {}

pub mod machine_model;