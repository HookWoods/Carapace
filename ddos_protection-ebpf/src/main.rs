#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use ddos_protection_common::{IpStats, RateLimitInfo};

#[map]
static mut IP_STATS: LruHashMap<u32, IpStats> = LruHashMap::with_max_entries(100000, 0);

#[map]
static mut BLACKLIST: HashMap<u32, u8> = HashMap::with_max_entries(100000, 0);

#[map]
static mut RATE_LIMIT: HashMap<u32, RateLimitInfo> = HashMap::with_max_entries(100000, 0);

#[xdp]
pub fn ddos_protection(ctx: XdpContext) -> u32 {
    match try_ddos_protection(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

#[inline(always)]
fn is_http(payload: &[u8]) -> bool {
    // Check for common HTTP methods
    const HTTP_METHODS: [&[u8]; 8] = [
        b"GET ", b"POST ", b"HEAD ", b"PUT ",
        b"DELETE ", b"OPTIONS ", b"TRACE ", b"CONNECT "
    ];

    HTTP_METHODS.iter().any(|&method| {
        payload.len() >= method.len() && &payload[..method.len()] == method
    })
}

#[inline(always)]
fn is_https(payload: &[u8]) -> bool {
    // Check for TLS handshake
    payload.len() >= 3 &&
        payload[0] == 0x16 && // Content Type: Handshake
        payload[1] == 0x03 && // Version: TLS 1.0, 1.1, 1.2
        (payload[2] == 0x01 || payload[2] == 0x02 || payload[2] == 0x03) // TLS 1.0, 1.1, 1.2
}

fn try_ddos_protection(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0).unwrap() };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN).unwrap() };
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Check blacklist
    if let Some(1) = unsafe { BLACKLIST.get(&src_ip) } {
        return Ok(xdp_action::XDP_DROP);
    }

    // Rate limiting
    if let Some(rate_info_ptr) = unsafe { RATE_LIMIT.get_ptr_mut(&src_ip) } {
        let rate_info = unsafe { &mut *rate_info_ptr };
        let now = unsafe { bpf_ktime_get_ns() };
        let time_passed = now - rate_info.last_seen;
        let tokens_to_add = (time_passed * rate_info.rate as u64 / 1_000_000_000) as u32;
        rate_info.tokens = (rate_info.tokens + tokens_to_add).min(rate_info.burst);

        if rate_info.tokens < 1 {
            return Ok(xdp_action::XDP_DROP); // Rate limit exceeded
        }

        rate_info.tokens -= 1;
        rate_info.last_seen = now;
    }

    // Update IP stats
    let stats_ptr = unsafe { IP_STATS.get_ptr_mut(&src_ip) };
    let stats = if let Some(s) = stats_ptr {
        unsafe { &mut *s }
    } else {
        let new_stats = IpStats::default();
        if unsafe { IP_STATS.insert(&src_ip, &new_stats, 0).is_err() } {
            return Ok(xdp_action::XDP_ABORTED);
        }
        match unsafe { IP_STATS.get_ptr_mut(&src_ip) } {
            Some(s) => unsafe { &mut *s },
            None => return Ok(xdp_action::XDP_ABORTED),
        }
    };

    stats.packet_count += 1;
    let packet_len = (ctx.data_end() - ctx.data()) as u32;
    stats.byte_count = stats.byte_count.saturating_add(packet_len);
    stats.last_seen = unsafe { bpf_ktime_get_ns() };

    let dst_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => unsafe {
            stats.tcp_count += 1;

            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).unwrap();
            let dst_port = u16::from_be((*tcphdr).dest);

            // TODO: decode the payload to check network content type
            let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
            let payload_start = unsafe { ptr_at::<u8>(&ctx, payload_offset)? };
            let payload_len = ctx.data_end() - (ctx.data() + payload_offset);

            if payload_len > 0 {
                let payload = unsafe { core::slice::from_raw_parts(payload_start, payload_len) };
                if is_http(payload) {
                    stats.http_count += 1;
                } else if is_https(payload) {
                    stats.https_count += 1;
                }
            }

            dst_port
        },
        IpProto::Udp => unsafe {
            stats.udp_count += 1;
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).unwrap();
            u16::from_be((*udphdr).dest)
        },
        IpProto::Icmp => {
            stats.icmp_count += 1;
            0
        }
        _ => 0,
    };

    stats.last_port = dst_port;

    unsafe { let _ = IP_STATS.insert(&src_ip, &stats, 0); };

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}