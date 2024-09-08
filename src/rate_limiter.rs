use std::collections::HashMap as StdHashMap;
use aya::maps::{HashMap, MapData};
use std::time::{SystemTime, UNIX_EPOCH};
use aya::Pod;
use crate::ip_stats::IpStats;
use crate::utils::TrafficTier;

pub struct RateLimiterConfig {
    pub base_rates: StdHashMap<TrafficTier, u32>,
    pub base_bursts: StdHashMap<TrafficTier, u32>,
    pub rate_increase_interval: u64,
    pub max_rate_multiplier: f64,
    pub rate_increase_factor: f64,
}

pub struct RateLimiter {
    config: RateLimiterConfig,
    current_load_factor: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitInfo {
    pub last_seen: u64,
    pub tokens: u32,
    pub rate: u32,
    pub burst: u32,
}

unsafe impl Pod for RateLimitInfo {}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            current_load_factor: 1.0,
        }
    }

    pub async fn update_rate_limit(&mut self, ip: u32, tier: TrafficTier, mut rate_limit_map: &mut HashMap<&mut MapData, u32, RateLimitInfo>) -> Result<(), anyhow::Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
        let base_rate = *self.config.base_rates.get(&tier).unwrap_or(&self.config.base_rates[&TrafficTier::Other]);
        let base_burst = *self.config.base_bursts.get(&tier).unwrap_or(&self.config.base_bursts[&TrafficTier::Other]);

        let rate = (base_rate as f64 * self.current_load_factor) as u32;
        let burst = (base_burst as f64 * self.current_load_factor) as u32;

        let rate_info = RateLimitInfo {
            last_seen: now,
            tokens: burst,
            rate,
            burst,
        };

        rate_limit_map.insert(&ip, &rate_info, 0)?;
        Ok(())
    }

    pub async fn update_load_factor(&mut self, mut ip_stats_map: &HashMap<&mut MapData, u32, IpStats>) {
        let mut total_traffic = 0;
        let mut ip_count = 0;

        let mut iter = ip_stats_map.iter();
        while let Some(Ok((_, stats))) = iter.next() {
            total_traffic += stats.byte_count;
            ip_count += 1;
        }

        if ip_count > 0 {
            let avg_traffic = total_traffic as f64 / ip_count as f64;
            self.current_load_factor = (1000.0 / avg_traffic).min(2.0).max(0.5);
            println!("Updated load factor: {}", self.current_load_factor);
        }
    }

    pub async fn cleanup_rate_limiter(&mut self, mut rate_limit_map: &mut HashMap<&mut MapData, u32, RateLimitInfo>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut to_remove = Vec::new();

        let mut iter = rate_limit_map.iter();
        while let Some(Ok((ip, info))) = iter.next() {
            if now - info.last_seen > 3600 { // Remove entries inactive for more than an hour
                to_remove.push(ip);
            }
        }

        for ip in to_remove {
            if let Err(e) = rate_limit_map.remove(&ip) {
                eprintln!("Failed to remove IP {} from rate limit map: {:?}", ip, e);
            }
        }
    }
}