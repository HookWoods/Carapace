use std::collections::HashMap as StdHashMap;
use aya::maps::{HashMap, MapData};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::ip_stats::IpStats;
use crate::utils::TrafficTier;

pub struct RateLimiterConfig {
    pub base_rates: StdHashMap<TrafficTier, f64>,
    pub base_capacities: StdHashMap<TrafficTier, f64>,
    pub rate_increase_interval: u64,
    pub max_rate_multiplier: f64,
    pub rate_increase_factor: f64,
}

pub struct RateLimiter {
    buckets: StdHashMap<(u32, TrafficTier), TokenBucket>,
    config: RateLimiterConfig,
    current_load_factor: f64,
}

pub struct TokenBucket {
    tokens: f64,
    last_update: u64,
    rate: f64,
    capacity: f64,
    good_behavior_streak: u32,
    last_rate_increase: u64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            rate,
            capacity,
            good_behavior_streak: 0,
            last_rate_increase: 0,
        }
    }

    fn update(&mut self, now: u64) {
        let elapsed = now - self.last_update;
        self.tokens = (self.tokens + elapsed as f64 * self.rate).min(self.capacity);
        self.last_update = now;
    }

    fn take(&mut self, tokens: f64) -> bool {
        if self.tokens >= tokens {
            self.tokens -= tokens;
            self.good_behavior_streak += 1;
            true
        } else {
            self.good_behavior_streak = 0;
            false
        }
    }

    fn increase_rate(&mut self, now: u64, config: &RateLimiterConfig) {
        if now - self.last_rate_increase >= config.rate_increase_interval && self.good_behavior_streak >= 100 {
            let new_rate = (self.rate * config.rate_increase_factor).min(self.rate * config.max_rate_multiplier);
            println!("Increasing rate from {} to {} tokens/s", self.rate, new_rate);
            self.rate = new_rate;
            self.last_rate_increase = now;
            self.good_behavior_streak = 0;
        }
    }
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            buckets: StdHashMap::new(),
            config,
            current_load_factor: 1.0,
        }
    }

    pub fn check_rate(&mut self, ip: u32, tier: TrafficTier, size: u32, now: u64) -> bool {
        let bucket = self.buckets.entry((ip, tier)).or_insert_with(|| {
            let rate = self.config.base_rates[&tier] * self.current_load_factor;
            let capacity = self.config.base_capacities[&tier];
            TokenBucket::new(rate, capacity)
        });
        bucket.update(now);
        let result = bucket.take(size as f64);
        bucket.increase_rate(now, &self.config);
        result
    }

    pub fn update_load_factor(&mut self, load_factor: f64) {
        self.current_load_factor = load_factor;
        for ((_, tier), bucket) in self.buckets.iter_mut() {
            let base_rate = self.config.base_rates[tier] * self.current_load_factor;
            bucket.rate = bucket.rate.max(base_rate);
        }
    }

    pub fn remove_expired(&mut self, now: u64, timeout: u64) {
        self.buckets.retain(|_, bucket| now - bucket.last_update < timeout);
    }
}

pub async fn update_load_factor(rate_limiter: &mut RateLimiter, ip_stats_map: &HashMap<MapData, u32, IpStats>) {
    let mut total_traffic = 0;
    let mut ip_count = 0;

    let mut iter = ip_stats_map.iter();
    while let Some(Ok((_, stats))) = iter.next() {
        total_traffic += stats.byte_count;
        ip_count += 1;
    }

    if ip_count > 0 {
        let avg_traffic = total_traffic as f64 / ip_count as f64;
        let load_factor = (1000.0 / avg_traffic).min(2.0).max(0.5);
        rate_limiter.update_load_factor(load_factor);
        println!("Updated load factor: {}", load_factor);
    }
}


pub async fn cleanup_rate_limiter(rate_limiter: &mut RateLimiter) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    rate_limiter.remove_expired(now, 3600); // Remove buckets inactive for more than an hour
}