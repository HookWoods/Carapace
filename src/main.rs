use anyhow::Context;
use aya::maps::{HashMap, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use aya_log::BpfLogger;
use clap::Parser;
use std::collections::{HashMap as StdHashMap, VecDeque};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::signal;
use tokio::time::{interval, Duration};

mod rate_limiter;
mod traffic_analyzer;
mod blacklist_manager;
mod ip_stats;
mod thresholds;
mod utils;
mod ml_model;

use crate::rate_limiter::{RateLimitInfo, RateLimiterConfig};
use crate::traffic_analyzer::TrafficAnalyzerConfig;
use crate::utils::TrafficTier;
use blacklist_manager::BlacklistManager;
use ip_stats::IpStats;
use rate_limiter::RateLimiter;
use thresholds::DynamicThreshold;
use traffic_analyzer::TrafficAnalyzer;
use crate::blacklist_manager::BlacklistConfig;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "eth0")]
    interface: String,
    /// Maximum number of historical entries per IP
    #[arg(long, default_value_t = 1000)]
    max_historical_entries: usize,

    /// Entry timeout in seconds
    #[arg(long, default_value_t = 3600)]
    entry_timeout: u64,

    /// Analysis interval in seconds
    #[arg(long, default_value_t = 60)]
    analysis_interval: u64,

    /// Cleanup interval in seconds
    #[arg(long, default_value_t = 300)]
    cleanup_interval: u64,

    /// Load update interval in seconds
    #[arg(long, default_value_t = 10)]
    load_update_interval: u64,

    /// ML training interval in seconds
    #[arg(long, default_value_t = 3600)]
    ml_train_interval: u64,

    /// Packet threshold base
    #[arg(long, default_value_t = 100)]
    packet_threshold_base: u32,

    /// Packet threshold multiplier
    #[arg(long, default_value_t = 1.5)]
    packet_threshold_multiplier: f32,

    /// Packet threshold max
    #[arg(long, default_value_t = 10000)]
    packet_threshold_max: u32,

    /// Byte threshold base
    #[arg(long, default_value_t = 10000)]
    byte_threshold_base: u32,

    /// Byte threshold multiplier
    #[arg(long, default_value_t = 1.5)]
    byte_threshold_multiplier: f32,

    /// Byte threshold max
    #[arg(long, default_value_t = 1000000)]
    byte_threshold_max: u32,

    /// Temporary blacklist duration in seconds
    #[arg(long, default_value_t = 3600)]
    temp_blacklist_duration: u64,

    /// Maximum number of offenses before permanent blacklisting
    #[arg(long, default_value_t = 3)]
    max_offenses: u32,

    /// Suspicion score threshold
    #[arg(long, default_value_t = 0.7)]
    suspicion_score_threshold: f32,

    /// ML anomaly score
    #[arg(long, default_value_t = 0.5)]
    ml_anomaly_score: f32,

    /// ML number of trees
    #[arg(long, default_value_t = 100)]
    ml_n_trees: usize,

    /// ML sample size
    #[arg(long, default_value_t = 256)]
    ml_sample_size: usize,

    /// ML anomaly threshold
    #[arg(long, default_value_t = 0.6)]
    ml_anomaly_threshold: f64,

    /// Rate increase interval in seconds
    #[arg(long, default_value_t = 3600)]
    rate_increase_interval: u64,

    /// Maximum rate multiplier
    #[arg(long, default_value_t = 2.0)]
    max_rate_multiplier: f64,

    /// Rate increase factor
    #[arg(long, default_value_t = 1.1)]
    rate_increase_factor: f64,

    #[arg(long, default_value_t = 300)]
    decay_interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    env_logger::init();
    let bpf_file_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("resources")
        .join("ddos_protection.bpf.o");

    let mut bpf = Bpf::load_file(bpf_file_path)?;
    BpfLogger::init(&mut bpf)?;

    let program: &mut Xdp = bpf.program_mut("xdp_ddos_filter")
        .context("error loading XDP program")?
        .try_into()?;
    program.load()?;
    program.attach(&args.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags")?;

    let mut ip_stats_map = HashMap::<MapData, u32, IpStats>::try_from(bpf.map_mut("ip_stats_map")
        .context("error getting ip_stats_map")?)?;
    let mut blacklist_map = HashMap::<MapData, u32, u8>::try_from(bpf.map_mut("blacklist_map")
        .context("error getting blacklist_map")?)?;
    let rate_limit_map = HashMap::<MapData, u32, RateLimitInfo>::try_from(bpf.map_mut("rate_limit_map")
        .context("error getting rate_limit_map")?)?;

    let packet_threshold = DynamicThreshold::new(
        args.packet_threshold_base,
        args.packet_threshold_multiplier,
        args.packet_threshold_max,
    );

    let byte_threshold = DynamicThreshold::new(
        args.byte_threshold_base,
        args.byte_threshold_multiplier,
        args.byte_threshold_max,
    );

    let traffic_analyzer_config = TrafficAnalyzerConfig {
        suspicion_score_threshold: args.suspicion_score_threshold,
        ml_anomaly_score: args.ml_anomaly_score,
        ml_n_trees: args.ml_n_trees,
        ml_sample_size: args.ml_sample_size,
        ml_anomaly_threshold: args.ml_anomaly_threshold,
    };

    let black_list_config = BlacklistConfig {
        temp_blacklist_duration: args.temp_blacklist_duration,
        max_offenses: args.max_offenses,
    };

    let rate_limiter_config = RateLimiterConfig {
        base_rates: std::collections::HashMap::from([
            (TrafficTier::HTTPS, 2000),
            (TrafficTier::HTTP, 1000),
            (TrafficTier::TCP, 800),
            (TrafficTier::UDP, 500),
            (TrafficTier::ICMP, 100),
            (TrafficTier::Other, 200),
        ]),
        base_bursts: std::collections::HashMap::from([
            (TrafficTier::HTTPS, 20000),
            (TrafficTier::HTTP, 10000),
            (TrafficTier::TCP, 8000),
            (TrafficTier::UDP, 5000),
            (TrafficTier::ICMP, 1000),
            (TrafficTier::Other, 2000),
        ]),
        rate_increase_interval: args.rate_increase_interval,
        max_rate_multiplier: args.max_rate_multiplier,
        rate_increase_factor: args.rate_increase_factor,
    };

    let mut ip_analyzers: StdHashMap<u32, TrafficAnalyzer> = StdHashMap::new();
    let mut ip_thresholds: StdHashMap<u32, (u32, u32)> = StdHashMap::new();
    let mut blacklist_manager = BlacklistManager::new(black_list_config);
    let mut rate_limiter = RateLimiter::new(rate_limiter_config, rate_limit_map);

    let mut historical_data: StdHashMap<u32, VecDeque<IpStats>> = StdHashMap::new();

    tokio::spawn(async move {
        let mut analysis_interval = interval(Duration::from_secs(args.analysis_interval));
        let mut cleanup_interval = interval(Duration::from_secs(args.cleanup_interval));
        let mut load_update_interval = interval(Duration::from_secs(args.load_update_interval));
        let mut ml_train_interval = interval(Duration::from_secs(args.ml_train_interval));

        loop {
            tokio::select! {
                _ = analysis_interval.tick() => {
                    traffic_analyzer::analyze_traffic(&ip_stats_map, &mut blacklist_map, &packet_threshold, &byte_threshold,
                        &mut ip_thresholds, &mut ip_analyzers, &mut blacklist_manager, &mut rate_limiter, traffic_analyzer_config).await;
                    update_historical_data(&mut historical_data, &ip_stats_map, args.max_historical_entries, args.decay_interval).await;
                }
                _ = cleanup_interval.tick() => {
                    blacklist_manager.cleanup_blacklist(&mut blacklist_map).await;
                    rate_limiter.cleanup_rate_limiter().await;
                    cleanup_old_entries(&mut ip_stats_map, &mut historical_data, &mut ip_analyzers, &mut ip_thresholds, args.entry_timeout).await;
                }
                _ = load_update_interval.tick() => {
                    rate_limiter.update_load_factor(&ip_stats_map).await;
                }
                _ = ml_train_interval.tick() => {
                    traffic_analyzer::train_ml_model(&mut ip_analyzers, &historical_data).await;
                }
                _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
            }
        }
    });

    println!("DDoS protection system running. Press Ctrl+C to exit.");
    println!("{:#?}", args);
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

async fn update_historical_data(
    historical_data: &mut StdHashMap<u32, VecDeque<IpStats>>,
    ip_stats_map: &HashMap<MapData, u32, IpStats>,
    max_entries: usize,
    decay_interval: u64,
) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    for (ip, stats) in ip_stats_map.iter().filter_map(|r| r.ok()) {
        let entry = historical_data.entry(ip).or_insert_with(|| VecDeque::with_capacity(max_entries));

        // Apply decay to existing entries
        for historical_stats in entry.iter_mut() {
            let elapsed = now - historical_stats.last_seen;
            historical_stats.decay_factor = 0.9f32.powf((elapsed as f32) / (decay_interval as f32));
            historical_stats.packet_count = (historical_stats.packet_count as f32 * historical_stats.decay_factor) as u32;
            historical_stats.byte_count = (historical_stats.byte_count as f32 * historical_stats.decay_factor) as u32;
            // Apply decay to other fields as needed
        }

        if entry.len() >= max_entries {
            entry.pop_front();
        }
        let mut new_stats = stats.clone();
        new_stats.decay_factor = 1.0; // Set initial decay factor to 1.0
        entry.push_back(new_stats);
    }
}

async fn cleanup_old_entries(
    ip_stats_map: &mut HashMap<MapData, u32, IpStats>,
    historical_data: &mut StdHashMap<u32, VecDeque<IpStats>>,
    ip_analyzers: &mut StdHashMap<u32, TrafficAnalyzer>,
    ip_thresholds: &mut StdHashMap<u32, (u32, u32)>,
    entry_timeout: u64,
) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut ips_to_remove = Vec::new();

    // Identify old entries
    for (ip, stats) in ip_stats_map.iter().filter_map(|r| r.ok()) {
        if now - stats.last_seen > entry_timeout {
            ips_to_remove.push(ip);
        }
    }

    // Remove old entries
    for ip in ips_to_remove {
        // Remove from ip_stats_map
        if let Err(e) = ip_stats_map.remove(&ip) {
            eprintln!("Error removing IP {} from ip_stats_map: {:?}", Ipv4Addr::from(ip), e);
        }

        // Remove from historical_data
        historical_data.remove(&ip);

        // Remove from ip_analyzers
        ip_analyzers.remove(&ip);

        // Remove from ip_thresholds
        ip_thresholds.remove(&ip);

        println!("Removed old entry for IP: {}", Ipv4Addr::from(ip));
    }
}