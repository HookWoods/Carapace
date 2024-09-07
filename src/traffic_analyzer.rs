use crate::blacklist_manager::BlacklistManager;
use crate::ip_stats::IpStats;
use crate::ml_model::{MLModel, engineer_features};
use crate::rate_limiter::RateLimiter;
use crate::thresholds::DynamicThreshold;
use crate::utils::determine_traffic_tier;
use aya::maps::{HashMap, MapData};
use ndarray::{Array1, Array2, ArrayView1};
use std::collections::HashMap as StdHashMap;
use std::collections::VecDeque;
use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
pub struct TrafficAnalyzerConfig {
    pub suspicion_score_threshold: f32,
    pub ml_anomaly_score: f32,
    pub ml_n_trees: usize,
    pub ml_sample_size: usize,
    pub ml_anomaly_threshold: f64,
}

pub struct TrafficAnalyzer {
    packet_sizes: VecDeque<u32>,
    packet_times: VecDeque<u64>,
    suspicion_score: f32,
    ml_model: MLModel,
    config: TrafficAnalyzerConfig,
}

impl TrafficAnalyzer {
    pub fn new(config: TrafficAnalyzerConfig) -> Self {
        Self {
            packet_sizes: VecDeque::with_capacity(1000),
            packet_times: VecDeque::with_capacity(1000),
            suspicion_score: 0.0,
            ml_model: MLModel::new(config.ml_n_trees, config.ml_sample_size, config.ml_anomaly_threshold),
            config,
        }
    }

    pub fn add_packet(&mut self, size: u32, time: u64) {
        if self.packet_sizes.len() >= 1000 {
            self.packet_sizes.pop_front();
            self.packet_times.pop_front();
        }
        self.packet_sizes.push_back(size);
        self.packet_times.push_back(time);
    }

    pub fn analyze(&mut self, stats: &IpStats) -> f32 {
        self.suspicion_score = 0.0;

        // Analyze packet size distribution
        let avg_size = self.packet_sizes.iter().sum::<u32>() as f32 / self.packet_sizes.len() as f32;
        let size_variance = self.packet_sizes.iter()
            .map(|&s| (s as f32 - avg_size).powi(2))
            .sum::<f32>() / self.packet_sizes.len() as f32;

        // Suspicious if variance is very low (could indicate uniform DDoS traffic)
        if size_variance < 100.0 {
            self.suspicion_score += 0.3;
        }

        // Analyze protocol distribution
        let total_packets = stats.tcp_count + stats.udp_count + stats.icmp_count;
        if total_packets > 0 {
            let tcp_ratio = stats.tcp_count as f32 / total_packets as f32;
            let udp_ratio = stats.udp_count as f32 / total_packets as f32;
            let icmp_ratio = stats.icmp_count as f32 / total_packets as f32;

            // Suspicious if any protocol dominates (>90%)
            if tcp_ratio > 0.9 || udp_ratio > 0.9 || icmp_ratio > 0.9 {
                self.suspicion_score += 0.3;
            }
        }

        // Analyze time distribution of packets
        if self.packet_times.len() > 1 {
            let time_diffs: Vec<u64> = self.packet_times.iter()
                .zip(self.packet_times.iter().skip(1))
                .map(|(&t1, &t2)| t2 - t1)
                .collect();
            let avg_diff = time_diffs.iter().sum::<u64>() as f64 / time_diffs.len() as f64;
            let time_variance = time_diffs.iter()
                .map(|&d| (d as f64 - avg_diff).powi(2))
                .sum::<f64>() / time_diffs.len() as f64;

            // Suspicious if time variance is very low (could indicate bot-driven DDoS)
            if time_variance < 1000.0 {
                self.suspicion_score += 0.4;
            }
        }

        // Check for abnormally high packet rate
        let packets_per_second = stats.packet_count as f32 / 60.0;  // Assuming 1-minute interval
        if packets_per_second > 10000.0 {
            self.suspicion_score += 0.5;
        }

        // ML-based analysis
        let features: Array1<f64> = engineer_features(&[
            stats.packet_count as f64,
            stats.byte_count as f64,
            stats.tcp_count as f64,
            stats.udp_count as f64,
            stats.icmp_count as f64,
            stats.http_count as f64,
            stats.https_count as f64,
        ]);

        let features_view: ArrayView1<f64> = features.view();
        if self.ml_model.predict(&features_view) {
            self.suspicion_score += 0.5; // Increase suspicion score if ML model detects an anomaly
        }

        self.suspicion_score
    }

    pub fn train(&mut self, historical_data: &VecDeque<IpStats>) {
        let training_data: Vec<Array1<f64>> = historical_data.iter().map(|stats| {
            engineer_features(&[
                stats.packet_count as f64,
                stats.byte_count as f64,
                stats.tcp_count as f64,
                stats.udp_count as f64,
                stats.icmp_count as f64,
                stats.http_count as f64,
                stats.https_count as f64,
            ])
        }).collect();

        let training_array = Array2::from_shape_vec((training_data.len(), training_data[0].len()),
                                                    training_data.into_iter().flatten().collect()).unwrap();

        // Perform cross-validation
        let cv_score = self.ml_model.cross_validate(&training_array, 5); // 5-fold cross-validation
        println!("Cross-validation score: {}", cv_score);

        // Train the model on the full dataset
        self.ml_model.train(&training_array);

        // Print feature importance
        let feature_importance = self.ml_model.get_feature_importance();
        println!("Feature importance: {:?}", feature_importance);
    }
}

pub async fn analyze_traffic(
    ip_stats_map: &HashMap<MapData, u32, IpStats>,
    blacklist_map: &mut HashMap<MapData, u32, u8>,
    packet_threshold: &DynamicThreshold,
    byte_threshold: &DynamicThreshold,
    ip_thresholds: &mut StdHashMap<u32, (u32, u32)>,
    ip_analyzers: &mut StdHashMap<u32, TrafficAnalyzer>,
    blacklist_manager: &mut BlacklistManager,
    rate_limiter: &mut RateLimiter,
    traffic_analyzer_config: TrafficAnalyzerConfig
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut iter = ip_stats_map.iter();
    while let Some(Ok((ip, stats))) = iter.next() {
        let ip_addr = Ipv4Addr::from(ip);

        if blacklist_manager.is_blacklisted(ip, now) {
            continue; // Skip analysis for blacklisted IPs
        }

        let traffic_tier = determine_traffic_tier(&stats);

        // Apply rate limiting
        if let Err(e) = rate_limiter.update_rate_limit(ip, traffic_tier).await {
            eprintln!("Failed to update rate limit for IP {}: {:?}", ip_addr, e);
        }

        let (packet_limit, byte_limit) = ip_thresholds
            .entry(ip)
            .or_insert((packet_threshold.base, byte_threshold.base));

        let analyzer = ip_analyzers.entry(ip).or_insert_with(|| TrafficAnalyzer::new(traffic_analyzer_config));
        let decayed_byte_count = (stats.byte_count as f32 * stats.decay_factor) as u32;
        let decayed_packet_count = (stats.packet_count as f32 * stats.decay_factor) as u32;
        analyzer.add_packet(decayed_byte_count, stats.last_seen);
        let suspicion_score = analyzer.analyze(&stats);

        if suspicion_score > 0.7 || decayed_packet_count > *packet_limit || decayed_byte_count > *byte_limit {
            println!("Potential DDoS from IP: {}", ip_addr);
            println!("Suspicion score: {}", suspicion_score);
            println!("Packet count: {}, Byte count: {}", decayed_packet_count, decayed_byte_count);
            println!("TCP: {}, UDP: {}, ICMP: {}", stats.tcp_count, stats.udp_count, stats.icmp_count);

            if suspicion_score > 0.9 {
                if blacklist_manager.add_to_blacklist(ip, now) {
                    blacklist_map.insert(&ip, &1, 0).unwrap();
                    println!("Permanently blacklisted IP: {}", ip_addr);
                } else {
                    println!("Temporarily blacklisted IP: {}", ip_addr);
                }
            } else {
                println!("Warning issued for IP: {}", ip_addr);
            }
        }

        // Update dynamic thresholds
        *packet_limit = packet_threshold.calculate(stats.packet_count);
        *byte_limit = byte_threshold.calculate(stats.byte_count);
    }
}

// Function to periodically train the ML model with historical data
pub async fn train_ml_model(ip_analyzers: &mut StdHashMap<u32, TrafficAnalyzer>, historical_data: &StdHashMap<u32, VecDeque<IpStats>>) {
    for (ip, analyzer) in ip_analyzers.iter_mut() {
        if let Some(ip_data) = historical_data.get(ip) {
            println!("Training ML model for IP: {}", Ipv4Addr::from(*ip));
            analyzer.train(ip_data);
        }
    }
}