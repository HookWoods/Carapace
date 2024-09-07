# Command Reference

This document provides a comprehensive list of all the customizable arguments available in the DDoS protection system.

## Command-line Arguments

The following command-line arguments can be used to configure the DDoS protection system:

- `--interface` (string): The network interface to monitor. Default: `eth0`.
- `--max-historical-entries` (usize): The maximum number of historical entries per IP address. Default: `1000`.
- `--entry-timeout` (u64): The timeout duration for inactive entries, in seconds. Default: `3600`.
- `--analysis-interval` (u64): The interval at which traffic analysis is performed, in seconds. Default: `60`.
- `--cleanup-interval` (u64): The interval at which cleanup operations are performed, in seconds. Default: `300`.
- `--load-update-interval` (u64): The interval at which load factors are updated, in seconds. Default: `10`.
- `--ml-train-interval` (u64): The interval at which machine learning models are retrained, in seconds. Default: `3600`.
- `--packet-threshold-base` (u32): The base value for the packet count threshold. Default: `100`.
- `--packet-threshold-multiplier` (f32): The multiplier for the packet count threshold. Default: `1.5`.
- `--packet-threshold-max` (u32): The maximum value for the packet count threshold. Default: `10000`.
- `--byte-threshold-base` (u32): The base value for the byte count threshold. Default: `10000`.
- `--byte-threshold-multiplier` (f32): The multiplier for the byte count threshold. Default: `1.5`.
- `--byte-threshold-max` (u32): The maximum value for the byte count threshold. Default: `1000000`.
- `--temp-blacklist-duration` (u64): The duration for temporary blacklisting, in seconds. Default: `3600`.
- `--max-offenses` (u32): The maximum number of offenses before permanent blacklisting. Default: `3`.
- `--suspicion-score-threshold` (f32): The threshold for the suspicion score. Default: `0.7`.
- `--ml-anomaly-score` (f32): The threshold for the machine learning anomaly score. Default: `0.5`.
- `--ml-n-trees` (usize): The number of trees in the machine learning model. Default: `100`.
- `--ml-sample-size` (usize): The sample size for the machine learning model. Default: `256`.
- `--ml-anomaly-threshold` (f64): The threshold for the machine learning anomaly detection. Default: `0.6`.
- `--rate-increase-interval` (u64): The interval at which rate limits are increased, in seconds. Default: `3600`.
- `--max-rate-multiplier` (f64): The maximum multiplier for rate limit increases. Default: `2.0`.
- `--rate-increase-factor` (f64): The factor by which rate limits are increased. Default: `1.1`.
- `--decay-interval` (u64): The interval at which decay is applied to historical data, in seconds. Default: `300`.

## Usage Examples

Here are some examples of how to use the command-line arguments:

1. Run the DDoS protection system with default settings:
   ```
   sudo ./target/release/ddos_protection
   ```

2. Run the DDoS protection system with a specific network interface:
   ```
   sudo ./target/release/ddos_protection --interface eth1
   ```

3. Run the DDoS protection system with custom thresholds and intervals:
   ```
   sudo ./target/release/ddos_protection --packet-threshold-base 200 --byte-threshold-max 2000000 --analysis-interval 120
   ```

4. Run the DDoS protection system with modified machine learning parameters:
   ```
   sudo ./target/release/ddos_protection --ml-n-trees 200 --ml-sample-size 512 --ml-anomaly-threshold 0.7
   ```

5. Run the DDoS protection system with a custom decay interval:
   ```
   sudo ./target/release/ddos_protection --decay-interval 600
   ```

For a complete list of available arguments and their descriptions, run:
```
./target/release/ddos_protection --help
```

## Configuration Files

In addition to command-line arguments, the DDoS protection system can also be configured using configuration files. The system looks for a configuration file named `ddos_protection.toml` in the current directory.

Here's an example configuration file:

```toml
interface = "eth0"
max_historical_entries = 1000
entry_timeout = 3600
analysis_interval = 60
cleanup_interval = 300
load_update_interval = 10
ml_train_interval = 3600
decay_interval = 300

[thresholds]
packet_threshold_base = 100
packet_threshold_multiplier = 1.5
packet_threshold_max = 10000
byte_threshold_base = 10000
byte_threshold_multiplier = 1.5
byte_threshold_max = 1000000

[blacklist]
temp_blacklist_duration = 3600
max_offenses = 3

[ml]
suspicion_score_threshold = 0.7
ml_anomaly_score = 0.5
ml_n_trees = 100
ml_sample_size = 256
ml_anomaly_threshold = 0.6

[rate_limiter]
rate_increase_interval = 3600
max_rate_multiplier = 2.0
rate_increase_factor = 1.1
```

The configuration file follows the TOML format and allows you to set the same options as the command-line arguments.

If a configuration file is present, the system will read the options from the file. Command-line arguments will override the corresponding options in the configuration file.

## Conclusion

This command reference provides a detailed overview of all the customizable arguments available in the DDoS protection system. By using these arguments, you can fine-tune the system's behavior to suit your specific requirements.

Remember to run the system with appropriate privileges (e.g., using `sudo`) and adjust the arguments based on your network environment and security needs.

If you have any further questions or need assistance, please refer to the project's documentation or reach out to the community for support.
