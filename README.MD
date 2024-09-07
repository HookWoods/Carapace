# DDoS Protection System

<p align="center">
  <img src="assets/project_logo.png" width="400" alt="project-logo">
</p>

A powerful and intelligent DDoS protection system built with Rust and eBPF. This system analyzes network traffic in real-time, detects potential DDoS attacks, and takes action to mitigate them.

**Note:** This project is currently in the development phase and not fully functional. Please stay tuned for updates and releases.

## Features

- **Real-time traffic analysis**: Continuously monitors network traffic and collects statistics for each IP address.
- **Dynamic thresholds**: Automatically adjusts packet and byte thresholds based on the current traffic patterns to minimize false positives.
- **Optimized IP tracking**: Registers incoming IP addresses and performs checks on them to quickly detect attacks while minimizing overhead.
- **Sophisticated analysis**: Employs advanced techniques to identify and mitigate DDoS attacks effectively.
- **Temporary blacklisting**: Temporarily blacklists IP addresses exhibiting malicious behavior to prevent further damage.
- **Decay mechanism**: Gradually decays the influence of past traffic data to adapt to changing traffic patterns over time.
- **Efficient and scalable**: Leverages eBPF and Rust's performance to handle high-volume traffic with low overhead.

### Rate Limiting
- **Rate limiting**: Applies rate limiting to different traffic tiers (HTTPS, HTTP, TCP, UDP, ICMP) to prevent resource exhaustion.
- **Dynamic rate limiting**: Adjusts rate limits based on the current load and traffic patterns to ensure optimal protection.
- **Tiered rate limiting**: Implements different rate limits for each traffic tier to prioritize and protect critical services.
- **Gradual rate limit increase**: Gradually increases rate limits for well-behaved IP addresses to reward good behavior and optimize resource utilization.
- **Adaptive increase factors**: Dynamically adjusts the rate limit increase factors based on the system's load and performance.

### Machine Learning
- **Machine learning-based anomaly detection**: Utilizes machine learning models to identify anomalous traffic patterns and suspicious activities.
- **Sophisticated feature engineering**: Applies advanced feature engineering techniques to extract meaningful insights from traffic data for improved ML model performance.
- **Cross-validation and model evaluation**: Employs cross-validation and other techniques to evaluate and improve the ML model's performance over time.

## Kubernetes Integration

The DDoS protection system is designed to work seamlessly with Kubernetes clusters. A Kubernetes operator will be developed to facilitate easy integration and deployment of the system within a Kubernetes environment. This operator will handle the necessary configuration and management tasks, allowing users to monitor and protect their applications running on Kubernetes.

## Native Linux Support

In addition to Kubernetes integration, the DDoS protection system will also be packaged as a standalone Linux application. This will enable users to run the system directly on Linux servers, similar to tools like iptables and fail2ban. The application will provide a simple and intuitive interface for configuring and managing DDoS protection on individual Linux servers.

## Architecture

![Architecture Diagram](https://via.placeholder.com/800x400.png?text=Architecture+Diagram)

The DDoS protection system consists of the following main components:

1. **eBPF XDP Program**: An eBPF program attached to the network interface that captures incoming packets and collects traffic statistics.
2. **User Space Application**: A Rust application that interacts with the eBPF program, analyzes traffic data, and makes decisions based on the analysis results.
3. **Traffic Analyzer**: Analyzes traffic patterns, applies machine learning models, and calculates suspicion scores for each IP address.
4. **Rate Limiter**: Enforces rate limiting rules for different traffic tiers to prevent resource exhaustion.
5. **Blacklist Manager**: Manages the temporary and permanent blacklisting of IP addresses based on their behavior.
6. **Machine Learning Models**: Trained models that detect anomalies and suspicious activities in network traffic.

## Todo

The following tasks and improvements are planned for the DDoS protection system:

- Implement the XDP native kernel code to monitor traffic efficiently.
- Make the application data persistent over time to preserve configurations and historical data across restarts.
- Enhance the scalability of the application by enabling data sharing between multiple instances.
- Develop a Kubernetes operator to simplify the integration and deployment of the system in Kubernetes clusters.
- Create a standalone Linux image for easy installation and usage on Linux servers, similar to iptables and fail2ban.
- Clean up and optimize the project codebase for better maintainability and performance.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/ddos-protection.git
   ```

2. Install the required dependencies:
   ```
   sudo apt-get update
   sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
   ```

3. Build the project:
   ```
   cargo build --release
   ```

## Usage

1. Run the DDoS protection system:
   ```
   sudo ./target/release/ddos_protection --interface eth0
   ```

2. The system will start monitoring network traffic on the specified interface and take action against potential DDoS attacks.

## Configuration

For more details on the configuration options, including usage examples and configuration files, please see the [Command Reference](COMMAND.md).

## Decay Mechanism

The DDoS protection system incorporates a decay mechanism to gradually reduce the influence of past traffic data over time. This allows the system to adapt to changing traffic patterns and minimizes the impact of stale data on the analysis results.

The decay factor is calculated based on the elapsed time since the last update and is applied to the packet count, byte count, and other relevant statistics. The decayed values are then used for rate limiting, anomaly detection, and updating dynamic thresholds.

## Machine Learning-based Suspicion

The system employs machine learning models to identify suspicious activities and anomalous traffic patterns. The models are trained on historical traffic data and continuously updated to improve their accuracy.

Advanced feature engineering techniques are applied to extract meaningful insights from traffic data, enhancing the ML model's performance. Cross-validation and other evaluation techniques are used to assess and improve the model's performance over time.

The machine learning component calculates a suspicion score for each IP address based on various features, such as packet size distribution, protocol distribution, and time-based patterns. A higher suspicion score indicates a higher likelihood of malicious behavior.

The suspicion scores are used in conjunction with dynamic thresholds and other analysis results to make informed decisions about blacklisting and mitigating potential DDoS attacks.

## Contributing

We welcome contributions to the DDoS protection system! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with descriptive commit messages.
4. Push your changes to your forked repository.
5. Submit a pull request to the main repository.

Please ensure that your code follows the project's coding conventions and includes appropriate documentation.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

We would like to thank the following individuals and organizations for their contributions and support:

- [Rust Community](https://www.rust-lang.org/)
- [eBPF Community](https://ebpf.io/)
- [Cloudflare](https://www.cloudflare.com/) for their inspiration and resources on DDoS protection.

## Contact

If you have any questions, suggestions, or feedback, please feel free to contact us at:

- Discord: hookwood

We appreciate your interest and support in making the internet a safer place!
