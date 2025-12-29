# Network Traffic Analyzer

A real-time network traffic monitoring and analysis tool built using **Python, Scapy, and Streamlit**.  
The system captures live packets, classifies traffic across transport, application, and security layers, and visualizes insights through a modern dark-mode dashboard.

---

## Features

### Packet Capture
- Live packet sniffing using Scapy
- Supports TCP, UDP, and ICMP traffic
- Saves raw traffic to PCAP for offline analysis

### Traffic Classification
- Transport Layer: TCP, UDP, ICMP
- Application Layer: HTTP, HTTPS, DNS, SSH, FTP, QUIC
- Security Classification: Encrypted vs Unencrypted
- Automatic grouping of low-frequency protocols

### DNS Performance Analysis
- Tracks DNS query–response pairs
- Computes real-time DNS latency (milliseconds)

### Detection Hooks
- High traffic detection
- Packet size anomaly detection
- DDoS rate monitoring
- Blacklisted IP detection (extensible)

### Interactive Dashboard
- Live traffic rate visualization
- Protocol distribution charts
- Application protocol breakdown
- Encrypted vs unencrypted traffic analysis
- Top talkers and raw traffic inspection
- Dark-mode enterprise UI

---

## Project Architecture

