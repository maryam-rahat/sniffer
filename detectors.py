import time
from scapy.all import IP, TCP, ICMP
from config import (
    SUSPICIOUS_PORTS,
    BLACKLIST,
    PORT_SCAN_THRESHOLD,
    DDOS_THRESHOLD,
    MIN_PACKET_SIZE,
    MAX_PACKET_SIZE,
    ENABLE_SIZE_WARNING
)
import stats
import csv 
from datetime import datetime


traffic_log = open("traffic_log.csv", "w", newline="")
traffic_writer = csv.writer(traffic_log)

traffic_writer.writerow([
    "timestamp", "protocol",
    "src_ip", "src_port",
    "dst_ip", "dst_port",
    "packet_size"
])

warning_log = open("warnings.log", "a")

def alert(level, message):
    print(f"[{level}] {message}")


def detect_high_traffic(packet):
    src = packet[IP].src
    stats.ip_count[src] = stats.ip_count.get(src, 0) + 1
    if stats.ip_count[src] > 50:
        alert("MEDIUM", f"High traffic from {src}")


def detect_packet_size(packet):
    if not ENABLE_SIZE_WARNING:
        return

    size = len(packet)
    if size < MIN_PACKET_SIZE or size > MAX_PACKET_SIZE:
        log_warning("LOW", f"Unusual packet size {size}")

def detect_blacklist(packet):
    src = packet[IP].src
    if src in BLACKLIST:
        alert("HIGH", f"BLACKLISTED IP detected: {src}")


def detect_ddos(packet):
    src = packet[IP].src
    now = time.time()

    timestamps = stats.ddos_tracker.get(src, [])
    timestamps.append(now)
    timestamps = [t for t in timestamps if now - t < 1]
    stats.ddos_tracker[src] = timestamps

    if len(timestamps) > DDOS_THRESHOLD:
        alert("HIGH", f"Possible DDoS attack from {src}")


def detect_icmp(packet):
    if ICMP in packet:
        stats.icmp_count += 1
        print(f"ICMP | {packet[IP].src} -> {packet[IP].dst}")
        return True
    return False


def detect_tcp(packet):
    if TCP not in packet:
        return

    stats.tcp_count += 1
    src = packet[IP].src
    dst = packet[IP].dst
    sport = packet[TCP].sport
    dport = packet[TCP].dport

    print(f"TCP | {src}:{sport} -> {dst}:{dport}")

    if dport in SUSPICIOUS_PORTS:
        alert("MEDIUM", f"Suspicious port {dport} accessed from {src}")

    ports = stats.port_scan_tracker.get(src, set())
    ports.add(dport)
    stats.port_scan_tracker[src] = ports

    if len(ports) > PORT_SCAN_THRESHOLD:
        alert("HIGH", f"Port scan detected from {src}")

def log_warning(level, message):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    warning_log.write(f"[{time}] [{level}] {message}\n")
