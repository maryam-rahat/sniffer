from scapy.all import sniff, IP, UDP, TCP, ICMP, DNS, wrpcap
import csv
from datetime import datetime
import time
import os

import stats
import config
from detectors import (
    detect_high_traffic,
    detect_packet_size,
    detect_blacklist,
    detect_ddos
)

# =====================================================
# ABSOLUTE CSV PATH (dashboard-safe)
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "traffic_log.csv")

print("Sniffer CSV path:", CSV_FILE)

# =====================================================
# DNS LATENCY TRACKING
# =====================================================
dns_query_times = {}   # (src_ip, dst_ip, dns_id) -> timestamp

# =====================================================
# PROTOCOL CLASSIFICATION
# =====================================================
def classify_protocol(transport_proto, src_port, dst_port):
    ports = {src_port, dst_port}

    # ---------- Application ----------
    app_protocol = "Other"

    if 53 in ports:
        app_protocol = "DNS"
    elif transport_proto == "UDP" and 443 in ports:
        app_protocol = "QUIC"   # HTTP/3
    elif 443 in ports:
        app_protocol = "HTTPS"
    elif 80 in ports:
        app_protocol = "HTTP"
    elif 22 in ports:
        app_protocol = "SSH"
    elif 21 in ports:
        app_protocol = "FTP"

    # ---------- Security ----------
    if app_protocol in {"HTTPS", "QUIC", "SSH"}:
        security = "Encrypted"
    elif app_protocol in {"HTTP", "FTP", "DNS"}:
        security = "Unencrypted"
    else:
        security = "Unencrypted"

    return app_protocol, security


# =====================================================
# CSV SETUP (FORCED CLEAN HEADER)
# =====================================================
traffic_log = open(CSV_FILE, "w", newline="")  # overwrite every run
traffic_writer = csv.writer(traffic_log)

traffic_writer.writerow([
    "timestamp",
    "transport_protocol",
    "application_protocol",
    "security_type",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "packet_size",
    "dns_latency_ms"
])


# =====================================================
# PACKET PROCESSOR
# =====================================================
def process_packet(packet):
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    packet_time = time.time()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    transport_proto = "OTHER"
    src_port = "-"
    dst_port = "-"
    dns_latency = ""

    stats.captured_packets.append(packet)

    # ---------- Detection hooks ----------
    detect_high_traffic(packet)
    detect_packet_size(packet)
    detect_blacklist(packet)
    detect_ddos(packet)

    # ---------- Transport ----------
    if ICMP in packet:
        transport_proto = "ICMP"
        stats.icmp_count += 1

    elif TCP in packet:
        transport_proto = "TCP"
        stats.tcp_count += 1
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        transport_proto = "UDP"
        stats.udp_count += 1
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ---------- DNS Latency ----------
    if packet.haslayer(DNS):
        dns = packet[DNS]

        if dns.qr == 0 and dns.qd:
            dns_query_times[(src_ip, dst_ip, dns.id)] = packet_time

        elif dns.qr == 1:
            key = (dst_ip, src_ip, dns.id)
            if key in dns_query_times:
                latency = (packet_time - dns_query_times[key]) * 1000
                dns_latency = round(latency, 2)
                del dns_query_times[key]

    # ---------- Classification ----------
    application_protocol, security_type = classify_protocol(
        transport_proto, src_port, dst_port
    )

    # ---------- Console output ----------
    print(
        f"{transport_proto} | {application_protocol} | "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    )

    # ---------- CSV write ----------
    traffic_writer.writerow([
        timestamp,
        transport_proto,
        application_protocol,
        security_type,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        len(packet),
        dns_latency
    ])

    traffic_log.flush()


# =====================================================
# MAIN
# =====================================================
def main():
    print("Starting Capture...")
    sniff(prn=process_packet, store=False)
    wrpcap(config.PCAP_FILE, stats.captured_packets)
    print(f"Packets saved to {config.PCAP_FILE}")


if __name__ == "__main__":
    main()
