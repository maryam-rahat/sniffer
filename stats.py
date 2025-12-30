from collections import defaultdict

tcp_count = 0
udp_count = 0
icmp_count = 0

captured_packets = []
ip_count = defaultdict(int)
port_scan_tracker = defaultdict(set)
ddos_tracker = defaultdict(list)

packet_times = []
captured_packets = []
