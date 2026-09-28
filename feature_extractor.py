import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, get_working_if, IFACES

# Configuration settings
WINDOW_SIZE_SECONDS = 5  # Aggregate packet metrics every 5 seconds

class WindowedFeatureExtractor:
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.reset_window()

    def reset_window(self):
        """Resets counters for the next time window."""
        self.start_time = time.time()
        self.packet_count = 0
        self.total_bytes = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.dest_ips = set()
        self.dest_ports = set()

    def process_packet(self, packet):
        """Processes an individual packet and extracts metrics."""
        current_time = time.time()

        if packet.haslayer(IP):
            self.packet_count += 1
            self.total_bytes += len(packet)
            self.dest_ips.add(packet[IP].dst)

            if packet.haslayer(TCP):
                self.tcp_count += 1
                self.dest_ports.add(packet[TCP].dport)
                flags = str(packet[TCP].flags)
                if 'S' in flags:
                    self.syn_count += 1
                if 'A' in flags:
                    self.ack_count += 1
                if 'F' in flags:
                    self.fin_count += 1

            elif packet.haslayer(UDP):
                self.udp_count += 1
                self.dest_ports.add(packet[UDP].dport)

        # Check if current time window has elapsed
        if current_time - self.start_time >= self.window_size:
            self.emit_features()
            self.reset_window()

    def emit_features(self):
        """Calculates aggregated metrics and prints feature vector."""
        elapsed = time.time() - self.start_time
        pkt_rate = round(self.packet_count / elapsed, 2)
        byte_rate = round(self.total_bytes / elapsed, 2)
        avg_pkt_size = round(self.total_bytes / max(1, self.packet_count), 2)
        syn_ratio = round(self.syn_count / max(1, self.tcp_count), 2)
        unique_dst_ips = len(self.dest_ips)
        unique_dst_ports = len(self.dest_ports)

        print("-" * 75)
        print(f"[WINDOW SUMMARY | {elapsed:.1f}s]")
        print(f" Packets: {self.packet_count:<6} | Pkt Rate: {pkt_rate:<8} pkts/s | Byte Rate: {byte_rate:<8} B/s")
        print(f" Avg Size: {avg_pkt_size:<6} B  | TCP Count: {self.tcp_count:<7} | UDP Count: {self.udp_count}")
        print(f" SYN Ratio: {syn_ratio:<5}  | Unique Dst IPs: {unique_dst_ips:<4} | Unique Dst Ports: {unique_dst_ports}")
        print("-" * 75)

def main():
    print("=" * 75)
    print("   Capstone IDS — Sliding Window Feature Extractor Prototype   ")
    print("=" * 75)

    # Search for active Wi-Fi / Wireless interface
    active_iface = None
    for iface in IFACES.values():
        name_lower = iface.name.lower()
        if "wi-fi" in name_lower or "wifi" in name_lower or "wireless" in name_lower:
            active_iface = iface
            break

    if not active_iface:
        active_iface = get_working_if()

    print(f"[*] Aggregating features on interface: {active_iface.name}")
    print(f"[*] Feature window size: {WINDOW_SIZE_SECONDS} seconds. Generating traffic...")
    print("[*] Press Ctrl+C to stop.\n")

    extractor = WindowedFeatureExtractor(window_size=WINDOW_SIZE_SECONDS)

    try:
        sniff(iface=active_iface, prn=extractor.process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Feature extractor stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Extraction error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()