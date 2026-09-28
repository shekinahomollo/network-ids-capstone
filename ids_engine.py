import sys
import time
import os
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, get_working_if, IFACES

MODEL_FILE = "ids_isolation_forest.joblib"
SCALER_FILE = "ids_scaler.joblib"
WINDOW_SIZE_SECONDS = 5

class RealTimeIDSEngine:
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.load_artifacts()
        self.reset_window()

    def load_artifacts(self):
        """Loads the pre-trained Isolation Forest model and feature scaler."""
        if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
            print(f"[!] Error: Model files ('{MODEL_FILE}', '{SCALER_FILE}') not found.")
            print("[!] Please run 'python train_model.py' first to generate model weights.")
            sys.exit(1)

        print("[*] Loading trained Isolation Forest model & scaler...")
        self.model = joblib.load(MODEL_FILE)
        self.scaler = joblib.load(SCALER_FILE)
        print("[✓] Model & Scaler successfully loaded.")

    def reset_window(self):
        """Resets counters for the next time window."""
        self.start_time = time.time()
        self.packet_count = 0
        self.total_bytes = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.syn_count = 0
        self.dest_ips = set()
        self.dest_ports = set()

    def process_packet(self, packet):
        """Processes live packet streams and triggers inference per time window."""
        current_time = time.time()

        if packet.haslayer(IP):
            self.packet_count += 1
            self.total_bytes += len(packet)
            self.dest_ips.add(packet[IP].dst)

            if packet.haslayer(TCP):
                self.tcp_count += 1
                self.dest_ports.add(packet[TCP].dport)
                if 'S' in str(packet[TCP].flags):
                    self.syn_count += 1
            elif packet.haslayer(UDP):
                self.udp_count += 1
                self.dest_ports.add(packet[UDP].dport)

        # Trigger model inference when time window completes
        if current_time - self.start_time >= self.window_size:
            self.evaluate_window()
            self.reset_window()

    def evaluate_window(self):
        """Extracts feature vector, runs model prediction, and outputs alert status."""
        elapsed = time.time() - self.start_time
        pkt_rate = round(self.packet_count / elapsed, 2)
        byte_rate = round(self.total_bytes / elapsed, 2)
        avg_pkt_size = round(self.total_bytes / max(1, self.packet_count), 2)
        syn_ratio = round(self.syn_count / max(1, self.tcp_count), 2)
        unique_dst_ips = len(self.dest_ips)
        unique_dst_ports = len(self.dest_ports)

        # Construct feature vector matching model training layout
        feature_names = [
            "pkt_rate", "byte_rate", "avg_pkt_size", "tcp_count",
            "udp_count", "syn_ratio", "unique_dst_ips", "unique_dst_ports"
        ]
        
        raw_features = pd.DataFrame([[
            pkt_rate, byte_rate, avg_pkt_size, self.tcp_count,
            self.udp_count, syn_ratio, unique_dst_ips, unique_dst_ports
        ]], columns=feature_names)

        # Scale features and predict
        scaled_features = self.scaler.transform(raw_features)
        prediction = self.model.predict(scaled_features)[0]  # 1 for normal, -1 for anomaly
        anomaly_score = self.model.decision_function(scaled_features)[0]

        timestamp = time.strftime("%H:%M:%S")

        print("-" * 75)
        if prediction == -1:
            print(f"[{timestamp}] 🚨 [ANOMALY DETECTED] Score: {anomaly_score:.3f}")
            print(f"    Alert Metrics -> Pkt Rate: {pkt_rate} p/s | Byte Rate: {byte_rate} B/s | SYN Ratio: {syn_ratio}")
        else:
            print(f"[{timestamp}] ✅ [NORMAL TRAFFIC]   Score: {anomaly_score:.3f}")
            print(f"    Status Metrics -> Pkt Rate: {pkt_rate} p/s | Byte Rate: {byte_rate} B/s | Unique IPs: {unique_dst_ips}")
        print("-" * 75)

def main():
    print("=" * 75)
    print("      Capstone IDS — Integrated Real-Time Detection Engine     ")
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

    engine = RealTimeIDSEngine(window_size=WINDOW_SIZE_SECONDS)

    print(f"[*] Live IDS monitoring on interface: {active_iface.name}")
    print("[*] Generating network traffic to observe real-time classification...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(iface=active_iface, prn=engine.process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] IDS Engine stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] IDS Execution error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()