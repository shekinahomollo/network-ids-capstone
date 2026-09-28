import sys
from scapy.all import sniff, IP, TCP, UDP, get_working_if, IFACES

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)
        protocol = "OTHER"
        src_port, dst_port = "-", "-"
        tcp_flags = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = f" [{packet[TCP].flags}]"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(f"[{protocol:<5}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {pkt_len} bytes{tcp_flags}")

def main():
    print("=" * 60)
    print("      Capstone IDS Packet Sniffer - Windows Prototype      ")
    print("=" * 60)

    # Search for active Wi-Fi / Wireless interface
    active_iface = None
    for iface in IFACES.values():
        name_lower = iface.name.lower()
        if "wi-fi" in name_lower or "wifi" in name_lower or "wireless" in name_lower:
            active_iface = iface
            break

    if not active_iface:
        active_iface = get_working_if()

    print(f"[*] Capturing on interface: {active_iface.name}")
    print("[*] Starting live packet capture. Generate traffic (e.g., browse web).")
    print("[*] Press Ctrl+C to stop sniffing.\n")

    try:
        sniff(iface=active_iface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Sniffing error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()