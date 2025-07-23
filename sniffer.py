import os
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Create logs directory if not exists
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
log_filename = datetime.now().strftime("packet_log_%Y%m%d_%H%M%S.log")
log_path = os.path.join(LOG_DIR, log_filename)

logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def process_packet(packet):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            info = f"[IP] {ip_src} -> {ip_dst} | Protocol: {protocol}"

            if TCP in packet:
                info = f"[TCP] {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}"
            elif UDP in packet:
                info = f"[UDP] {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}"
            elif ICMP in packet:
                info = f"[ICMP] {ip_src} -> {ip_dst} | Type: {packet[ICMP].type}"

            if Raw in packet:
                raw_data = packet[Raw].load[:50]  # Limit output
                info += f" | Raw: {raw_data}"

            print(info)
            logging.info(info)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def main():
    print("🔍 Starting Advanced Network Packet Sniffer...")
    print("📦 Logging packets to:", log_path)
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Stopping Sniffer...")
    except Exception as e:
        logging.error(f"Sniffer crashed: {e}")
        print("❌ Error:", e)

if __name__ == "__main__":
    main()
