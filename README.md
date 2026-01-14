# 🛡️ Advanced Network Packet Sniffer

A professional-grade, modular, and extensible Python-based network packet sniffer. This tool captures, analyzes, and logs real-time network traffic with detailed insights into packet-level data. Built using Scapy and designed for ethical hacking, cybersecurity training, and network diagnostics.

---

## ✨ Features

- 🎯 **Real-time Packet Capturing**  
  Monitor live incoming and outgoing traffic with detailed insights.

- 🔎 **Protocol Filtering**  
  Filter packets by TCP, UDP, ICMP, ARP, HTTP, DNS, and more.

- 📊 **Traffic Statistics**  
  Live counters for packet count, data size, protocols, and session tracking.

- 🛠️ **Modular & Extensible Architecture**  
  Plug-and-play design for future protocol parsers or detection modules.

- 💾 **Packet Export**  
  Save captured packets to `.pcap` format for offline analysis.

- 🧪 **Deep Packet Inspection**  
  Extract payloads, headers, and flags from Layer 2–4.

- 🔐 **Security-Oriented Add-ons**  
  - Packet anomaly detection  
  - Suspicious payload flagging  
  - MAC/IP spoofing detection  
  - ARP poisoning alerts

- 🌈 **Rich Terminal UI**  
  Styled with `rich` and `tabulate` for easy visualization.

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.7 or higher
- Admin/root privileges for interface access (Linux recommended)

### Install Dependencies

Clone the repository and install required packages:

```bash
git clone https://github.com/AyanMasih/Advanced-Network-Packet-Sniffer.git
cd advanced-packet-sniffer
python sniffer.py
