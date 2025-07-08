# 🛰️ Network Packet Sniffer (CLI)

A simple Python-based network sniffer that captures live packets and detects suspicious activity based on packet volume.

## 🔧 Features
- Captures real-time traffic using `scapy`
- Logs source/destination IPs, protocol, and size
- Stores packet info in SQLite database
- Detects potential flood or scanning behavior

## 🚀 How to Run
```bash
sudo python3 network_packet_sniffer.py wlan0
```
> Replace `wlan0` with your actual network interface (use `ip a` to check)

## 📦 Requirements
- Python 3
- scapy
- sqlite3

## ⚠️ Note
Root privileges (`sudo`) are required to sniff packets.

---
Created by **Manas Rane** | Internship Project
