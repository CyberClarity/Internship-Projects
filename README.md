# 🚀 Cybersecurity Internship Projects

This repository contains CLI-based implementations of cybersecurity tools developed during the internship phase. These tools are meant for educational and demonstration purposes only.

---

## 📡 1. Network Packet Sniffer with Anomaly Detection

### 📌 Description
A real-time packet sniffer that logs traffic details and flags potential anomalies (like flooding or port scans).

### ⚙️ Technologies Used
- Python
- `scapy`
- `sqlite3`

### 💡 Features
- Captures live packets and logs them to SQLite
- Records IPs, protocols, lengths, and timestamps
- Flags any IP with more than 100 packets per run

### ▶️ How to Run
```bash
sudo python3 network_packet_sniffer.py wlan0
```

> Replace `wlan0` with your actual network interface (use `ip a` to check).

---

## 📁 Repository Structure
```
.
├── WebVuln.py                     # Website Vulnerability Analysis
├── network_packet_sniffer.py      # Packet sniffer with logging
├── README.md                      # Project descriptions and instructions
```

---

## 🔍 2. Web Application Vulnerability Scanner (CLI)

### 📌 Description
A Python-based tool to scan target websites for common vulnerabilities like:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)

### ⚙️ Technologies Used
- Python
- BeautifulSoup
- `requests`
- `re` module

### 💡 Features
- Crawls internal links on a target domain
- Submits malicious payloads via forms and URL params
- Detects potential vulnerabilities using basic pattern matching

### ▶️ How to Run
```bash
python3 web_vuln_scanner_cli.py http://testphp.vulnweb.com
```

> Note: The tool defaults to `http://testphp.vulnweb.com` if no URL is passed.

---

## ⚠️ Disclaimer
These tools are for **educational** and **research** purposes only. Unauthorized scanning or sniffing of networks you do not own or have permission to test is illegal and unethical.

---

## 🧠 Author
Manas Rane  
Cybersecurity Intern
