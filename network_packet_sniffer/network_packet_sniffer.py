# network_packet_sniffer.py
import scapy.all as scapy
from datetime import datetime
import sqlite3
import os
import sys

DB_NAME = "packet_logs.db"
THRESHOLD = 100  # packets per IP per run to flag as suspicious
DEFAULT_IFACE = "wlan0"  # change this to your active interface like "eth0", "lo", etc.

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
                        timestamp TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT,
                        length INTEGER
                    )''')
    conn.commit()
    conn.close()

# Insert packet data into DB
def log_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        proto = packet.lastlayer().name
        length = len(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?)",
                       (timestamp, ip_layer.src, ip_layer.dst, proto, length))
        conn.commit()
        conn.close()

        print(f"[{timestamp}] {ip_layer.src} -> {ip_layer.dst} | {proto} | {length} bytes")

# Analyze for anomalies (basic flood detection)
def analyze_packets():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT src_ip, COUNT(*) FROM packets GROUP BY src_ip")
    rows = cursor.fetchall()
    conn.close()

    print("\n[!] Anomaly Report:")
    for ip, count in rows:
        if count > THRESHOLD:
            print(f"[!] High packet count from {ip}: {count} packets (Possible Flooding or Scan)")

# Main sniffing loop
def start_sniffing(iface):
    print(f"[*] Starting packet sniffing on interface '{iface}'... Press CTRL+C to stop.\n")
    try:
        scapy.sniff(prn=log_packet, store=False, iface=iface)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")
        analyze_packets()
    except Exception as e:
        print(f"[!] Failed to start sniffing: {e}")

if __name__ == "__main__":
    iface = DEFAULT_IFACE
    if len(sys.argv) > 1:
        iface = sys.argv[1]

    init_db()
    start_sniffing(iface)
