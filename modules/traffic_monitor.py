from scapy.all import *
from collections import defaultdict
import time
import json

# Seuil pour détecter une attaque DDoS (paquets/seconde)
DDOS_THRESHOLD = 1000

def packet_handler(packet, ip_packet_counts):
    """Gère chaque paquet capturé."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_packet_counts[src_ip] += 1

def run(target, **kwargs):
    """Surveille le trafic réseau en temps réel."""
    config = kwargs.get("config", {})
    timeout = config.get("monitor_timeout", 60)  # Durée de la surveillance (secondes)
    ip_packet_counts = defaultdict(int)

    print(f"[*] Surveillance du trafic pendant {timeout} secondes... (Ctrl+C pour arrêter)")
    start_time = time.time()

    try:
        while time.time() - start_time < timeout:
            sniff(prn=lambda pkt: packet_handler(pkt, ip_packet_counts), timeout=1, store=0)
    except KeyboardInterrupt:
        pass

    results = {
        "target": target,
        "traffic_analysis": [],
        "ddos_detected": False
    }

    for ip, count in ip_packet_counts.items():
        if count > DDOS_THRESHOLD:
            results["ddos_detected"] = True
            results["traffic_analysis"].append({
                "ip": ip,
                "packets": count,
                "status": "DDoS suspecté"
            })
        else:
            results["traffic_analysis"].append({
                "ip": ip,
                "packets": count,
                "status": "Normal"
            })

    return results
