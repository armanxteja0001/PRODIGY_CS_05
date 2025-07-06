# packet_sniffer.py

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ""
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"
        
        print(f"\n[+] Packet Captured:")
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {protocol}")
        print(f"Payload        : {bytes(packet.payload)}")

# Start sniffing
print("Starting packet capture... Press CTRL+C to stop.")
sniff(prn=packet_callback, count=10)
