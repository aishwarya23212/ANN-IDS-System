from scapy.all import sniff, IP, ICMP
import time
from datetime import datetime

icmp_times = []
attack_active = False

def packet_callback(packet):
    global attack_active
    if ICMP in packet and IP in packet:
        now = time.time()
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        # Store timestamp and keep only last 2 seconds
        icmp_times.append(now)
        icmp_times[:] = [t for t in icmp_times if now - t <= 2]
        rate = len(icmp_times)

        # Detect attack: rate > 30 OR packet size > 1000
        if rate > 30 or size > 1000:
            if not attack_active:
                attack_active = True
                print("\n" + "=" * 70)
                print(f" ICMP FLOOD ATTACK detected at {datetime.now().strftime('%H:%M:%S')}")
                print("=" * 70)
                print(f"   Source IP:      {src}")
                print(f"   Destination IP: {dst}")
                print(f"   Packet rate:    {rate} packets/sec")
                print(f"   Packet size:    {size} bytes")
                print("=" * 70)
        else:
            if attack_active:
                attack_active = False
                print(f"\n Attack stopped at {datetime.now().strftime('%H:%M:%S')}\n")

print("=" * 70)
print("ICMP FLOOD DETECTOR (Rule‑Based, Always Works)")
print("=" * 70)
print("Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=0, filter="icmp")