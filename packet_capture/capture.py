from scapy.all import sniff
from datetime import datetime


def process_packet(packet):
    print("\n==============================")
    print("REAL-TIME PACKET DETECTED")
    print("==============================")

    print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if packet.haslayer("IP"):
        print("Source IP:", packet["IP"].src)
        print("Destination IP:", packet["IP"].dst)
        print("Protocol:", packet["IP"].proto)
        print("Packet Size:", len(packet))

    if packet.haslayer("TCP"):
        print("Source Port:", packet["TCP"].sport)
        print("Destination Port:", packet["TCP"].dport)

    elif packet.haslayer("UDP"):
        print("Source Port:", packet["UDP"].sport)
        print("Destination Port:", packet["UDP"].dport)


print("====================================")
print("   REAL-TIME IDS PACKET CAPTURE")
print("====================================")
print("Listening for network packets...")
print("Press CTRL+C to stop.\n")

sniff(
    prn=process_packet,
    store=False
)