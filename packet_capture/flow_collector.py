from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import time


flows = {}

FLOW_TIMEOUT = 10


def get_flow_key(packet):
    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        src_port = 0
        dst_port = 0

    # Treat both directions as one flow
    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    if endpoint1 <= endpoint2:
        return (endpoint1, endpoint2, protocol)
    else:
        return (endpoint2, endpoint1, protocol)


def process_packet(packet):
    if not packet.haslayer(IP):
        return

    key = get_flow_key(packet)

    if key is None:
        return

    current_time = time.time()
    packet_size = len(packet)

    if key not in flows:
        flows[key] = {
            "start_time": current_time,
            "last_time": current_time,
            "packet_count": 0,
            "total_bytes": 0
        }

    flow = flows[key]

    flow["last_time"] = current_time
    flow["packet_count"] += 1
    flow["total_bytes"] += packet_size


def print_completed_flows():
    current_time = time.time()

    completed = []

    for key, flow in flows.items():

        if current_time - flow["last_time"] >= FLOW_TIMEOUT:

            endpoint1, endpoint2, protocol = key

            duration = flow["last_time"] - flow["start_time"]

            print("\n====================================")
            print("          COMPLETED FLOW")
            print("====================================")

            print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            print("Endpoint 1:", endpoint1[0], "Port:", endpoint1[1])
            print("Endpoint 2:", endpoint2[0], "Port:", endpoint2[1])

            print("Protocol:", protocol)
            print("Duration:", round(duration, 4), "seconds")
            print("Packets:", flow["packet_count"])
            print("Total Bytes:", flow["total_bytes"])

            if duration > 0:
                print(
                    "Bytes/sec:",
                    round(flow["total_bytes"] / duration, 2)
                )

            completed.append(key)

    for key in completed:
        del flows[key]


def main():

    print("====================================")
    print("      REAL-TIME FLOW COLLECTOR")
    print("====================================")
    print("Collecting network flows...")
    print("Flow timeout:", FLOW_TIMEOUT, "seconds")
    print("Press CTRL+C to stop.\n")

    last_check = time.time()

    def packet_callback(packet):
        nonlocal last_check

        process_packet(packet)

        if time.time() - last_check >= 1:
            print_completed_flows()
            last_check = time.time()

    sniff(
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":
    main()