from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
import time
import csv
import os
import joblib


# Load the protocol encoder used during training
encoder = joblib.load("models/protocol_encoder.pkl")

flows = {}
connection_context = defaultdict(deque)

FLOW_TIMEOUT = 10
CONNECTION_CONTEXT_WINDOW = 2.0

OUTPUT_FILE = "data/live_flows.csv"


def get_connection_context_count(destination_ip, timestamp):
    history = connection_context[destination_ip]
    cutoff = timestamp - CONNECTION_CONTEXT_WINDOW
    while history and history[0] < cutoff:
        history.popleft()
    history.append(timestamp)
    return len(history)


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

    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    if endpoint1 <= endpoint2:
        return endpoint1, endpoint2, protocol

    return endpoint2, endpoint1, protocol


def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "tcp"

    if packet.haslayer(UDP):
        return "udp"

    return "other"


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    key = get_flow_key(packet)

    if key is None:
        return

    now = time.time()

    if key not in flows:

        endpoint1, endpoint2, protocol = key

        flows[key] = {
            "src_ip": endpoint1[0],
            "src_port": endpoint1[1],
            "dst_ip": endpoint2[0],
            "dst_port": endpoint2[1],
            "protocol": get_protocol_name(packet),
            "start_time": now,
            "last_time": now,
            "packet_count": 0,
            "connection_count": get_connection_context_count(packet[IP].dst, now),
            "src_bytes": 0,
            "dst_bytes": 0,
            "total_bytes": 0
        }

    flow = flows[key]

    flow["last_time"] = now
    flow["packet_count"] += 1

    packet_size = len(packet)

    # Determine direction relative to the flow's first endpoint
    if packet.haslayer(IP):

        if (
            packet[IP].src == flow["src_ip"]
            and packet[IP].dst == flow["dst_ip"]
        ):
            flow["src_bytes"] += packet_size

        else:
            flow["dst_bytes"] += packet_size

    flow["total_bytes"] += packet_size


def save_completed_flows():

    now = time.time()

    completed = []

    for key, flow in flows.items():

        if now - flow["last_time"] >= FLOW_TIMEOUT:

            duration = flow["last_time"] - flow["start_time"]

            # Avoid zero duration
            if duration <= 0:
                duration = 0.0001

            # Convert protocol name to the same numeric encoding
            try:
                protocol_encoded = encoder.transform(
                    [flow["protocol"]]
                )[0]

            except ValueError:

                # Unknown protocol
                protocol_encoded = 0

            # NSL-KDD-compatible live features
            features = [
                duration,
                protocol_encoded,
                flow["src_bytes"],
                flow["dst_bytes"],
                flow["connection_count"]
            ]

            print("\n====================================")
            print("       LIVE FLOW FEATURES")
            print("====================================")

            print("Source:", flow["src_ip"], flow["src_port"])
            print("Destination:", flow["dst_ip"], flow["dst_port"])
            print("Protocol:", flow["protocol"])

            print("Duration:", round(duration, 4))
            print("Protocol encoded:", protocol_encoded)
            print("Source bytes:", flow["src_bytes"])
            print("Destination bytes:", flow["dst_bytes"])
            print("Packet count:", flow["packet_count"])

            with open(
                OUTPUT_FILE,
                "a",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow(features)

            completed.append(key)

    for key in completed:
        del flows[key]


def main():

    os.makedirs("data", exist_ok=True)

    # Create CSV with headers
    if not os.path.exists(OUTPUT_FILE):

        with open(
            OUTPUT_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "duration",
                "protocol_type",
                "src_bytes",
                "dst_bytes",
                "count"
            ])

    print("====================================")
    print("     LIVE IDS FEATURE EXTRACTOR")
    print("====================================")
    print("Capturing real network traffic...")
    print("Model-compatible features:")
    print("duration, protocol_type, src_bytes, dst_bytes, count")
    print("\nPress CTRL+C to stop.\n")

    last_check = time.time()

    def callback(packet):

        nonlocal last_check

        process_packet(packet)

        if time.time() - last_check >= 1:

            save_completed_flows()

            last_check = time.time()

    sniff(
        prn=callback,
        store=False
    )


if __name__ == "__main__":
    main()