import os
import sys
import importlib
from collections import defaultdict, deque

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    ARP,
    IPv6,
    DNS,
    DNSQR
)

import joblib
import pandas as pd
import time
import csv
from datetime import datetime
from ml.dns_tunneling import analyze_dns_query
from ml.c2_detector import analyze_c2_traffic
from ml.exfiltration_detector import analyze_data_exfiltration
from ml.risk_engine import calculate_risk

psutil = importlib.import_module("psutil")

# ============================================================
# REAL-TIME IDS CONFIGURATION
# ============================================================

MODEL_PATH = os.path.join(BASE_DIR, "models", "live_ids_model.pkl")

ENCODER_PATH = os.path.join(BASE_DIR, "models", "protocol_encoder.pkl")

THRESHOLD_PATH = os.path.join(BASE_DIR, "models", "attack_threshold.pkl")


# Existing project data file.
# IMPORTANT:
# We APPEND to this file.
# We do NOT delete or recreate it.
PREDICTIONS_FILE = os.path.join(BASE_DIR, "data", "live_predictions.csv")

# Separate runtime telemetry keeps the historical prediction CSV compatible.
LATENCY_FILE = os.path.join(BASE_DIR, "data", "live_latency.csv")

RUNTIME_FILE = os.path.join(BASE_DIR, "data", "live_runtime.csv")


# Control file used by Flask to request STOP.
CONTROL_FILE = os.path.join(BASE_DIR, "data", "ids_control.txt")


# Your active Wi-Fi adapter
NETWORK_INTERFACE = (
    r"\Device\NPF_{CD7D0A57-6716-4956-9A9C-405992C00BE1}"
)


# Flow timeout in seconds
FLOW_TIMEOUT = 5

# NSL-KDD `count` is the number of recent connections to the same
# destination host within a two-second context window.
CONNECTION_CONTEXT_WINDOW = 2.0


# How often completed flows are checked
PREDICTION_INTERVAL = 1


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(
    MODEL_PATH
)
model.n_jobs = 1

encoder = joblib.load(
    ENCODER_PATH
)

attack_threshold = joblib.load(
    THRESHOLD_PATH
)


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}

connection_context = defaultdict(deque)


# ============================================================
# RUNTIME STATISTICS
# ============================================================

packet_count = 0

flow_count = 0

normal_count = 0

attack_count = 0

runtime_process = psutil.Process(os.getpid())
session_started_at = None
last_runtime_sample_at = None
last_runtime_packet_count = 0


# ============================================================
# SCANNER STATE
# ============================================================

scanner_running = True


def get_connection_context_count(destination_ip, timestamp):
    """Return the NSL-KDD-style recent connection count for a destination."""
    history = connection_context[destination_ip]
    cutoff = timestamp - CONNECTION_CONTEXT_WINDOW
    while history and history[0] < cutoff:
        history.popleft()
    history.append(timestamp)
    return len(history)


# ============================================================
# PROTOCOL IDENTIFICATION
# ============================================================

def get_protocol(packet):

    # --------------------------------------------------------
    # ARP
    # --------------------------------------------------------

    if packet.haslayer(ARP):

        return "arp"


    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    if packet.haslayer(IPv6):

        if packet.haslayer(TCP):

            return get_tcp_protocol(
                packet
            )


        if packet.haslayer(UDP):

            return get_udp_protocol(
                packet
            )


        return "ipv6"


    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    if packet.haslayer(ICMP):

        return "icmp"


    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        return get_tcp_protocol(
            packet
        )


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if packet.haslayer(UDP):

        return get_udp_protocol(
            packet
        )


    return "other"


# ============================================================
# TCP PROTOCOL IDENTIFICATION
# ============================================================

def get_tcp_protocol(packet):

    src_port = packet[TCP].sport

    dst_port = packet[TCP].dport

    ports = {
        src_port,
        dst_port
    }


    if 80 in ports:

        return "http"


    if 443 in ports:

        return "https"


    if 22 in ports:

        return "ssh"


    if 21 in ports:

        return "ftp"


    if 20 in ports:

        return "ftp-data"


    if 25 in ports or 587 in ports:

        return "smtp"


    if 110 in ports:

        return "pop3"


    if 143 in ports:

        return "imap"


    if 993 in ports:

        return "imaps"


    if 995 in ports:

        return "pop3s"


    if 23 in ports:

        return "telnet"


    if 445 in ports:

        return "smb"


    if 139 in ports:

        return "netbios"


    if 3389 in ports:

        return "rdp"


    if 3306 in ports:

        return "mysql"


    if 5432 in ports:

        return "postgresql"


    return "tcp"


# ============================================================
# UDP PROTOCOL IDENTIFICATION
# ============================================================

def get_udp_protocol(packet):

    src_port = packet[UDP].sport

    dst_port = packet[UDP].dport

    ports = {
        src_port,
        dst_port
    }


    if 53 in ports:

        return "dns"


    if 67 in ports or 68 in ports:

        return "dhcp"


    if 123 in ports:

        return "ntp"


    if 161 in ports or 162 in ports:

        return "snmp"


    if 500 in ports or 4500 in ports:

        return "ipsec"


    if 443 in ports:

        return "quic_or_udp443"


    return "udp"


# ============================================================
# DISPLAY PROTOCOL -> ML PROTOCOL
#
# The ML model was trained with only:
#
# icmp
# tcp
# udp
#
# Therefore the detailed protocol is preserved for display,
# while the model receives the correct broad protocol category.
# ============================================================

def get_ml_protocol(protocol):

    if protocol in {
        "icmp",
        "icmpv6"
    }:

        return "icmp"


    if protocol in {
        "tcp",
        "http",
        "https",
        "ssh",
        "ftp",
        "ftp-data",
        "smtp",
        "pop3",
        "imap",
        "imaps",
        "pop3s",
        "telnet",
        "smb",
        "netbios",
        "rdp",
        "mysql",
        "postgresql"
    }:

        return "tcp"


    if protocol in {
        "udp",
        "dns",
        "dhcp",
        "ntp",
        "snmp",
        "ipsec",
        "quic_or_udp443"
    }:

        return "udp"


    return None


# ============================================================
# FLOW KEY
# ============================================================

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


    endpoint1 = (
        src_ip,
        src_port
    )


    endpoint2 = (
        dst_ip,
        dst_port
    )


    if endpoint1 <= endpoint2:

        return (
            endpoint1,
            endpoint2,
            protocol
        )


    return (
        endpoint2,
        endpoint1,
        protocol
    )


# ============================================================
# PROCESS PACKET
# ============================================================

def process_packet(packet):

    global packet_count


    if not packet.haslayer(IP):

        return


    key = get_flow_key(
        packet
    )


    if key is None:

        return


    now = time.time()


    packet_count += 1


    # --------------------------------------------------------
    # CREATE FLOW
    # --------------------------------------------------------

    if key not in flows:

        if packet.haslayer(TCP):

            src_port = packet[TCP].sport

            dst_port = packet[TCP].dport


        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport

            dst_port = packet[UDP].dport


        else:

            src_port = 0

            dst_port = 0


        flows[key] = {

            "src_ip":
                packet[IP].src,

            "src_port":
                src_port,

            "dst_ip":
                packet[IP].dst,

            "dst_port":
                dst_port,

            "protocol":
                get_protocol(packet),

            "start_time":
                now,

            "last_time":
                now,

            "packet_count":
                0,

            "connection_count":
                get_connection_context_count(packet[IP].dst, now),

            "src_bytes":
                0,

            "dst_bytes":
                0

        }


    flow = flows[key]


    flow["last_time"] = now


    flow["packet_count"] += 1


    packet_size = len(packet)


    # --------------------------------------------------------
    # SOURCE / DESTINATION BYTES
    # --------------------------------------------------------

    if (

        packet[IP].src ==
        flow["src_ip"]

        and

        packet[IP].dst ==
        flow["dst_ip"]

    ):

        flow["src_bytes"] += packet_size

    else:

        flow["dst_bytes"] += packet_size

    # --------------------------------------------------------
    # DNS TUNNELING CHECK (Problem 2)
    # --------------------------------------------------------
    if packet.haslayer(DNSQR):
        try:
            raw_qname = packet[DNSQR].qname
            if isinstance(raw_qname, bytes):
                qname_str = raw_qname.decode("utf-8", errors="ignore")
            else:
                qname_str = str(raw_qname)
            dns_res = analyze_dns_query(qname_str)
            if dns_res.get("is_tunneling"):
                flow["dns_analysis"] = dns_res
        except Exception:
            pass


# ============================================================
# SAVE PREDICTION
# ============================================================

def save_prediction(
    flow,
    prediction,
    confidence,
    attack_probability,
    duration,
    threat_type="NORMAL",
    severity="LOW",
    risk_score=0.0
):

    global flow_count
    global normal_count
    global attack_count

    os.makedirs(
        "data",
        exist_ok=True
    )

    file_exists = os.path.exists(
        PREDICTIONS_FILE
    )

    with open(
        PREDICTIONS_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(
            file
        )

        if (
            not file_exists
            or os.path.getsize(PREDICTIONS_FILE) == 0
        ):
            writer.writerow([
                "time",
                "source",
                "destination",
                "protocol",
                "duration",
                "src_bytes",
                "dst_bytes",
                "packet_count",
                "prediction",
                "confidence",
                "attack_probability",
                "threat_type",
                "severity",
                "risk_score"
            ])

        writer.writerow([
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            (
                f'{flow["src_ip"]}:'
                f'{flow["src_port"]}'
            ),
            (
                f'{flow["dst_ip"]}:'
                f'{flow["dst_port"]}'
            ),
            flow["protocol"],
            round(
                duration,
                4
            ),
            flow["src_bytes"],
            flow["dst_bytes"],
            flow["packet_count"],
            prediction,
            round(
                confidence,
                2
            ),
            round(
                attack_probability * 100,
                2
            ),
            threat_type,
            severity,
            round(
                risk_score,
                2
            )
        ])

    flow_count += 1

    if prediction == "ATTACK":
        attack_count += 1
    else:
        normal_count += 1


def record_latency(flow, prediction_started, alert_finished):
    """Persist flow-to-alert and processing latency for runtime evaluation."""
    os.makedirs(os.path.dirname(LATENCY_FILE), exist_ok=True)
    file_exists = os.path.exists(LATENCY_FILE)
    processing_ms = (alert_finished - prediction_started) * 1000
    capture_to_alert_ms = (time.time() - flow["last_time"]) * 1000

    with open(LATENCY_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists or os.path.getsize(LATENCY_FILE) == 0:
            writer.writerow([
                "time",
                "source",
                "destination",
                "capture_to_alert_ms",
                "prediction_processing_ms"
            ])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            f'{flow["src_ip"]}:{flow["src_port"]}',
            f'{flow["dst_ip"]}:{flow["dst_port"]}',
            round(capture_to_alert_ms, 3),
            round(processing_ms, 3)
        ])


def record_runtime_sample(sample_time=None):
    """Persist resource and throughput telemetry for the active capture session."""
    global last_runtime_sample_at
    global last_runtime_packet_count

    sample_time = sample_time or time.time()
    if last_runtime_sample_at is None:
        last_runtime_sample_at = sample_time
        last_runtime_packet_count = packet_count
        runtime_process.cpu_percent(interval=None)
        return

    interval = max(sample_time - last_runtime_sample_at, 0.001)
    packet_rate = (packet_count - last_runtime_packet_count) / interval
    file_exists = os.path.exists(RUNTIME_FILE)
    os.makedirs(os.path.dirname(RUNTIME_FILE), exist_ok=True)

    with open(RUNTIME_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists or os.path.getsize(RUNTIME_FILE) == 0:
            writer.writerow([
                "time", "session_elapsed_seconds", "packets_seen", "flows_predicted",
                "packets_per_second", "cpu_percent", "rss_mb"
            ])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            round(sample_time - (session_started_at or sample_time), 3),
            packet_count,
            flow_count,
            round(packet_rate, 3),
            round(runtime_process.cpu_percent(interval=None), 3),
            round(runtime_process.memory_info().rss / (1024 * 1024), 3)
        ])

    last_runtime_sample_at = sample_time
    last_runtime_packet_count = packet_count


# ============================================================
# PREDICT COMPLETED FLOWS
# ============================================================

def predict_completed_flows(
    force=False
):

    global flows


    now = time.time()


    completed = []


    for key, flow in list(
        flows.items()
    ):


        # ----------------------------------------------------
        # Normal mode:
        # wait until flow timeout.
        #
        # Stop mode:
        # force all remaining flows to prediction.
        # ----------------------------------------------------

        if (

            not force

            and

            (
                now -
                flow["last_time"]
            ) < FLOW_TIMEOUT

        ):

            continue


        duration = (

            flow["last_time"]

            -

            flow["start_time"]

        )


        if duration <= 0:

            duration = 0.0001

        prediction_started = time.perf_counter()


        # ----------------------------------------------------
        # Convert display protocol to ML protocol
        # ----------------------------------------------------

        ml_protocol = get_ml_protocol(
                flow["protocol"]
            )


        if ml_protocol is None:

            print(
                "\nSkipping unsupported "
                "ML protocol:",
                flow["protocol"]
            )

            completed.append(
                key
            )

            continue


        # ----------------------------------------------------
        # Encode protocol
        # ----------------------------------------------------

        try:

            protocol_encoded = (
                encoder.transform(
                    [ml_protocol]
                )[0]
            )


        except ValueError:

            print(
                "\nSkipping protocol not "
                "known by model:",
                ml_protocol
            )

            completed.append(
                key
            )

            continue


        # ----------------------------------------------------
        # FEATURES
        # ----------------------------------------------------

        features = pd.DataFrame([{

            "duration":
                duration,

            "protocol_type":
                protocol_encoded,

            "src_bytes":
                flow["src_bytes"],

            "dst_bytes":
                flow["dst_bytes"],

            "count":
                flow["connection_count"]

        }])


        # ----------------------------------------------------
        # MODEL PREDICTION
        # ----------------------------------------------------

        probabilities = (
            model.predict_proba(
                features
            )[0]
        )


        attack_probability = (
            probabilities[1]
        )
        

        # ----------------------------------------------------
        # THRESHOLD
        # ----------------------------------------------------

        if (

            attack_probability >=
            attack_threshold

        ):

            result = "ATTACK"


        else:

            result = "NORMAL"


        # --------------------------------------------------------
        # CONFIDENCE
        # --------------------------------------------------------

        if result == "ATTACK":

            confidence = (
                attack_probability *
                100
            )

        else:

            confidence = (
                probabilities[0] *
                100
            )


        # ========================================================
        # SPECIALIZED DETECTORS & RISK ENGINE (Problems 1, 2, 5, 7)
        # ========================================================
        c2_res = analyze_c2_traffic(
            src_ip=flow["src_ip"],
            dst_ip=flow["dst_ip"],
            dst_port=flow["dst_port"],
            src_bytes=flow["src_bytes"],
            dst_bytes=flow["dst_bytes"]
        )

        exfil_res = analyze_data_exfiltration(
            src_ip=flow["src_ip"],
            dst_ip=flow["dst_ip"],
            src_bytes=flow["src_bytes"],
            dst_bytes=flow["dst_bytes"],
            duration=duration
        )

        risk_result = calculate_risk(
            source_ip=flow["src_ip"],
            attack_probability=attack_probability * 100,
            packet_count=flow["packet_count"],
            src_bytes=flow["src_bytes"],
            dst_bytes=flow["dst_bytes"],
            duration=duration,
            dns_analysis=flow.get("dns_analysis"),
            c2_analysis=c2_res,
            exfil_analysis=exfil_res
        )

        risk_score = risk_result["risk_score"]
        risk_severity = risk_result["severity"]
        threat_type = risk_result["threat_type"]
        result = risk_result["prediction"]
        suspicious_observations = risk_result["suspicious_observations"]

        # Keep confidence semantically consistent: it is always the model's
        # probability for the selected class. Risk score is logged separately.
        confidence = (
            attack_probability * 100
            if result == "ATTACK"
            else probabilities[0] * 100
        )

        print("Threat Type:", threat_type)
        print("Risk score:", risk_score)
        print("Risk severity:", risk_severity)
        print("Suspicious observations:", suspicious_observations)

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------
        save_prediction(
            flow=flow,
            prediction=result,
            confidence=confidence,
            attack_probability=attack_probability,
            duration=duration,
            threat_type=threat_type,
            severity=risk_severity,
            risk_score=risk_score
        )

        record_latency(
            flow=flow,
            prediction_started=prediction_started,
            alert_finished=time.perf_counter()
        )


        # ----------------------------------------------------
        # CONSOLE OUTPUT
        # ----------------------------------------------------

        print(
            "\n===================================="
        )

        print(
            "       REAL-TIME IDS PREDICTION"
        )

        print(
            "===================================="
        )

        print(
            "Source:",
            flow["src_ip"],
            flow["src_port"]
        )

        print(
            "Destination:",
            flow["dst_ip"],
            flow["dst_port"]
        )

        print(
            "Protocol:",
            flow["protocol"]
        )

        print(
            "ML Protocol:",
            ml_protocol
        )

        print(
            "Duration:",
            round(
                duration,
                4
            )
        )

        print(
            "Source bytes:",
            flow["src_bytes"]
        )

        print(
            "Destination bytes:",
            flow["dst_bytes"]
        )

        print(
            "Packet count:",
            flow["packet_count"]
        )

        print(
            "------------------------------------"
        )

        print(
            "Attack probability:",
            round(
                attack_probability * 100,
                2
            ),
            "%"
        )

        print(
            "Threshold:",
            attack_threshold
        )

        print(
            "Prediction:",
            result
        )

        print(
            "Confidence:",
            round(
                confidence,
                2
            ),
            "%"
        )

        print(
            "Saved to:",
            PREDICTIONS_FILE
        )

        print(
            "===================================="
        )


        completed.append(
            key
        )


    # --------------------------------------------------------
    # Remove completed flows
    # --------------------------------------------------------

    for key in completed:

        if key in flows:

            del flows[key]


# ============================================================
# CONTROL FILE
# ============================================================

def write_control_state(
    state
):

    os.makedirs(
        "data",
        exist_ok=True
    )


    with open(
        CONTROL_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            state
        )


# ============================================================
# CHECK STOP REQUEST
# ============================================================

def stop_requested():

    if not os.path.exists(
        CONTROL_FILE
    ):

        return False


    try:

        with open(
            CONTROL_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            state = (
                file.read()
                .strip()
                .upper()
            )


        return state == "STOP"


    except Exception:

        return False


# ============================================================
# CLEAR STOP REQUEST
# ============================================================

def clear_stop_request():

    if os.path.exists(
        CONTROL_FILE
    ):

        try:

            os.remove(
                CONTROL_FILE
            )

        except Exception:

            pass


# ============================================================
# PRINT STATISTICS
# ============================================================

def print_statistics():

    print(
        "\n===================================="
    )

    print(
        "        IDS SCANNING STOPPED"
    )

    print(
        "===================================="
    )

    print(
        "Packets:",
        packet_count
    )

    print(
        "Flows:",
        flow_count
    )

    print(
        "Normal:",
        normal_count
    )

    print(
        "Attacks:",
        attack_count
    )

    print(
        "Prediction file:",
        PREDICTIONS_FILE
    )

    print(
        "===================================="
    )


# ============================================================
# FINALIZE SCANNER
# ============================================================

def finalize_scanner():

    global scanner_running


    scanner_running = False


    print(
        "\nFinalizing remaining flows..."
    )


    # --------------------------------------------------------
    # Predict ALL flows that are still active.
    # This is important because stopping the scanner should
    # not lose packets/flows that were being tracked.
    # --------------------------------------------------------

    predict_completed_flows(
        force=True
    )


    print_statistics()


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(
    packet
):

    global scanner_running


    # --------------------------------------------------------
    # Check for dashboard STOP request.
    # --------------------------------------------------------

    if stop_requested():

        scanner_running = False

        return


    process_packet(
        packet
    )


# ============================================================
# MAIN
# ============================================================

def main():

    global scanner_running
    global session_started_at
    global last_runtime_sample_at
    global last_runtime_packet_count


    print(
        "===================================="
    )

    print(
        "       REAL-TIME ML INTRUSION"
    )

    print(
        "          DETECTION SYSTEM"
    )

    print(
        "===================================="
    )


    print(
        "Model:",
        MODEL_PATH
    )


    print(
        "Attack threshold:",
        attack_threshold
    )


    print(
        "ML protocols:",
        list(
            encoder.classes_
        )
    )


    print(
        "Network interface:",
        NETWORK_INTERFACE
    )


    print(
        "Prediction log:",
        PREDICTIONS_FILE
    )


    # --------------------------------------------------------
    # Remove an old STOP command before starting.
    # --------------------------------------------------------

    clear_stop_request()


    scanner_running = True
    connection_context.clear()
    session_started_at = time.time()
    last_runtime_sample_at = None
    last_runtime_packet_count = packet_count
    runtime_process.cpu_percent(interval=None)


    print(
        "\n===================================="
    )

    print(
        "        IDS SCANNING STARTED"
    )

    print(
        "===================================="
    )

    print(
        "Listening for network traffic..."
    )

    print(
        "Press CTRL+C to stop."
    )

    print(
        "====================================\n"
    )


    last_check = time.time()


    try:

        # ----------------------------------------------------
        # Use short sniff intervals.
        #
        # This is important on Windows because it allows the
        # scanner to notice the STOP control without using
        # SIGINT through subprocess.send_signal().
        # ----------------------------------------------------

        while scanner_running:

            sniff(

                iface=NETWORK_INTERFACE,

                prn=packet_callback,

                store=False,

                timeout=1

            )

            record_runtime_sample()


            # ------------------------------------------------
            # Check STOP request after each sniff interval.
            # ------------------------------------------------

            if stop_requested():

                scanner_running = False

                break


            # ------------------------------------------------
            # Predict flows that reached timeout.
            # ------------------------------------------------

            if (

                time.time() -
                last_check

            ) >= PREDICTION_INTERVAL:

                predict_completed_flows()

                last_check = time.time()


    except KeyboardInterrupt:

        print(
            "\nCTRL+C received."
        )


    except Exception as error:

        print(
            "\nScanner error:",
            error
        )


    finally:

        finalize_scanner()

        record_runtime_sample()

        clear_stop_request()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()