from collections import defaultdict
import time
import math
import statistics

# ============================================================
# ENCRYPTED C2 BEACONING DETECTOR (Problem 1)
# ============================================================

# Tracks connection history per pair: (src_ip, dst_ip, dst_port)
# Value: list of dicts: {"time": float, "src_bytes": int, "dst_bytes": int}
c2_flow_history = defaultdict(list)

HISTORY_WINDOW_SECONDS = 300  # 5-minute memory window
MIN_BEACON_OBSERVATIONS = 3   # Minimum flows needed to establish periodicity


def cleanup_c2_history():
    """Remove records older than the sliding window."""
    now = time.time()
    for key in list(c2_flow_history.keys()):
        c2_flow_history[key] = [
            record
            for record in c2_flow_history[key]
            if (now - record["time"]) <= HISTORY_WINDOW_SECONDS
        ]
        if not c2_flow_history[key]:
            del c2_flow_history[key]


def analyze_c2_traffic(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    src_bytes: int = 0,
    dst_bytes: int = 0
) -> dict:
    """
    Analyze flow timing and size patterns for covert C2 beaconing:
    - Highly regular intervals (low standard deviation / low jitter)
    - Small, consistent heartbeat payload sizes
    - Works on encrypted traffic (TLS/HTTPS port 443) without payload inspection
    """
    now = time.time()
    key = (src_ip, dst_ip, dst_port)

    cleanup_c2_history()

    c2_flow_history[key].append({
        "time": now,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes
    })

    records = c2_flow_history[key]

    if len(records) < MIN_BEACON_OBSERVATIONS:
        return {
            "is_c2": False,
            "confidence": 0.0,
            "interval_seconds": 0.0,
            "jitter": 0.0,
            "reasons": "Insufficient observations for beacon profiling"
        }

    # Calculate intervals between consecutive flows
    timestamps = [r["time"] for r in records]
    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    # Filter out sub-second micro bursts to focus on beacon periods
    valid_intervals = [dt for dt in intervals if dt >= 1.0]

    if len(valid_intervals) < 2:
        return {
            "is_c2": False,
            "confidence": 0.0,
            "interval_seconds": 0.0,
            "jitter": 0.0,
            "reasons": "Burst traffic, not periodic beaconing"
        }

    mean_interval = statistics.mean(valid_intervals)
    jitter = statistics.stdev(valid_intervals) if len(valid_intervals) > 1 else 0.0

    # Coefficient of Variation (CV) = standard deviation / mean
    cv = (jitter / mean_interval) if mean_interval > 0 else 1.0

    c2_score = 0.0
    reasons = []

    # 1. Periodicity check (low jitter indicates machine-generated timer)
    if cv <= 0.15:
        c2_score += 55
        reasons.append(f"Highly periodic beaconing (~{round(mean_interval, 1)}s interval, {round(cv*100, 1)}% jitter)")
    elif cv <= 0.30:
        c2_score += 35
        reasons.append(f"Semi-periodic beaconing with jitter (~{round(mean_interval, 1)}s interval)")

    # 2. Frequent recurring connection count
    if len(records) >= 6:
        c2_score += 25
        reasons.append(f"High recurrence ({len(records)} connections in window)")
    elif len(records) >= 3:
        c2_score += 15
        reasons.append(f"Recurring connections ({len(records)} in window)")

    # 3. Small-to-medium heartbeat flow size check
    avg_src_bytes = statistics.mean([r["src_bytes"] for r in records])
    if avg_src_bytes < 4000:
        c2_score += 20
        reasons.append("Consistent lightweight heartbeat payloads")

    c2_score = min(100.0, c2_score)
    is_c2 = c2_score >= 60.0

    return {
        "is_c2": is_c2,
        "confidence": round(c2_score, 2),
        "interval_seconds": round(mean_interval, 2),
        "jitter": round(jitter, 2),
        "reasons": "; ".join(reasons) if reasons else "Non-periodic standard traffic"
    }


def reset_c2_history():
    """Reset C2 tracking memory."""
    c2_flow_history.clear()
