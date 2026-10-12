from collections import defaultdict
import time

# ============================================================
# COMPRESSED DATA EXFILTRATION DETECTOR (Problem 5)
# ============================================================

# Tracks outbound volume per host: host_ip -> list of {"time": float, "src_bytes": int}
host_egress_history = defaultdict(list)

EXFIL_WINDOW_SECONDS = 60      # 1-minute velocity window
HIGH_SINGLE_FLOW_BYTES = 500_000   # 500 KB in a single outbound flow
MASSIVE_SINGLE_FLOW_BYTES = 2_000_000  # 2 MB in a single flow
CUMULATIVE_BURST_BYTES = 5_000_000     # 5 MB within 60 seconds


def cleanup_exfil_history():
    """Remove records older than the sliding window."""
    now = time.time()
    for host in list(host_egress_history.keys()):
        host_egress_history[host] = [
            record
            for record in host_egress_history[host]
            if (now - record["time"]) <= EXFIL_WINDOW_SECONDS
        ]
        if not host_egress_history[host]:
            del host_egress_history[host]


def analyze_data_exfiltration(
    src_ip: str,
    dst_ip: str,
    src_bytes: int,
    dst_bytes: int,
    duration: float
) -> dict:
    """
    Analyze flow for rapid, high-volume data exfiltration:
    - High outbound volume in short durations
    - Severe upload-to-download asymmetry (normal browsing is download-heavy)
    - Burst transfer velocity (MB/s)
    - Cumulative outbound bursts per host within 60s
    """
    now = time.time()
    cleanup_exfil_history()

    host_egress_history[src_ip].append({
        "time": now,
        "src_bytes": src_bytes
    })

    cumulative_egress = sum(
        r["src_bytes"] for r in host_egress_history[src_ip]
    )

    safe_duration = max(0.001, duration)
    velocity_bytes_per_sec = src_bytes / safe_duration
    asymmetry_ratio = src_bytes / max(1, dst_bytes)

    exfil_score = 0.0
    reasons = []

    # 1. Extreme outbound upload asymmetry (Exfiltration is heavily source-to-dest)
    if src_bytes >= 100_000 and asymmetry_ratio >= 15.0:
        exfil_score += 40
        reasons.append(f"Severe upload asymmetry ({round(asymmetry_ratio, 1)}x outbound ratio)")
    elif src_bytes >= 50_000 and asymmetry_ratio >= 8.0:
        exfil_score += 20
        reasons.append(f"Upload-heavy asymmetry ({round(asymmetry_ratio, 1)}x)")

    # 2. Single flow massive volume check
    if src_bytes >= MASSIVE_SINGLE_FLOW_BYTES:
        exfil_score += 40
        reasons.append(f"Massive single-flow upload ({round(src_bytes / 1_000_000, 2)} MB)")
    elif src_bytes >= HIGH_SINGLE_FLOW_BYTES:
        exfil_score += 25
        reasons.append(f"High single-flow upload ({round(src_bytes / 1_000, 1)} KB)")

    # 3. High transfer velocity in compressed timeframe (< 60s)
    if velocity_bytes_per_sec >= 1_000_000 and src_bytes >= 200_000:
        exfil_score += 30
        reasons.append(f"High-velocity transfer ({round(velocity_bytes_per_sec / 1_000_000, 2)} MB/s)")
    elif velocity_bytes_per_sec >= 300_000 and src_bytes >= 100_000:
        exfil_score += 15
        reasons.append(f"Elevated transfer velocity ({round(velocity_bytes_per_sec / 1_000, 1)} KB/s)")

    # 4. Cumulative 60-second host egress check
    if cumulative_egress >= CUMULATIVE_BURST_BYTES:
        exfil_score += 30
        reasons.append(f"Cumulative egress burst ({round(cumulative_egress / 1_000_000, 2)} MB / 60s)")

    exfil_score = min(100.0, exfil_score)
    is_exfil = exfil_score >= 60.0

    return {
        "is_exfiltration": is_exfil,
        "confidence": round(exfil_score, 2),
        "asymmetry_ratio": round(asymmetry_ratio, 2),
        "velocity_kbps": round(velocity_bytes_per_sec / 1000, 2),
        "cumulative_mb": round(cumulative_egress / 1_000_000, 2),
        "reasons": "; ".join(reasons) if reasons else "Normal bidirectional flow volume"
    }


def reset_exfil_history():
    """Reset exfiltration tracking memory."""
    host_egress_history.clear()
