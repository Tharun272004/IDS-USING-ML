from collections import defaultdict
import time

# ============================================================
# UNIFIED FALSE-POSITIVE REDUCTION & RISK ENGINE (Problem 7)
# ============================================================

# Store recent observations for each source IP
source_history = defaultdict(list)

# Sliding memory window in seconds
HISTORY_WINDOW = 120


def cleanup_history(source_ip: str):
    """Remove observations older than the sliding window."""
    now = time.time()
    source_history[source_ip] = [
        item
        for item in source_history[source_ip]
        if (now - item["time"]) <= HISTORY_WINDOW
    ]


def calculate_risk(
    source_ip: str,
    attack_probability: float,
    packet_count: int = 0,
    src_bytes: int = 0,
    dst_bytes: int = 0,
    duration: float = 0.0,
    dns_analysis: dict = None,
    c2_analysis: dict = None,
    exfil_analysis: dict = None
) -> dict:
    """
    Correlate signals across multiple detection vectors to eliminate false positives
    and produce a high-fidelity risk score and attack category.

    Vectors analyzed:
    1. Machine Learning (Random Forest) probability
    2. DNS Subdomain Tunneling (Problem 2)
    3. Encrypted TLS C2 Beaconing (Problem 1)
    4. Compressed Data Exfiltration (Problem 5)
    5. Host behavioral history & repetition over time (Problem 7)
    """
    now = time.time()

    ml_prob = max(0.0, min(100.0, float(attack_probability)))

    dns_tunnel = dns_analysis or {}
    c2_data = c2_analysis or {}
    exfil_data = exfil_analysis or {}

    is_dns_tunnel = dns_tunnel.get("is_tunneling", False)
    dns_conf = dns_tunnel.get("confidence", 0.0)

    is_c2 = c2_data.get("is_c2", False)
    c2_conf = c2_data.get("confidence", 0.0)

    is_exfil = exfil_data.get("is_exfiltration", False)
    exfil_conf = exfil_data.get("confidence", 0.0)

    # --------------------------------------------------------
    # Update Behavioral Host History
    # --------------------------------------------------------
    is_any_suspicious = (
        ml_prob >= 50.0 or is_dns_tunnel or is_c2 or is_exfil
    )

    source_history[source_ip].append({
        "time": now,
        "ml_prob": ml_prob,
        "is_suspicious": is_any_suspicious,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes
    })

    cleanup_history(source_ip)
    history = source_history[source_ip]

    recent_suspicious_count = sum(
        1 for item in history if item["is_suspicious"]
    )

    # --------------------------------------------------------
    # Determine Primary Threat Category
    # --------------------------------------------------------
    threat_reasons = []

    if is_dns_tunnel:
        threat_type = "DNS_TUNNELING"
        threat_reasons.append(f"DNS Covert Tunnel: {dns_tunnel.get('reasons', '')}")
    elif is_c2:
        threat_type = "C2_BEACON"
        threat_reasons.append(f"Encrypted C2 Beacon: {c2_data.get('reasons', '')}")
    elif is_exfil:
        threat_type = "DATA_EXFILTRATION"
        threat_reasons.append(f"Data Exfiltration: {exfil_data.get('reasons', '')}")
    elif ml_prob >= 50.0:
        threat_type = "ANOMALOUS_FLOW"
        threat_reasons.append(f"Random Forest ML Intrusion ({round(ml_prob, 1)}% prob)")
    else:
        threat_type = "NORMAL"

    # --------------------------------------------------------
    # Calculate Unified Risk Score (0 - 100)
    # --------------------------------------------------------
    # Base risk from the most confident specialized detector or ML
    base_scores = [ml_prob]
    if is_dns_tunnel:
        base_scores.append(dns_conf)
    if is_c2:
        base_scores.append(c2_conf)
    if is_exfil:
        base_scores.append(exfil_conf)

    risk_score = max(base_scores)

    # False-positive dampening: If only ML triggered with weak probability (< 65%)
    # and no behavioral repetition or volume anomalies, reduce the score.
    if threat_type == "ANOMALOUS_FLOW" and ml_prob < 65.0 and recent_suspicious_count <= 1:
        if src_bytes < 5000 and packet_count <= 10:
            risk_score = max(20.0, risk_score - 15.0)  # De-escalate isolated minor anomalies

    # Behavioral escalation: Repeated suspicious activities from the same host boost risk
    if recent_suspicious_count > 1:
        repetition_bonus = min((recent_suspicious_count - 1) * 4.0, 15.0)
        risk_score += repetition_bonus
        threat_reasons.append(f"Persistent activity ({recent_suspicious_count} events)")

    # Volume / Activity bonus
    if src_bytes >= 1_000_000:
        risk_score += 5.0
    if packet_count >= 100:
        risk_score += 3.0

    risk_score = max(0.0, min(100.0, risk_score))

    # --------------------------------------------------------
    # Assign Actionable Severity Bands
    # --------------------------------------------------------
    if risk_score >= 80.0 or is_dns_tunnel or is_exfil or is_c2:
        if threat_type != "NORMAL":
            severity = "CRITICAL" if risk_score >= 80.0 else "HIGH"
        else:
            severity = "LOW"
    elif risk_score >= 60.0:
        severity = "HIGH"
    elif risk_score >= 35.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Normalize prediction state
    final_prediction = "ATTACK" if (threat_type != "NORMAL" and risk_score >= 50.0) else "NORMAL"

    return {
        "risk_score": round(risk_score, 2),
        "severity": severity,
        "threat_type": threat_type,
        "prediction": final_prediction,
        "suspicious_observations": recent_suspicious_count,
        "details": "; ".join(threat_reasons) if threat_reasons else "Benign traffic"
    }


def reset_history():
    """Clear stored behavioral history."""
    source_history.clear()