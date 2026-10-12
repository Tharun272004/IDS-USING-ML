import math
from collections import Counter
import re

# ============================================================
# DNS TUNNELING DETECTOR (Problem 2)
# ============================================================

# Whitelisted standard/popular domains to avoid false positives on CDNs/telemetry
KNOWN_SAFE_SUFFIXES = {
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com",
    "azure.com", "windows.com", "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com", "cloudflare.com", "github.com",
    "akamaiedge.net", "akadns.net", "trafficmanager.net"
}


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon Entropy of a string.
    Random/encoded strings (Base64/Hex) yield high entropy (> 3.5 - 4.5).
    English words and regular domain names yield low entropy (< 3.0).
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text.lower())
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return round(entropy, 3)


def is_whitelisted_domain(domain: str) -> bool:
    """Check if the root domain belongs to known high-entropy CDN/telemetry providers."""
    domain_clean = domain.strip(".").lower()
    for safe in KNOWN_SAFE_SUFFIXES:
        if domain_clean == safe or domain_clean.endswith("." + safe):
            return True
    return False


def analyze_dns_query(qname: str) -> dict:
    """
    Analyze a DNS query name for signs of covert tunneling:
    - High Shannon entropy in the subdomain payload
    - Unusually long full query name (> 45 chars) or label length (> 30 chars)
    - High ratio of numerical/hex characters
    - High number of subdomain levels
    """
    if not qname:
        return {
            "is_tunneling": False,
            "confidence": 0.0,
            "entropy": 0.0,
            "reasons": "Empty query"
        }

    # Normalize domain name (remove trailing dot)
    domain = qname.strip(".").lower()

    if is_whitelisted_domain(domain):
        return {
            "is_tunneling": False,
            "confidence": 0.0,
            "entropy": 0.0,
            "reasons": "Whitelisted provider"
        }

    labels = domain.split(".")
    if len(labels) <= 1:
        return {
            "is_tunneling": False,
            "confidence": 0.0,
            "entropy": 0.0,
            "reasons": "Single label"
        }

    # Focus on the subdomain part (the prefix containing potential encoded payload)
    subdomain_parts = labels[:-2] if len(labels) >= 3 else labels[:-1]
    subdomain_payload = "".join(subdomain_parts)

    entropy = calculate_shannon_entropy(subdomain_payload)
    total_length = len(domain)
    longest_label_len = max(len(l) for l in labels)

    tunneling_score = 0.0
    reasons = []

    # 1. High Shannon Entropy test
    if entropy >= 4.0:
        tunneling_score += 45
        reasons.append(f"High entropy ({entropy})")
    elif entropy >= 3.6:
        tunneling_score += 25
        reasons.append(f"Elevated entropy ({entropy})")

    # 2. Query length check
    if total_length >= 65:
        tunneling_score += 35
        reasons.append(f"Excessive query length ({total_length} chars)")
    elif total_length >= 45:
        tunneling_score += 20
        reasons.append(f"Long query length ({total_length} chars)")

    # 3. Longest individual label check (DNS allows up to 63 chars per label)
    if longest_label_len >= 35:
        tunneling_score += 25
        reasons.append(f"Long label ({longest_label_len} chars)")

    # 4. Hex / Base32 / Base64 character pattern check
    hex_pattern = re.match(r"^[0-9a-fA-F]+$", subdomain_payload)
    base64_like = re.match(r"^[0-9a-zA-Z_\-]+$", subdomain_payload)

    if hex_pattern and len(subdomain_payload) >= 20:
        tunneling_score += 20
        reasons.append("Hex-encoded payload pattern")
    elif base64_like and len(subdomain_payload) >= 25 and entropy >= 3.7:
        tunneling_score += 15
        reasons.append("Base64/Base32 payload pattern")

    tunneling_score = min(100.0, tunneling_score)
    is_tunneling = tunneling_score >= 60.0

    return {
        "is_tunneling": is_tunneling,
        "confidence": round(tunneling_score, 2),
        "entropy": entropy,
        "query_length": total_length,
        "reasons": "; ".join(reasons) if reasons else "Normal query structure"
    }
