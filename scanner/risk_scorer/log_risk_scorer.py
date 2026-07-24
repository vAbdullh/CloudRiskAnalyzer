import argparse
import json
import math
import re
from typing import Dict, List, Tuple


CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"L": 0.22, "H": 0.56, "N": 0.0},
    "I": {"L": 0.22, "H": 0.56, "N": 0.0},
    "A": {"L": 0.22, "H": 0.56, "N": 0.0},
    "S": {"U": 1.0, "C": 1.0},
}


def extract_log_lines(log_text: str) -> List[str]:
    return [line.strip() for line in log_text.splitlines() if line.strip()]


def infer_metric(log_lines: List[str], keyword_map: Dict[str, Tuple[str, ...]], default: str) -> str:
    lower = "\n".join(log_lines).lower()
    for metric, keywords in keyword_map.items():
        if any(keyword in lower for keyword in keywords):
            return metric
    return default


def infer_cvss_metrics(log_text: str) -> Dict[str, str]:
    lines = extract_log_lines(log_text)
    lower = "\n".join(lines).lower()

    attack_vector = "N"
    if any(k in lower for k in ["internal", "localhost", "local", "trusted network"]):
        attack_vector = "A"
    elif any(k in lower for k in ["vpn", "private network", "restricted"]):
        attack_vector = "P"
    elif any(k in lower for k in ["internet", "remote", "unauthorized", "public", "external"]):
        attack_vector = "N"
    else:
        attack_vector = "L"

    attack_complexity = "L"
    if any(k in lower for k in ["credential stuffing", "brute force", "retries", "manual", "social"]):
        attack_complexity = "H"

    privileges_required = "N"
    if any(k in lower for k in ["admin", "root", "privileged", "service account"]):
        privileges_required = "H"
    elif any(k in lower for k in ["authenticated", "user account", "limited"]):
        privileges_required = "L"

    user_interaction = "N"
    if any(k in lower for k in ["clicked", "opened attachment", "user interaction", "phishing"]):
        user_interaction = "R"

    scope = "U"
    if any(k in lower for k in ["cross-service", "shared resource", "cross boundary", "tenant", "multi-tenant"]):
        scope = "C"

    confidentiality = "N"
    if any(k in lower for k in ["data leak", "exfiltration", "secret", "credential", "pii"]):
        confidentiality = "H"
    elif any(k in lower for k in ["accessed", "read"]):
        confidentiality = "L"

    integrity = "N"
    if any(k in lower for k in ["tamper", "changed", "modified", "write", "update"]):
        integrity = "H"
    elif any(k in lower for k in ["changed state", "policy update"]):
        integrity = "L"

    availability = "N"
    if any(k in lower for k in ["outage", "denial", "service unavailable", "unreachable", "crash"]):
        availability = "H"
    elif any(k in lower for k in ["degraded", "slow", "latency"]):
        availability = "L"

    return {
        "AV": attack_vector,
        "AC": attack_complexity,
        "PR": privileges_required,
        "UI": user_interaction,
        "S": scope,
        "C": confidentiality,
        "I": integrity,
        "A": availability,
    }


def calculate_cvss_base(metrics: Dict[str, str]) -> Tuple[float, str]:
    av = CVSS_METRICS["AV"][metrics["AV"]]
    ac = CVSS_METRICS["AC"][metrics["AC"]]
    pr = CVSS_METRICS["PR"][metrics["PR"]]
    ui = CVSS_METRICS["UI"][metrics["UI"]]
    c = CVSS_METRICS["C"][metrics["C"]]
    i = CVSS_METRICS["I"][metrics["I"]]
    a = CVSS_METRICS["A"][metrics["A"]]
    scope = metrics["S"]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploit = 8.22 * av * ac * pr * ui

    if scope == "U":
        impact = 6.42 * iss
        score = min(10.0, impact + exploit)
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        score = min(10.0, impact + exploit)

    score = round(score, 1)
    if score >= 9.0:
        severity = "CRITICAL"
    elif score >= 7.0:
        severity = "HIGH"
    elif score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return score, severity


def cvss_vector(metrics: Dict[str, str]) -> str:
    vector = [
        f"AV:{metrics['AV']}",
        f"AC:{metrics['AC']}",
        f"PR:{metrics['PR']}",
        f"UI:{metrics['UI']}",
        f"S:{metrics['S']}",
        f"C:{metrics['C']}",
        f"I:{metrics['I']}",
        f"A:{metrics['A']}",
    ]
    return "/".join(vector)


def parse_log(log_text: str) -> Dict[str, object]:
    metrics = infer_cvss_metrics(log_text)
    score, severity = calculate_cvss_base(metrics)
    return {
        "score": score,
        "severity": severity,
        "vector": cvss_vector(metrics),
        "metrics": metrics,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a CVSS-style risk score from a log sample.")
    parser.add_argument("log_file", nargs="?", default="log_file.log", help="Path to the log file to scan.")
    args = parser.parse_args()

    try:
        with open(args.log_file, "r", encoding="utf-8", errors="ignore") as handle:
            score_log = handle.read()
    except FileNotFoundError:
        score_log = ""

    result = parse_log(score_log)
    print(json.dumps(result, indent=2))
""" elif __name__ == "log-risk-scorer":
    # This block is for when the module is imported as part of the scanner
    def score_log(log_text: str) -> Dict[str, object]:
        return parse_log(log_text)
 """