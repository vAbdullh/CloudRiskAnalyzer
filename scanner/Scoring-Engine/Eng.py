"""
Cloud Risk Scoring Engine
=========================
Computes a normalized 0.0–10.0 risk score for cloud security findings
using the formula:

    Final Risk Score (R) = min(10.0, (R_base + E) × C)

Where:
    R_base  — Base Severity / Identity Scope        (0.0–10.0)
    E       — Exposure Factor (reachability/network) (0.0–3.0)
    C       — Chain / Attack Path Multiplier         (1.0–1.5)

Priority mapping (Action Priority):
    9.0–10.0  →  Immediate (P0) if R_base >= 9.0, else Critical (P1)
    7.0–8.9   →  High (P2)
    4.0–6.9   →  Medium (P3)
    0.0–3.9   →  Low / Info (P4)
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


# ---------------------------------------------------------------------------
# Priority / SLA constants
# ---------------------------------------------------------------------------

PRIORITY_MAP = [
    # (min_score, max_score, label_function, sla)
    (9.0, 10.0, None, "Fix within 24 hours"),       # label resolved dynamically
    (7.0,  8.9, "High (P2)", "Fix within 7 days"),
    (4.0,  6.9, "Medium (P3)", "Fix within 30 days"),
    (0.0,  3.9, "Low / Info (P4)", "Informational / Best Effort"),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ScanFinding:
    """Represents a single security finding to be scored."""
    rule_id: str
    resource_id: str
    resource_type: str
    r_base: float
    exposure_factor: float
    chain_multiplier: float
    resource_name: str = ""
    condition_description: str = ""
    cloud_provider: str = ""


# ---------------------------------------------------------------------------
# Core scoring logic
# ---------------------------------------------------------------------------

def determine_priority(final_score: float, r_base: float) -> tuple:
    """
    Map a final risk score to an action priority label and SLA recommendation.

    Returns:
        (priority_label, sla_recommendation)
    """
    if final_score >= 9.0:
        label = "Immediate (P0)" if r_base >= 9.0 else "Critical (P1)"
        return label, "Fix within 24 hours"
    elif final_score >= 7.0:
        return "High (P2)", "Fix within 7 days"
    elif final_score >= 4.0:
        return "Medium (P3)", "Fix within 30 days"
    else:
        return "Low / Info (P4)", "Informational / Best Effort"


def calculate_risk_score(finding: ScanFinding) -> Dict[str, Any]:
    """
    Compute the normalized 0.0–10.0 risk score and full metric breakdown
    for a given scan finding.

    Formula:  R = min(10.0, (R_base + E) × C)

    Returns a dict containing:
        - rule_id, resource_id, resource_name
        - final_score           (float, 0.0–10.0)
        - action_priority       (str)
        - sla                   (str)
        - metrics               (dict with r_base, exposure_factor, chain_multiplier)
        - calculation_logic     (str showing the math)
    """
    r_base = finding.r_base
    exposure = finding.exposure_factor
    chain = finding.chain_multiplier

    raw_score = (r_base + exposure) * chain
    final_score = round(min(10.0, max(0.0, raw_score)), 1)

    priority, sla = determine_priority(final_score, r_base)

    calculation = (
        f"min(10.0, ({r_base} + {exposure}) × {chain}) "
        f"= min(10.0, {round(raw_score, 2)}) = {final_score}"
    )

    return {
        "rule_id": finding.rule_id,
        "resource_id": finding.resource_id,
        "resource_name": finding.resource_name,
        "cloud_provider": finding.cloud_provider,
        "final_score": final_score,
        "action_priority": priority,
        "sla": sla,
        "metrics": {
            "r_base": r_base,
            "exposure_factor": exposure,
            "chain_multiplier": chain,
        },
        "calculation_logic": calculation,
    }


# ---------------------------------------------------------------------------
# Dynamic override helpers
# ---------------------------------------------------------------------------

def apply_dynamic_overrides(
    rule: dict,
    configuration: dict,
) -> tuple:
    """
    Adjust exposure_factor (E) and chain_multiplier (C) based on runtime
    configuration context.

    Returns:
        (adjusted_exposure_factor, adjusted_chain_multiplier)
    """
    e = rule.get("exposure_factor", 1.0)
    c = rule.get("chain_multiplier", 1.0)
    rule_id = rule.get("id", "").upper()

    # --- Security Group / Security List: unattached resources have no blast radius ---
    attached_count = configuration.get("attached_resources_count")
    if attached_count is not None and attached_count == 0:
        # If the SG/Security List is not attached to any resource, exposure drops
        if rule_id in ("SEC-012", "SEC-013") or e > 0:
            # For explicitly unattached findings, E = 0.0
            if rule_id in ("SEC-013",):
                e = 0.0
            # For SEC-012 (outbound all) with no ENIs, reduce but keep some base
            elif rule_id == "SEC-012":
                e = 0.0

    # --- Direct internet exposure: if config shows 0.0.0.0/0 or ::/0 ---
    raw_data = configuration.get("raw_data", {})

    # AWS Security Group: check for public_ssh flag already computed by provider
    if configuration.get("public_ssh", False):
        e = max(e, 3.0)

    # OCI Security List: check ingress rules for 0.0.0.0/0
    ingress_rules = raw_data.get("ingress_security_rules", [])
    for irule in ingress_rules:
        source = irule.get("source", "")
        if source in ("0.0.0.0/0", "::/0"):
            e = max(e, 3.0)
            break

    # OCI Object Storage: public access
    public_access = raw_data.get("public_access_type", "NoPublicAccess")
    if public_access != "NoPublicAccess":
        e = max(e, 3.0)

    # OCI Subnet: public subnet exposure
    if raw_data.get("prohibit_public_ip_on_vnic") is False:
        e = max(e, 1.5)

    return e, c


# ---------------------------------------------------------------------------
# Convenience: score from a rule dict + config (used by executor)
# ---------------------------------------------------------------------------

def score_finding(
    rule: dict,
    resource: dict,
    configuration: dict,
    cloud_provider: str = "",
) -> Dict[str, Any]:
    """
    High-level helper that takes a rule definition dict and resource
    configuration, applies dynamic overrides, and returns the full
    scored result.
    """
    e, c = apply_dynamic_overrides(rule, configuration)

    finding = ScanFinding(
        rule_id=rule.get("id", ""),
        resource_id=resource.get("id", ""),
        resource_type=resource.get("type", ""),
        resource_name=resource.get("name", ""),
        r_base=rule.get("r_base", 0.0),
        exposure_factor=e,
        chain_multiplier=c,
        condition_description=rule.get("description", ""),
        cloud_provider=cloud_provider,
    )

    return calculate_risk_score(finding)