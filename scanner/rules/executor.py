import sys
import os

# Add the scanner directory to the path so Scoring-Engine can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.aws import ec2 as aws_ec2, s3 as aws_s3, iam as aws_iam

# Import the scoring engine
try:
    from importlib import import_module
    _eng_mod = import_module("Scoring-Engine.Eng")
    score_finding = _eng_mod.score_finding
    _SCORING_AVAILABLE = True
except Exception:
    # Fallback: try direct import with path manipulation
    try:
        _scoring_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Scoring-Engine")
        sys.path.insert(0, _scoring_dir)
        from Eng import score_finding
        _SCORING_AVAILABLE = True
    except Exception:
        _SCORING_AVAILABLE = False


def get_rules_for_provider(provider_name: str) -> list:
    """Return all rule definitions for the specified cloud provider."""
    # Convert provider name to lowercase to match keys
    name = provider_name.lower()
    
    if name == "aws":
        rules = []
        rules.extend(getattr(aws_ec2, "RULES", []))
        rules.extend(getattr(aws_s3, "RULES", []))
        rules.extend(getattr(aws_iam, "RULES", []))
        return rules
        
    if "oci" in name or "oracle" in name:
        try:
            from rules.oci.oci import RULES as oci_rules
            return oci_rules
        except ImportError:
            return []
            
    # Placeholder for other providers (GCP)
    return []


def _detect_cloud_provider(resource: dict, rules: list) -> str:
    """Infer the cloud provider from the resource or rule context."""
    resource_id = resource.get("id", "")
    resource_type = resource.get("type", "").upper()

    if resource_id.startswith("ocid1.") or resource_type.startswith("OCI"):
        return "OCI"
    if resource_id.startswith("arn:aws:") or resource_type in (
        "EC2", "S3", "IAM", "IAM ROLE", "SECURITY GROUPS"
    ):
        return "AWS"

    # Check rules for OCI prefix
    for rule in rules:
        if rule.get("id", "").upper().startswith("OCI"):
            return "OCI"

    return "AWS"


def evaluate_rules(resource: dict, configuration: dict, rules: list) -> list:
    """Evaluate all applicable rules against a resource configuration.
    
    Returns a list of rule evaluation results (dicts representing the status of each rule).
    Each failed finding is enriched with risk scoring data when the scoring engine is available.
    """
    evaluations = []
    resource_type = resource.get("type", "").upper()
    resource_id = resource.get("id", "")
    resource_name = resource.get("name", "")

    cloud_provider = _detect_cloud_provider(resource, rules)
    
    for rule in rules:
        rule_id = rule.get("id", "").upper()
        
        # Determine if rule matches the resource type
        match = False
        if rule_id.startswith("SEC") and resource_type == "SECURITY GROUPS":
            match = True
        elif rule_id.startswith("EC2") and resource_type == "EC2":
            match = True
        elif rule_id.startswith("S3") and resource_type == "S3":
            match = True
        elif rule_id.startswith("IAM") and resource_type.startswith("IAM"):
            match = True
        elif rule_id.startswith("OCI") and rule.get("resource_type", "").upper() == resource_type:
            match = True
            
        if match:
            try:
                # The rule check returns True if the check fails (finding exists)
                check_func = rule.get("check")
                failed = False
                if check_func:
                    failed = check_func(configuration)
                
                status = rule.get("severity", "WARNING").upper() if failed else "SAFE"
                
                evaluation = {
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "status": status,
                    "description": rule.get("description"),
                    "recommendation": rule.get("recommendation") if failed else None,
                    "resource_type": resource["type"],
                    "resource_id": resource_id,
                    "resource_name": resource_name,
                    # Default scoring fields (populated below if finding is active)
                    "risk_score": None,
                    "action_priority": None,
                    "sla": None,
                    "scoring_metrics": None,
                    "calculation_logic": None,
                }

                # --- Risk Scoring: only score active (non-SAFE) findings ---
                if failed and _SCORING_AVAILABLE:
                    try:
                        score_result = score_finding(
                            rule=rule,
                            resource=resource,
                            configuration=configuration,
                            cloud_provider=cloud_provider,
                        )
                        evaluation["risk_score"] = score_result.get("final_score")
                        evaluation["action_priority"] = score_result.get("action_priority")
                        evaluation["sla"] = score_result.get("sla")
                        evaluation["scoring_metrics"] = score_result.get("metrics")
                        evaluation["calculation_logic"] = score_result.get("calculation_logic")
                    except Exception as score_err:
                        print(f"[Scoring] Warning: Failed to score rule {rule.get('id')}: {score_err}")

                evaluations.append(evaluation)
            except Exception as e:
                print(f"[Error] Failed to evaluate rule {rule.get('id')} on resource {resource_id}: {e}")
                
    return evaluations
