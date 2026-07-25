import sys
import pprint
from providers.aws import AWSProvider
from providers.gcp import GCPProvider
from providers.orc import OrcProvider
from rules.executor import get_rules_for_provider, evaluate_rules

SUPPORTED_PROVIDERS = {
    "aws": AWSProvider,
    "gcp": GCPProvider,
    "oci": OrcProvider,
}


def choose_provider():
    print("Supported providers:")

    for name in SUPPORTED_PROVIDERS:
        print(f" - {name}")

    while True:
        choice = input("\nSelect provider: ").strip().lower()

        if choice in SUPPORTED_PROVIDERS:
            return SUPPORTED_PROVIDERS[choice]()

        print("Invalid provider.")


def request_credentials(provider):
    credentials = {}

    print(f"\nCredentials required for {provider.name}:\n")

    for field in provider.required_credentials():
        credentials[field["name"]] = input(f'{field["label"]}: ')

    return credentials


def _print_risk_summary(all_evaluations: list):
    """Print an aggregated Risk Score Summary at the end of the scan."""
    # Collect all scored (non-SAFE) findings
    scored = [e for e in all_evaluations if e.get("risk_score") is not None]

    if not scored:
        print("\n--- Risk Score Summary ---")
        print("No active findings were scored.")
        return

    # Sort by risk score descending
    scored.sort(key=lambda e: e["risk_score"], reverse=True)

    # Count by priority bucket
    priority_counts = {}
    for e in scored:
        p = e.get("action_priority", "Unknown")
        priority_counts[p] = priority_counts.get(p, 0) + 1

    # Determine overall posture
    max_score = scored[0]["risk_score"]
    if max_score >= 9.0:
        posture = "CRITICAL — Immediate action required"
    elif max_score >= 7.0:
        posture = "HIGH RISK — Significant issues detected"
    elif max_score >= 4.0:
        posture = "MODERATE — Some findings need attention"
    else:
        posture = "LOW RISK — Minor findings only"

    print("\n" + "=" * 70)
    print("  RISK SCORE SUMMARY")
    print("=" * 70)
    print(f"\n  Overall Risk Posture:  {posture}")
    print(f"  Total Scored Findings: {len(scored)}")
    print()

    # Priority breakdown
    print("  Findings by Priority:")
    priority_order = [
        "Immediate (P0)", "Critical (P1)", "High (P2)", "Medium (P3)", "Low / Info (P4)"
    ]
    for p in priority_order:
        count = priority_counts.get(p, 0)
        if count > 0:
            print(f"    {p:25s}  {count}")
    print()

    # Top 5 highest-risk findings
    top_n = min(5, len(scored))
    print(f"  Top {top_n} Highest-Risk Findings:")
    print(f"  {'Score':>6s}  {'Priority':25s}  {'Rule ID':20s}  Resource")
    print(f"  {'─' * 6}  {'─' * 25}  {'─' * 20}  {'─' * 30}")
    for e in scored[:top_n]:
        score_str = f"{e['risk_score']:.1f}"
        print(
            f"  {score_str:>6s}  {e.get('action_priority', ''):25s}  "
            f"{e.get('rule_id', ''):20s}  {e.get('resource_name', '')}"
        )

    print("\n" + "=" * 70)


def main():
    provider = choose_provider()

    credentials = request_credentials(provider)

    provider.connect(credentials)

    if not provider.validate_credentials():
        print("Authentication failed.")
        return

    # Load security rules for the selected provider
    provider_key = "aws" if "aws" in provider.name.lower() else provider.name.lower()
    rules = get_rules_for_provider(provider_key)

    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    
    # Extract clean provider name
    prov_name = "PROVIDER"
    if hasattr(provider, "name") and provider.name:
        prov_upper = provider.name.upper()
        if "AWS" in prov_upper:
            prov_name = "AWS"
        elif "GCP" in prov_upper:
            prov_name = "GCP"
        elif "OCI" in prov_upper or "ORC" in prov_upper:
            prov_name = "OCI"
            
    account_id = getattr(provider, "account_id", None)
    if not account_id:
        account_id = "UNKNOWN"
        
    filename = f"RESULT-{prov_name}-{account_id}-{timestamp}.log"

    print(f"\nScanning started. Redirecting all output to {filename}...")

    # Collect all evaluations across all resources for the summary
    all_evaluations = []

    with open(filename, "w", encoding="utf-8") as f:
        # Redirect stdout to the dynamic log file
        original_stdout = sys.stdout
        sys.stdout = f

        try:
            print("--- Step 1: Discovering Resources ---")
            resources = provider.discover_resources()
            print(f"\n[Scanner] Discovered {len(resources)} resources:")
            for resource in resources:
                print(f" - Type: {resource['type']} | ID: {resource['id']} | Name: {resource['name']}")

            print("\n--- Step 2 & 3: Scanning Resources ---")
            for idx, resource in enumerate(resources, 1):
                # Print progress to both the log file and the interactive console
                progress_msg = f"[{idx}/{len(resources)}] Scanning resource: [{resource['type']}] {resource['name']} ({resource['id']})..."
                print(f"\n{progress_msg}")
                print(progress_msg, file=sys.__stdout__, flush=True)

                # Step 2: Collect configuration
                configuration = provider.get_configuration(resource)
                print("Configuration collected:")
                pprint.pprint(configuration, indent=2)

                # Step 3: Evaluate security rules
                resource_evaluations = evaluate_rules(resource, configuration, rules)
                all_evaluations.extend(resource_evaluations)

                print(f"Rule Evaluations (Checks: {len(resource_evaluations)}):")
                for rule_idx, eval_res in enumerate(resource_evaluations, 1):
                    status_str = f"[{eval_res['status']}]"
                    print(f"  - {status_str} Rule: {eval_res['rule_name']} ({eval_res['rule_id']})")
                    print(f"    Description:    {eval_res['description']}")

                    # --- Risk Score output for non-SAFE findings ---
                    if eval_res['status'] != "SAFE" and eval_res.get("risk_score") is not None:
                        score = eval_res["risk_score"]
                        priority = eval_res.get("action_priority", "")
                        sla = eval_res.get("sla", "")
                        metrics = eval_res.get("scoring_metrics", {})

                        r_base = metrics.get("r_base", 0)
                        exposure = metrics.get("exposure_factor", 0)
                        chain = metrics.get("chain_multiplier", 1.0)

                        print(f"    Risk Score:     {score:.1f} / 10.0  |  Priority: {priority}  |  SLA: {sla}")
                        print(f"    Metrics:        R_base={r_base}  E={exposure}  C={chain}x")

                    if eval_res['status'] != "SAFE":
                        print(f"    Recommendation: {eval_res['recommendation']}")

            # --- Risk Score Summary ---
            _print_risk_summary(all_evaluations)

            provider.disconnect()

        finally:
            # Restore original stdout
            sys.stdout = original_stdout

    print(f"Scan completed successfully. Results saved in {filename}.")


if __name__ == "__main__":
    main()