import sys
import pprint
from providers.aws import AWSProvider
from providers.gcp import GCPProvider
from providers.oci import OCIProvider
from rules.executor import get_rules_for_provider, evaluate_rules

SUPPORTED_PROVIDERS = {
    "aws": AWSProvider,
    "gcp": GCPProvider,
    "oci": OCIProvider,
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


def main():
    provider = choose_provider()

    credentials = request_credentials(provider)

    provider.connect(credentials)

    if not provider.validate_credentials():
        print("Authentication failed.")
        return

    # Load security rules for the selected provider
    if "aws" in provider.name.lower():
        provider_key = "aws"
    elif "gcp" in provider.name.lower():
        provider_key = "gcp"
    elif "oci" in provider.name.lower() or "orc" in provider.name.lower():
        provider_key = "oci"
    else:
        raise ValueError(f"Unknown provider: {provider.name}")
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
        elif "OCI" in prov_upper:
            prov_name = "OCI"
            
    account_id = getattr(provider, "account_id", None)
    if not account_id:
        account_id = "UNKNOWN"
        
    filename = f"RESULT-{prov_name}-{account_id}-{timestamp}.log"

    print(f"\nScanning started. Redirecting all output to {filename}...")

    with open(filename, "w", encoding="utf-8") as f:
        try:
            def log_and_print(msg):
                print(msg)
                f.write(msg + "\n")

            log_and_print("--- Step 1: Discovering Resources ---")
            resources = provider.discover_resources()
            log_and_print(f"\n[Scanner] Discovered {len(resources)} resources:")
            for resource in resources:
                log_and_print(f" - Type: {resource['type']} | ID: {resource['id']} | Name: {resource['name']}")

            log_and_print("\n--- Step 2 & 3: Scanning Resources ---")
            for idx, resource in enumerate(resources, 1):
                progress_msg = f"[{idx}/{len(resources)}] Scanning resource: [{resource['type']}] {resource['name']} ({resource['id']})..."
                log_and_print(f"\n{progress_msg}")

                # Step 2: Collect configuration
                configuration = provider.get_configuration(resource)
                log_and_print("Configuration collected:")
                log_and_print(pprint.pformat(configuration, indent=2))

                # Step 3: Evaluate security rules
                resource_evaluations = evaluate_rules(resource, configuration, rules)
                log_and_print(f"Rule Evaluations (Checks: {len(resource_evaluations)}):")
                for rule_idx, eval_res in enumerate(resource_evaluations, 1):
                    status_str = f"[{eval_res['status']}]"
                    log_and_print(f"  - {status_str} Rule: {eval_res['rule_name']} ({eval_res['rule_id']})")
                    log_and_print(f"    Description:    {eval_res['description']}")
                    if eval_res['status'] != "SAFE":
                        log_and_print(f"    Recommendation: {eval_res['recommendation']}")

            provider.disconnect()

        except Exception as e:
            log_and_print(f"Fatal error during scan: {e}")

    print(f"Scan completed successfully. Results saved in {filename}.")


if __name__ == "__main__":
    main()