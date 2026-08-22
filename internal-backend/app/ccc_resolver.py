import json
import os
from functools import lru_cache

# Adjust base dir to project root assuming this file is in internal-backend/app/
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def get_path(filename):
    paths = [
        os.path.join(BASE_DIR, "ccc_integration", filename),
        f"/ccc_integration/{filename}",
        os.path.join(os.path.dirname(__file__), "..", "ccc_integration", filename)
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return filename

MAPPING_FILE = get_path("finding_to_ccc_mapping.json")
CONTROLS_FILE = get_path("ccc_controls.json")

class CCCResolver:
    def __init__(self):
        self.mapping = {}
        self.controls_cache = {}
        self._load_data()

    def _load_data(self):
        try:
            with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
                mapping_data = json.load(f)
                for item in mapping_data.get("findings", []):
                    self.mapping[item["finding_type"]] = item

            with open(CONTROLS_FILE, 'r', encoding='utf-8') as f:
                controls_data = json.load(f)
                for domain in controls_data.get("domains", []):
                    for subdomain in domain.get("subdomains", []):
                        for control in subdomain.get("controls", []):
                            # Store top level control text just in case
                            self.controls_cache[control["id"]] = control["text"]
                            for subcontrol in control.get("subcontrols", []):
                                self.controls_cache[subcontrol["id"]] = subcontrol["text"]
        except Exception as e:
            print(f"Error loading CCC data: {e}")

    def get_controls_for_finding(self, finding_type: str, applicability: str) -> list[dict]:
        """
        Returns relevant CCC control subcontrols for a finding based on applicability (CSP or CST).
        """
        if not finding_type or finding_type not in self.mapping:
            return []

        finding_mapping = self.mapping[finding_type]
        
        # Determine the key to use based on applicability
        # The prompt mentioned ccc_applicability is "CSP" or "CST"
        if applicability and applicability.upper() == "CSP":
            control_ids = finding_mapping.get("ccc_controls_csp", [])
        else:
            # Default or CST
            control_ids = finding_mapping.get("ccc_controls_cst", [])

        result = []
        for cid in control_ids:
            if cid in self.controls_cache:
                result.append({
                    "id": cid,
                    "text": self.controls_cache[cid]
                })
            else:
                result.append({
                    "id": cid,
                    "text": "Control text not found."
                })
        
        return result

# Singleton instance
resolver = CCCResolver()

def get_controls_for_finding(finding_type: str, applicability: str) -> list[dict]:
    return resolver.get_controls_for_finding(finding_type, applicability)
