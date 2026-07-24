import requests
from providers.base import BaseProvider

class DOCProvider(BaseProvider):
    name = "DOC"

    def __init__(self):
        self._session = None
        self.api_token = None
        self.base_url = "https://api.digitalocean.com/v2"
        self.account_id = None

    def required_credentials(self) -> list[dict]:
        """Return the credentials required by this provider."""
        return [
            {
                "name": "api_token",
                "label": "DigitalOcean API Token",
                "secret": True,
            },
        ]

    def connect(self, credentials: dict) -> None:
        """Authenticate with DigitalOcean and initialize the API session."""
        self.api_token = credentials.get("api_token")
        
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        })
        print("[DigitalOcean] Initialized connection session.")

    def validate_credentials(self) -> bool:
        """Verify the provided credentials using the account API."""
        if self._session is None:
            print("[DigitalOcean] Not connected. Call connect() first.")
            return False
        try:
            response = self._session.get(f"{self.base_url}/account")
            if response.status_code == 200:
                account_data = response.json().get("account", {})
                self.account_id = account_data.get("email")
                print(f"[DigitalOcean] Authenticated as Account: {self.account_id}")
                return True
            else:
                print(f"[DigitalOcean] Connection validation failed: {response.status_code} - {response.text}")
                return False
        except Exception as err:
            print(f"[DigitalOcean] Unexpected validation error: {err}")
            return False

    def disconnect(self) -> None:
        """Close the connection and clear stored credentials."""
        if self._session:
            self._session.close()
        self._session = None
        self.api_token = None
        self.account_id = None
        print("[DigitalOcean] Disconnected.")

    def list_supported_resources(self) -> list[str]:
        """Return supported DigitalOcean resource types."""
        return [
            "Droplets",
            "Volumes",
            "Spaces",
            "Firewalls",
        ]

    def discover_resources(self) -> list[dict]:
        """Discover all scannable resources in the target environment."""
        if self._session is None:
            print("[DigitalOcean] Not connected. Call connect() first.")
            return []

        resources = []
        print("[DigitalOcean] Starting resource discovery...")

        # 1. Discover Droplets
        try:
            response = self._session.get(f"{self.base_url}/droplets")
            if response.status_code == 200:
                for droplet in response.json().get("droplets", []):
                    resources.append({
                        "type": "Droplets",
                        "id": str(droplet["id"]),
                        "name": droplet["name"]
                    })
        except Exception as err:
            print(f"[DigitalOcean] Failed to discover Droplets: {err}")

        # 2. Discover Volumes
        try:
            response = self._session.get(f"{self.base_url}/volumes")
            if response.status_code == 200:
                for volume in response.json().get("volumes", []):
                    resources.append({
                        "type": "Volumes",
                        "id": volume["id"],
                        "name": volume["name"]
                    })
        except Exception as err:
            print(f"[DigitalOcean] Failed to discover Volumes: {err}")

        # 3. Discover Spaces (Object Storage Buckets)
        try:
            response = self._session.get(f"{self.base_url}/spaces")
            if response.status_code == 200:
                for space in response.json().get("spaces", []):
                    resources.append({
                        "type": "Spaces",
                        "id": space["name"],
                        "name": space["name"]
                    })
        except Exception as err:
            print(f"[DigitalOcean] Failed to discover Spaces: {err}")

        # 4. Discover Firewalls
        try:
            response = self._session.get(f"{self.base_url}/firewalls")
            if response.status_code == 200:
                for firewall in response.json().get("firewalls", []):
                    resources.append({
                        "type": "Firewalls",
                        "id": firewall["id"],
                        "name": firewall["name"]
                    })
        except Exception as err:
            print(f"[DigitalOcean] Failed to discover Firewalls: {err}")

        print(f"[DigitalOcean] Discovered {len(resources)} resources.")
        return resources

    def get_configuration(self, resource: dict) -> dict:
        """Retrieve the configuration for a resource."""
        if self._session is None:
            print("[DigitalOcean] Not connected. Call connect() first.")
            return {}

        resource_type = resource.get("type")
        resource_id = resource.get("id")
        resource_name = resource.get("name")
        print(f"[DigitalOcean] Collecting configuration for {resource_type} ({resource_id})...")

        config = {}

        if resource_type == "Droplets":
            try:
                response = self._session.get(f"{self.base_url}/droplets/{resource_id}")
                if response.status_code == 200:
                    droplet = response.json().get("droplet", {})
                    config["raw_data"] = droplet
                    config["public_ips"] = [ip.get("address") for ip in droplet.get("networks", {}).get("v4", []) if ip.get("type") == "public"]
                    config["firewall_ids"] = droplet.get("firewall_ids", [])
            except Exception as err:
                print(f"[DigitalOcean] Failed to get configuration for Droplet {resource_id}: {err}")

        elif resource_type == "Volumes":
            try:
                response = self._session.get(f"{self.base_url}/volumes/{resource_id}")
                if response.status_code == 200:
                    volume = response.json().get("volume", {})
                    config["raw_data"] = volume
                    config["size_gb"] = volume.get("size_gigabytes")
                    config["droplet_ids"] = volume.get("droplet_ids", [])
            except Exception as err:
                print(f"[DigitalOcean] Failed to get configuration for Volume {resource_id}: {err}")

        elif resource_type == "Spaces":
            try:
                # Spaces ACL configuration
                config["name"] = resource_name
                config["acl"] = "private"  # Default assumption, adjust based on your needs
            except Exception as err:
                print(f"[DigitalOcean] Failed to get configuration for Space {resource_name}: {err}")

        elif resource_type == "Firewalls":
            try:
                response = self._session.get(f"{self.base_url}/firewalls/{resource_id}")
                if response.status_code == 200:
                    firewall = response.json().get("firewall", {})
                    config["raw_data"] = firewall
                    config["inbound_rules"] = firewall.get("inbound_rules", [])
                    config["outbound_rules"] = firewall.get("outbound_rules", [])
                    config["droplet_ids"] = firewall.get("droplet_ids", [])
            except Exception as err:
                print(f"[DigitalOcean] Failed to get configuration for Firewall {resource_id}: {err}")

        return config