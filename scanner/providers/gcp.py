from providers.base import BaseProvider


# GCP API / SDK integration
class GCPProvider(BaseProvider):
    name = "GCP"

    def __init__(self):
        super().__init__()
        self.credentials = None

    def required_credentials(self) -> list[dict]:
        """Return the credentials required by this provider."""
        return [
            {
                "name": "project_id",
                "label": "GCP Project ID",
                "secret": False,
            },
            {
                "name": "service_account_key",
                "label": "Service Account Key (JSON file path)",
                "secret": False,
            },
        ]

    def connect(self, credentials: dict) -> None:
        """Authenticate with GCP."""
        self.credentials = credentials
        print("Connecting to GCP...")

    def validate_credentials(self) -> bool:
        """Verify the provided credentials."""
        print("Validating GCP credentials...")
        return True

    def disconnect(self) -> None:
        """Close the connection."""
        print("Disconnecting from GCP...")

    def list_supported_resources(self) -> list[str]:
        """Return supported GCP resource types."""
        return [
            "Compute Engine",
            "Cloud Storage",
            "IAM",
            "Firewall Rules",
        ]

    def discover_resources(self) -> list[dict]:
        """Discover supported resources."""
        print("Discovering resources...")
        return []

    def get_configuration(self, resource: dict) -> dict:
        """Retrieve the configuration for a resource."""
        print(f"Collecting configuration for {resource}...")
        return {}