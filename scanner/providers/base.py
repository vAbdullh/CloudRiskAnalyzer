from abc import ABC, abstractmethod


class BaseProvider(ABC):
    name = "BaseProvider"

    @abstractmethod
    def required_credentials(self) -> list[dict]:
        """Return a list of credential fields needed by this provider.

        Each entry is a dict with:
            - name  (str):   machine key, e.g. "access_key"
            - label (str):   human-readable prompt, e.g. "AWS Access Key ID"
            - secret (bool): True if the value should be masked on input
        """

    @abstractmethod
    def connect(self, credentials: dict) -> None:
        """Authenticate with the cloud provider using *credentials*."""

    @abstractmethod
    def validate_credentials(self) -> bool:
        """Verify the stored credentials are valid.

        Returns True when the provider can successfully reach the cloud
        API and confirm the caller's identity.
        """

    @abstractmethod
    def disconnect(self) -> None:
        """Release any resources / sessions held by the provider."""

    @abstractmethod
    def list_supported_resources(self) -> list[str]:
        """Return the resource type names this provider can scan."""

    @abstractmethod
    def discover_resources(self) -> list[dict]:
        """Discover all scannable resources in the target environment.

        Returns a list of resource dicts, each containing at minimum:
            - type (str):  resource type name
            - id   (str):  provider-specific unique identifier
            - name (str):  human-readable resource name
        """

    @abstractmethod
    def get_configuration(self, resource: dict) -> dict:
        """Retrieve the full configuration for a single *resource*.

        The returned dict should contain all fields needed by the
        security rules engine to evaluate the resource.
        """