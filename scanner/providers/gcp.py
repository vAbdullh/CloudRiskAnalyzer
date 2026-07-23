"""
gcp.py
======

Google Cloud Platform provider for CloudRiskAnalyzer.

Implements resource discovery and configuration retrieval for GCP using the
official Google Cloud Python client libraries. This provider focuses on four
resource groups that commonly drive cloud misconfiguration risk:

    - Compute Engine  (VM instances)
    - Cloud Storage   (buckets)
    - IAM             (project service accounts + project IAM policy)
    - Firewall Rules  (VPC firewall configurations)

The output of `discover_resources()` and `get_configuration()` is intentionally
plain-Python (dicts, lists, str, bool, int) so that a downstream rules engine
can evaluate it without needing to understand GCP proto-plus objects.

Dependencies (add to requirements.txt):
    google-cloud-compute>=1.19.0
    google-cloud-storage>=2.16.0
    google-cloud-resource-manager>=1.12.0
    google-api-python-client>=2.130.0
    google-auth>=2.29.0
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import resourcemanager_v3
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from .base import BaseProvider

logger = logging.getLogger(__name__)


class GCPProvider(BaseProvider):
    """
    CloudRiskAnalyzer provider implementation for Google Cloud Platform.

    Usage:
        provider = GCPProvider()
        provider.connect({
            "project_id": "my-gcp-project",
            "service_account_key": "/path/to/service-account.json",
        })
        if provider.validate_credentials():
            resources = provider.discover_resources()
            for r in resources:
                config = provider.get_configuration(r)
    """

    name = "GCPProvider"

    # Resource type constants exposed to the rest of the scanner.
    TYPE_COMPUTE_INSTANCE = "Compute Engine"
    TYPE_STORAGE_BUCKET = "Cloud Storage"
    TYPE_IAM = "IAM"
    TYPE_FIREWALL_RULE = "Firewall Rules"

    # Scopes required for the operations this provider performs.
    _SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

    def __init__(self) -> None:
        self.project_id: Optional[str] = None
        self.credentials = None

        # GCP API clients — instantiated in connect()
        self._instances_client: Optional[compute_v1.InstancesClient] = None
        self._firewalls_client: Optional[compute_v1.FirewallsClient] = None
        self._storage_client: Optional[storage.Client] = None
        self._crm_client: Optional[resourcemanager_v3.ProjectsClient] = None
        self._iam_service = None  # googleapiclient discovery resource for IAM API

        self._connected = False

    # ------------------------------------------------------------------ #
    # BaseProvider: credential contract
    # ------------------------------------------------------------------ #

    def required_credentials(self) -> list[dict]:
        """
        Declares the credential fields CloudRiskAnalyzer must collect from the
        user (e.g. rendered as a form in the UI) before connect() is called.
        """
        return [
            {
                "key": "project_id",
                "label": "GCP Project ID",
                "type": "string",
                "required": True,
                "description": "The GCP project to scan, e.g. 'my-company-prod'.",
            },
            {
                "key": "service_account_key",
                "label": "Service Account Key File Path",
                "type": "file_path",
                "required": True,
                "description": (
                    "Path to a JSON key file for a service account with, at minimum, "
                    "'roles/viewer' and 'roles/iam.securityReviewer' on the target project."
                ),
            },
        ]

    # ------------------------------------------------------------------ #
    # BaseProvider: connection lifecycle
    # ------------------------------------------------------------------ #

    def connect(self, credentials: dict) -> None:
        """
        Establish authenticated GCP API clients using a service account key file.

        Args:
            credentials: dict containing 'project_id' and 'service_account_key'
                         (path to the JSON key file), as declared in
                         required_credentials().

        Raises:
            ValueError: if required credential fields are missing.
            GoogleAuthError: if the service account file is invalid or unreadable.
        """
        project_id = credentials.get("project_id")
        key_path = credentials.get("service_account_key")

        if not project_id or not key_path:
            raise ValueError(
                "GCPProvider.connect() requires both 'project_id' and "
                "'service_account_key' in the credentials dict."
            )

        try:
            self.credentials = service_account.Credentials.from_service_account_file(
                key_path, scopes=self._SCOPES
            )
        except (GoogleAuthError, FileNotFoundError, ValueError) as exc:
            logger.error("Failed to load GCP service account credentials: %s", exc)
            raise GoogleAuthError(f"Invalid service account key file: {exc}") from exc

        self.project_id = project_id

        try:
            self._instances_client = compute_v1.InstancesClient(credentials=self.credentials)
            self._firewalls_client = compute_v1.FirewallsClient(credentials=self.credentials)
            self._storage_client = storage.Client(
                project=self.project_id, credentials=self.credentials
            )
            self._crm_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            # IAM API (service accounts, project policy) via googleapiclient discovery,
            # since google-cloud-iam's high-level client coverage for project-level
            # service account listing is thinner than the discovery-based client.
            self._iam_service = discovery.build(
                "iam", "v1", credentials=self.credentials, cache_discovery=False
            )
        except Exception as exc:  # noqa: BLE001 - surface any client-init failure clearly
            logger.error("Failed to initialize GCP API clients: %s", exc)
            raise

        self._connected = True
        logger.info("GCPProvider connected to project '%s'.", self.project_id)

    def validate_credentials(self) -> bool:
        """
        Lightweight check that the current credentials are valid and have at
        least read access to the target project, via the Cloud Resource
        Manager API.

        Returns:
            True if credentials are valid and usable, False otherwise.
        """
        if not self._connected or self._crm_client is None or not self.project_id:
            logger.warning("validate_credentials() called before connect().")
            return False

        try:
            self._crm_client.get_project(name=f"projects/{self.project_id}")
            return True
        except gcp_exceptions.PermissionDenied:
            logger.error("Credentials valid but lack permission on project '%s'.", self.project_id)
            return False
        except gcp_exceptions.NotFound:
            logger.error("Project '%s' not found.", self.project_id)
            return False
        except GoogleAuthError as exc:
            logger.error("Credential validation failed (auth error): %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001 - validation must never raise
            logger.error("Unexpected error validating GCP credentials: %s", exc)
            return False

    def disconnect(self) -> None:
        """
        Release client references. GCP client libraries don't require explicit
        socket teardown, but we clear references so a stale provider instance
        can't be reused accidentally.
        """
        self._instances_client = None
        self._firewalls_client = None
        self._storage_client = None
        self._crm_client = None
        self._iam_service = None
        self.credentials = None
        self._connected = False
        logger.info("GCPProvider disconnected from project '%s'.", self.project_id)

    # ------------------------------------------------------------------ #
    # BaseProvider: resource inventory
    # ------------------------------------------------------------------ #

    def list_supported_resources(self) -> list[str]:
        """Returns the resource group names this provider knows how to scan."""
        return [
            self.TYPE_COMPUTE_INSTANCE,
            self.TYPE_STORAGE_BUCKET,
            self.TYPE_IAM,
            self.TYPE_FIREWALL_RULE,
        ]

    def discover_resources(self) -> list[dict]:
        """
        Enumerate resources across all four supported resource groups.

        Returns:
            A flat list of dicts: {"type": str, "id": str, "name": str}.
            Individual API failures (e.g. missing permissions on one service)
            are caught and logged so a single failing resource group doesn't
            abort discovery for the others.
        """
        self._require_connected()
        resources: list[dict] = []

        resources.extend(self._discover_compute_instances())
        resources.extend(self._discover_storage_buckets())
        resources.extend(self._discover_iam_service_accounts())
        resources.extend(self._discover_firewall_rules())

        logger.info("Discovered %d total resources in project '%s'.", len(resources), self.project_id)
        return resources

    def _discover_compute_instances(self) -> list[dict]:
        """List all Compute Engine instances across all zones in the project."""
        found: list[dict] = []
        try:
            request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            agg_list = self._instances_client.aggregated_list(request=request)
            for zone, response in agg_list:
                if not response.instances:
                    continue
                for instance in response.instances:
                    found.append(
                        {
                            "type": self.TYPE_COMPUTE_INSTANCE,
                            "id": str(instance.id),
                            "name": instance.name,
                            # extra hint used internally by get_configuration() to
                            # avoid re-deriving the zone from the instance id.
                            "_zone": zone.split("/")[-1],
                        }
                    )
        except gcp_exceptions.PermissionDenied as exc:
            logger.warning("Permission denied listing Compute instances: %s", exc)
        except gcp_exceptions.GoogleAPICallError as exc:
            logger.warning("API error listing Compute instances: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error listing Compute instances: %s", exc)
        return found

    def _discover_storage_buckets(self) -> list[dict]:
        """List all Cloud Storage buckets in the project."""
        found: list[dict] = []
        try:
            for bucket in self._storage_client.list_buckets():
                found.append(
                    {
                        "type": self.TYPE_STORAGE_BUCKET,
                        "id": bucket.id,
                        "name": bucket.name,
                    }
                )
        except gcp_exceptions.PermissionDenied as exc:
            logger.warning("Permission denied listing Storage buckets: %s", exc)
        except gcp_exceptions.GoogleAPICallError as exc:
            logger.warning("API error listing Storage buckets: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error listing Storage buckets: %s", exc)
        return found

    def _discover_iam_service_accounts(self) -> list[dict]:
        """List all IAM service accounts belonging to the project."""
        found: list[dict] = []
        try:
            request = (
                self._iam_service.projects()
                .serviceAccounts()
                .list(name=f"projects/{self.project_id}")
            )
            while request is not None:
                response = request.execute()
                for sa in response.get("accounts", []):
                    found.append(
                        {
                            "type": self.TYPE_IAM,
                            "id": sa.get("uniqueId", sa.get("email", "")),
                            "name": sa.get("email", sa.get("displayName", "unknown")),
                        }
                    )
                request = self._iam_service.projects().serviceAccounts().list_next(
                    previous_request=request, previous_response=response
                )
        except HttpError as exc:
            logger.warning("HTTP error listing IAM service accounts: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error listing IAM service accounts: %s", exc)

        # The project-level IAM policy itself is also treated as a scannable
        # "IAM" resource (e.g. to check for overly broad primitive role bindings).
        found.append(
            {
                "type": self.TYPE_IAM,
                "id": f"projects/{self.project_id}/iamPolicy",
                "name": f"{self.project_id} - Project IAM Policy",
                "_is_project_policy": True,
            }
        )
        return found

    def _discover_firewall_rules(self) -> list[dict]:
        """List all VPC firewall rules in the project."""
        found: list[dict] = []
        try:
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            for rule in self._firewalls_client.list(request=request):
                found.append(
                    {
                        "type": self.TYPE_FIREWALL_RULE,
                        "id": str(rule.id),
                        "name": rule.name,
                    }
                )
        except gcp_exceptions.PermissionDenied as exc:
            logger.warning("Permission denied listing firewall rules: %s", exc)
        except gcp_exceptions.GoogleAPICallError as exc:
            logger.warning("API error listing firewall rules: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error listing firewall rules: %s", exc)
        return found

    # ------------------------------------------------------------------ #
    # BaseProvider: configuration fetch
    # ------------------------------------------------------------------ #

    def get_configuration(self, resource: dict) -> dict:
        """
        Fetch the full configuration for a single previously-discovered
        resource and normalize it into a plain dict for the rules engine.

        Args:
            resource: a dict as returned by discover_resources(), containing
                      at least "type", "id", and "name".

        Returns:
            A dict of normalized configuration fields. On error, returns a
            dict with an "error" key rather than raising, so a scan of many
            resources can continue past individual failures.
        """
        self._require_connected()
        resource_type = resource.get("type")

        handlers = {
            self.TYPE_COMPUTE_INSTANCE: self._get_compute_instance_config,
            self.TYPE_STORAGE_BUCKET: self._get_storage_bucket_config,
            self.TYPE_IAM: self._get_iam_config,
            self.TYPE_FIREWALL_RULE: self._get_firewall_rule_config,
        }

        handler = handlers.get(resource_type)
        if handler is None:
            logger.error("Unsupported resource type for get_configuration(): %s", resource_type)
            return {"error": f"Unsupported resource type: {resource_type}"}

        try:
            return handler(resource)
        except Exception as exc:  # noqa: BLE001 - never let one bad resource kill a scan
            logger.error(
                "Failed to fetch configuration for %s '%s': %s",
                resource_type,
                resource.get("name"),
                exc,
            )
            return {"error": str(exc), "type": resource_type, "name": resource.get("name")}

    # -- Compute Engine ---------------------------------------------------

    def _get_compute_instance_config(self, resource: dict) -> dict:
        """Fetch and normalize a Compute Engine instance's configuration."""
        zone = resource.get("_zone")
        if not zone:
            raise ValueError(f"Missing zone for instance resource '{resource.get('name')}'.")

        instance = self._instances_client.get(
            project=self.project_id, zone=zone, instance=resource["name"]
        )

        has_external_ip = False
        network_interfaces = []
        for nic in instance.network_interfaces:
            external_ips = [ac.nat_i_p for ac in nic.access_configs if ac.nat_i_p]
            if external_ips:
                has_external_ip = True
            network_interfaces.append(
                {
                    "network": nic.network.split("/")[-1] if nic.network else None,
                    """
                    gcp.py
                    ======
        
                    Google Cloud Platform provider for CloudRiskAnalyzer.
        
                    Implements resource discovery and configuration retrieval for GCP using the
                    official Google Cloud Python client libraries. This provider focuses on four
                    resource groups that commonly drive cloud misconfiguration risk:
        
                        - Compute Engine  (VM instances)
                        - Cloud Storage   (buckets)
                        - IAM             (project service accounts + project IAM policy)
                        - Firewall Rules  (VPC firewall configurations)
        
                    The output of `discover_resources()` and `get_configuration()` is intentionally
                    plain-Python (dicts, lists, str, bool, int) so that a downstream rules engine
                    can evaluate it without needing to understand GCP proto-plus objects.
        
                    Dependencies (add to requirements.txt):
                        google-cloud-compute>=1.19.0
                        google-cloud-storage>=2.16.0
                        google-cloud-resource-manager>=1.12.0
                        google-api-python-client>=2.130.0
                        google-auth>=2.29.0
                    """

            from __future__ import annotations

            import logging
            from typing import Any, Optional

            from google.api_core import exceptions as gcp_exceptions
            from google.auth.exceptions import GoogleAuthError
            from google.oauth2 import service_account
            from google.cloud import compute_v1
            from google.cloud import storage
            from google.cloud import resourcemanager_v3
            from googleapiclient import discovery
            from googleapiclient.errors import HttpError

            from .base import BaseProvider

            logger = logging.getLogger(__name__)

            class GCPProvider(BaseProvider):
                """
                CloudRiskAnalyzer provider implementation for Google Cloud Platform.

                Usage:
                    provider = GCPProvider()
                    provider.connect({
                        "project_id": "my-gcp-project",
                        "service_account_key": "/path/to/service-account.json",
                    })
                    if provider.validate_credentials():
                        resources = provider.discover_resources()
                        for r in resources:
                            config = provider.get_configuration(r)
                """

                name = "GCPProvider"

                # Resource type constants exposed to the rest of the scanner.
                TYPE_COMPUTE_INSTANCE = "Compute Engine"
                TYPE_STORAGE_BUCKET = "Cloud Storage"
                TYPE_IAM = "IAM"
                TYPE_FIREWALL_RULE = "Firewall Rules"

                # Scopes required for the operations this provider performs.
                _SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

                def __init__(self) -> None:
                    self.project_id: Optional[str] = None
                    self.credentials = None

                    # GCP API clients — instantiated in connect()
                    self._instances_client: Optional[compute_v1.InstancesClient] = None
                    self._firewalls_client: Optional[compute_v1.FirewallsClient] = None
                    self._storage_client: Optional[storage.Client] = None
                    self._crm_client: Optional[resourcemanager_v3.ProjectsClient] = None
                    self._iam_service = None  # googleapiclient discovery resource for IAM API

                    self._connected = False

                # ------------------------------------------------------------------ #
                # BaseProvider: credential contract
                # ------------------------------------------------------------------ #

                def required_credentials(self) -> list[dict]:
                    """
                    Declares the credential fields CloudRiskAnalyzer must collect from the
                    user (e.g. rendered as a form in the UI) before connect() is called.
                    """
                    return [
                        {
                            "key": "project_id",
                            "label": "GCP Project ID",
                            "type": "string",
                            "required": True,
                            "description": "The GCP project to scan, e.g. 'my-company-prod'.",
                        },
                        {
                            "key": "service_account_key",
                            "label": "Service Account Key File Path",
                            "type": "file_path",
                            "required": True,
                            "description": (
                                "Path to a JSON key file for a service account with, at minimum, "
                                "'roles/viewer' and 'roles/iam.securityReviewer' on the target project."
                            ),
                        },
                    ]

                # ------------------------------------------------------------------ #
                # BaseProvider: connection lifecycle
                # ------------------------------------------------------------------ #

                def connect(self, credentials: dict) -> None:
                    """
                    Establish authenticated GCP API clients using a service account key file.

                    Args:
                        credentials: dict containing 'project_id' and 'service_account_key'
                                     (path to the JSON key file), as declared in
                                     required_credentials().

                    Raises:
                        ValueError: if required credential fields are missing.
                        GoogleAuthError: if the service account file is invalid or unreadable.
                    """
                    project_id = credentials.get("project_id")
                    key_path = credentials.get("service_account_key")

                    if not project_id or not key_path:
                        raise ValueError(
                            "GCPProvider.connect() requires both 'project_id' and "
                            "'service_account_key' in the credentials dict."
                        )

                    try:
                        self.credentials = service_account.Credentials.from_service_account_file(
                            key_path, scopes=self._SCOPES
                        )
                    except (GoogleAuthError, FileNotFoundError, ValueError) as exc:
                        logger.error("Failed to load GCP service account credentials: %s", exc)
                        raise GoogleAuthError(f"Invalid service account key file: {exc}") from exc

                    self.project_id = project_id

                    try:
                        self._instances_client = compute_v1.InstancesClient(credentials=self.credentials)
                        self._firewalls_client = compute_v1.FirewallsClient(credentials=self.credentials)
                        self._storage_client = storage.Client(
                            project=self.project_id, credentials=self.credentials
                        )
                        self._crm_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
                        # IAM API (service accounts, project policy) via googleapiclient discovery,
                        # since google-cloud-iam's high-level client coverage for project-level
                        # service account listing is thinner than the discovery-based client.
                        self._iam_service = discovery.build(
                            "iam", "v1", credentials=self.credentials, cache_discovery=False
                        )
                    except Exception as exc:  # noqa: BLE001 - surface any client-init failure clearly
                        logger.error("Failed to initialize GCP API clients: %s", exc)
                        raise

                    self._connected = True
                    logger.info("GCPProvider connected to project '%s'.", self.project_id)

                def validate_credentials(self) -> bool:
                    """
                    Lightweight check that the current credentials are valid and have at
                    least read access to the target project, via the Cloud Resource
                    Manager API.

                    Returns:
                        True if credentials are valid and usable, False otherwise.
                    """
                    if not self._connected or self._crm_client is None or not self.project_id:
                        logger.warning("validate_credentials() called before connect().")
                        return False

                    try:
                        self._crm_client.get_project(name=f"projects/{self.project_id}")
                        return True
                    except gcp_exceptions.PermissionDenied:
                        logger.error("Credentials valid but lack permission on project '%s'.", self.project_id)
                        return False
                    except gcp_exceptions.NotFound:
                        logger.error("Project '%s' not found.", self.project_id)
                        return False
                    except GoogleAuthError as exc:
                        logger.error("Credential validation failed (auth error): %s", exc)
                        return False
                    except Exception as exc:  # noqa: BLE001 - validation must never raise
                        logger.error("Unexpected error validating GCP credentials: %s", exc)
                        return False

                def disconnect(self) -> None:
                    """
                    Release client references. GCP client libraries don't require explicit
                    socket teardown, but we clear references so a stale provider instance
                    can't be reused accidentally.
                    """
                    self._instances_client = None
                    self._firewalls_client = None
                    self._storage_client = None
                    self._crm_client = None
                    self._iam_service = None
                    self.credentials = None
                    self._connected = False
                    logger.info("GCPProvider disconnected from project '%s'.", self.project_id)

                # ------------------------------------------------------------------ #
                # BaseProvider: resource inventory
                # ------------------------------------------------------------------ #

                def list_supported_resources(self) -> list[str]:
                    """Returns the resource group names this provider knows how to scan."""
                    return [
                        self.TYPE_COMPUTE_INSTANCE,
                        self.TYPE_STORAGE_BUCKET,
                        self.TYPE_IAM,
                        self.TYPE_FIREWALL_RULE,
                    ]

                def discover_resources(self) -> list[dict]:
                    """
                    Enumerate resources across all four supported resource groups.

                    Returns:
                        A flat list of dicts: {"type": str, "id": str, "name": str}.
                        Individual API failures (e.g. missing permissions on one service)
                        are caught and logged so a single failing resource group doesn't
                        abort discovery for the others.
                    """
                    self._require_connected()
                    resources: list[dict] = []

                    resources.extend(self._discover_compute_instances())
                    resources.extend(self._discover_storage_buckets())
                    resources.extend(self._discover_iam_service_accounts())
                    resources.extend(self._discover_firewall_rules())

                    logger.info("Discovered %d total resources in project '%s'.", len(resources), self.project_id)
                    return resources

                def _discover_compute_instances(self) -> list[dict]:
                    """List all Compute Engine instances across all zones in the project."""
                    found: list[dict] = []
                    try:
                        request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
                        agg_list = self._instances_client.aggregated_list(request=request)
                        for zone, response in agg_list:
                            if not response.instances:
                                continue
                            for instance in response.instances:
                                found.append(
                                    {
                                        "type": self.TYPE_COMPUTE_INSTANCE,
                                        "id": str(instance.id),
                                        "name": instance.name,
                                        # extra hint used internally by get_configuration() to
                                        # avoid re-deriving the zone from the instance id.
                                        "_zone": zone.split("/")[-1],
                                    }
                                )
                    except gcp_exceptions.PermissionDenied as exc:
                        logger.warning("Permission denied listing Compute instances: %s", exc)
                    except gcp_exceptions.GoogleAPICallError as exc:
                        logger.warning("API error listing Compute instances: %s", exc)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Unexpected error listing Compute instances: %s", exc)
                    return found

                def _discover_storage_buckets(self) -> list[dict]:
                    """List all Cloud Storage buckets in the project."""
                    found: list[dict] = []
                    try:
                        for bucket in self._storage_client.list_buckets():
                            found.append(
                                {
                                    "type": self.TYPE_STORAGE_BUCKET,
                                    "id": bucket.id,
                                    "name": bucket.name,
                                }
                            )
                    except gcp_exceptions.PermissionDenied as exc:
                        logger.warning("Permission denied listing Storage buckets: %s", exc)
                    except gcp_exceptions.GoogleAPICallError as exc:
                        logger.warning("API error listing Storage buckets: %s", exc)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Unexpected error listing Storage buckets: %s", exc)
                    return found

                def _discover_iam_service_accounts(self) -> list[dict]:
                    """List all IAM service accounts belonging to the project."""
                    found: list[dict] = []
                    try:
                        request = (
                            self._iam_service.projects()
                            .serviceAccounts()
                            .list(name=f"projects/{self.project_id}")
                        )
                        while request is not None:
                            response = request.execute()
                            for sa in response.get("accounts", []):
                                found.append(
                                    {
                                        "type": self.TYPE_IAM,
                                        "id": sa.get("uniqueId", sa.get("email", "")),
                                        "name": sa.get("email", sa.get("displayName", "unknown")),
                                    }
                                )
                            request = self._iam_service.projects().serviceAccounts().list_next(
                                previous_request=request, previous_response=response
                            )
                    except HttpError as exc:
                        logger.warning("HTTP error listing IAM service accounts: %s", exc)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Unexpected error listing IAM service accounts: %s", exc)

                    # The project-level IAM policy itself is also treated as a scannable
                    # "IAM" resource (e.g. to check for overly broad primitive role bindings).
                    found.append(
                        {
                            "type": self.TYPE_IAM,
                            "id": f"projects/{self.project_id}/iamPolicy",
                            "name": f"{self.project_id} - Project IAM Policy",
                            "_is_project_policy": True,
                        }
                    )
                    return found

                def _discover_firewall_rules(self) -> list[dict]:
                    """List all VPC firewall rules in the project."""
                    found: list[dict] = []
                    try:
                        request = compute_v1.ListFirewallsRequest(project=self.project_id)
                        for rule in self._firewalls_client.list(request=request):
                            found.append(
                                {
                                    "type": self.TYPE_FIREWALL_RULE,
                                    "id": str(rule.id),
                                    "name": rule.name,
                                }
                            )
                    except gcp_exceptions.PermissionDenied as exc:
                        logger.warning("Permission denied listing firewall rules: %s", exc)
                    except gcp_exceptions.GoogleAPICallError as exc:
                        logger.warning("API error listing firewall rules: %s", exc)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Unexpected error listing firewall rules: %s", exc)
                    return found

                # ------------------------------------------------------------------ #
                # BaseProvider: configuration fetch
                # ------------------------------------------------------------------ #

                def get_configuration(self, resource: dict) -> dict:
                    """
                    Fetch the full configuration for a single previously-discovered
                    resource and normalize it into a plain dict for the rules engine.

                    Args:
                        resource: a dict as returned by discover_resources(), containing
                                  at least "type", "id", and "name".

                    Returns:
                        A dict of normalized configuration fields. On error, returns a
                        dict with an "error" key rather than raising, so a scan of many
                        resources can continue past individual failures.
                    """
                    self._require_connected()
                    resource_type = resource.get("type")

                    handlers = {
                        self.TYPE_COMPUTE_INSTANCE: self._get_compute_instance_config,
                        self.TYPE_STORAGE_BUCKET: self._get_storage_bucket_config,
                        self.TYPE_IAM: self._get_iam_config,
                        self.TYPE_FIREWALL_RULE: self._get_firewall_rule_config,
                    }

                    handler = handlers.get(resource_type)
                    if handler is None:
                        logger.error("Unsupported resource type for get_configuration(): %s", resource_type)
                        return {"error": f"Unsupported resource type: {resource_type}"}

                    try:
                        return handler(resource)
                    except Exception as exc:  # noqa: BLE001 - never let one bad resource kill a scan
                        logger.error(
                            "Failed to fetch configuration for %s '%s': %s",
                            resource_type,
                            resource.get("name"),
                            exc,
                        )
                        return {"error": str(exc), "type": resource_type, "name": resource.get("name")}

                # -- Compute Engine ---------------------------------------------------

                def _get_compute_instance_config(self, resource: dict) -> dict:
                    """Fetch and normalize a Compute Engine instance's configuration."""
                    zone = resource.get("_zone")
                    if not zone:
                        raise ValueError(f"Missing zone for instance resource '{resource.get('name')}'.")

                    instance = self._instances_client.get(
                        project=self.project_id, zone=zone, instance=resource["name"]
                    )

                    has_external_ip = False
                    network_interfaces = []
                    for nic in instance.network_interfaces:
                        external_ips = [ac.nat_i_p for ac in nic.access_configs if ac.nat_i_p]
                        if external_ips:
                            has_external_ip = True
                        network_interfaces.append(
                            {
                                "network": nic.network.split("/")[-1] if nic.network else None,
                                "internal_ip": nic.network_i_p,
                                "external_ips": external_ips,
                            }
                        )

                    service_accounts = [
                        {"email": sa.email, "scopes": list(sa.scopes)} for sa in instance.service_accounts
                    ]

                    disks = [
                        {
                            "device_name": disk.device_name,
                            "boot": disk.boot,
                            "auto_delete": disk.auto_delete,
                            "encrypted_with_csek": bool(disk.disk_encryption_key.sha256),
                        }
                        for disk in instance.disks
                    ]

                    return {
                        "type": self.TYPE_COMPUTE_INSTANCE,
                        "id": str(instance.id),
                        "name": instance.name,
                        "zone": zone,
                        "machine_type": instance.machine_type.split("/")[-1] if instance.machine_type else None,
                        "status": instance.status,
                        "has_external_ip": has_external_ip,
                        "network_interfaces": network_interfaces,
                        "service_accounts": service_accounts,
                        "disks": disks,
                        "shielded_vm_config": {
                            "enable_secure_boot": instance.shielded_instance_config.enable_secure_boot,
                            "enable_vtpm": instance.shielded_instance_config.enable_vtpm,
                            "enable_integrity_monitoring": (
                                instance.shielded_instance_config.enable_integrity_monitoring
                            ),
                        },
                        "can_ip_forward": instance.can_ip_forward,
                        "labels": dict(instance.labels) if instance.labels else {},
                        "metadata_serial_port_enabled": self._serial_port_enabled(instance),
                    }

                @staticmethod
                def _serial_port_enabled(instance) -> bool:
                    """Checks instance metadata for 'serial-port-enable' set to a truthy value."""
                    for item in instance.metadata.items:
                        if item.key == "serial-port-enable" and item.value.strip().lower() in ("true", "1"):
                            return True
                    return False

                # -- Cloud Storage ------------------------------------------------------

                def _get_storage_bucket_config(self, resource: dict) -> dict:
                    """Fetch and normalize a Cloud Storage bucket's configuration."""
                    bucket = self._storage_client.get_bucket(resource["name"])

                    # Determine public accessibility via the bucket's IAM policy.
                    is_public = False
                    try:
                        policy = bucket.get_iam_policy(requested_policy_version=3)
                        for binding in policy.bindings:
                            members = binding.get("members", [])
                            if "allUsers" in members or "allAuthenticatedUsers" in members:
                                is_public = True
                                break
                    except gcp_exceptions.PermissionDenied:
                        logger.warning("Permission denied reading IAM policy for bucket '%s'.", bucket.name)

                    encryption_type = "google-managed"
                    if bucket.default_kms_key_name:
                        encryption_type = "customer-managed (CMEK)"

                    return {
                        "type": self.TYPE_STORAGE_BUCKET,
                        "id": bucket.id,
                        "name": bucket.name,
                        "location": bucket.location,
                        "storage_class": bucket.storage_class,
                        "is_public": is_public,
                        "uniform_bucket_level_access": bool(
                            bucket.iam_configuration.uniform_bucket_level_access_enabled
                        ),
                        "public_access_prevention": getattr(
                            bucket.iam_configuration, "public_access_prevention", None
                        ),
                        "versioning_enabled": bucket.versioning_enabled,
                        "encryption_type": encryption_type,
                        "retention_policy_locked": bool(
                            bucket.retention_policy and bucket.retention_policy.get("isLocked")
                        ),
                        "logging_enabled": bool(bucket.logging),
                        "labels": dict(bucket.labels) if bucket.labels else {},
                    }

                # -- IAM ------------------------------------------------------------

                def _get_iam_config(self, resource: dict) -> dict:
                    """
                    Fetch and normalize IAM configuration. Handles both individual
                    service accounts and the project-level IAM policy, distinguished by
                    the '_is_project_policy' flag set during discovery.
                    """
                    if resource.get("_is_project_policy"):
                        return self._get_project_iam_policy_config(resource)
                    return self._get_service_account_config(resource)

                def _get_service_account_config(self, resource: dict) -> dict:
                    """Fetch details for a single IAM service account, including keys."""
                    sa_name = f"projects/{self.project_id}/serviceAccounts/{resource['name']}"
                    sa = self._iam_service.projects().serviceAccounts().get(name=sa_name).execute()

                    keys_response = (
                        self._iam_service.projects().serviceAccounts().keys().list(name=sa_name).execute()
                    )
                    user_managed_keys = [
                        {
                            "key_id": key.get("name", "").split("/")[-1],
                            "key_type": key.get("keyType"),
                            "valid_after": key.get("validAfterTime"),
                            "valid_before": key.get("validBeforeTime"),
                        }
                        for key in keys_response.get("keys", [])
                        if key.get("keyType") == "USER_MANAGED"
                    ]

                    return {
                        "type": self.TYPE_IAM,
                        "subtype": "service_account",
                        "id": sa.get("uniqueId"),
                        "name": sa.get("email"),
                        "display_name": sa.get("displayName"),
                        "disabled": sa.get("disabled", False),
                        "user_managed_key_count": len(user_managed_keys),
                        "user_managed_keys": user_managed_keys,
                    }

                def _get_project_iam_policy_config(self, resource: dict) -> dict:
                    """Fetch and normalize the project-level IAM policy bindings."""
                    policy = self._crm_client.get_iam_policy(
                        request={"resource": f"projects/{self.project_id}"}
                    )

                    bindings = []
                    has_public_binding = False
                    has_primitive_role_binding = False

                    for binding in policy.bindings:
                        members = list(binding.members)
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            has_public_binding = True
                        if binding.role in ("roles/owner", "roles/editor", "roles/viewer"):
                            has_primitive_role_binding = True
                        bindings.append({"role": binding.role, "members": members})

                    return {
                        "type": self.TYPE_IAM,
                        "subtype": "project_iam_policy",
                        "id": resource["id"],
                        "name": resource["name"],
                        "bindings": bindings,
                        "has_public_binding": has_public_binding,
                        "has_primitive_role_binding": has_primitive_role_binding,
                        "binding_count": len(bindings),
                    }

                # -- Firewall Rules ---------------------------------------------------

                def _get_firewall_rule_config(self, resource: dict) -> dict:
                    """Fetch and normalize a VPC firewall rule's configuration."""
                    rule = self._firewalls_client.get(project=self.project_id, firewall=resource["name"])

                    source_ranges = list(rule.source_ranges)
                    is_open_to_internet = "0.0.0.0/0" in source_ranges

                    allowed = [
                        {"protocol": a.I_p_protocol, "ports": list(a.ports)} for a in rule.allowed
                    ]
                    denied = [
                        {"protocol": d.I_p_protocol, "ports": list(d.ports)} for d in rule.denied
                    ]

                    risky_open_ports = []
                    if is_open_to_internet:
                        sensitive_ports = {"22", "3389", "3306", "5432", "1433", "6379", "27017"}
                        for rule_entry in allowed:
                            ports = rule_entry["ports"] or []
                            # An empty ports list on an "allow" entry with protocol tcp/udp/all
                            # means all ports are allowed for that protocol.
                            if not ports and rule_entry["protocol"] in ("tcp", "udp", "all"):
                                risky_open_ports.append("ALL")
                            else:
                                risky_open_ports.extend(p for p in ports if p in sensitive_ports)

                    return {
                        "type": self.TYPE_FIREWALL_RULE,
                        "id": str(rule.id),
                        "name": rule.name,
                        "network": rule.network.split("/")[-1] if rule.network else None,
                        "direction": rule.direction,
                        "disabled": rule.disabled,
                        "priority": rule.priority,
                        "source_ranges": source_ranges,
                        "target_tags": list(rule.target_tags),
                        "is_open_to_internet": is_open_to_internet,
                        "allowed": allowed,
                        "denied": denied,
                        "risky_open_ports": sorted(set(risky_open_ports)),
                    }

                # ------------------------------------------------------------------ #
                # Internal helpers
                # ------------------------------------------------------------------ #

                def _require_connected(self) -> None:
                    """Guard used by discovery/config methods to fail fast with a clear error."""
                    if not self._connected:
                        raise RuntimeError(
                            "GCPProvider is not connected. Call connect(credentials) before "
                            "discover_resources() or get_configuration()."
                        )
                    "internal_ip": nic.network_i_p,
                    "external_ips": external_ips,
                }
            )

        service_accounts = [
            {"email": sa.email, "scopes": list(sa.scopes)} for sa in instance.service_accounts
        ]

        disks = [
            {
                "device_name": disk.device_name,
                "boot": disk.boot,
                "auto_delete": disk.auto_delete,
                "encrypted_with_csek": bool(disk.disk_encryption_key.sha256),
            }
            for disk in instance.disks
        ]

        return {
            "type": self.TYPE_COMPUTE_INSTANCE,
            "id": str(instance.id),
            "name": instance.name,
            "zone": zone,
            "machine_type": instance.machine_type.split("/")[-1] if instance.machine_type else None,
            "status": instance.status,
            "has_external_ip": has_external_ip,
            "network_interfaces": network_interfaces,
            "service_accounts": service_accounts,
            "disks": disks,
            "shielded_vm_config": {
                "enable_secure_boot": instance.shielded_instance_config.enable_secure_boot,
                "enable_vtpm": instance.shielded_instance_config.enable_vtpm,
                "enable_integrity_monitoring": (
                    instance.shielded_instance_config.enable_integrity_monitoring
                ),
            },
            "can_ip_forward": instance.can_ip_forward,
            "labels": dict(instance.labels) if instance.labels else {},
            "metadata_serial_port_enabled": self._serial_port_enabled(instance),
        }

    @staticmethod
    def _serial_port_enabled(instance) -> bool:
        """Checks instance metadata for 'serial-port-enable' set to a truthy value."""
        for item in instance.metadata.items:
            if item.key == "serial-port-enable" and item.value.strip().lower() in ("true", "1"):
                return True
        return False

    # -- Cloud Storage ------------------------------------------------------

    def _get_storage_bucket_config(self, resource: dict) -> dict:
        """Fetch and normalize a Cloud Storage bucket's configuration."""
        bucket = self._storage_client.get_bucket(resource["name"])

        # Determine public accessibility via the bucket's IAM policy.
        is_public = False
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    is_public = True
                    break
        except gcp_exceptions.PermissionDenied:
            logger.warning("Permission denied reading IAM policy for bucket '%s'.", bucket.name)

        encryption_type = "google-managed"
        if bucket.default_kms_key_name:
            encryption_type = "customer-managed (CMEK)"

        return {
            "type": self.TYPE_STORAGE_BUCKET,
            "id": bucket.id,
            "name": bucket.name,
            "location": bucket.location,
            "storage_class": bucket.storage_class,
            "is_public": is_public,
            "uniform_bucket_level_access": bool(
                bucket.iam_configuration.uniform_bucket_level_access_enabled
            ),
            "public_access_prevention": getattr(
                bucket.iam_configuration, "public_access_prevention", None
            ),
            "versioning_enabled": bucket.versioning_enabled,
            "encryption_type": encryption_type,
            "retention_policy_locked": bool(
                bucket.retention_policy and bucket.retention_policy.get("isLocked")
            ),
            "logging_enabled": bool(bucket.logging),
            "labels": dict(bucket.labels) if bucket.labels else {},
        }

    # -- IAM ------------------------------------------------------------

    def _get_iam_config(self, resource: dict) -> dict:
        """
        Fetch and normalize IAM configuration. Handles both individual
        service accounts and the project-level IAM policy, distinguished by
        the '_is_project_policy' flag set during discovery.
        """
        if resource.get("_is_project_policy"):
            return self._get_project_iam_policy_config(resource)
        return self._get_service_account_config(resource)

    def _get_service_account_config(self, resource: dict) -> dict:
        """Fetch details for a single IAM service account, including keys."""
        sa_name = f"projects/{self.project_id}/serviceAccounts/{resource['name']}"
        sa = self._iam_service.projects().serviceAccounts().get(name=sa_name).execute()

        keys_response = (
            self._iam_service.projects().serviceAccounts().keys().list(name=sa_name).execute()
        )
        user_managed_keys = [
            {
                "key_id": key.get("name", "").split("/")[-1],
                "key_type": key.get("keyType"),
                "valid_after": key.get("validAfterTime"),
                "valid_before": key.get("validBeforeTime"),
            }
            for key in keys_response.get("keys", [])
            if key.get("keyType") == "USER_MANAGED"
        ]

        return {
            "type": self.TYPE_IAM,
            "subtype": "service_account",
            "id": sa.get("uniqueId"),
            "name": sa.get("email"),
            "display_name": sa.get("displayName"),
            "disabled": sa.get("disabled", False),
            "user_managed_key_count": len(user_managed_keys),
            "user_managed_keys": user_managed_keys,
        }

    def _get_project_iam_policy_config(self, resource: dict) -> dict:
        """Fetch and normalize the project-level IAM policy bindings."""
        policy = self._crm_client.get_iam_policy(
            request={"resource": f"projects/{self.project_id}"}
        )

        bindings = []
        has_public_binding = False
        has_primitive_role_binding = False

        for binding in policy.bindings:
            members = list(binding.members)
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                has_public_binding = True
            if binding.role in ("roles/owner", "roles/editor", "roles/viewer"):
                has_primitive_role_binding = True
            bindings.append({"role": binding.role, "members": members})

        return {
            "type": self.TYPE_IAM,
            "subtype": "project_iam_policy",
            "id": resource["id"],
            "name": resource["name"],
            "bindings": bindings,
            "has_public_binding": has_public_binding,
            "has_primitive_role_binding": has_primitive_role_binding,
            "binding_count": len(bindings),
        }

    # -- Firewall Rules ---------------------------------------------------

    def _get_firewall_rule_config(self, resource: dict) -> dict:
        """Fetch and normalize a VPC firewall rule's configuration."""
        rule = self._firewalls_client.get(project=self.project_id, firewall=resource["name"])

        source_ranges = list(rule.source_ranges)
        is_open_to_internet = "0.0.0.0/0" in source_ranges

        allowed = [
            {"protocol": a.I_p_protocol, "ports": list(a.ports)} for a in rule.allowed
        ]
        denied = [
            {"protocol": d.I_p_protocol, "ports": list(d.ports)} for d in rule.denied
        ]

        risky_open_ports = []
        if is_open_to_internet:
            sensitive_ports = {"22", "3389", "3306", "5432", "1433", "6379", "27017"}
            for rule_entry in allowed:
                ports = rule_entry["ports"] or []
                # An empty ports list on an "allow" entry with protocol tcp/udp/all
                # means all ports are allowed for that protocol.
                if not ports and rule_entry["protocol"] in ("tcp", "udp", "all"):
                    risky_open_ports.append("ALL")
                else:
                    risky_open_ports.extend(p for p in ports if p in sensitive_ports)

        return {
            "type": self.TYPE_FIREWALL_RULE,
            "id": str(rule.id),
            "name": rule.name,
            "network": rule.network.split("/")[-1] if rule.network else None,
            "direction": rule.direction,
            "disabled": rule.disabled,
            "priority": rule.priority,
            "source_ranges": source_ranges,
            "target_tags": list(rule.target_tags),
            "is_open_to_internet": is_open_to_internet,
            "allowed": allowed,
            "denied": denied,
            "risky_open_ports": sorted(set(risky_open_ports)),
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _require_connected(self) -> None:
        """Guard used by discovery/config methods to fail fast with a clear error."""
        if not self._connected:
            raise RuntimeError(
                "GCPProvider is not connected. Call connect(credentials) before "
                "discover_resources() or get_configuration()."
            )