import oci
from oci.config import from_file, validate_config
from providers.base import BaseProvider

class OrcProvider(BaseProvider):
    name = "OCI (Oracle Cloud)"
    
    def __init__(self) -> None:
        """Initialize OCI provider instance variables."""
        self._config = None
        self._identity_client = None
        self._compute_client = None
        self._network_client = None
        self._object_storage_client = None
        self._tenancy_id = None
        self._compartment_id = None
        self._namespace = None

    def required_credentials(self) -> list[dict]:
        """Return the required credentials for OCI connection."""
        return []

    def connect(self, credentials: dict) -> None:
        """Connect to OCI using a local config file or manually entered credentials."""
        import os
        self._manually_entered = False
        
        use_config = input("Load OCI credentials from default config file (~/.oci/config)? (y/n): ").strip().lower()
        if use_config == 'y':
            try:
                self._config = from_file()
                validate_config(self._config)
            except Exception as exc:
                print(f"[OCI] Failed to load config file: {exc}")
                self._config = None
                return
        else:
            self._manually_entered = True
            print("\nPlease enter your OCI Credentials details manually:")
            user = input("user (OCID): ").strip()
            fingerprint = input("fingerprint: ").strip()
            tenancy = input("tenancy (OCID): ").strip()
            region = input("region: ").strip()
            key_file = input("key_file (path to private key file): ").strip()
            
            key_file = os.path.expanduser(key_file)
            
            self._config = {
                "user": user,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": region,
                "key_file": key_file
            }
            
            try:
                validate_config(self._config)
            except Exception as exc:
                print(f"[OCI] Provided config attributes are invalid: {exc}")
                self._config = None
                return

        self._tenancy_id = self._config["tenancy"]
        self._compartment_id = self._tenancy_id
        self.account_id = self._tenancy_id

        try:
            self._identity_client = oci.identity.IdentityClient(self._config)
        except Exception as exc:
            print(f"[OCI] Could not initialize Identity client: {exc}")

        try:
            self._compute_client = oci.core.ComputeClient(self._config)
        except Exception as exc:
            print(f"[OCI] Could not initialize Compute client: {exc}")

        try:
            self._network_client = oci.core.VirtualNetworkClient(self._config)
        except Exception as exc:
            print(f"[OCI] Could not initialize Network client: {exc}")

        try:
            self._object_storage_client = oci.object_storage.ObjectStorageClient(self._config)
        except Exception as exc:
            print(f"[OCI] Could not initialize Object Storage client: {exc}")

        try:
            self._namespace = self._object_storage_client.get_namespace().data
        except Exception as exc:
            print(f"[OCI] Could not fetch Object Storage namespace: {exc}")

        print(f"[OCI] Connected - tenancy: {self._tenancy_id}")

    def validate_credentials(self) -> bool:
        """Validate current OCI connection credentials by performing a test identity call."""
        if self._config is None or self._identity_client is None:
            print("[OCI] Not connected. Call connect() first.")
            return False

        try:
            user = self._identity_client.get_user(self._config["user"]).data
            print(f"[OCI] Authenticated as: {user.name} ({user.id})")
            
            if getattr(self, "_manually_entered", False):
                save_choice = input("\nSuccessfully authenticated! Save these credentials to ~/.oci/config? (y/n): ").strip().lower()
                if save_choice == 'y':
                    try:
                        import os
                        oci_dir = os.path.expanduser(os.path.join("~", ".oci"))
                        if not os.path.exists(oci_dir):
                            os.makedirs(oci_dir, mode=0o700)
                        
                        config_path = os.path.join(oci_dir, "config")
                        
                        config_content = f"""[DEFAULT]
user={self._config['user']}
fingerprint={self._config['fingerprint']}
key_file={self._config['key_file']}
tenancy={self._config['tenancy']}
region={self._config['region']}
"""
                        with open(config_path, "w") as f:
                            f.write(config_content)
                        
                        try:
                            os.chmod(config_path, 0o600)
                        except Exception:
                            pass
                            
                        print(f"[OCI] Credentials successfully saved to {config_path}")
                    except Exception as e:
                        print(f"[OCI] Failed to save config file: {e}")
                else:
                    print("[OCI] Running this session only without saving credentials.")
            return True
        except Exception as exc:
            print(f"[OCI] Connection validation failed: {exc}")
            return False

    def disconnect(self) -> None:
        """Disconnect and clear all loaded OCI client configurations."""
        self._identity_client = None
        self._compute_client = None
        self._network_client = None
        self._object_storage_client = None
        self._config = None
        self._tenancy_id = None
        self._compartment_id = None
        self._namespace = None
        print("[OCI] Disconnected.")

    def list_supported_resources(self) -> list[str]:
        """Return a list of resource types supported by this scanner provider."""
        return ["Compute", "VCN", "Subnet", "SecurityList", "ObjectStorage", "IAM_Users", "IAM_Policies"]

    def discover_resources(self) -> list[dict]:
        """Discover and list supported OCI resources across all accessible compartments."""
        compartments = [self._tenancy_id]
        try:
            #Listing all compartments in the tenancy and get the active ones
            all_comps = oci.pagination.list_call_get_all_results(
                self._identity_client.list_compartments,
                compartment_id=self._tenancy_id,
                compartment_id_in_subtree=True,
                access_level="ACCESSIBLE"
            ).data
            for comp in all_comps:
                if comp.lifecycle_state == "ACTIVE":
                    compartments.append(comp.id)
        except Exception as exc:
            print(f"[OCI] Error listing compartments: {exc}")

        print(f"[OCI] Found {len(compartments)} active compartments to scan.")

        resources = []
        resources.extend(self._discover_compute(compartments))
        resources.extend(self._discover_vcns(compartments))
        resources.extend(self._discover_subnets(compartments))
        resources.extend(self._discover_security_lists(compartments))
        resources.extend(self._discover_buckets(compartments))
        resources.extend(self._discover_iam_users())
        resources.extend(self._discover_iam_policies(compartments))

        print(f"[OCI] Discovered {len(resources)} resources across all compartments.")
        return resources

    def _discover_compute(self, compartments: list[str]) -> list[dict]:
        """Discover active Compute instances in the specified compartments."""
        results = []
        for cid in compartments:
            try:
                instances = oci.pagination.list_call_get_all_results(
                    self._compute_client.list_instances,
                    compartment_id=cid
                ).data
                for inst in instances:
                    if inst.lifecycle_state != "TERMINATED":
                        results.append({
                            "type": "Compute",
                            "id": inst.id,
                            "name": inst.display_name,
                            "compartment_id": cid
                        })
            except Exception as exc:
                print(f"[OCI] Error listing instances in compartment {cid}: {exc}")
        return results

    def _discover_vcns(self, compartments: list[str]) -> list[dict]:
        """Discover Virtual Cloud Networks (VCNs) in the specified compartments."""
        results = []
        for cid in compartments:
            try:
                vcns = oci.pagination.list_call_get_all_results(
                    self._network_client.list_vcns,
                    compartment_id=cid
                ).data
                for vcn in vcns:
                    results.append({
                        "type": "VCN",
                        "id": vcn.id,
                        "name": vcn.display_name,
                        "compartment_id": cid
                    })
            except Exception as exc:
                print(f"[OCI] Error listing VCNs in compartment {cid}: {exc}")
        return results

    def _discover_subnets(self, compartments: list[str]) -> list[dict]:
        """Discover Subnets in the specified compartments."""
        results = []
        for cid in compartments:
            try:
                subnets = oci.pagination.list_call_get_all_results(
                    self._network_client.list_subnets,
                    compartment_id=cid
                ).data
                for subnet in subnets:
                    results.append({
                        "type": "Subnet",
                        "id": subnet.id,
                        "name": subnet.display_name,
                        "vcn_id": subnet.vcn_id,
                        "compartment_id": cid
                    })
            except Exception as exc:
                print(f"[OCI] Error listing subnets in compartment {cid}: {exc}")
        return results

    def _discover_security_lists(self, compartments: list[str]) -> list[dict]:
        """Discover Security Lists in the specified compartments."""
        results = []
        for cid in compartments:
            try:
                sec_lists = oci.pagination.list_call_get_all_results(
                    self._network_client.list_security_lists,
                    compartment_id=cid
                ).data
                for sl in sec_lists:
                    results.append({
                        "type": "SecurityList",
                        "id": sl.id,
                        "name": sl.display_name,
                        "vcn_id": sl.vcn_id,
                        "compartment_id": cid
                    })
            except Exception as exc:
                print(f"[OCI] Error listing security lists in compartment {cid}: {exc}")
        return results

    def _discover_buckets(self, compartments: list[str]) -> list[dict]:
        """Discover Object Storage Buckets in the specified compartments."""
        results = []
        if not (self._object_storage_client and self._namespace):
            return results
        for cid in compartments:
            try:
                buckets = oci.pagination.list_call_get_all_results(
                    self._object_storage_client.list_buckets,
                    namespace_name=self._namespace,
                    compartment_id=cid
                ).data
                for bucket in buckets:
                    results.append({
                        "type": "ObjectStorage",
                        "id": bucket.name,
                        "name": bucket.name,
                        "namespace": self._namespace,
                        "compartment_id": cid
                    })
            except Exception as exc:
                print(f"[OCI] Error listing buckets in compartment {cid}: {exc}")
        return results

    def _discover_iam_users(self) -> list[dict]:
        """Discover IAM Users in the tenancy."""
        results = []
        try:
            users = oci.pagination.list_call_get_all_results(
                self._identity_client.list_users,
                compartment_id=self._tenancy_id
            ).data
            for user in users:
                results.append({
                    "type": "IAM_Users",
                    "id": user.id,
                    "name": user.name,
                    "compartment_id": self._tenancy_id
                })
        except Exception as exc:
            print(f"[OCI] Error listing IAM Users: {exc}")
        return results

    def _discover_iam_policies(self, compartments: list[str]) -> list[dict]:
        """Discover IAM Policies in the specified compartments."""
        results = []
        for cid in compartments:
            try:
                policies = oci.pagination.list_call_get_all_results(
                    self._identity_client.list_policies,
                    compartment_id=cid
                ).data
                for policy in policies:
                    results.append({
                        "type": "IAM_Policies",
                        "id": policy.id,
                        "name": policy.name,
                        "compartment_id": cid
                    })
            except Exception as exc:
                print(f"[OCI] Error listing IAM Policies in compartment {cid}: {exc}")
        return results

    def get_configuration(self, resource: dict) -> dict:
        """Collect detailed configuration settings for a given resource."""
        print(f"[OCI] Collecting configuration for {resource['type']}: {resource['name']}...")
        rtype = resource.get("type", "")
        cid = resource.get("compartment_id", self._compartment_id)

        dispatch = {
            "Compute": lambda: self._get_compute_config(resource, cid),
            "VCN": lambda: self._get_vcn_config(resource),
            "Subnet": lambda: self._get_subnet_config(resource),
            "SecurityList": lambda: self._get_security_list_config(resource),
            "ObjectStorage": lambda: self._get_bucket_config(resource),
            "IAM_Users": lambda: self._get_iam_user_config(resource),
            "IAM_Policies": lambda: self._get_iam_policy_config(resource)
        }

        handler = dispatch.get(rtype)
        if handler:
            return handler()

        return {
            "id": resource.get("id"),
            "name": resource.get("name"),
            "type": rtype
        }

    def _get_compute_config(self, resource, cid):
        """Retrieve detailed configuration for a Compute instance."""
        try:
            inst = self._compute_client.get_instance(resource["id"]).data
            vnic_attachments = oci.pagination.list_call_get_all_results(
                self._compute_client.list_vnic_attachments,
                compartment_id=cid,
                instance_id=inst.id
            ).data
            vnics = []
            for va in vnic_attachments:
                try:
                    vnic = self._network_client.get_vnic(va.vnic_id).data
                    vnics.append(oci.util.to_dict(vnic))
                except Exception:
                    pass
            raw_data = oci.util.to_dict(inst)
            raw_data["vnics"] = vnics
            return {
                "id": inst.id,
                "name": inst.display_name,
                "raw_data": raw_data
            }
        except Exception as exc:
            print(f"[OCI] Error getting compute config: {exc}")
            return {}

    def _get_vcn_config(self, resource):
        """Retrieve configuration details for a VCN."""
        try:
            vcn = self._network_client.get_vcn(resource["id"]).data
            return {
                "id": vcn.id,
                "name": vcn.display_name,
                "raw_data": oci.util.to_dict(vcn)
            }
        except Exception as exc:
            print(f"[OCI] Error getting VCN config: {exc}")
            return {}

    def _get_subnet_config(self, resource):
        """Retrieve configuration details for a Subnet."""
        try:
            subnet = self._network_client.get_subnet(resource["id"]).data
            return {
                "id": subnet.id,
                "name": subnet.display_name,
                "raw_data": oci.util.to_dict(subnet)
            }
        except Exception as exc:
            print(f"[OCI] Error getting Subnet config: {exc}")
            return {}

    def _get_security_list_config(self, resource):
        """Retrieve and parse security rules for a Security List."""
        try:
            sl = self._network_client.get_security_list(resource["id"]).data
            return {
                "id": sl.id,
                "name": sl.display_name,
                "raw_data": oci.util.to_dict(sl)
            }
        except Exception as exc:
            print(f"[OCI] Error getting SecurityList config: {exc}")
            return {}

    def _get_bucket_config(self, resource):
        """Retrieve configuration details for an Object Storage bucket."""
        try:
            bucket = self._object_storage_client.get_bucket(
                namespace_name=resource["namespace"],
                bucket_name=resource["name"]
            ).data
            return {
                "id": bucket.name,
                "name": bucket.name,
                "raw_data": oci.util.to_dict(bucket)
            }
        except Exception as exc:
            print(f"[OCI] Error getting Bucket config: {exc}")
            return {}

    def _get_iam_user_config(self, resource):
        """Retrieve configuration and API keys for an IAM User."""
        try:
            user = self._identity_client.get_user(resource["id"]).data
            api_keys = []
            try:
                api_keys_data = self._identity_client.list_api_keys(user_id=user.id).data
                api_keys = [oci.util.to_dict(key) for key in api_keys_data]
            except Exception:
                pass
            raw_data = oci.util.to_dict(user)
            raw_data["api_keys"] = api_keys
            return {
                "id": user.id,
                "name": user.name,
                "raw_data": raw_data
            }
        except Exception as exc:
            print(f"[OCI] Error getting IAM User config: {exc}")
            return {}

    def _get_iam_policy_config(self, resource):
        """Retrieve policy statements for an IAM Policy."""
        try:
            policy = self._identity_client.get_policy(resource["id"]).data
            return {
                "id": policy.id,
                "name": policy.name,
                "raw_data": oci.util.to_dict(policy)
            }
        except Exception as exc:
            print(f"[OCI] Error getting IAM Policy config: {exc}")
            return {}
