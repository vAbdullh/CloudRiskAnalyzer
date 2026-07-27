RULES = [
    {
        "id": "OCI-COMPUTE-001",
        "resource_type": "Compute",
        "name": "Instance with Public IP",
        "severity": "Medium",
        "description": "Compute instance has a public IP address and is exposed to the internet.",
        "recommendation": "Remove public IP attachment and use a bastion or private endpoint.",
        "r_base": 4.0,
        "exposure_factor": 1.5,
        "chain_multiplier": 1.1,
        "check": lambda config: any(
            vnic.get("public_ip") is not None
            for vnic in config.get("raw_data", {}).get("vnics", [])
        ),
    },
    {
        "id": "OCI-NET-001",
        "resource_type": "Subnet",
        "name": "Public Subnet Enabled",
        "severity": "Low",
        "description": "Subnet is public and allows public IP addresses on VNICs.",
        "recommendation": "Make the subnet private and route traffic through a NAT Gateway.",
        "r_base": 2.5,
        "exposure_factor": 1.5,
        "chain_multiplier": 1.0,
        "check": lambda config: not config.get("raw_data", {}).get("prohibit_public_ip_on_vnic", True),
    },
    {
        "id": "OCI-NET-002",
        "resource_type": "SecurityList",
        "name": "Public SSH Access Allowed",
        "severity": "High",
        "description": "Security List allows incoming SSH traffic (port 22) from all source IPs (0.0.0.0/0).",
        "recommendation": "Restrict source CIDR blocks to trusted IP addresses.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: any(
            r.get("source") == "0.0.0.0/0" and
            r.get("protocol") == "6" and
            r.get("tcp_options") is not None and
            r["tcp_options"].get("destination_port_range") is not None and
            r["tcp_options"]["destination_port_range"].get("min", 0) <= 22 <= r["tcp_options"]["destination_port_range"].get("max", 0)
            for r in config.get("raw_data", {}).get("ingress_security_rules", [])
        ),
    },
    {
        "id": "OCI-NET-003",
        "resource_type": "SecurityList",
        "name": "Public RDP Access Allowed",
        "severity": "High",
        "description": "Security List allows incoming RDP traffic (port 3389) from all source IPs (0.0.0.0/0).",
        "recommendation": "Restrict source CIDR blocks to trusted IP addresses.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: any(
            r.get("source") == "0.0.0.0/0" and
            r.get("protocol") == "6" and
            r.get("tcp_options") is not None and
            r["tcp_options"].get("destination_port_range") is not None and
            r["tcp_options"]["destination_port_range"].get("min", 0) <= 3389 <= r["tcp_options"]["destination_port_range"].get("max", 0)
            for r in config.get("raw_data", {}).get("ingress_security_rules", [])
        ),
    },
    {
        "id": "OCI-STORAGE-001",
        "resource_type": "ObjectStorage",
        "name": "Public Object Storage Bucket",
        "severity": "High",
        "description": "Object Storage bucket allows public access.",
        "recommendation": "Configure the bucket's public access type to 'NoPublicAccess'.",
        "r_base": 6.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.1,
        "check": lambda config: config.get("raw_data", {}).get("public_access_type") != "NoPublicAccess",
    },
    {
        "id": "OCI-STORAGE-002",
        "resource_type": "ObjectStorage",
        "name": "Bucket Customer-Managed Key Encryption Disabled",
        "severity": "Medium",
        "description": "Object Storage bucket is not encrypted using a Customer-Managed Key (KMS).",
        "recommendation": "Enable KMS Customer-Managed Key encryption on the bucket.",
        "r_base": 3.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: config.get("raw_data", {}).get("kms_key_id") is None,
    },
    {
        "id": "OCI-IAM-001",
        "resource_type": "IAM_Users",
        "name": "MFA Not Enabled for User",
        "severity": "High",
        "description": "IAM User does not have Multi-Factor Authentication (MFA) enabled.",
        "recommendation": "Enable MFA for the user under identity credentials.",
        "r_base": 5.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: not config.get("raw_data", {}).get("is_mfa_activated", False),
    },
    {
        "id": "OCI-IAM-002",
        "resource_type": "IAM_Users",
        "name": "Too Many Active API Keys",
        "severity": "Low",
        "description": "IAM User has more than 1 active API key.",
        "recommendation": "Delete or rotate unused API keys to reduce credential leak risks.",
        "r_base": 2.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: len(config.get("raw_data", {}).get("api_keys", [])) > 1,
    },
    {
        "id": "OCI-IAM-003",
        "resource_type": "IAM_Policies",
        "name": "Overly Permissive Policy",
        "severity": "High",
        "description": "IAM Policy contains statements that allow managing all resources.",
        "recommendation": "Restrict policy statements to follow the principle of least privilege.",
        "r_base": 7.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.1,
        "check": lambda config: any(
            "manage all-resources" in s.lower()
            for s in config.get("raw_data", {}).get("statements", [])
        ),
    }
]
