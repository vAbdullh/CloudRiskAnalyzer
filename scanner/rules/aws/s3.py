RULES = [
    {
        "id": "S3-001",
        "name": "Public Bucket",
        "severity": "High",
        "description": "S3 bucket allows public access.",
        "recommendation": "Disable public access and review the bucket policy.",
        "r_base": 6.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.1,
        "check": lambda config: config.get("public", False),
    },
    {
        "id": "S3-002",
        "name": "Encryption Disabled",
        "severity": "Medium",
        "description": "S3 bucket encryption is disabled.",
        "recommendation": "Enable server-side encryption.",
        "r_base": 3.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: not config.get("encrypted", False),
    },
]