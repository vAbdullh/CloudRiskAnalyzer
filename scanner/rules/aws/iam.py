def check_key_older_than_90_days(config: dict) -> bool:
    row = config.get("credential_report_row", {})
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for key_num in ["1", "2"]:
        if row.get(f"access_key_{key_num}_active") == "true":
            rotated_str = row.get(f"access_key_{key_num}_last_rotated")
            if rotated_str and rotated_str != "N/A":
                try:
                    rotated = datetime.fromisoformat(rotated_str.replace("Z", "+00:00"))
                    if (now - rotated).days > 90:
                        return True
                except Exception:
                    pass
    return False


def check_key_unused_90_days(config: dict) -> bool:
    row = config.get("credential_report_row", {})
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for key_num in ["1", "2"]:
        if row.get(f"access_key_{key_num}_active") == "true":
            used_str = row.get(f"access_key_{key_num}_last_used_date")
            if used_str == "N/A":
                # If key has never been used, check rotation/creation date
                rotated_str = row.get(f"access_key_{key_num}_last_rotated")
                if rotated_str and rotated_str != "N/A":
                    try:
                        rotated = datetime.fromisoformat(rotated_str.replace("Z", "+00:00"))
                        if (now - rotated).days > 90:
                            return True
                    except Exception:
                        pass
            elif used_str:
                try:
                    used = datetime.fromisoformat(used_str.replace("Z", "+00:00"))
                    if (now - used).days > 90:
                        return True
                except Exception:
                    pass
    return False


def check_user_inactive_90_days(config: dict) -> bool:
    if config.get("is_root", False):
        return False
    row = config.get("credential_report_row", {})
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    last_active = None
    pwd_used = row.get("password_last_used")
    if pwd_used and pwd_used not in ["N/A", "no_information"]:
        try:
            last_active = datetime.fromisoformat(pwd_used.replace("Z", "+00:00"))
        except Exception:
            pass
            
    for key_num in ["1", "2"]:
        if row.get(f"access_key_{key_num}_active") == "true":
            key_used = row.get(f"access_key_{key_num}_last_used_date")
            if key_used and key_used != "N/A":
                try:
                    dt = datetime.fromisoformat(key_used.replace("Z", "+00:00"))
                    if last_active is None or dt > last_active:
                        last_active = dt
                except Exception:
                    pass
                    
    if last_active:
        return (now - last_active).days > 90
    return False


def check_policy_statement(doc: dict, match_fn) -> bool:
    if not isinstance(doc, dict):
        return False
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            if match_fn(stmt):
                return True
    return False


def check_admin_wildcard(config: dict) -> bool:
    def match_admin(stmt):
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        return "*" in actions and "*" in resources

    for p in config.get("attached_policies", []) + config.get("inline_policies", []):
        doc = p.get("PolicyDocument", {})
        if check_policy_statement(doc, match_admin):
            return True
    return False


def check_wildcard_service_permissions(config: dict) -> bool:
    def match_wildcard_service(stmt):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for act in actions:
            if act != "*" and act.endswith(":*"):
                return True
        return False

    for p in config.get("attached_policies", []) + config.get("inline_policies", []):
        doc = p.get("PolicyDocument", {})
        if check_policy_statement(doc, match_wildcard_service):
            return True
    return False


def check_privilege_escalation(config: dict) -> bool:
    escalation_actions = [
        "iam:passrole",
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:updateloginprofile",
        "iam:attachuserpolicy",
        "iam:attachrolepolicy",
        "iam:attachgrouppolicy",
        "iam:putuserpolicy",
        "iam:putrolepolicy",
        "iam:putgrouppolicy"
    ]
    def match_escalation(stmt):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for act in actions:
            act_lower = act.lower()
            if act_lower in escalation_actions or act_lower == "iam:*":
                return True
        return False

    for p in config.get("attached_policies", []) + config.get("inline_policies", []):
        doc = p.get("PolicyDocument", {})
        if check_policy_statement(doc, match_escalation):
            return True
    return False


def check_wildcard_principal_trust(config: dict) -> bool:
    if not config.get("is_role", False):
        return False
    doc = config.get("raw_data", {}).get("AssumeRolePolicyDocument", {})
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            principal = stmt.get("Principal", {})
            if principal == "*":
                return True
            if isinstance(principal, dict):
                for key, val in principal.items():
                    if val == "*":
                        return True
                    if isinstance(val, list) and "*" in val:
                        return True
    return False


def check_external_account_trust(config: dict) -> bool:
    if not config.get("is_role", False):
        return False
    doc = config.get("raw_data", {}).get("AssumeRolePolicyDocument", {})
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS", [])
                if isinstance(aws_principal, str):
                    aws_principal = [aws_principal]
                for p in aws_principal:
                    if "arn:aws:iam::" in p:
                        parts = p.split(":")
                        if len(parts) > 4:
                            target_account = parts[4]
                            role_arn = config.get("raw_data", {}).get("Arn", "")
                            role_parts = role_arn.split(":")
                            if len(role_parts) > 4:
                                self_account = role_parts[4]
                                if target_account != self_account:
                                    return True
    return False


def check_multiple_active_keys(config: dict) -> bool:
    row = config.get("credential_report_row", {})
    return row.get("access_key_1_active") == "true" and row.get("access_key_2_active") == "true"


RULES = [
    {
        "id": "IAM-001",
        "name": "Root Account Access Keys Active",
        "severity": "Critical",
        "description": "Root account has active access keys. Root keys are dangerous and cannot be restricted by IAM policies.",
        "recommendation": "Delete the root account access keys immediately and use IAM users/roles instead.",
        "r_base": 10.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: config.get("is_root", False) and (config.get("credential_report_row", {}).get("access_key_1_active") == "true" or config.get("credential_report_row", {}).get("access_key_2_active") == "true"),
    },
    {
        "id": "IAM-002",
        "name": "Root Account MFA Disabled",
        "severity": "Critical",
        "description": "Root account does not have Multi-Factor Authentication (MFA) enabled.",
        "recommendation": "Enable MFA on the root account immediately.",
        "r_base": 10.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: config.get("is_root", False) and config.get("credential_report_row", {}).get("mfa_active") == "false",
    },
    {
        "id": "IAM-003",
        "name": "User Direct Administrator Access",
        "severity": "Critical",
        "description": "IAM User has AdministratorAccess policy directly attached.",
        "recommendation": "Remove direct AdministratorAccess policy attachment and assign privileges via IAM Groups or Roles.",
        "r_base": 7.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.1,
        "check": lambda config: not config.get("is_root", False) and not config.get("is_role", False) and any(p.get("PolicyName") == "AdministratorAccess" for p in config.get("attached_policies", [])),
    },
    {
        "id": "IAM-004",
        "name": "Role has AdministratorAccess",
        "severity": "Critical",
        "description": "IAM Role has AdministratorAccess policy attached.",
        "recommendation": "Review this role's permissions and enforce least privilege restrictions.",
        "r_base": 7.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.1,
        "check": lambda config: config.get("is_role", False) and any(p.get("PolicyName") == "AdministratorAccess" for p in config.get("attached_policies", [])),
    },
    {
        "id": "IAM-005",
        "name": "IAM Policy Allows Full Admin Wildcards",
        "severity": "Critical",
        "description": "IAM policy allows Action:* and Resource:* (full admin rights).",
        "recommendation": "Specify explicit allowed actions and target resource ARNs.",
        "r_base": 7.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.1,
        "check": check_admin_wildcard,
    },
    {
        "id": "IAM-006",
        "name": "IAM Policy Allows Privilege Escalation",
        "severity": "Critical",
        "description": "IAM policy grants permissions that allow privilege escalation (e.g. PassRole, AttachRolePolicy).",
        "recommendation": "Restrict iam:PassRole and policy attachment actions to authorized admins only.",
        "r_base": 6.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.1,
        "check": check_privilege_escalation,
    },
    {
        "id": "IAM-007",
        "name": "IAM User Console Login without MFA",
        "severity": "High",
        "description": "IAM User has console login password active but Multi-Factor Authentication (MFA) is disabled.",
        "recommendation": "Enable MFA immediately for this user.",
        "r_base": 5.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: not config.get("is_root", False) and not config.get("is_role", False) and config.get("credential_report_row", {}).get("password_active") == "true" and config.get("credential_report_row", {}).get("mfa_active") == "false",
    },
    {
        "id": "IAM-008",
        "name": "IAM Access Key Older than 90 Days",
        "severity": "Warning",
        "description": "Active access key was created or rotated more than 90 days ago.",
        "recommendation": "Rotate your active access keys regularly (every 90 days).",
        "r_base": 3.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": check_key_older_than_90_days,
    },
    {
        "id": "IAM-009",
        "name": "Unused IAM Access Key",
        "severity": "Warning",
        "description": "Active access key has not been used to make API calls in the last 90 days.",
        "recommendation": "Deactivate or delete unused access keys to reduce the attack surface.",
        "r_base": 3.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": check_key_unused_90_days,
    },
    {
        "id": "IAM-010",
        "name": "Inactive IAM User",
        "severity": "Warning",
        "description": "IAM user has not used their password or access keys in the last 90 days.",
        "recommendation": "Deactivate and clean up inactive IAM users.",
        "r_base": 3.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": check_user_inactive_90_days,
    },
    {
        "id": "IAM-011",
        "name": "IAM Password Never Rotated",
        "severity": "Warning",
        "description": "IAM user password has never been rotated.",
        "recommendation": "Set a password rotation policy or rotate the password regularly.",
        "r_base": 3.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: not config.get("is_root", False) and not config.get("is_role", False) and config.get("credential_report_row", {}).get("password_active") == "true" and (config.get("credential_report_row", {}).get("password_last_changed") == "N/A" or config.get("credential_report_row", {}).get("password_last_changed") is None),
    },
    {
        "id": "IAM-012",
        "name": "Programmatic User Has Console Login",
        "severity": "High",
        "description": "User has both active Access Keys and a Console Password.",
        "recommendation": "Do not grant console login access to programmatic service accounts/users.",
        "r_base": 4.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: not config.get("is_root", False) and not config.get("is_role", False) and config.get("credential_report_row", {}).get("password_active") == "true" and (config.get("credential_report_row", {}).get("access_key_1_active") == "true" or config.get("credential_report_row", {}).get("access_key_2_active") == "true"),
    },
    {
        "id": "IAM-013",
        "name": "IAM Policy Wildcard Service Permissions",
        "severity": "High",
        "description": "IAM policy allows service-wide wildcards (e.g. ec2:* or s3:*).",
        "recommendation": "Refine policy actions to only the required API endpoints (e.g. s3:GetObject).",
        "r_base": 5.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": check_wildcard_service_permissions,
    },
    {
        "id": "IAM-014",
        "name": "Wildcard Principal in Role Trust",
        "severity": "Critical",
        "description": "IAM Role allows wildcard Principal (*) to assume it, making it publicly accessible.",
        "recommendation": "Restrict the Trust Relationship principal to specific trusted ARNs.",
        "r_base": 8.0,
        "exposure_factor": 1.5,
        "chain_multiplier": 1.2,
        "check": check_wildcard_principal_trust,
    },
    {
        "id": "IAM-015",
        "name": "IAM Role Trusts External AWS Account",
        "severity": "High",
        "description": "IAM Role trust relationship allows access from an external AWS account ID.",
        "recommendation": "Verify that this external account trust is authorized and uses an External ID.",
        "r_base": 5.0,
        "exposure_factor": 1.5,
        "chain_multiplier": 1.0,
        "check": check_external_account_trust,
    },
    {
        "id": "IAM-016",
        "name": "IAM User Inline Policy Attached",
        "severity": "Medium",
        "description": "IAM user has inline policies attached directly to their profile.",
        "recommendation": "Convert inline policies to IAM managed policies for better auditing and reuse.",
        "r_base": 2.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: len(config.get("inline_policies", [])) > 0,
    },
    {
        "id": "IAM-017",
        "name": "Multiple Active Access Keys",
        "severity": "Warning",
        "description": "IAM User has two active access keys.",
        "recommendation": "Limit users to one active key to reduce credential exposure.",
        "r_base": 2.5,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": check_multiple_active_keys,
    }
]
