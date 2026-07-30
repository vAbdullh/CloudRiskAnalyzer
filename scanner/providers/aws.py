import boto3
from botocore.exceptions import ClientError
from providers.base import BaseProvider


class AWSProvider(BaseProvider):
    name = "AWS"

    def __init__(self):
        super().__init__()
        self._session = None
        self.access_key = None
        self.secret_key = None
        self.region = None
        self._credential_report = None

    def required_credentials(self) -> list[dict]:
        """Return the credentials required by this provider."""
        return [
            {
                "name": "access_key",
                "label": "AWS Access Key ID",
                "secret": False,
            },
            {
                "name": "secret_key",
                "label": "AWS Secret Access Key",
                "secret": True,
            },
            {
                "name": "region",
                "label": "AWS Region",
                "secret": False,
            },
        ]

    def connect(self, credentials: dict) -> None:
        """Authenticate with AWS and load the account-wide credential report."""
        self.access_key = credentials.get("access_key")
        self.secret_key = credentials.get("secret_key")
        self.region = credentials.get("region")

        self._session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
        )
        print("[AWS] Initialized connection session.")

        # Generate and fetch credential report
        try:
            iam_client = self._session.client("iam")
            print("[AWS] Generating credential report...")
            iam_client.generate_credential_report()
            
            import time
            import csv
            import io
            
            for _ in range(5):
                try:
                    report_resp = iam_client.get_credential_report()
                    report_csv = report_resp["Content"].decode("utf-8")
                    reader = csv.DictReader(io.StringIO(report_csv))
                    self._credential_report = list(reader)
                    print("[AWS] Credential report loaded successfully.")
                    break
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ReportInProgress":
                        time.sleep(1)
                    else:
                        raise e
        except Exception as e:
            print(f"[AWS] Failed to generate/load credential report: {e}")

    def validate_credentials(self) -> bool:
        """Verify the provided credentials using STS get_caller_identity."""
        if self._session is None:
            print("[AWS] Not connected. Call connect() first.")
            return False
        try:
            sts_client = self._session.client("sts")
            identity = sts_client.get_caller_identity()
            self.account_id = identity.get("Account")
            print(f"[AWS] Authenticated as Account: {self.account_id}")
            return True
        except ClientError as err:
            print(f"[AWS] Connection validation failed: {err}")
            return False
        except Exception as err:
            print(f"[AWS] Unexpected validation error: {err}")
            return False

    def disconnect(self) -> None:
        """Close the connection and clear stored credentials."""
        self._session = None
        self.access_key = None
        self.secret_key = None
        self.region = None
        self.account_id = None
        self._credential_report = None
        print("[AWS] Disconnected.")

    def list_supported_resources(self) -> list[str]:
        """Return supported AWS resource types."""
        return [
            "EC2",
            "S3",
            "IAM",
            "Security Groups",
        ]

    def discover_resources(self) -> list[dict]:
        """Discover all scannable resources in the target environment."""
        if self._session is None:
            print("[AWS] Not connected. Call connect() first.")
            return []

        resources = []
        print("[AWS] Starting resource discovery...")

        # 1. Discover EC2 Instances
        try:
            ec2_client = self._session.client("ec2")
            response = ec2_client.describe_instances()
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    name = instance_id
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break
                    resources.append({
                        "type": "EC2",
                        "id": instance_id,
                        "name": name
                    })
        except ClientError as err:
            print(f"[AWS] Failed to discover EC2 resources: {err.response['Error']['Message']}")
        except Exception as err:
            print(f"[AWS] Unexpected error discovering EC2 resources: {err}")

        # 2. Discover Security Groups
        try:
            ec2_client = self._session.client("ec2")
            response = ec2_client.describe_security_groups()
            for sg in response.get("SecurityGroups", []):
                resources.append({
                    "type": "Security Groups",
                    "id": sg["GroupId"],
                    "name": sg["GroupName"]
                })
        except ClientError as err:
            print(f"[AWS] Failed to discover Security Groups: {err.response['Error']['Message']}")
        except Exception as err:
            print(f"[AWS] Unexpected error discovering Security Groups: {err}")

        # 3. Discover S3 Buckets
        try:
            s3_client = self._session.client("s3")
            response = s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                resources.append({
                    "type": "S3",
                    "id": bucket_name,
                    "name": bucket_name
                })
        except ClientError as err:
            print(f"[AWS] Failed to discover S3 resources: {err.response['Error']['Message']}")
        except Exception as err:
            print(f"[AWS] Unexpected error discovering S3 resources: {err}")

        # 4. Discover IAM Users
        try:
            iam_client = self._session.client("iam")
            response = iam_client.list_users()
            for user in response.get("Users", []):
                username = user["UserName"]
                resources.append({
                    "type": "IAM",
                    "id": user["UserId"],
                    "name": username
                })
        except ClientError as err:
            print(f"[AWS] Failed to discover IAM resources: {err.response['Error']['Message']}")
        except Exception as err:
            print(f"[AWS] Unexpected error discovering IAM resources: {err}")

        # 5. Discover Root Account
        resources.append({
            "type": "IAM",
            "id": "<root_account>",
            "name": "<root_account>"
        })

        # 6. Discover IAM Roles
        try:
            iam_client = self._session.client("iam")
            response = iam_client.list_roles()
            for role in response.get("Roles", []):
                role_name = role["RoleName"]
                if "/aws-service-role/" in role.get("Path", ""):
                    continue
                resources.append({
                    "type": "IAM Role",
                    "id": role["RoleId"],
                    "name": role_name
                })
        except ClientError as err:
            print(f"[AWS] Failed to discover IAM Roles: {err.response['Error']['Message']}")
        except Exception as err:
            print(f"[AWS] Unexpected error discovering IAM Roles: {err}")

        print(f"[AWS] Discovered {len(resources)} resources.")
        return resources

    def get_configuration(self, resource: dict) -> dict:
        """Retrieve the configuration for a resource."""
        if self._session is None:
            print("[AWS] Not connected. Call connect() first.")
            return {}

        resource_type = resource.get("type")
        resource_id = resource.get("id")
        resource_name = resource.get("name")
        print(f"[AWS] Collecting configuration for {resource_type} ({resource_id})...")

        config = {}

        if resource_type == "Security Groups":
            try:
                ec2_client = self._session.client("ec2")
                response = ec2_client.describe_security_groups(GroupIds=[resource_id])
                if response.get("SecurityGroups"):
                    sg = response["SecurityGroups"][0]
                    config["raw_data"] = sg
                    config["public_ssh"] = self._is_security_group_public_ssh(sg)
                    
                    # Fetch attached network interfaces (resources) count
                    try:
                        enis = ec2_client.describe_network_interfaces(
                            Filters=[{'Name': 'group-id', 'Values': [resource_id]}]
                        )
                        config["attached_resources_count"] = len(enis.get("NetworkInterfaces", []))
                    except ClientError as e:
                        print(f"[AWS] Failed to fetch ENIs for Security Group {resource_id}: {e}")
                        config["attached_resources_count"] = 0
            except ClientError as err:
                print(f"[AWS] Failed to get configuration for Security Group {resource_id}: {err}")
            except Exception as err:
                print(f"[AWS] Unexpected error: {err}")

        elif resource_type == "EC2":
            try:
                ec2_client = self._session.client("ec2")
                response = ec2_client.describe_instances(InstanceIds=[resource_id])
                if response.get("Reservations"):
                    instance = response["Reservations"][0]["Instances"][0]
                    
                    # Convert LaunchTime datetime to string
                    if "LaunchTime" in instance:
                        instance["LaunchTime"] = instance["LaunchTime"].isoformat()
                    
                    config["raw_data"] = instance
                    
                    # Also resolve attached security groups for deep scanning
                    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                    if sg_ids:
                        sg_response = ec2_client.describe_security_groups(GroupIds=sg_ids)
                        config["security_groups"] = sg_response.get("SecurityGroups", [])
                        
                        public_ssh = False
                        for sg in sg_response.get("SecurityGroups", []):
                            if self._is_security_group_public_ssh(sg):
                                public_ssh = True
                                break
                        config["public_ssh"] = public_ssh
            except ClientError as err:
                print(f"[AWS] Failed to get configuration for EC2 {resource_id}: {err}")
            except Exception as err:
                print(f"[AWS] Unexpected error: {err}")

        elif resource_type == "S3":
            try:
                s3_client = self._session.client("s3")
                config["bucket_name"] = resource_id
                
                # Fetch Public Access Block
                try:
                    pab = s3_client.get_public_access_block(Bucket=resource_id)
                    config["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
                except ClientError as e:
                    config["public_access_block"] = {"error": str(e)}

                # Fetch Encryption
                try:
                    enc = s3_client.get_bucket_encryption(Bucket=resource_id)
                    config["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
                except ClientError as e:
                    config["encryption"] = {"error": str(e)}

                # Fetch Bucket Policy
                try:
                    policy = s3_client.get_bucket_policy(Bucket=resource_id)
                    config["policy"] = policy.get("Policy", "")
                except ClientError as e:
                    config["policy"] = {"error": str(e)}

                # Fetch Bucket ACL
                try:
                    acl = s3_client.get_bucket_acl(Bucket=resource_id)
                    config["acl"] = {
                        "Owner": acl.get("Owner", {}),
                        "Grants": acl.get("Grants", [])
                    }
                except ClientError as e:
                    config["acl"] = {"error": str(e)}

            except ClientError as err:
                print(f"[AWS] Failed to get configuration for S3 {resource_id}: {err}")
            except Exception as err:
                print(f"[AWS] Unexpected error: {err}")

        elif resource_type == "IAM":
            try:
                iam_client = self._session.client("iam")
                
                # Check if it is the root account
                if resource_id == "<root_account>":
                    config["is_root"] = True
                    report_row = {}
                    if self._credential_report:
                        for row in self._credential_report:
                            if row.get("user") == "<root_account>":
                                report_row = row
                                break
                    config["credential_report_row"] = report_row
                    return config

                config["is_root"] = False
                
                # Standard IAM User config collection
                user_response = iam_client.get_user(UserName=resource_name)
                user_data = user_response.get("User", {})
                
                if "CreateDate" in user_data:
                    user_data["CreateDate"] = user_data["CreateDate"].isoformat()
                if "PasswordLastUsed" in user_data:
                    user_data["PasswordLastUsed"] = user_data["PasswordLastUsed"].isoformat()

                config["raw_data"] = user_data

                # Fetch attached policy documents
                try:
                    policies = iam_client.list_attached_user_policies(UserName=resource_name)
                    attached_policies = policies.get("AttachedPolicies", [])
                    config["attached_policies"] = []
                    for p in attached_policies:
                        p_arn = p["PolicyArn"]
                        p_name = p["PolicyName"]
                        p_info = iam_client.get_policy(PolicyArn=p_arn)
                        default_version_id = p_info.get("Policy", {}).get("DefaultVersionId")
                        p_ver = iam_client.get_policy_version(PolicyArn=p_arn, VersionId=default_version_id)
                        config["attached_policies"].append({
                            "PolicyName": p_name,
                            "PolicyArn": p_arn,
                            "PolicyDocument": p_ver.get("PolicyVersion", {}).get("Document", {})
                        })
                except ClientError as e:
                    config["attached_policies"] = {"error": str(e)}

                # Fetch inline policy documents
                try:
                    inline = iam_client.list_user_policies(UserName=resource_name)
                    inline_policies = inline.get("PolicyNames", [])
                    config["inline_policies"] = []
                    for p_name in inline_policies:
                        p_doc = iam_client.get_user_policy(UserName=resource_name, PolicyName=p_name)
                        config["inline_policies"].append({
                            "PolicyName": p_name,
                            "PolicyDocument": p_doc.get("PolicyDocument", {})
                        })
                except ClientError as e:
                    config["inline_policies"] = {"error": str(e)}

                # Fetch groups
                try:
                    groups = iam_client.list_groups_for_user(UserName=resource_name)
                    config["groups"] = groups.get("Groups", [])
                except ClientError as e:
                    config["groups"] = {"error": str(e)}

                # Fetch MFA devices
                try:
                    mfa = iam_client.list_mfa_devices(UserName=resource_name)
                    config["mfa_devices"] = mfa.get("MFADevices", [])
                except ClientError as e:
                    config["mfa_devices"] = {"error": str(e)}

                # Fetch credential report row
                report_row = {}
                if self._credential_report:
                    for row in self._credential_report:
                        if row.get("user") == resource_name:
                            report_row = row
                            break
                config["credential_report_row"] = report_row

            except ClientError as err:
                print(f"[AWS] Failed to get configuration for IAM User {resource_name}: {err}")
            except Exception as err:
                print(f"[AWS] Unexpected error: {err}")

        elif resource_type == "IAM Role":
            try:
                iam_client = self._session.client("iam")
                role_response = iam_client.get_role(RoleName=resource_name)
                role_data = role_response.get("Role", {})
                
                if "CreateDate" in role_data:
                    role_data["CreateDate"] = role_data["CreateDate"].isoformat()
                    
                config["raw_data"] = role_data
                config["is_role"] = True

                # Fetch attached policy documents
                try:
                    policies = iam_client.list_attached_role_policies(RoleName=resource_name)
                    attached_policies = policies.get("AttachedPolicies", [])
                    config["attached_policies"] = []
                    for p in attached_policies:
                        p_arn = p["PolicyArn"]
                        p_name = p["PolicyName"]
                        p_info = iam_client.get_policy(PolicyArn=p_arn)
                        default_version_id = p_info.get("Policy", {}).get("DefaultVersionId")
                        p_ver = iam_client.get_policy_version(PolicyArn=p_arn, VersionId=default_version_id)
                        config["attached_policies"].append({
                            "PolicyName": p_name,
                            "PolicyArn": p_arn,
                            "PolicyDocument": p_ver.get("PolicyVersion", {}).get("Document", {})
                        })
                except ClientError as e:
                    config["attached_policies"] = {"error": str(e)}

                # Fetch inline policy documents
                try:
                    inline = iam_client.list_role_policies(RoleName=resource_name)
                    inline_policies = inline.get("PolicyNames", [])
                    config["inline_policies"] = []
                    for p_name in inline_policies:
                        p_doc = iam_client.get_role_policy(RoleName=resource_name, PolicyName=p_name)
                        config["inline_policies"].append({
                            "PolicyName": p_name,
                            "PolicyDocument": p_doc.get("PolicyDocument", {})
                        })
                except ClientError as e:
                    config["inline_policies"] = {"error": str(e)}

            except ClientError as err:
                print(f"[AWS] Failed to get configuration for IAM Role {resource_name}: {err}")
            except Exception as err:
                print(f"[AWS] Unexpected error: {err}")

        return config

    def _is_security_group_public_ssh(self, sg_data: dict) -> bool:
        """Check if a security group allows port 22 (SSH) from any IP (0.0.0.0/0 or ::/0)."""
        for permission in sg_data.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            ip_protocol = permission.get("IpProtocol")

            if ip_protocol in ["tcp", "-1"]:
                port_matches = False
                if from_port is None or to_port is None:
                    port_matches = True
                elif from_port <= 22 <= to_port:
                    port_matches = True

                if port_matches:
                    for ip_range in permission.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True
                    for ipv6_range in permission.get("Ipv6Ranges", []):
                        if ipv6_range.get("CidrIpv6") == "::/0":
                            return True
        return False