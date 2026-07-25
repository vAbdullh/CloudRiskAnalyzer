def check_port_open_in_sg(sg: dict, target_port: int, cidr: str) -> bool:
    """Check if a port is open to the specified CIDR."""
    for perm in sg.get("IpPermissions", []):
        ip_proto = perm.get("IpProtocol")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        if ip_proto == "tcp" or ip_proto == "-1":
            port_matches = False
            if from_port is None or to_port is None:
                port_matches = True
            elif from_port <= target_port <= to_port:
                port_matches = True

            if port_matches:
                if cidr == "0.0.0.0/0":
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True
                elif cidr == "::/0":
                    for ipv6_range in perm.get("Ipv6Ranges", []):
                        if ipv6_range.get("CidrIpv6") == "::/0":
                            return True
    return False


def check_db_ports(sg: dict) -> bool:
    """Check if database ports are open to the internet."""
    for port in [3306, 5432, 1433, 27017, 6379, 9200]:
        if check_port_open_in_sg(sg, port, "0.0.0.0/0") or check_port_open_in_sg(sg, port, "::/0"):
            return True
    return False


def check_all_tcp(sg: dict) -> bool:
    """Check if all TCP ports are open to the internet."""
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") == "tcp":
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            if (from_port == 0 and to_port == 65535) or (from_port is None or to_port is None):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return True
                for ipv6_range in perm.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        return True
    return False


def check_all_protocols(sg: dict) -> bool:
    """Check if all protocols are open to the internet."""
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") == "-1":
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return True
            for ipv6_range in perm.get("Ipv6Ranges", []):
                if ipv6_range.get("CidrIpv6") == "::/0":
                    return True
    return False


def check_sensitive_ports(sg: dict) -> bool:
    """Check if sensitive infrastructure ports are open to the internet."""
    sensitive_ports = [
        20, 21, 23, 25, 53, 69, 88, 110, 143, 161, 162, 389, 445, 465, 636, 993, 995
    ]
    for port in sensitive_ports:
        if check_port_open_in_sg(sg, port, "0.0.0.0/0") or check_port_open_in_sg(sg, port, "::/0"):
            return True
    return False


def check_inbound_count(sg: dict) -> bool:
    """Check if the security group has more than 20 inbound rules."""
    total = 0
    for perm in sg.get("IpPermissions", []):
        total += len(perm.get("IpRanges", []))
        total += len(perm.get("Ipv6Ranges", []))
        total += len(perm.get("UserIdGroupPairs", []))
        total += len(perm.get("PrefixListIds", []))
    return total > 20


def check_outbound_all(sg: dict) -> bool:
    """Check if all outbound traffic is allowed."""
    for perm in sg.get("IpPermissionsEgress", []):
        if perm.get("IpProtocol") == "-1":
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return True
            for ipv6_range in perm.get("Ipv6Ranges", []):
                if ipv6_range.get("CidrIpv6") == "::/0":
                    return True
    return False


RULES = [
    {
        "id": "SEC-001",
        "name": "Public SSH (IPv4) Access",
        "severity": "Critical",
        "description": "Security Group allows SSH (22) from 0.0.0.0/0.",
        "recommendation": "Restrict inbound SSH access to trusted IP addresses.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_port_open_in_sg(config.get("raw_data", {}), 22, "0.0.0.0/0"),
    },
    {
        "id": "SEC-002",
        "name": "Public SSH (IPv6) Access",
        "severity": "Critical",
        "description": "Security Group allows SSH (22) from ::/0.",
        "recommendation": "Restrict inbound SSH access to trusted IP addresses.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_port_open_in_sg(config.get("raw_data", {}), 22, "::/0"),
    },
    {
        "id": "SEC-003",
        "name": "Public RDP (IPv4) Access",
        "severity": "Critical",
        "description": "Security Group allows RDP (3389) from 0.0.0.0/0.",
        "recommendation": "Restrict inbound RDP access to trusted IP addresses.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_port_open_in_sg(config.get("raw_data", {}), 3389, "0.0.0.0/0"),
    },
    {
        "id": "SEC-004",
        "name": "Public RDP (IPv6) Access",
        "severity": "Critical",
        "description": "Security Group allows RDP (3389) from ::/0.",
        "recommendation": "Restrict inbound RDP access to trusted IP addresses.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_port_open_in_sg(config.get("raw_data", {}), 3389, "::/0"),
    },
    {
        "id": "SEC-005",
        "name": "Public Database Access",
        "severity": "Critical",
        "description": "Security Group allows database ports (3306, 5432, etc.) open to the internet.",
        "recommendation": "Restrict database access to internal subnets or trusted static IPs.",
        "r_base": 5.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_db_ports(config.get("raw_data", {})),
    },
    {
        "id": "SEC-006",
        "name": "All TCP Ports Open to Internet",
        "severity": "Critical",
        "description": "Security Group allows all TCP ports (0-65535) open to the internet.",
        "recommendation": "Explicitly define allowed ports instead of allowing all TCP ports.",
        "r_base": 6.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_all_tcp(config.get("raw_data", {})),
    },
    {
        "id": "SEC-007",
        "name": "All Protocols Open to Internet",
        "severity": "Critical",
        "description": "Security Group allows all protocols (any port/traffic) open to the internet.",
        "recommendation": "Restrict traffic to specific required protocols and ports.",
        "r_base": 6.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.2,
        "check": lambda config: check_all_protocols(config.get("raw_data", {})),
    },
    {
        "id": "SEC-008",
        "name": "Public HTTP Access",
        "severity": "Info",
        "description": "Security Group allows inbound HTTP (80) traffic from the internet.",
        "recommendation": "None. Verify this server is intended to serve public web traffic.",
        "r_base": 1.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: check_port_open_in_sg(config.get("raw_data", {}), 80, "0.0.0.0/0") or check_port_open_in_sg(config.get("raw_data", {}), 80, "::/0"),
    },
    {
        "id": "SEC-009",
        "name": "Public HTTPS Access",
        "severity": "Info",
        "description": "Security Group allows inbound HTTPS (443) traffic from the internet.",
        "recommendation": "None. Verify this server is intended to serve public web traffic.",
        "r_base": 1.0,
        "exposure_factor": 1.0,
        "chain_multiplier": 1.0,
        "check": lambda config: check_port_open_in_sg(config.get("raw_data", {}), 443, "0.0.0.0/0") or check_port_open_in_sg(config.get("raw_data", {}), 443, "::/0"),
    },
    {
        "id": "SEC-010",
        "name": "Public Sensitive Ports Access",
        "severity": "High",
        "description": "Security Group allows sensitive management ports (e.g. FTP, Telnet, SMB) open to the internet.",
        "recommendation": "Block sensitive ports from the public internet.",
        "r_base": 4.0,
        "exposure_factor": 3.0,
        "chain_multiplier": 1.1,
        "check": lambda config: check_sensitive_ports(config.get("raw_data", {})),
    },
    {
        "id": "SEC-011",
        "name": "Too Many Inbound Rules",
        "severity": "Medium",
        "description": "Security Group has more than 20 inbound rules configured.",
        "recommendation": "Consolidate your security group rules to keep policies clean and auditable.",
        "r_base": 2.0,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: check_inbound_count(config.get("raw_data", {})),
    },
    {
        "id": "SEC-012",
        "name": "All Outbound Traffic Allowed",
        "severity": "Warning",
        "description": "Security Group allows unrestricted outbound traffic to the internet.",
        "recommendation": "Restricting outbound traffic to only required ports and destinations is a good defense-in-depth practice.",
        "r_base": 1.5,
        "exposure_factor": 0.5,
        "chain_multiplier": 1.0,
        "check": lambda config: check_outbound_all(config.get("raw_data", {})),
    },
    {
        "id": "SEC-013",
        "name": "Unattached Security Group",
        "severity": "Info",
        "description": "Security Group is not associated with any active network interfaces.",
        "recommendation": "Consider deleting unused security groups to simplify management.",
        "r_base": 1.0,
        "exposure_factor": 0.0,
        "chain_multiplier": 1.0,
        "check": lambda config: config.get("attached_resources_count", 0) == 0,
    }
]