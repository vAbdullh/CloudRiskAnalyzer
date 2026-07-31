-- ==============================================================
-- Database Seed Data (Dummy Data for Local Development)
-- ==============================================================


-- 3. Insert Static Security Rules into public.rules
INSERT INTO public.rules (id, provider, name, severity, description, recommendation) VALUES
('AWS-S3-001', 'aws', 'S3 Buckets should not be publicly readable', 'HIGH', 'Checks if any Amazon S3 buckets are configured with public read access, which could expose sensitive data to unauthorized users.', 'Modify the S3 bucket access control list (ACL) or bucket policy to disable public read access. Enable "Block public access" settings.'),
('AWS-EC2-001', 'aws', 'Security Groups should not allow unrestricted SSH access', 'CRITICAL', 'Checks if any security groups allow incoming traffic on port 22 (SSH) from any IP address (0.0.0.0/0).', 'Restrict the source IP address in the security group rule to only trusted IP ranges or specific office IPs.'),
('AWS-IAM-001', 'aws', 'MFA should be enabled for the Root User', 'CRITICAL', 'Checks if Multi-Factor Authentication (MFA) is active for the root account to prevent credential compromise.', 'Log in as the root user and activate MFA in the IAM console.')
ON CONFLICT (id) DO NOTHING;

-- 4. Insert Cloud Connections into public.connections
INSERT INTO public.connections (id, user_id, name, provider, credentials, created_at) VALUES
('6ecf4951-6d11-4d47-83c9-eeca64cbd732', '6e7b3ee1-db4a-4ef5-a81a-c4b4aafbc255', 'Production AWS Account', 'aws', '{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}', '2026-07-29 15:40:39.955+00')
ON CONFLICT (id) DO NOTHING;

-- 5. Insert Scan Jobs into public.scan_jobs
INSERT INTO public.scan_jobs (id, connection_id, user_id, status, started_at, completed_at, created_at) VALUES
('564f21a5-cb6e-422c-b8a4-e286d8051b0a', '6ecf4951-6d11-4d47-83c9-eeca64cbd732', '6e7b3ee1-db4a-4ef5-a81a-c4b4aafbc255', 'COMPLETED', '2026-07-29 14:40:39.966+00', '2026-07-29 15:40:39.966+00', '2026-07-29 15:40:39.968+00')
ON CONFLICT (id) DO NOTHING;

-- 6. Insert Resources into public.resources
INSERT INTO public.resources (id, scan_job_id, resource_type, provider_resource_id, name, region, configuration, created_at) VALUES
('38938ee8-3861-42d8-9d35-055cf70ff82a', '564f21a5-cb6e-422c-b8a4-e286d8051b0a', 's3_bucket', 'arn:aws:s3:::my-public-reports', 'my-public-reports', 'us-east-1', '{"is_public": true, "bucket_name": "my-public-reports", "versioning_enabled": false}', '2026-07-29 15:40:39.978+00'),
('aa724ad8-1dc3-4874-a86d-e835d5c1f461', '564f21a5-cb6e-422c-b8a4-e286d8051b0a', 'security_group', 'sg-0a8b9c10d11e12f', 'default', 'us-west-2', '{"group_id": "sg-0a8b9c10d11e12f", "group_name": "default", "ip_permissions": [{"to_port": 22, "from_port": 22, "ip_ranges": [{"cidr_ip": "0.0.0.0/0"}], "ip_protocol": "tcp"}]}', '2026-07-29 15:40:39.99+00')
ON CONFLICT (id) DO NOTHING;

-- 7. Insert Findings into public.findings
INSERT INTO public.findings (id, scan_job_id, resource_id, rule_id, status, details, created_at) VALUES
('539eaac4-578e-4a37-8d6c-d8e79e2f32da', '564f21a5-cb6e-422c-b8a4-e286d8051b0a', '38938ee8-3861-42d8-9d35-055cf70ff82a', 'AWS-S3-001', 'FAIL', '{"reason": "Bucket permissions set to public read via ACL."}', '2026-07-29 15:40:40.006+00'),
('9fd0d050-1b3c-43ae-99a9-c8f657ea8b7c', '564f21a5-cb6e-422c-b8a4-e286d8051b0a', 'aa724ad8-1dc3-4874-a86d-e835d5c1f461', 'AWS-EC2-001', 'FAIL', '{"reason": "Port 22 is open to the entire internet (0.0.0.0/0)."}', '2026-07-29 15:40:40.017+00')
ON CONFLICT (id) DO NOTHING;
