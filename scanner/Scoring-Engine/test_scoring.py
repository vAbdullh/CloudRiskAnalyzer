"""
Unit tests for the Cloud Risk Scoring Engine.
Validates the core formula against every row from the CSV scoring matrix,
plus edge cases and dynamic override logic.

Run with:
    python -m pytest scanner/Scoring-Engine/test_scoring.py -v
    OR
    python scanner/Scoring-Engine/test_scoring.py
"""

import sys
import os
import unittest

# Ensure the scoring engine is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from Eng import (
    ScanFinding,
    calculate_risk_score,
    determine_priority,
    apply_dynamic_overrides,
    score_finding,
)
from cvss.cvss_scorer import build_consolidated_report


class TestCoreFormula(unittest.TestCase):
    """Test the core formula: min(10.0, (R_base + E) × C)"""

    def _score(self, r_base, exposure, chain):
        finding = ScanFinding(
            rule_id="TEST",
            resource_id="test-resource",
            resource_type="Test",
            r_base=r_base,
            exposure_factor=exposure,
            chain_multiplier=chain,
        )
        return calculate_risk_score(finding)["final_score"]

    # ---------------------------------------------------------------
    # CSV Matrix rows — exact expected values
    # ---------------------------------------------------------------

    def test_csv_iam001_root_keys_active(self):
        """IAM-001/IAM-002: Root keys active, R=10.0, E=1.0, C=1.0 → 10.0"""
        self.assertEqual(self._score(10.0, 1.0, 1.0), 10.0)

    def test_csv_oci_iam003_admin_policy(self):
        """OCI-IAM-003: Full admin policy, R=7.0, E=1.0, C=1.1 → 8.8"""
        self.assertEqual(self._score(7.0, 1.0, 1.1), 8.8)

    def test_csv_oci_storage001_public_bucket(self):
        """OCI-STORAGE-001: Public bucket, R=6.0, E=3.0, C=1.1 → 9.9"""
        self.assertEqual(self._score(6.0, 3.0, 1.1), 9.9)

    def test_csv_oci_net002_public_ssh(self):
        """OCI-NET-002: Public SSH, R=5.0, E=3.0, C=1.2 → 9.6"""
        self.assertEqual(self._score(5.0, 3.0, 1.2), 9.6)

    def test_csv_oci_storage002_no_kms(self):
        """OCI-STORAGE-002: No KMS encryption, R=3.0, E=0.5, C=1.0 → 3.5"""
        self.assertEqual(self._score(3.0, 0.5, 1.0), 3.5)

    def test_csv_oci_net001_public_subnet(self):
        """OCI-NET-001: Public subnet, R=2.5, E=1.5, C=1.0 → 4.0"""
        self.assertEqual(self._score(2.5, 1.5, 1.0), 4.0)

    def test_csv_sec012_sec013_unattached_sg(self):
        """SEC-012/SEC-013: Unattached SG, R=1.0, E=0.0, C=1.0 → 1.0"""
        self.assertEqual(self._score(1.0, 0.0, 1.0), 1.0)

    def test_csv_pam001_pam_vault(self):
        """PAM-001: PAM vault MFA missing, R=8.0, E=1.5, C=1.25 → 10.0 (capped)"""
        self.assertEqual(self._score(8.0, 1.5, 1.25), 10.0)

    def test_csv_pam002_static_key(self):
        """PAM-002: Static API key, R=5.0, E=1.0, C=1.0 → 6.0"""
        self.assertEqual(self._score(5.0, 1.0, 1.0), 6.0)

    # ---------------------------------------------------------------
    # Edge cases
    # ---------------------------------------------------------------

    def test_zero_score(self):
        """All zeros → 0.0"""
        self.assertEqual(self._score(0.0, 0.0, 1.0), 0.0)

    def test_cap_at_10(self):
        """Score caps at 10.0"""
        self.assertEqual(self._score(10.0, 3.0, 1.5), 10.0)

    def test_no_negative(self):
        """Score never goes below 0.0"""
        self.assertEqual(self._score(0.0, 0.0, 0.0), 0.0)

    def test_rounding(self):
        """Result is rounded to one decimal place"""
        # (2.0 + 0.3) * 1.0 = 2.3
        self.assertEqual(self._score(2.0, 0.3, 1.0), 2.3)


class TestPriorityMapping(unittest.TestCase):
    """Test the priority label and SLA mapping."""

    def test_p0_immediate(self):
        label, sla = determine_priority(10.0, 10.0)
        self.assertEqual(label, "Immediate (P0)")
        self.assertEqual(sla, "Fix within 24 hours")

    def test_p1_critical(self):
        """R_base < 9.0 but score >= 9.0 → Critical (P1)"""
        label, sla = determine_priority(9.6, 5.0)
        self.assertEqual(label, "Critical (P1)")
        self.assertEqual(sla, "Fix within 24 hours")

    def test_p0_threshold(self):
        """R_base >= 9.0 and score >= 9.0 → Immediate (P0)"""
        label, _ = determine_priority(9.0, 9.0)
        self.assertEqual(label, "Immediate (P0)")

    def test_p2_high(self):
        label, sla = determine_priority(8.8, 7.0)
        self.assertEqual(label, "High (P2)")
        self.assertEqual(sla, "Fix within 7 days")

    def test_p2_boundary(self):
        label, _ = determine_priority(7.0, 5.0)
        self.assertEqual(label, "High (P2)")

    def test_p3_medium(self):
        label, sla = determine_priority(6.0, 5.0)
        self.assertEqual(label, "Medium (P3)")
        self.assertEqual(sla, "Fix within 30 days")

    def test_p3_boundary(self):
        label, _ = determine_priority(4.0, 2.5)
        self.assertEqual(label, "Medium (P3)")

    def test_p4_low(self):
        label, sla = determine_priority(3.5, 3.0)
        self.assertEqual(label, "Low / Info (P4)")
        self.assertEqual(sla, "Informational / Best Effort")

    def test_p4_zero(self):
        label, _ = determine_priority(0.0, 0.0)
        self.assertEqual(label, "Low / Info (P4)")


class TestDynamicOverrides(unittest.TestCase):
    """Test dynamic exposure/chain overrides based on runtime configuration."""

    def test_unattached_sg_sec013(self):
        """SEC-013: unattached SG → E forced to 0.0"""
        rule = {"id": "SEC-013", "exposure_factor": 1.0, "chain_multiplier": 1.0}
        config = {"attached_resources_count": 0}
        e, c = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 0.0)

    def test_unattached_sg_sec012(self):
        """SEC-012: outbound all with no ENIs → E forced to 0.0"""
        rule = {"id": "SEC-012", "exposure_factor": 0.5, "chain_multiplier": 1.0}
        config = {"attached_resources_count": 0}
        e, c = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 0.0)

    def test_public_ssh_flag_boosts_exposure(self):
        """public_ssh=True in config → E boosted to at least 3.0"""
        rule = {"id": "SEC-001", "exposure_factor": 1.0, "chain_multiplier": 1.2}
        config = {"public_ssh": True, "raw_data": {}}
        e, _ = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 3.0)

    def test_oci_ingress_0000_boosts_exposure(self):
        """OCI ingress from 0.0.0.0/0 → E boosted to at least 3.0"""
        rule = {"id": "OCI-NET-002", "exposure_factor": 1.0, "chain_multiplier": 1.2}
        config = {
            "raw_data": {
                "ingress_security_rules": [{"source": "0.0.0.0/0", "protocol": "6"}]
            }
        }
        e, _ = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 3.0)

    def test_oci_public_bucket_boosts_exposure(self):
        """OCI public bucket → E boosted to at least 3.0"""
        rule = {"id": "OCI-STORAGE-001", "exposure_factor": 1.0, "chain_multiplier": 1.1}
        config = {"raw_data": {"public_access_type": "ObjectRead"}}
        e, _ = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 3.0)

    def test_oci_public_subnet_boosts_exposure(self):
        """OCI public subnet → E boosted to at least 1.5"""
        rule = {"id": "OCI-NET-001", "exposure_factor": 0.5, "chain_multiplier": 1.0}
        config = {"raw_data": {"prohibit_public_ip_on_vnic": False}}
        e, _ = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 1.5)

    def test_no_override_when_attached(self):
        """SG with attached resources keeps its default E"""
        rule = {"id": "SEC-001", "exposure_factor": 3.0, "chain_multiplier": 1.2}
        config = {"attached_resources_count": 2, "raw_data": {}}
        e, c = apply_dynamic_overrides(rule, config)
        self.assertEqual(e, 3.0)
        self.assertEqual(c, 1.2)


class TestConsolidatedReport(unittest.TestCase):
    """Validate that the merged log report contains all requested sections."""

    def test_build_consolidated_report_includes_result_sections(self):
        results = "Scan results\n[PASS] Public bucket exposed to internet"
        evaluations = [
            {
                "rule_id": "OCI-STORAGE-001",
                "risk_score": 9.9,
                "action_priority": "Critical (P1)",
                "sla": "Fix within 24 hours",
            }
        ]

        report = build_consolidated_report(results, evaluations)

        self.assertIn("=== RESULTS ===", report)
        self.assertIn("Scan results", report)
        self.assertIn("=== CVSS SCORE ===", report)
        self.assertIn('"severity":', report)
        self.assertIn("=== CUSTOM SCORING ENGINE SCORES ===", report)
        self.assertIn("OCI-STORAGE-001", report)


class TestScoreFinding(unittest.TestCase):
    """Test the high-level score_finding helper used by the executor."""

    def test_oci_net002_public_ssh(self):
        """End-to-end: OCI-NET-002 with 0.0.0.0/0 ingress → score 9.6"""
        rule = {
            "id": "OCI-NET-002",
            "description": "Public SSH",
            "r_base": 5.0,
            "exposure_factor": 3.0,
            "chain_multiplier": 1.2,
        }
        resource = {
            "id": "ocid1.securitylist.oc1.test",
            "type": "SecurityList",
            "name": "Default Security List",
        }
        config = {
            "raw_data": {
                "ingress_security_rules": [
                    {"source": "0.0.0.0/0", "protocol": "6"}
                ]
            }
        }
        result = score_finding(rule, resource, config, cloud_provider="OCI")
        self.assertEqual(result["final_score"], 9.6)
        self.assertEqual(result["action_priority"], "Critical (P1)")
        self.assertEqual(result["sla"], "Fix within 24 hours")

    def test_aws_root_keys(self):
        """End-to-end: IAM-001 root keys → score 10.0, Immediate (P0)"""
        rule = {
            "id": "IAM-001",
            "description": "Root keys active",
            "r_base": 10.0,
            "exposure_factor": 1.0,
            "chain_multiplier": 1.0,
        }
        resource = {
            "id": "<root_account>",
            "type": "IAM",
            "name": "<root_account>",
        }
        config = {"is_root": True, "raw_data": {}}
        result = score_finding(rule, resource, config, cloud_provider="AWS")
        self.assertEqual(result["final_score"], 10.0)
        self.assertEqual(result["action_priority"], "Immediate (P0)")

    def test_aws_unattached_sg(self):
        """End-to-end: SEC-013 unattached SG → E overridden to 0.0, score 1.0"""
        rule = {
            "id": "SEC-013",
            "description": "Unattached SG",
            "r_base": 1.0,
            "exposure_factor": 0.0,
            "chain_multiplier": 1.0,
        }
        resource = {
            "id": "sg-test123",
            "type": "Security Groups",
            "name": "default",
        }
        config = {"attached_resources_count": 0, "raw_data": {}}
        result = score_finding(rule, resource, config, cloud_provider="AWS")
        self.assertEqual(result["final_score"], 1.0)
        self.assertEqual(result["action_priority"], "Low / Info (P4)")

    def test_result_has_all_fields(self):
        """Verify the result dict contains all expected keys."""
        rule = {
            "id": "TEST-001",
            "description": "Test rule",
            "r_base": 5.0,
            "exposure_factor": 1.0,
            "chain_multiplier": 1.0,
        }
        resource = {"id": "res-1", "type": "Test", "name": "test-resource"}
        config = {"raw_data": {}}
        result = score_finding(rule, resource, config, cloud_provider="TEST")

        expected_keys = {
            "rule_id", "resource_id", "resource_name", "cloud_provider",
            "final_score", "action_priority", "sla", "metrics", "calculation_logic"
        }
        self.assertTrue(expected_keys.issubset(result.keys()))
        self.assertIn("r_base", result["metrics"])
        self.assertIn("exposure_factor", result["metrics"])
        self.assertIn("chain_multiplier", result["metrics"])


if __name__ == "__main__":
    unittest.main()
