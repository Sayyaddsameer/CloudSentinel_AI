"""
Unit tests for cloud_scanner.py
Sayyad Sameer
"""

import json
import unittest
from unittest.mock import MagicMock, patch
from datetime import timezone, datetime

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "cloud-infra"))


class TestBuildRisk(unittest.TestCase):
    def setUp(self):
        # Patch env before importing so TABLE_NAME resolves
        os.environ.setdefault("DYNAMODB_TABLE", "cloudsentinel-risks")
        os.environ.setdefault("AWS_REGION",     "us-east-1")
        import cloud_scanner as cs
        self.cs = cs

    def test_risk_has_required_fields(self):
        r = self.cs.build_risk(
            "cloud-infra", "S3 Bucket", "my-bucket",
            "Public Access Enabled", "Bucket policy allows public read", "High"
        )
        required = [
            "resourceId", "riskTimestamp", "module", "cloudProvider",
            "resource", "resourceName", "riskType", "riskReason",
            "riskPriority", "remediationSteps", "alternativeSolutions",
            "aiExplanation", "riskCategory", "status", "region",
        ]
        for f in required:
            self.assertIn(f, r, f"Missing field: {f}")

    def test_risk_priority_values(self):
        for priority in ("High", "Medium", "Low"):
            r = self.cs.build_risk("cloud-infra", "S3 Bucket", "b", "T", "R", priority)
            self.assertEqual(r["riskPriority"], priority)

    def test_risk_module_field(self):
        r = self.cs.build_risk("cloud-infra", "IAM", "account", "No Policy", "Reason", "High")
        self.assertEqual(r["module"], "cloud-infra")

    def test_ai_explanation_starts_empty(self):
        r = self.cs.build_risk("cloud-infra", "S3 Bucket", "b", "T", "R", "Low")
        self.assertEqual(r["aiExplanation"], "")

    def test_status_starts_open(self):
        r = self.cs.build_risk("cloud-infra", "S3 Bucket", "b", "T", "R", "Low")
        self.assertEqual(r["status"], "OPEN")

    def test_cloud_provider_default_aws(self):
        r = self.cs.build_risk("cloud-infra", "S3 Bucket", "b", "T", "R", "Medium")
        self.assertEqual(r["cloudProvider"], "AWS")

    def test_gcp_cloud_provider(self):
        r = self.cs.build_risk(
            "cloud-infra", "GCS Bucket", "gcs-bucket", "T", "R", "High",
            cloud_provider="GCP"
        )
        self.assertEqual(r["cloudProvider"], "GCP")

    def test_resource_id_format(self):
        r = self.cs.build_risk("cloud-infra", "S3 Bucket", "my-bucket", "T", "R", "High")
        self.assertTrue(r["resourceId"].startswith("cloud-infra-"))
        self.assertIn("my-bucket", r["resourceId"])


class TestScanIAMPasswordPolicy(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("DYNAMODB_TABLE", "cloudsentinel-risks")
        os.environ.setdefault("AWS_REGION",     "us-east-1")
        import cloud_scanner as cs
        self.cs = cs

    def test_no_policy_flags_high(self):
        from botocore.exceptions import ClientError
        iam = MagicMock()
        iam.get_account_password_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": ""}}, "GetAccountPasswordPolicy"
        )
        table = MagicMock()
        risks = self.cs.scan_iam_password_policy({"iam": iam}, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "High")

    def test_short_password_flags_medium(self):
        iam = MagicMock()
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 6}
        }
        table = MagicMock()
        risks = self.cs.scan_iam_password_policy({"iam": iam}, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "Medium")

    def test_strong_policy_no_risk(self):
        iam = MagicMock()
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 16}
        }
        table = MagicMock()
        risks = self.cs.scan_iam_password_policy({"iam": iam}, table)
        self.assertEqual(len(risks), 0)


if __name__ == "__main__":
    unittest.main()
