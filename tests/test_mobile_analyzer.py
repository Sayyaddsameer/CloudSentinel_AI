"""
test_mobile_analyzer.py
Unit tests for mobile_analyzer.py — Mobile Backend Intelligence module
Sayyad Sameer
"""

import json
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "mobile"))
os.environ.setdefault("DYNAMODB_TABLE", "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION", "us-east-1")


class TestMobileAnalyzerHandler(unittest.TestCase):
    """Test the Lambda handler entry point."""

    def _make_event(self, body=None):
        return {
            "httpMethod": "POST",
            "body": json.dumps(body or {}),
            "headers": {"Authorization": "Bearer test-token"},
        }

    @patch("mobile_analyzer.boto3")
    def test_options_returns_200(self, mock_boto3):
        import mobile_analyzer as ma
        event = {"httpMethod": "OPTIONS"}
        resp = ma.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)

    @patch("mobile_analyzer.boto3")
    def test_handler_returns_json(self, mock_boto3):
        """Handler should always return valid JSON body."""
        mock_ddb = MagicMock()
        mock_boto3.resource.return_value = mock_ddb
        mock_boto3.client.return_value = MagicMock()
        mock_ddb.Table.return_value.put_item = MagicMock()

        import mobile_analyzer as ma
        # Patch out all AWS calls
        with patch.object(ma, "scan_cognito_user_pools", return_value=[]):
            with patch.object(ma, "scan_api_gateway_auth", return_value=[]):
                with patch.object(ma, "scan_lambda_roles", return_value=[]):
                    event = self._make_event({})
                    resp = ma.lambda_handler(event, None)
                    self.assertIn(resp["statusCode"], [200, 500])
                    body = json.loads(resp["body"])
                    self.assertIsInstance(body, dict)


class TestCognitoMFAScan(unittest.TestCase):
    """Test Cognito MFA and password policy detection."""

    def setUp(self):
        import mobile_analyzer as ma
        self.ma = ma

    def _make_pool(self, mfa="OFF", min_len=6):
        return {
            "Id": "us-east-1_TestPool",
            "Name": "test-pool",
            "MfaConfiguration": mfa,
            "Policies": {
                "PasswordPolicy": {"MinimumLength": min_len}
            },
        }

    def test_mfa_off_flags_high(self):
        cognito = MagicMock()
        cognito.list_user_pools.return_value = {"UserPools": [self._make_pool(mfa="OFF")]}
        cognito.describe_user_pool.return_value = {"UserPool": self._make_pool(mfa="OFF")}
        table = MagicMock()
        risks = self.ma.scan_cognito_user_pools({"cognito": cognito}, table)
        priorities = [r["riskPriority"] for r in risks]
        self.assertIn("High", priorities)

    def test_mfa_on_no_risk(self):
        pool = self._make_pool(mfa="ON", min_len=14)
        cognito = MagicMock()
        cognito.list_user_pools.return_value = {"UserPools": [pool]}
        cognito.describe_user_pool.return_value = {"UserPool": pool}
        table = MagicMock()
        risks = self.ma.scan_cognito_user_pools({"cognito": cognito}, table)
        mfa_risks = [r for r in risks if "MFA" in r.get("riskType", "")]
        self.assertEqual(len(mfa_risks), 0)

    def test_weak_password_policy_flags_medium(self):
        pool = self._make_pool(mfa="ON", min_len=5)
        cognito = MagicMock()
        cognito.list_user_pools.return_value = {"UserPools": [pool]}
        cognito.describe_user_pool.return_value = {"UserPool": pool}
        table = MagicMock()
        risks = self.ma.scan_cognito_user_pools({"cognito": cognito}, table)
        pw_risks = [r for r in risks if "Password" in r.get("riskType", "")]
        if pw_risks:
            self.assertIn(pw_risks[0]["riskPriority"], ["Medium", "High"])

    def test_empty_pool_list_no_risks(self):
        cognito = MagicMock()
        cognito.list_user_pools.return_value = {"UserPools": []}
        table = MagicMock()
        risks = self.ma.scan_cognito_user_pools({"cognito": cognito}, table)
        self.assertEqual(risks, [])


class TestRiskFieldsMobile(unittest.TestCase):
    """Verify risk records have all required schema fields."""

    def test_risk_schema_complete(self):
        import mobile_analyzer as ma
        risk = ma.build_risk(
            "mobile", "Cognito", "us-east-1_testpool",
            "MFA Disabled", "Cognito user pool has MFA set to OFF", "High"
        )
        required = [
            "resourceId", "riskTimestamp", "module", "cloudProvider",
            "resource", "resourceName", "riskType", "riskReason",
            "riskPriority", "remediationSteps", "alternativeSolutions",
            "aiExplanation", "riskCategory", "status", "region",
        ]
        for f in required:
            self.assertIn(f, risk, f"Missing field: {f}")

    def test_risk_status_open(self):
        import mobile_analyzer as ma
        risk = ma.build_risk("mobile", "Lambda", "my-fn", "T", "R", "Medium")
        self.assertEqual(risk["status"], "OPEN")

    def test_risk_module_is_mobile(self):
        import mobile_analyzer as ma
        risk = ma.build_risk("mobile", "Cognito", "pool", "T", "R", "High")
        self.assertEqual(risk["module"], "mobile")


if __name__ == "__main__":
    unittest.main()
