"""
Unit tests for fullstack_analyzer.py
Janapareddy Dyns Gowrish
"""

import os
import sys
import unittest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

os.environ.setdefault("DYNAMODB_TABLE",     "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION",         "us-east-1")
os.environ.setdefault("LATENCY_THRESHOLD_MS", "2000")
os.environ.setdefault("ERROR_5XX_THRESHOLD",  "10")

import fullstack_analyzer as fa


class TestBuildRisk(unittest.TestCase):
    def test_required_fields_present(self):
        r = fa.build_risk("my-api", "/data", "Unauthenticated Endpoint", "No auth.", "High")
        for field in ["resourceId", "module", "riskType", "riskPriority", "status"]:
            self.assertIn(field, r)

    def test_module_is_fullstack(self):
        r = fa.build_risk("api", "/", "T", "R", "High")
        self.assertEqual(r["module"], "fullstack")

    def test_priority_preserved(self):
        for p in ("High", "Medium", "Low"):
            r = fa.build_risk("api", "/", "T", "R", p)
            self.assertEqual(r["riskPriority"], p)


class TestScanAuthentication(unittest.TestCase):
    def _make_apigw(self, auth_type="NONE", api_key_required=False):
        apigw = MagicMock()
        apigw.get_rest_apis.return_value = {
            "items": [{"id": "abc123", "name": "test-api"}]
        }
        apigw.get_resources.return_value = {
            "items": [{
                "id": "res1",
                "path": "/data",
                "resourceMethods": {"GET": {}},
            }]
        }
        apigw.get_method.return_value = {
            "authorizationType": auth_type,
            "apiKeyRequired":    api_key_required,
        }
        return apigw

    def test_unauthenticated_endpoint_flagged(self):
        apigw = self._make_apigw("NONE", False)
        table = MagicMock()
        risks = fa.scan_api_authentication(apigw, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "High")
        self.assertEqual(risks[0]["riskType"], "Unauthenticated API Endpoint")

    def test_cognito_auth_no_risk(self):
        apigw = self._make_apigw("COGNITO_USER_POOLS", False)
        table = MagicMock()
        risks = fa.scan_api_authentication(apigw, table)
        self.assertEqual(len(risks), 0)

    def test_iam_auth_no_risk(self):
        apigw = self._make_apigw("AWS_IAM", False)
        table = MagicMock()
        risks = fa.scan_api_authentication(apigw, table)
        self.assertEqual(len(risks), 0)

    def test_api_key_required_no_risk(self):
        apigw = self._make_apigw("NONE", True)
        table = MagicMock()
        risks = fa.scan_api_authentication(apigw, table)
        self.assertEqual(len(risks), 0)


class TestScanThrottling(unittest.TestCase):
    def test_no_throttling_flagged_medium(self):
        apigw = MagicMock()
        apigw.get_rest_apis.return_value = {
            "items": [{"id": "abc123", "name": "my-api"}]
        }
        apigw.get_stages.return_value = {
            "item": [{"stageName": "dev", "methodSettings": {}}]
        }
        table = MagicMock()
        risks = fa.scan_throttling(apigw, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "Medium")


if __name__ == "__main__":
    unittest.main()
