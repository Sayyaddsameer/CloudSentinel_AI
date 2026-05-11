"""
Unit tests for devops_analyzer.py
Kantipudi Vivek Vardhan
"""

import os
import sys
import unittest

os.environ.setdefault("DYNAMODB_TABLE", "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION",     "us-east-1")

import devops_analyzer as da


PIPELINE_WITH_TESTS = {
    "jobs": {
        "build": {
            "steps": [
                {"name": "install", "run": "pip install -r requirements.txt"},
                {"name": "run tests", "run": "pytest tests/ -v"},
                {"name": "rollback on fail", "run": "aws lambda rollback --function-name x"},
                {"name": "health check", "run": "curl https://myapi.com/health"},
            ]
        }
    }
}

PIPELINE_WITHOUT_TESTS = {
    "jobs": {
        "build": {
            "steps": [
                {"name": "install", "run": "pip install -r requirements.txt"},
                {"name": "deploy",  "run": "aws lambda update-function-code --function-name x"},
            ]
        }
    }
}

PIPELINE_WITH_SECRET = {
    "jobs": {
        "build": {
            "steps": [
                {"name": "set creds", "run": "export password=SuperSecret123"},
                {"name": "deploy",    "run": "aws lambda update-function-code --function-name x"},
            ]
        }
    }
}

PIPELINE_WITH_AWS_KEY = {
    "jobs": {
        "build": {
            "steps": [
                {"name": "deploy", "run": "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"},
            ]
        }
    }
}


class TestFlattenSteps(unittest.TestCase):
    def test_returns_all_steps(self):
        steps = da.flatten_steps(PIPELINE_WITH_TESTS)
        self.assertEqual(len(steps), 4)

    def test_empty_pipeline(self):
        steps = da.flatten_steps({})
        self.assertEqual(steps, [])

    def test_step_has_job_key(self):
        steps = da.flatten_steps(PIPELINE_WITHOUT_TESTS)
        for s in steps:
            self.assertIn("job", s)
            self.assertIn("name", s)
            self.assertIn("run", s)


class TestScanForTests(unittest.TestCase):
    def test_pipeline_missing_tests_flagged(self):
        steps  = da.flatten_steps(PIPELINE_WITHOUT_TESTS)
        risks  = da.scan_for_test_steps("repo", steps)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "High")

    def test_pipeline_with_tests_clean(self):
        steps = da.flatten_steps(PIPELINE_WITH_TESTS)
        risks = da.scan_for_test_steps("repo", steps)
        self.assertEqual(len(risks), 0)


class TestScanForRollback(unittest.TestCase):
    def test_no_rollback_flagged(self):
        steps = da.flatten_steps(PIPELINE_WITHOUT_TESTS)
        risks = da.scan_for_rollback("repo", steps)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "Medium")

    def test_rollback_present_clean(self):
        steps = da.flatten_steps(PIPELINE_WITH_TESTS)
        risks = da.scan_for_rollback("repo", steps)
        self.assertEqual(len(risks), 0)


class TestScanForSecrets(unittest.TestCase):
    def test_password_pattern_flagged(self):
        steps = da.flatten_steps(PIPELINE_WITH_SECRET)
        risks = da.scan_for_secrets("repo", steps)
        self.assertGreaterEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "High")

    def test_aws_key_pattern_flagged(self):
        steps = da.flatten_steps(PIPELINE_WITH_AWS_KEY)
        risks = da.scan_for_secrets("repo", steps)
        self.assertGreaterEqual(len(risks), 1)

    def test_clean_pipeline_no_secrets(self):
        steps = da.flatten_steps(PIPELINE_WITH_TESTS)
        risks = da.scan_for_secrets("repo", steps)
        self.assertEqual(len(risks), 0)


class TestRiskFields(unittest.TestCase):
    def test_risk_module_is_devops(self):
        steps = da.flatten_steps(PIPELINE_WITHOUT_TESTS)
        risks = da.scan_for_test_steps("my-repo", steps)
        self.assertEqual(risks[0]["module"], "devops")

    def test_risk_resource_is_pipeline(self):
        steps = da.flatten_steps(PIPELINE_WITHOUT_TESTS)
        risks = da.scan_for_test_steps("my-repo", steps)
        self.assertEqual(risks[0]["resource"], "CI/CD Pipeline")


if __name__ == "__main__":
    unittest.main()
