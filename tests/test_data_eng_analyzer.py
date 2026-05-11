"""
Unit tests for data_eng_analyzer.py
Bikkavolu Srivallisa Sai Veerabhadra Ayyan
"""

import os
import sys
import unittest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

os.environ.setdefault("DYNAMODB_TABLE",   "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION",       "us-east-1")
os.environ.setdefault("GLUE_FAIL_THRESHOLD", "2")
os.environ.setdefault("GLUE_RUNS_WINDOW",    "5")

import data_eng_analyzer as de


class TestSensitiveName(unittest.TestCase):
    def test_customer_is_sensitive(self):
        self.assertTrue(de.is_sensitive_name("customer-records"))

    def test_user_is_sensitive(self):
        self.assertTrue(de.is_sensitive_name("user-uploads"))

    def test_pii_is_sensitive(self):
        self.assertTrue(de.is_sensitive_name("pii-data-bucket"))

    def test_app_logs_not_sensitive(self):
        self.assertFalse(de.is_sensitive_name("app-logs"))

    def test_static_assets_not_sensitive(self):
        self.assertFalse(de.is_sensitive_name("static-assets"))

    def test_case_insensitive(self):
        self.assertTrue(de.is_sensitive_name("CUSTOMER-DATA"))


class TestBuildRisk(unittest.TestCase):
    def test_module_field_is_data_eng(self):
        r = de.build_risk("Data Storage", "test-bucket", "T", "R", "High")
        self.assertEqual(r["module"], "data-eng")

    def test_status_starts_open(self):
        r = de.build_risk("Data Storage", "test-bucket", "T", "R", "Medium")
        self.assertEqual(r["status"], "OPEN")

    def test_priority_preserved(self):
        for p in ("High", "Medium", "Low"):
            r = de.build_risk("Data Storage", "b", "T", "R", p)
            self.assertEqual(r["riskPriority"], p)


class TestS3Scan(unittest.TestCase):
    def test_sensitive_bucket_no_pab_gives_high(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "customer-records"}]}
        s3.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": ""}},
            "GetPublicAccessBlock"
        )
        table = MagicMock()
        risks = de.scan_s3_data_buckets(s3, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "High")

    def test_non_sensitive_bucket_no_pab_gives_medium(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "app-logs"}]}
        s3.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": ""}},
            "GetPublicAccessBlock"
        )
        table = MagicMock()
        risks = de.scan_s3_data_buckets(s3, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "Medium")


class TestGlueFailures(unittest.TestCase):
    def test_two_failures_flagged(self):
        glue = MagicMock()
        glue.get_jobs.return_value = {"Jobs": [{"Name": "etl-load"}]}
        glue.get_job_runs.return_value = {
            "JobRuns": [
                {"JobRunState": "FAILED", "ErrorMessage": "OOM"},
                {"JobRunState": "FAILED", "ErrorMessage": "OOM"},
                {"JobRunState": "SUCCEEDED"},
            ]
        }
        table = MagicMock()
        risks = de.scan_glue_jobs(glue, table)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["riskPriority"], "High")

    def test_single_failure_not_flagged(self):
        glue = MagicMock()
        glue.get_jobs.return_value = {"Jobs": [{"Name": "etl-load"}]}
        glue.get_job_runs.return_value = {
            "JobRuns": [
                {"JobRunState": "FAILED", "ErrorMessage": "timeout"},
                {"JobRunState": "SUCCEEDED"},
                {"JobRunState": "SUCCEEDED"},
            ]
        }
        table = MagicMock()
        risks = de.scan_glue_jobs(glue, table)
        self.assertEqual(len(risks), 0)


if __name__ == "__main__":
    unittest.main()
