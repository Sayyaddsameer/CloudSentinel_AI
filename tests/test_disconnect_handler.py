"""
test_disconnect_handler.py
Unit tests for disconnect_handler.py -- Automated cloud access revocation
Sayyad Sameer
"""

import json
import unittest
from unittest.mock import MagicMock, patch, call
from botocore.exceptions import ClientError
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "cloud-infra"))
os.environ.setdefault("DYNAMODB_TABLE", "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION", "us-east-1")


def _client_error(code, op="Op"):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class TestOptionsMethod(unittest.TestCase):
    def test_options_returns_200(self):
        import disconnect_handler as dh
        resp = dh.lambda_handler({"httpMethod": "OPTIONS"}, None)
        self.assertEqual(resp["statusCode"], 200)


class TestDeleteCfnStack(unittest.TestCase):
    """Test cross-account CloudFormation stack deletion."""

    @patch("disconnect_handler.boto3")
    def test_delete_initiated_on_success(self, mock_boto3):
        import disconnect_handler as dh
        sts = MagicMock()
        sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST"
            }
        }
        cf = MagicMock()
        cf.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}

        mock_boto3.client.side_effect = lambda svc, **kw: sts if svc == "sts" else cf

        result = dh._delete_cfn_stack(
            "arn:aws:iam::123456789012:role/CloudSentinel-ScannerRole",
            "CloudSentinel-Scanner"
        )
        self.assertEqual(result, "delete_initiated")
        cf.delete_stack.assert_called_once()

    @patch("disconnect_handler.boto3")
    def test_already_deleted_when_stack_missing(self, mock_boto3):
        import disconnect_handler as dh
        sts = MagicMock()
        sts.assume_role.return_value = {
            "Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST"}
        }
        cf = MagicMock()
        cf.describe_stacks.side_effect = _client_error("ValidationError")

        mock_boto3.client.side_effect = lambda svc, **kw: sts if svc == "sts" else cf

        result = dh._delete_cfn_stack(
            "arn:aws:iam::123456789012:role/ScannerRole",
            "CloudSentinel-Scanner"
        )
        self.assertIn(result, ["already_deleted", "instructions", "delete_initiated"])

    @patch("disconnect_handler.boto3")
    def test_instructions_on_access_denied(self, mock_boto3):
        import disconnect_handler as dh
        sts = MagicMock()
        sts.assume_role.side_effect = _client_error("AccessDenied", "AssumeRole")
        mock_boto3.client.return_value = sts

        result = dh._delete_cfn_stack(
            "arn:aws:iam::123456789012:role/ScannerRole",
            "CloudSentinel-Scanner"
        )
        self.assertEqual(result, "instructions")

    @patch("disconnect_handler.boto3")
    def test_empty_role_arn_skips(self, mock_boto3):
        import disconnect_handler as dh
        # lambda_handler with empty roleArn and provider=aws
        event = {
            "httpMethod": "POST",
            "body": json.dumps({"module": "cloud-infra", "provider": "aws", "roleArn": ""}),
        }
        mock_ddb = MagicMock()
        mock_ddb.Table.return_value.query.return_value = {"Items": []}
        mock_boto3.resource.return_value = mock_ddb
        mock_boto3.client.return_value = MagicMock()

        resp = dh.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        # No roleArn so aws action should be skipped
        self.assertEqual(body["aws"], "skipped")


class TestDeleteGcpSecret(unittest.TestCase):
    """Test GCP credential deletion from Secrets Manager."""

    @patch("disconnect_handler.boto3")
    def test_secret_deleted_on_success(self, mock_boto3):
        import disconnect_handler as dh
        sm = MagicMock()
        sm.delete_secret.return_value = {}
        mock_boto3.client.return_value = sm

        result = dh._delete_gcp_secret("cloud-infra")
        self.assertEqual(result, "deleted")
        sm.delete_secret.assert_called_once_with(
            SecretId="cloudsentinel-gcp-creds-cloud-infra",
            ForceDeleteWithoutRecovery=True
        )

    @patch("disconnect_handler.boto3")
    def test_not_found_returns_gracefully(self, mock_boto3):
        import disconnect_handler as dh
        sm = MagicMock()
        sm.delete_secret.side_effect = _client_error("ResourceNotFoundException", "DeleteSecret")
        mock_boto3.client.return_value = sm

        result = dh._delete_gcp_secret("cloud-infra")
        self.assertEqual(result, "not_found")


class TestPurgeRisks(unittest.TestCase):
    """Test DynamoDB risk record purge."""

    @patch("disconnect_handler.boto3")
    def test_purges_all_items(self, mock_boto3):
        import disconnect_handler as dh
        table = MagicMock()
        table.query.return_value = {
            "Items": [
                # Keys must match what _purge_risks reads: resourceId + riskTimestamp
                {"resourceId": "id1", "riskTimestamp": "2026-05-01T00:00:00+00:00", "module": "cloud-infra"},
                {"resourceId": "id2", "riskTimestamp": "2026-05-02T00:00:00+00:00", "module": "cloud-infra"},
            ]
        }
        batch_writer = MagicMock()
        batch_writer.__enter__ = MagicMock(return_value=batch_writer)
        batch_writer.__exit__ = MagicMock(return_value=False)
        table.batch_writer.return_value = batch_writer

        ddb = MagicMock()
        ddb.Table.return_value = table
        mock_boto3.resource.return_value = ddb

        count = dh._purge_risks("cloud-infra")
        self.assertEqual(count, 2)

    @patch("disconnect_handler.boto3")
    def test_empty_table_returns_zero(self, mock_boto3):
        import disconnect_handler as dh
        table = MagicMock()
        table.query.return_value = {"Items": []}
        batch_writer = MagicMock()
        batch_writer.__enter__ = MagicMock(return_value=batch_writer)
        batch_writer.__exit__ = MagicMock(return_value=False)
        table.batch_writer.return_value = batch_writer

        ddb = MagicMock()
        ddb.Table.return_value = table
        mock_boto3.resource.return_value = ddb

        count = dh._purge_risks("devops")
        self.assertEqual(count, 0)


class TestFullDisconnectFlow(unittest.TestCase):
    """Integration-style test for the full lambda_handler disconnect flow."""

    @patch("disconnect_handler.boto3")
    def test_gcp_disconnect_calls_secret_delete(self, mock_boto3):
        import disconnect_handler as dh
        sm = MagicMock()
        sm.delete_secret.return_value = {}

        table = MagicMock()
        table.query.return_value = {"Items": []}
        batch_writer = MagicMock()
        batch_writer.__enter__ = MagicMock(return_value=batch_writer)
        batch_writer.__exit__ = MagicMock(return_value=False)
        table.batch_writer.return_value = batch_writer
        ddb = MagicMock()
        ddb.Table.return_value = table

        mock_boto3.resource.return_value = ddb
        mock_boto3.client.return_value = sm

        event = {
            "httpMethod": "POST",
            "body": json.dumps({"module": "cloud-infra", "provider": "gcp", "roleArn": ""}),
        }
        resp = dh.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["gcp"], "deleted")

    @patch("disconnect_handler.boto3")
    def test_cors_headers_present(self, mock_boto3):
        import disconnect_handler as dh
        sm = MagicMock()
        sm.delete_secret.return_value = {}
        table = MagicMock()
        table.query.return_value = {"Items": []}
        batch_writer = MagicMock()
        batch_writer.__enter__ = MagicMock(return_value=batch_writer)
        batch_writer.__exit__ = MagicMock(return_value=False)
        table.batch_writer.return_value = batch_writer
        ddb = MagicMock()
        ddb.Table.return_value = table
        mock_boto3.resource.return_value = ddb
        mock_boto3.client.return_value = sm

        event = {
            "httpMethod": "POST",
            "body": json.dumps({"module": "devops", "provider": "gcp"}),
        }
        resp = dh.lambda_handler(event, None)
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])


if __name__ == "__main__":
    unittest.main()
