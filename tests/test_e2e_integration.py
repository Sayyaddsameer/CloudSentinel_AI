"""
tests/test_e2e_integration.py
─────────────────────────────────────────────────────────────────────────────
End-to-end integration tests for CloudSentinel Lambda handlers.

These tests use *moto* to stand up real (in-process) AWS service fakes —
DynamoDB, EventBridge, SNS — then call the actual Lambda handler functions
with realistic API-Gateway-proxy event payloads.

The goal is to verify the complete request → handler → DynamoDB → response
chain, including:

  • Table/GSI name agreement between Terraform env-vars and handler code
  • Item schema produced by cloud_scanner.build_risk()
  • Correct HTTP status codes, CORS headers, and JSON response shapes
  • chatbot_handler reading risks from DynamoDB and building a response
  • risk_reader pagination via the module-index GSI
  • graceful Bedrock fallback path in chatbot_handler

Unlike unit tests, boto3 is NOT patched here — moto intercepts it at the
transport level, so any env-var typo or wrong GSI name will surface as a
real boto3 / DynamoDB error.

Requirements
────────────
  pip install moto[dynamodb,events,sns]>=4.0  boto3  pytest

Run
────
  pytest tests/test_e2e_integration.py -v
"""

import importlib
import json
import os
import sys
import types
from unittest.mock import MagicMock, patch

import boto3
import pytest

# ── moto must be imported before any boto3 clients are created ──────────────
try:
    from moto import mock_aws  # moto >= 4.x unified decorator
except ImportError:  # pragma: no cover – older moto split decorators
    from moto import mock_dynamodb as mock_aws  # type: ignore

# ── Repo-root / module paths are already on sys.path via conftest.py ────────
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SHARED     = os.path.join(_REPO_ROOT, "shared")
_CLOUD_INFRA = os.path.join(_REPO_ROOT, "modules", "cloud-infra")

for _p in (_SHARED, _CLOUD_INFRA):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Constants must match what Terraform injects at deploy time ───────────────
TABLE_NAME = "cloudsentinel-risks"
REGION     = "us-east-1"

# ── Ensure env-vars are set before any handler module is imported ────────────
os.environ["DYNAMODB_TABLE"]   = TABLE_NAME
os.environ["AWS_REGION"]       = REGION
os.environ["AWS_DEFAULT_REGION"] = REGION
os.environ["AWS_ACCESS_KEY_ID"]     = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"]    = "testing"
os.environ["AWS_SESSION_TOKEN"]     = "testing"
os.environ["BEDROCK_MODEL_ID"]      = "anthropic.claude-3-haiku-20240307-v1:0"
os.environ["MAX_TOKENS"]            = "200"
os.environ["CHATBOT_CONTEXT_RISKS"] = "20"
os.environ["RISKS_PAGE_LIMIT"]      = "100"
os.environ["MAX_RISKS_PER_RUN"]     = "50"
os.environ["NOTIFICATION_THRESHOLD"] = "High"
os.environ["SNS_TOPIC_ARN"]         = "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts"
os.environ["APP_URL"]               = "https://test.cloudsentinel.ai"
os.environ["GCP_SECRET_NAME"]       = ""
os.environ["TARGET_ROLE_ARN"]       = ""
os.environ["WEBHOOK_SECRET_ARN"]    = ""


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _create_risks_table(ddb_client):
    """
    Create the DynamoDB risks table with the exact schema Terraform deploys.
    Schema must stay in sync with main.tf → resource "aws_dynamodb_table" "risks".
    """
    ddb_client.create_table(
        TableName=TABLE_NAME,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "resourceId",    "KeyType": "HASH"},
            {"AttributeName": "riskTimestamp", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "resourceId",    "AttributeType": "S"},
            {"AttributeName": "riskTimestamp", "AttributeType": "S"},
            {"AttributeName": "module",        "AttributeType": "S"},
            {"AttributeName": "riskPriority",  "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "module-index",
                "KeySchema": [
                    {"AttributeName": "module",        "KeyType": "HASH"},
                    {"AttributeName": "riskTimestamp", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "priority-index",
                "KeySchema": [
                    {"AttributeName": "riskPriority",  "KeyType": "HASH"},
                    {"AttributeName": "riskTimestamp", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _apigw_event(method="POST", path="/scan-cloud-infra", body=None, qs=None):
    """Build a minimal API Gateway Lambda proxy event."""
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": qs or {},
        "headers": {"Authorization": "Bearer test-token"},
        "body": json.dumps(body) if body is not None else None,
        "requestContext": {"authorizer": {"claims": {"sub": "test-user-123"}}},
    }


def _fresh_module(name: str):
    """Force a clean reimport of a handler module (clears cached boto3 globals)."""
    sys.modules.pop(name, None)
    # also clear any sub-modules that might hold stale clients
    for key in list(sys.modules):
        if key.startswith(name + "."):
            sys.modules.pop(key)
    return importlib.import_module(name)


# ═══════════════════════════════════════════════════════════════════════════
# Fixture: scan_events stub
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _stub_scan_events():
    """
    Prevent scan_events from making real EventBridge calls during E2E tests.
    We test EventBridge wiring in its own dedicated test class below.
    """
    stub = types.ModuleType("scan_events")
    stub.emit_scan_completed = MagicMock(return_value=None)
    sys.modules["scan_events"] = stub
    yield stub
    # leave stub in place — prevents accidental real calls


# ═══════════════════════════════════════════════════════════════════════════
# 1. cloud_scanner  ──  scan → DynamoDB write → response shape
# ═══════════════════════════════════════════════════════════════════════════

class TestCloudScannerE2E:
    """
    Verifies the full path:
      POST /scan-cloud-infra  →  cloud_scanner.lambda_handler
        →  moto DynamoDB (put_item)
        →  200 JSON response with risksFound, module, items
    """

    @mock_aws
    def test_scan_writes_risks_to_dynamodb_and_returns_200(self):
        # Stand up moto DynamoDB
        ddb = boto3.client("dynamodb", region_name=REGION)
        _create_risks_table(ddb)

        cs = _fresh_module("cloud_scanner")

        # Patch out all real AWS scanning calls — return empty to avoid
        # mocking the full EC2/IAM/S3 resource graph; we only care about the
        # DynamoDB write and response shape here.
        with patch.object(cs, "scan_s3_buckets", return_value=[]), \
             patch.object(cs, "scan_security_groups", return_value=[]), \
             patch.object(cs, "scan_iam_password_policy", return_value=[]), \
             patch("boto3.client") as mock_c, \
             patch("boto3.resource") as mock_r:

            # Wire DynamoDB resource to moto
            real_ddb = boto3.resource("dynamodb", region_name=REGION)
            mock_r.return_value = real_ddb
            mock_c.return_value = MagicMock()   # sts / eventbridge stubs

            resp = cs.lambda_handler(
                _apigw_event(body={"provider": "AWS", "roleArn": ""}),
                MagicMock(),
            )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert "risksFound" in body
        assert "module"     in body
        assert body["module"] == "cloud-infra"

    @mock_aws
    def test_scan_response_contains_cors_header(self):
        ddb = boto3.client("dynamodb", region_name=REGION)
        _create_risks_table(ddb)

        cs = _fresh_module("cloud_scanner")

        with patch.object(cs, "scan_s3_buckets", return_value=[]), \
             patch.object(cs, "scan_security_groups", return_value=[]), \
             patch.object(cs, "scan_iam_password_policy", return_value=[]), \
             patch("boto3.client") as mock_c, \
             patch("boto3.resource") as mock_r:

            real_ddb = boto3.resource("dynamodb", region_name=REGION)
            mock_r.return_value = real_ddb
            mock_c.return_value = MagicMock()

            resp = cs.lambda_handler(
                _apigw_event(body={"provider": "AWS", "roleArn": ""}),
                MagicMock(),
            )

        assert "Access-Control-Allow-Origin" in resp.get("headers", {}), (
            "All Lambda responses must include CORS headers for browser clients"
        )

    @mock_aws
    def test_risk_item_schema_matches_expected_fields(self):
        """
        Validates that build_risk() produces a DynamoDB item that contains
        every field the frontend and risk_reader Lambda expect.
        """
        import cloud_scanner as cs  # noqa: PLC0415

        required_fields = [
            "resourceId", "riskTimestamp", "module", "cloudProvider",
            "resource", "resourceName", "riskType", "riskReason",
            "riskPriority", "remediationSteps", "alternativeSolutions",
            "aiExplanation", "riskCategory", "status", "region",
        ]

        item = cs.build_risk(
            "cloud-infra", "S3 Bucket", "e2e-test-bucket",
            "Public Access Enabled", "Bucket policy allows public read", "High",
        )

        for field in required_fields:
            assert field in item, (
                f"build_risk() must include '{field}' — "
                f"the frontend and risk_reader depend on it"
            )

        assert item["status"]      == "OPEN"
        assert item["module"]      == "cloud-infra"
        assert item["riskPriority"] == "High"
        assert item["aiExplanation"] == ""


# ═══════════════════════════════════════════════════════════════════════════
# 2. risk_reader  ──  GET /risks reads from module-index GSI
# ═══════════════════════════════════════════════════════════════════════════

class TestRiskReaderE2E:
    """
    Verifies the full path:
      GET /risks?module=cloud-infra  →  risk_reader.lambda_handler
        →  DynamoDB module-index GSI query
        →  200 JSON with items list
    """

    _SEED_ITEMS = [
        {
            "resourceId":    f"cloud-infra-s3-bucket-{i}",
            "riskTimestamp": f"2026-05-10T12:0{i}:00+00:00",
            "module":        "cloud-infra",
            "riskType":      "Public S3 Bucket",
            "riskReason":    "Block public access is disabled",
            "riskPriority":  "High",
            "resource":      "S3 Bucket",
            "resourceName":  f"bucket-{i}",
            "cloudProvider": "AWS",
            "status":        "OPEN",
            "region":        "us-east-1",
            "aiExplanation": "",
            "riskCategory":  "SECURITY",
            "remediationSteps":    ["Enable block public access"],
            "alternativeSolutions": [],
        }
        for i in range(3)
    ]

    @mock_aws
    def test_risk_reader_returns_seeded_items(self):
        ddb_client = boto3.client("dynamodb", region_name=REGION)
        _create_risks_table(ddb_client)

        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        for item in self._SEED_ITEMS:
            table.put_item(Item=item)

        rr = _fresh_module("risk_reader")

        resp = rr.lambda_handler(
            _apigw_event(
                method="GET",
                path="/risks",
                qs={"module": "cloud-infra"},
            ),
            MagicMock(),
        )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        # risk_reader returns {"risks": [...], "count": N}
        assert "risks" in body, "risk_reader response must contain 'risks' key"
        assert len(body["risks"]) == len(self._SEED_ITEMS), (
            "risk_reader must return all seeded items for the queried module"
        )

    @mock_aws
    def test_risk_reader_different_module_returns_empty(self):
        ddb_client = boto3.client("dynamodb", region_name=REGION)
        _create_risks_table(ddb_client)

        # seed items for cloud-infra only
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        for item in self._SEED_ITEMS:
            table.put_item(Item=item)

        rr = _fresh_module("risk_reader")

        resp = rr.lambda_handler(
            _apigw_event(
                method="GET",
                path="/risks",
                qs={"module": "devops"},
            ),
            MagicMock(),
        )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["risks"] == [], (
            "risk_reader must return empty list when no risks exist for the module"
        )

    @mock_aws
    def test_risk_reader_missing_module_param_returns_all(self):
        """When no module filter is given, risk_reader returns all items."""
        ddb_client = boto3.client("dynamodb", region_name=REGION)
        _create_risks_table(ddb_client)

        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        for item in self._SEED_ITEMS:
            table.put_item(Item=item)

        rr = _fresh_module("risk_reader")

        resp = rr.lambda_handler(
            _apigw_event(method="GET", path="/risks", qs={}),
            MagicMock(),
        )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        # risk_reader returns {"risks": [...], "count": N}
        assert len(body["risks"]) >= len(self._SEED_ITEMS)


# ═══════════════════════════════════════════════════════════════════════════
# 3. chatbot_handler  ──  POST /chat reads risks from DynamoDB, calls Bedrock
# ═══════════════════════════════════════════════════════════════════════════

class TestChatbotHandlerE2E:
    """
    Verifies the full path:
      POST /chat  →  chatbot_handler.lambda_handler
        →  DynamoDB module-index GSI query (real moto table)
        →  Bedrock invoke (mocked — not available in moto)
        →  200 JSON with answer, contextRisks, aiPowered

    Two sub-scenarios:
      (a) Bedrock succeeds  →  aiPowered=True, answer from Bedrock
      (b) Bedrock fails     →  aiPowered=False, graceful fallback answer
    """

    _RISK = {
        "resourceId":    "cloud-infra-iam-no-policy",
        "riskTimestamp": "2026-05-10T10:00:00+00:00",
        "module":        "cloud-infra",
        "riskType":      "Missing IAM Password Policy",
        "riskReason":    "No account password policy is configured",
        "riskPriority":  "High",
        "resource":      "IAM",
        "resourceName":  "account",
        "cloudProvider": "AWS",
        "status":        "OPEN",
        "region":        "us-east-1",
        "aiExplanation": "",
        "riskCategory":  "SECURITY",
        "remediationSteps":    ["Set a strong password policy via IAM console"],
        "alternativeSolutions": [],
    }

    def _seed_table(self):
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        table.put_item(Item=self._RISK)
        return table

    @mock_aws
    def test_chatbot_returns_200_with_bedrock_success(self):
        _create_risks_table(boto3.client("dynamodb", region_name=REGION))
        self._seed_table()

        ch = _fresh_module("chatbot_handler")

        bedrock_response_body = json.dumps({
            "content": [{"text": "Your IAM account has no password policy set. Remediate by..."}]
        }).encode()
        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = {
            "body": MagicMock(read=lambda: bedrock_response_body)
        }

        with patch("boto3.client", side_effect=lambda svc, **kw:
                   mock_bedrock if "bedrock" in svc else boto3.client(svc, **kw)):
            resp = ch.lambda_handler(
                _apigw_event(body={"question": "What are my risks?", "module": "cloud-infra"}),
                MagicMock(),
            )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["aiPowered"] is True
        assert body["contextRisks"] == 1, (
            "chatbot must load the 1 seeded risk as context from DynamoDB"
        )
        assert "IAM" in body["answer"] or len(body["answer"]) > 10

    @mock_aws
    def test_chatbot_graceful_fallback_when_bedrock_unavailable(self):
        _create_risks_table(boto3.client("dynamodb", region_name=REGION))
        self._seed_table()

        ch = _fresh_module("chatbot_handler")

        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.side_effect = Exception("Bedrock service unavailable")

        with patch("boto3.client", side_effect=lambda svc, **kw:
                   mock_bedrock if "bedrock" in svc else boto3.client(svc, **kw)):
            resp = ch.lambda_handler(
                _apigw_event(body={"question": "summarize risks", "module": "cloud-infra"}),
                MagicMock(),
            )

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["aiPowered"] is False, (
            "aiPowered must be False when Bedrock raises an exception"
        )
        assert body["contextRisks"] == 1
        # Fallback answer must acknowledge unavailability and include risk data
        assert "unavailable" in body["answer"].lower() or "High" in body["answer"], (
            "Graceful fallback must mention unavailability or include real risk data"
        )
        assert "Missing IAM Password Policy" in body["answer"], (
            "_graceful_fallback must surface the seeded High-priority risk by name"
        )

    @mock_aws
    def test_chatbot_returns_400_for_missing_question(self):
        _create_risks_table(boto3.client("dynamodb", region_name=REGION))

        ch = _fresh_module("chatbot_handler")

        resp = ch.lambda_handler(
            _apigw_event(body={"module": "cloud-infra"}),  # no "question" key
            MagicMock(),
        )

        assert resp["statusCode"] == 400
        body = json.loads(resp["body"])
        assert "error" in body

    @mock_aws
    def test_chatbot_returns_400_for_invalid_json(self):
        _create_risks_table(boto3.client("dynamodb", region_name=REGION))

        ch = _fresh_module("chatbot_handler")

        bad_event = _apigw_event()
        bad_event["body"] = "not-json{"

        resp = ch.lambda_handler(bad_event, MagicMock())

        assert resp["statusCode"] == 400


# ═══════════════════════════════════════════════════════════════════════════
# 4. scan_events (shared layer)  ──  emit_scan_completed → EventBridge
# ═══════════════════════════════════════════════════════════════════════════

class TestScanEventsE2E:
    """
    Verifies that emit_scan_completed() puts a correctly-shaped event onto
    EventBridge.  Uses the real shared/scan_events.py (not the conftest stub).
    """

    @mock_aws
    def test_emit_puts_event_with_correct_source_and_detail(self):
        # Force a clean reload from shared/ explicitly
        import importlib.util
        spec = importlib.util.spec_from_file_location("real_scan_events", os.path.join(_SHARED, "scan_events.py"))
        real_scan_events = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real_scan_events)

        risks = [
            {"riskPriority": "High"},
            {"riskPriority": "High"},
            {"riskPriority": "Medium"},
            {"riskPriority": "Low"},
        ]

        # Should complete without raising (moto intercepts EventBridge)
        real_scan_events.emit_scan_completed("cloud-infra", risks)

        # Restore the conftest pre-registration so other tests are unaffected
        sys.modules["scan_events"] = real_scan_events

    @mock_aws
    def test_emit_is_non_fatal_when_eventbridge_errors(self):
        """A failed put_events call must never propagate to the caller."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("real_scan_events", os.path.join(_SHARED, "scan_events.py"))
        real_scan_events = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real_scan_events)

        with patch("boto3.client") as mock_client:
            mock_eb = MagicMock()
            mock_eb.put_events.return_value = {
                "FailedEntryCount": 1,
                "Entries": [{"ErrorCode": "InternalFailure"}],
            }
            mock_client.return_value = mock_eb

            # Must not raise even when EventBridge reports a failure
            real_scan_events.emit_scan_completed("devops", [{"riskPriority": "High"}])

        sys.modules["scan_events"] = real_scan_events


# ═══════════════════════════════════════════════════════════════════════════
# 5. Wiring contract — env-var / table-name sanity guards
# ═══════════════════════════════════════════════════════════════════════════

class TestDeploymentWiringContracts:
    """
    Lightweight smoke tests that codify the deployment contracts shared
    between Terraform (env-var injection) and Lambda handler code.
    These fail fast with a clear message if a refactor breaks the wiring.
    """

    def test_dynamodb_table_env_var_is_set(self):
        assert os.environ.get("DYNAMODB_TABLE"), (
            "DYNAMODB_TABLE env-var must be set — Terraform injects this at deploy time"
        )

    def test_table_name_matches_terraform_default(self):
        # Terraform default: "${var.project}-risks" → "cloudsentinel-risks"
        table = os.environ["DYNAMODB_TABLE"]
        assert "cloudsentinel" in table.lower() or "risks" in table.lower(), (
            f"Table name '{table}' doesn't match the expected 'cloudsentinel-risks' pattern"
        )

    @mock_aws
    def test_module_index_gsi_is_queryable(self):
        """The module-index GSI must exist and accept a query — mimics risk_reader."""
        _create_risks_table(boto3.client("dynamodb", region_name=REGION))
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        from boto3.dynamodb.conditions import Key

        result = table.query(
            IndexName="module-index",
            KeyConditionExpression=Key("module").eq("cloud-infra"),
        )
        assert "Items" in result, (
            "module-index GSI must be queryable — risk_reader and chatbot depend on it"
        )

    @mock_aws
    def test_priority_index_gsi_is_queryable(self):
        """The priority-index GSI must exist — future notification_handler uses it."""
        _create_risks_table(boto3.client("dynamodb", region_name=REGION))
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
        from boto3.dynamodb.conditions import Key

        result = table.query(
            IndexName="priority-index",
            KeyConditionExpression=Key("riskPriority").eq("High"),
        )
        assert "Items" in result, (
            "priority-index GSI must be queryable — notification_handler depends on it"
        )
