"""
tests/test_ai_explainer.py
Unit tests for modules/cloud-infra/ai_explainer.py

Covers:
  - classify_risk_with_comprehend() key-phrase mapping → SECURITY / COMPLIANCE / RELIABILITY
  - classify_risk_with_comprehend() Comprehend exception → defaults to SECURITY
  - lambda_handler() end-to-end: fetches OPEN risks, calls Bedrock, calls Comprehend, writes back
"""

import importlib
import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# conftest.py already puts modules/cloud-infra on sys.path.
# We still need a stub for scan_events so importing ai_explainer doesn't fail.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def stub_scan_events():
    """Provide a minimal scan_events stub so ai_explainer can be imported."""
    mod = types.ModuleType("scan_events")
    mod.emit_scan_completed = MagicMock()
    sys.modules.setdefault("scan_events", mod)
    yield
    # leave the stub in place for the duration of the session


@pytest.fixture()
def ai_explainer():
    """Fresh import of ai_explainer for each test (avoids module-level cache issues)."""
    if "ai_explainer" in sys.modules:
        del sys.modules["ai_explainer"]
    import ai_explainer as m
    return m


# ---------------------------------------------------------------------------
# classify_risk_with_comprehend — keyword mapping
# ---------------------------------------------------------------------------

class TestClassifyRiskWithComprehend:
    def _make_comp(self, phrases):
        """Return a mock Comprehend client whose detect_key_phrases returns *phrases*."""
        client = MagicMock()
        client.detect_key_phrases.return_value = {
            "KeyPhrases": [{"Text": p} for p in phrases]
        }
        return client

    def test_security_keywords_map_to_security(self, ai_explainer):
        comp = self._make_comp(["exposed bucket", "public acl"])
        result = ai_explainer.classify_risk_with_comprehend(comp, "exposed bucket public acl")
        assert result == "SECURITY"

    def test_compliance_keywords_map_to_compliance(self, ai_explainer):
        comp = self._make_comp(["unencrypted disk", "pii data"])
        result = ai_explainer.classify_risk_with_comprehend(comp, "unencrypted pii data")
        assert result == "COMPLIANCE"

    def test_reliability_keywords_map_to_reliability(self, ai_explainer):
        comp = self._make_comp(["crash", "downtime", "retry storm"])
        result = ai_explainer.classify_risk_with_comprehend(comp, "crash downtime retry")
        assert result == "RELIABILITY"

    def test_comprehend_exception_defaults_to_security(self, ai_explainer):
        comp = MagicMock()
        comp.detect_key_phrases.side_effect = Exception("throttled")
        result = ai_explainer.classify_risk_with_comprehend(comp, "some risk text")
        assert result == "SECURITY"

    def test_no_matching_keywords_defaults_to_security(self, ai_explainer):
        comp = self._make_comp(["completely unrelated phrase"])
        result = ai_explainer.classify_risk_with_comprehend(comp, "unrelated phrase")
        assert result == "SECURITY"


# ---------------------------------------------------------------------------
# lambda_handler — end-to-end with mocked AWS clients
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    _OPEN_RISK = {
        "resourceId":    "cloud-infra-iam-public-read",
        "riskTimestamp": "2026-05-01T12:00:00+00:00",
        "riskType":      "IAM Public Read",
        "riskReason":    "Bucket has public read access",
        "riskPriority":  "High",
        "resource":      "S3 Bucket",
        "resourceName":  "my-bucket",
        "aiExplanation": "",
    }

    def _make_table(self, items):
        table = MagicMock()
        table.scan.return_value = {"Items": items}
        table.update_item.return_value = {}
        return table

    def test_handler_processes_open_risk_and_writes_back(self, ai_explainer):
        table     = self._make_table([self._OPEN_RISK])
        bedrock   = MagicMock()
        comp      = MagicMock()

        # Bedrock returns a plain-text explanation
        bedrock.invoke_model.return_value = {
            "body": MagicMock(read=lambda: json.dumps({
                "content": [{"text": "This is a security risk because ..."}]
            }).encode())
        }

        # Comprehend classifies it as SECURITY
        comp.detect_key_phrases.return_value = {
            "KeyPhrases": [{"Text": "public read"}, {"Text": "iam"}]
        }

        with patch("boto3.resource") as mock_resource, \
             patch("boto3.client") as mock_client:

            mock_resource.return_value.Table.return_value = table
            # boto3.client is called twice: bedrock-runtime, comprehend
            mock_client.side_effect = lambda svc, **kw: bedrock if "bedrock" in svc else comp

            resp = ai_explainer.lambda_handler({}, MagicMock())

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["processed"] == 1

        # Verify update_item was called with the right keys
        call_kwargs = table.update_item.call_args.kwargs
        assert call_kwargs["Key"]["resourceId"] == "cloud-infra-iam-public-read"
        assert ":ex" in call_kwargs["ExpressionAttributeValues"]
        assert call_kwargs["ExpressionAttributeValues"][":cat"] == "SECURITY"

    def test_handler_uses_fallback_when_groq_fails(self, ai_explainer):
        """When Groq is unavailable the handler uses a template fallback and still
        persists an explanation — processed stays 1 (not 0)."""
        table   = self._make_table([self._OPEN_RISK])
        comp    = MagicMock()
        comp.detect_key_phrases.return_value = {"KeyPhrases": []}

        with patch("boto3.resource") as mock_resource, \
             patch("boto3.client") as mock_client, \
             patch("urllib.request.urlopen", side_effect=Exception("connection refused")):

            mock_resource.return_value.Table.return_value = table
            mock_client.return_value = comp

            resp = ai_explainer.lambda_handler({}, MagicMock())

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        # Fallback explanation is written even when Groq is down
        assert body["processed"] == 1
        table.update_item.assert_called_once()

    def test_handler_returns_200_when_no_open_risks(self, ai_explainer):
        table = self._make_table([])

        with patch("boto3.resource") as mock_resource, \
             patch("boto3.client"):

            mock_resource.return_value.Table.return_value = table
            resp = ai_explainer.lambda_handler({}, MagicMock())

        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["processed"] == 0
