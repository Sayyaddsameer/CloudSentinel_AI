"""
conftest.py — shared pytest fixtures and path setup for CloudSentinel test suite.
Ensures all module source directories are on sys.path before any test file imports.
"""
import os
import sys
import pytest

# ── Resolve module paths relative to this file's location ──────────────────
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

MODULE_DIRS = [
    os.path.join(_REPO_ROOT, "modules", "cloud-infra"),
    os.path.join(_REPO_ROOT, "modules", "devops"),
    os.path.join(_REPO_ROOT, "modules", "fullstack"),
    os.path.join(_REPO_ROOT, "modules", "mobile"),
    os.path.join(_REPO_ROOT, "modules", "data-eng"),
]

for _d in MODULE_DIRS:
    if _d not in sys.path:
        sys.path.insert(0, _d)


# ── Environment defaults (set before any module-level import in test files) ─
os.environ.setdefault("DYNAMODB_TABLE",      "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION",          "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION",  "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID",   "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("BEDROCK_MODEL_ID",    "anthropic.claude-3-haiku-20240307-v1:0")
os.environ.setdefault("MAX_TOKENS",          "400")
os.environ.setdefault("MAX_RISKS_PER_RUN",   "50")
os.environ.setdefault("RISKS_PAGE_LIMIT",    "100")
os.environ.setdefault("CHATBOT_CONTEXT_RISKS", "20")
os.environ.setdefault("NOTIFICATION_THRESHOLD", "High")
os.environ.setdefault("SNS_TOPIC_ARN",       "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts")
os.environ.setdefault("APP_URL",             "https://example.cloudsentinel.ai")
os.environ.setdefault("WEBHOOK_SECRET_ARN",  "")
os.environ.setdefault("GCP_SECRET_NAME",     "")
os.environ.setdefault("TARGET_ROLE_ARN",     "")
