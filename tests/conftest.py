"""
conftest.py — shared pytest fixtures and path setup for CloudSentinel test suite.

Path strategy
─────────────
  shared/          → inserted at index 0 (highest priority) so that
                     `from scan_events import emit_scan_completed` always
                     resolves to the single authoritative implementation.
  modules/*/       → appended so they never shadow shared/.

scan_events is also pre-registered in sys.modules right here, before any
analyzer module is imported, making the resolution order immune to further
sys.path.insert(0, ...) calls in individual test files.

E2E integration tests (test_e2e_integration.py) additionally require:
  pip install "moto[dynamodb,events,sns]>=4.0"
"""
import os
import sys

# ── Root paths ──────────────────────────────────────────────────────────────
_REPO_ROOT  = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SHARED_DIR = os.path.join(_REPO_ROOT, "shared")

_MODULE_DIRS = [
    os.path.join(_REPO_ROOT, "modules", "cloud-infra"),
    os.path.join(_REPO_ROOT, "modules", "devops"),
    os.path.join(_REPO_ROOT, "modules", "fullstack"),
    os.path.join(_REPO_ROOT, "modules", "data-eng"),
    os.path.join(_REPO_ROOT, "modules", "mobile"),
]

# shared/ must be first — append module dirs so they never beat it
for _d in _MODULE_DIRS:
    if _d not in sys.path:
        sys.path.append(_d)

# Ensure shared/ is at index 0 (re-insert in case it was added elsewhere)
if _SHARED_DIR in sys.path:
    sys.path.remove(_SHARED_DIR)
sys.path.insert(0, _SHARED_DIR)

# ── Pre-register the real scan_events into sys.modules ─────────────────────
# With shared/ now firmly at index 0, this import resolves to
# shared/scan_events.py.  Caching it in sys.modules means every subsequent
# `from scan_events import emit_scan_completed` in any analyzer is a cache
# hit — no file-system lookup, no risk of a comment-only marker winning.
import scan_events as _real_scan_events  # noqa: E402
sys.modules["scan_events"] = _real_scan_events

# ── Environment defaults ────────────────────────────────────────────────────
os.environ.setdefault("DYNAMODB_TABLE",       "cloudsentinel-risks")
os.environ.setdefault("AWS_REGION",           "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION",   "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID",    "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY","testing")
os.environ.setdefault("BEDROCK_MODEL_ID",     "anthropic.claude-3-haiku-20240307-v1:0")
os.environ.setdefault("MAX_TOKENS",           "400")
os.environ.setdefault("MAX_RISKS_PER_RUN",    "50")
os.environ.setdefault("RISKS_PAGE_LIMIT",     "100")
os.environ.setdefault("CHATBOT_CONTEXT_RISKS","20")
os.environ.setdefault("NOTIFICATION_THRESHOLD","High")
os.environ.setdefault("SNS_TOPIC_ARN",
                       "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts")
os.environ.setdefault("APP_URL",              "https://example.cloudsentinel.ai")
os.environ.setdefault("WEBHOOK_SECRET_ARN",   "")
os.environ.setdefault("GCP_SECRET_NAME",      "")
os.environ.setdefault("TARGET_ROLE_ARN",      "")
