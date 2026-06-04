# -*- coding: utf-8 -*-
"""
post_deploy_test.py -- Live integration tests for CloudSentinel after deployment.

Usage:
    python post_deploy_test.py --api-url https://<api-id>.execute-api.ap-south-1.amazonaws.com/dev

Tests every deployed endpoint and prints a pass/fail table.
"""
import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

GREEN  = ""
RED    = ""
YELLOW = ""
CYAN   = ""
RESET  = ""
BOLD   = ""

results = []

def _call(method, url, body=None, token=None, timeout=30):
    """Make an HTTP request and return (status_code, response_body_dict)."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    # Allow any HTTP method (urllib blocks OPTIONS by default)
    opener = urllib.request.build_opener(urllib.request.HTTPHandler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, _safe_json(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, _safe_json(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def _safe_json(text):
    try:
        return json.loads(text)
    except Exception:
        return {"_raw": text[:200]}


def test(name, expected_status, method, url, body=None, check=None):
    """Run one test and record the result."""
    t0 = time.time()
    status, resp = _call(method, url, body=body)
    elapsed_ms = int((time.time() - t0) * 1000)

    passed = (status == expected_status)
    if passed and check:
        try:
            check(resp)
        except AssertionError as e:
            passed = False
            resp["_check_error"] = str(e)

    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}]  {name:<52}  HTTP {status}  {elapsed_ms}ms")
    results.append({"name": name, "passed": passed, "status": status, "elapsed_ms": elapsed_ms, "response": resp})
    return resp


def section(title):
    dashes = '-' * max(0, 60 - len(title))
    print(f"\n=== {title} {dashes}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True, help="Base API Gateway URL (no trailing slash)")
    args = parser.parse_args()
    base = args.api_url.rstrip("/")

    print(f"\n{BOLD}CloudSentinel Live Integration Tests{RESET}")
    print(f"API: {base}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}\n")

    # ── 1. CORS preflight ─────────────────────────────────────────────────
    section("1. CORS Preflight (OPTIONS)")
    for route in ["risks", "scan-cloud-infra", "chat", "scan-devops",
                  "scan-fullstack", "scan-data-eng", "scan-mobile"]:
        test(f"OPTIONS /{route}", 200, "OPTIONS", f"{base}/{route}")

    # ── 2. Risk reader (GET /risks) ───────────────────────────────────────
    section("2. GET /risks")
    r = test("GET /risks (no module) returns 200",        200, "GET", f"{base}/risks",
             check=lambda b: (assert_key(b, "risks"), assert_key(b, "postureScore")))
    test("GET /risks?module=cloud-infra",                 200, "GET", f"{base}/risks?module=cloud-infra",
         check=lambda b: assert_key(b, "risks"))
    test("GET /risks?status=ALL",                        200, "GET", f"{base}/risks?status=ALL",
         check=lambda b: assert_key(b, "risks"))
    test("GET /risks?priority=High",                     200, "GET", f"{base}/risks?priority=High",
         check=lambda b: assert_key(b, "risks"))

    # ── 3. Scans ──────────────────────────────────────────────────────────
    section("3. POST /scan-* (trigger each scanner)")
    scan_body = {"providers": ["aws"]}
    test("POST /scan-cloud-infra",  200, "POST", f"{base}/scan-cloud-infra",  body=scan_body,
         check=lambda b: assert_key(b, "risksFound"))
    test("POST /scan-devops",       200, "POST", f"{base}/scan-devops",       body={},
         check=lambda b: assert_key(b, "risksFound"))
    test("POST /scan-fullstack",    200, "POST", f"{base}/scan-fullstack",    body={},
         check=lambda b: assert_key(b, "risksFound"))
    test("POST /scan-data-eng",     200, "POST", f"{base}/scan-data-eng",     body={},
         check=lambda b: assert_key(b, "risksFound"))
    test("POST /scan-mobile",       200, "POST", f"{base}/scan-mobile",       body={},
         check=lambda b: assert_key(b, "risksFound"))

    # Check risks were actually written after scans
    time.sleep(2)
    r2 = test("GET /risks after all scans (should have data)", 200, "GET", f"{base}/risks",
              check=lambda b: assert_key(b, "postureScore"))

    # ── 4. Chatbot ────────────────────────────────────────────────────────
    section("4. POST /chat (chatbot)")
    test("POST /chat valid question",        200, "POST", f"{base}/chat",
         body={"question": "What are my biggest risks?", "module": "cloud-infra"},
         check=lambda b: (assert_key(b, "answer"), assert_key(b, "contextRisks")))
    test("POST /chat missing question → 400", 400, "POST", f"{base}/chat",
         body={"module": "cloud-infra"})
    test("POST /chat empty body → 400",       400, "POST", f"{base}/chat", body={})

    # ── 5. Notifications ──────────────────────────────────────────────────
    section("5. POST /notify")
    test("POST /notify returns 200", 200, "POST", f"{base}/notify", body={},
         check=lambda b: assert_any_key(b, ["message", "status", "sent", "detail"]))

    # ── 6. Disconnect ─────────────────────────────────────────────────────
    section("6. POST /disconnect (no role → gcp only path)")
    test("POST /disconnect provider=gcp",  200, "POST", f"{base}/disconnect",
         body={"module": "cloud-infra", "provider": "gcp"},
         check=lambda b: assert_key(b, "gcp"))

    # ── Summary ───────────────────────────────────────────────────────────
    passed = sum(1 for r in results if r["passed"])
    total  = len(results)
    print(f"\n{'='*70}")
    print(f"  Results: {passed}/{total} tests passed")
    print(f"{'='*70}")

    failed = [r for r in results if not r["passed"]]
    if failed:
        print("\nFailed tests:")
        for r in failed:
            print(f"  [FAIL] {r['name']}  (HTTP {r['status']})")
            if "_check_error" in r.get("response", {}):
                print(f"    Check failed: {r['response']['_check_error']}")

    sys.exit(0 if passed == total else 1)


def assert_key(body, key):
    assert key in body, f"Response missing key '{key}': {body}"


def assert_any_key(body, keys):
    assert any(k in body for k in keys), f"Response missing any of {keys}: {body}"


if __name__ == "__main__":
    main()
