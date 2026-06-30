import base64
import hashlib
import hmac
import json
import os
import logging
import re
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

import boto3
from botocore.exceptions import ClientError

from shared.scan_events import emit_scan_completed
from shared.schemas.risk_record import build_risk_record

try:
    import yaml
except ImportError:          # PyYAML not installed in test env — fallback parser
    yaml = None

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME           = os.environ["DYNAMODB_TABLE"]
REGION               = os.environ["AWS_REGION"]
DDB_REGION           = os.environ.get("DDB_REGION") or REGION
AI_EXPLAINER_FN      = os.environ.get("AI_EXPLAINER_FUNCTION_NAME", "cloudsentinel-ai-explainer")
WEBHOOK_SECRET_ARN   = os.environ.get("WEBHOOK_SECRET_ARN", "")
GITHUB_PAT_SECRET_ARN = os.environ.get("GITHUB_PAT_SECRET_ARN", "")
GITHUB_API_BASE      = "https://api.github.com"

# Set by lambda_handler to the user-chosen scan region before any build_risk calls
_SCAN_REGION = REGION

# Regex patterns for secret detection
SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|token|api_key|apikey)\s*[:=]\s*["\']?\S{8,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),                   # AWS access key ID
    re.compile(r'(?i)aws_secret_access_key\s*=\s*\S+'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),                # GitHub PAT
    re.compile(r'ghs_[A-Za-z0-9]{36}'),                # GitHub Actions token
    re.compile(r'sk-[A-Za-z0-9]{32,}'),                # OpenAI / Stripe keys
    re.compile(r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'),  # Private keys
    re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}'),         # Bearer tokens
    re.compile(r'(?i)(client_secret|consumer_secret)\s*[:=]\s*\S{8,}'),
]

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}


# ---------------------------------------------------------------------------
# Webhook signature verification
# GitHub signs every webhook payload with HMAC-SHA256 using WEBHOOK_SECRET
# ---------------------------------------------------------------------------

def _get_secret(arn):
    """Generic Secrets Manager retrieval — returns None on any error."""
    if not arn:
        return None
    try:
        sm = boto3.client("secretsmanager", region_name=REGION)
        return sm.get_secret_value(SecretId=arn)["SecretString"]
    except Exception as e:
        logger.error(f"Could not retrieve secret {arn}: {e}")
        return None


def get_webhook_secret():
    return _get_secret(WEBHOOK_SECRET_ARN)


def get_github_pat():
    return _get_secret(GITHUB_PAT_SECRET_ARN)


# ---------------------------------------------------------------------------
# GitHub API — fetch workflow YAML files from a repository
# Calls GET /repos/{owner}/{repo}/contents/.github/workflows to list all
# YAML files, then fetches and merges each one into a single pipeline_config
# dict so the existing scan checks run against real pipeline definitions.
# ---------------------------------------------------------------------------

def _github_api_get(path, pat):
    """Make an authenticated GET request to the GitHub API."""
    url = f"{GITHUB_API_BASE}{path}"
    headers = {
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "CloudSentinel-DevOps-Analyzer/1.0",
    }
    if pat:
        headers["Authorization"] = f"Bearer {pat}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        logger.warning(f"GitHub API request failed for {path}: {e}")
        return None


def _parse_yaml_content(raw_text):
    """Parse a YAML workflow file; returns dict or {} on failure."""
    if yaml is None:
        # PyYAML unavailable — return an empty config that triggers gap checks
        logger.warning("PyYAML not available; skipping YAML parse")
        return {}
    try:
        return yaml.safe_load(raw_text) or {}
    except Exception as e:
        logger.warning(f"YAML parse error: {e}")
        return {}


def _fetch_workflow_from_github(full_repo_name):
    """
    Fetch all .github/workflows/*.yml files for *full_repo_name* (owner/repo).
    Returns a merged pipeline_config dict compatible with flatten_steps(), or
    None if the fetch fails.
    """
    pat = get_github_pat()
    if not pat:
        logger.info("No GITHUB_PAT_SECRET_ARN configured — skipping GitHub API fetch")
        return None

    owner_repo = full_repo_name.replace(" ", "-")  # safety normalise
    listing = _github_api_get(
        f"/repos/{owner_repo}/contents/.github/workflows", pat
    )
    if not listing or not isinstance(listing, list):
        logger.warning(f"Could not list workflow files for {owner_repo}")
        return None

    merged_jobs = {}
    for entry in listing:
        name = entry.get("name", "")
        if not name.endswith((".yml", ".yaml")):
            continue
        file_meta = _github_api_get(f"/repos/{owner_repo}/contents/.github/workflows/{name}", pat)
        if not file_meta or "content" not in file_meta:
            continue
        try:
            raw_yaml = base64.b64decode(file_meta["content"]).decode("utf-8")
        except Exception as e:
            logger.warning(f"Base64 decode failed for {name}: {e}")
            continue
        workflow = _parse_yaml_content(raw_yaml)
        jobs = workflow.get("jobs", {})
        # Prefix job names with the workflow file name to avoid collisions
        prefix = name.replace(".yml", "").replace(".yaml", "")
        for job_key, job_val in jobs.items():
            merged_jobs[f"{prefix}__{job_key}"] = job_val
        logger.info(f"Fetched {len(jobs)} job(s) from {name}")

    if not merged_jobs:
        logger.warning("No jobs found in fetched workflow files")
        return None

    logger.info(f"GitHub API fetch complete — {len(merged_jobs)} total job(s) for {owner_repo}")
    return {"jobs": merged_jobs}


def verify_github_signature(payload_bytes, signature_header, secret):
    """Constant-time HMAC-SHA256 comparison against the GitHub signature header."""
    if not signature_header or not secret:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ---------------------------------------------------------------------------
# Risk builder
# ---------------------------------------------------------------------------

def build_risk(repo_name, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None):
    slug = risk_type.lower().replace(" ", "-")
    # Facade over shared schema to preserve caller compatibility
    return build_risk_record(
        module="devops",
        resource="CI/CD Pipeline",
        resource_name=f"{repo_name} {slug}",
        risk_type=risk_type,
        risk_reason=risk_reason,
        priority=priority,
        remediation_steps=remediation_steps,
        alternative_solutions=alternative_solutions,
        cloud_provider="AWS",
        region=_SCAN_REGION,
    )


def save_risk(table, risk):
    try:
        table.put_item(Item=risk)
        logger.info(f"Saved devops risk: {risk['riskType']}")
    except ClientError as e:
        logger.error(f"DynamoDB put_item failed: {e}")


# ---------------------------------------------------------------------------
# Scan checks
# ---------------------------------------------------------------------------

def flatten_steps(pipeline_config):
    """Pull all step names and run commands out of the pipeline config."""
    steps = []
    jobs = pipeline_config.get("jobs", {})
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            steps.append({
                "job":     job_name,
                "name":    step.get("name", ""),
                "run":     step.get("run", ""),
                "uses":    step.get("uses", ""),
                "env":     step.get("env", {}),
            })
    return steps


def scan_for_secrets(repo_name, steps):
    """High — hardcoded credentials or secret patterns in commands or env vars."""
    risks = []
    for step in steps:
        text_to_check = f"{step['name']} {step['run']}"
        # check env values too
        for k, v in step.get("env", {}).items():
            text_to_check += f" {k}={v}"

        for pattern in SECRET_PATTERNS:
            if pattern.search(text_to_check):
                r = build_risk(
                    repo_name,
                    "Hardcoded Credentials in Pipeline",
                    f"Possible secret detected in step '{step['name']}' (job: {step['job']}).",
                    "High",
                    remediation_steps=[
                        "Move secrets to GitHub Actions Secrets (Settings > Secrets and Variables)",
                        "Reference secrets as ${{ secrets.MY_SECRET }} in the workflow",
                        "Run git-secrets or GitLeaks to audit repo history",
                    ],
                    alternative_solutions=[
                        "Store secrets in AWS Secrets Manager and retrieve at runtime",
                        "Use OIDC-based authentication to avoid storing any credentials",
                    ],
                )
                risks.append(r)
                break       # one risk per step is enough

    return risks


def scan_for_test_steps(repo_name, steps):
    """High — no test step in the pipeline."""
    test_keywords = {"pytest", "test", "unittest", "jest", "mocha", "coverage"}
    has_tests = any(
        any(kw in step["name"].lower() or kw in step["run"].lower() for kw in test_keywords)
        for step in steps
    )
    if not has_tests:
        return [build_risk(
            repo_name,
            "No Automated Tests in CI Pipeline",
            "Pipeline has no test step — code is being deployed without being tested.",
            "High",
            remediation_steps=[
                "Add a test job that runs pytest (or equivalent) before the deploy job",
                "Configure the pipeline to fail and block deployment if tests do not pass",
            ],
            alternative_solutions=[
                "Set up a GitHub Actions test matrix across multiple Python versions",
                "Use pre-commit hooks to run tests locally before push",
            ],
        )]
    return []


def scan_for_rollback(repo_name, steps):
    """Medium — no rollback strategy defined."""
    rollback_keywords = {"rollback", "roll back", "revert", "undo", "previous version"}
    has_rollback = any(
        any(kw in step["name"].lower() or kw in step["run"].lower() for kw in rollback_keywords)
        for step in steps
    )
    if not has_rollback:
        return [build_risk(
            repo_name,
            "No Rollback Strategy in Pipeline",
            "The pipeline has no rollback step — a bad deployment requires manual intervention.",
            "Medium",
            remediation_steps=[
                "Add a rollback step that triggers the previous Lambda version on failure",
                "Use AWS CodeDeploy deployment groups with automatic rollback on alarms",
            ],
            alternative_solutions=[
                "Use blue/green deployments to switch back instantly",
                "Keep the previous Lambda alias pointing to the stable version",
            ],
        )]
    return []


def scan_for_monitoring(repo_name, steps):
    """Medium — no post-deploy monitoring or health check."""
    monitor_keywords = {"cloudwatch", "health", "monitor", "alert", "check", "alarm", "smoke"}
    has_monitor = any(
        any(kw in step["name"].lower() or kw in step["run"].lower() for kw in monitor_keywords)
        for step in steps
    )
    if not has_monitor:
        return [build_risk(
            repo_name,
            "No Post-Deploy Monitoring in Pipeline",
            "There is no health check or monitoring step after deployment.",
            "Medium",
            remediation_steps=[
                "Add a smoke test step that hits the API endpoint after deploy",
                "Set up a CloudWatch alarm that triggers if error rate spikes post-deploy",
            ],
            alternative_solutions=[
                "Integrate AWS CloudWatch Synthetics canaries for continuous post-deploy testing",
            ],
        )]
    return []


# ---------------------------------------------------------------------------
# PR Generation -- Scaffolding for Future Scope
# ---------------------------------------------------------------------------

def generate_github_pr_for_remediation(repo_name, risk):
    """
    Placeholder for future automated PR generation.
    Will create a new branch, commit the fix (e.g. adding a test step), and
    open a Pull Request using the GitHub API.
    """
    logger.info("Automated PR generation not yet implemented (v2 scope).")
    return None


# ---------------------------------------------------------------------------
# Pipeline security scans — third-party actions & permissions
# ---------------------------------------------------------------------------

# Regex to match a full 40-character hex SHA commit pin
_SHA_PIN_RE = re.compile(r'^[0-9a-f]{40}$')

# Trusted action namespace prefixes that don't require SHA pinning
_TRUSTED_NAMESPACES = ("actions/", "aws-actions/", "docker/")


def scan_for_unverified_actions(repo_name, pipeline_config):
    """
    High — third-party GitHub Actions not pinned to a full commit SHA.

    Iterates all jobs' steps looking for ``uses:`` values that are neither:
    * from a trusted first-party namespace (actions/, aws-actions/, docker/)
    * pinned to a full 40-character hex SHA (e.g. ``uses: owner/action@<sha>``)
    """
    risks = []
    jobs = pipeline_config.get("jobs", {})
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            uses = (step.get("uses") or "").strip()
            if not uses:
                continue

            # Skip trusted first-party namespaces
            if any(uses.startswith(ns) for ns in _TRUSTED_NAMESPACES):
                continue

            # Check whether the reference is pinned to a full SHA
            ref = uses.split("@", 1)[-1] if "@" in uses else ""
            if _SHA_PIN_RE.match(ref):
                continue

            # Unverified / unpinned third-party action found
            step_name = step.get("name") or uses
            risks.append(build_risk(
                repo_name,
                "Unverified Third-Party Action in Pipeline",
                f"Step '{step_name}' in job '{job_name}' uses a third-party action "
                f"('{uses}') that is not pinned to a full commit SHA.",
                "High",
                remediation_steps=[
                    "Pin third-party actions to a specific commit SHA (uses: action/name@sha)",
                    "Audit all third-party actions before use",
                    "Use only verified actions from trusted publishers",
                ],
            ))
    return risks


def scan_for_admin_permissions(repo_name, pipeline_config):
    """
    Medium — pipeline or individual jobs grant overly broad permissions.

    Checks both the top-level ``permissions`` key and each job's ``permissions``
    for values of ``write-all``, ``*``, or ``admin``.
    """
    BROAD_VALUES = {"write-all", "*", "admin"}

    def _is_broad(perms):
        """Return True if *perms* (str or dict) is considered overly broad."""
        if isinstance(perms, str):
            return perms.strip().lower() in BROAD_VALUES
        if isinstance(perms, dict):
            return any(str(v).strip().lower() in BROAD_VALUES for v in perms.values())
        return False

    risks = []

    # Top-level permissions
    top_perms = pipeline_config.get("permissions")
    if top_perms is not None and _is_broad(top_perms):
        risks.append(build_risk(
            repo_name,
            "Pipeline Has Overly Broad Permissions",
            "The workflow's top-level 'permissions' key grants overly broad access "
            f"(value: {top_perms!r}). This allows any job to read/write all repository scopes.",
            "Medium",
            remediation_steps=[
                "Replace 'permissions: write-all' with the minimal set of scopes required",
                "Define permissions per-job rather than at the workflow level",
                "Follow the principle of least privilege for each GitHub Actions workflow",
            ],
        ))

    # Per-job permissions
    for job_name, job in pipeline_config.get("jobs", {}).items():
        job_perms = job.get("permissions")
        if job_perms is not None and _is_broad(job_perms):
            risks.append(build_risk(
                repo_name,
                "Pipeline Has Overly Broad Permissions",
                f"Job '{job_name}' has overly broad permissions "
                f"(value: {job_perms!r}). Granting write-all or wildcard scopes exposes the "
                "repository to supply-chain attacks if the job is compromised.",
                "Medium",
                remediation_steps=[
                    "Replace 'permissions: write-all' with the minimal set of scopes required",
                    "Define permissions per-job rather than at the workflow level",
                    "Follow the principle of least privilege for each GitHub Actions workflow",
                ],
            ))

    return risks


# ---------------------------------------------------------------------------
# Entry point — dual mode: GitHub Webhook OR manual JSON
# ---------------------------------------------------------------------------

def purge_module_risks(table, module):
    try:
        resp = table.query(
            IndexName="module-index",
            KeyConditionExpression="#m = :m",
            ExpressionAttributeNames={"#m": "module"},
            ExpressionAttributeValues={":m": module},
        )
        items = resp.get("Items", [])
        while "LastEvaluatedKey" in resp:
            resp = table.query(
                IndexName="module-index",
                KeyConditionExpression="#m = :m",
                ExpressionAttributeNames={"#m": "module"},
                ExpressionAttributeValues={":m": module},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))

        with table.batch_writer(overwrite_by_pkeys=["resourceId", "riskTimestamp"]) as batch:
            for item in items:
                rid = item.get("resourceId")
                rts = item.get("riskTimestamp")
                if rid and rts:
                    batch.delete_item(Key={"resourceId": rid, "riskTimestamp": rts})
    except Exception as e:
        logger.error(f"Failed to purge old risks: {e}")

def lambda_handler(event, context):
    _start = time.time()
    logger.info("devops-analyzer invoked")
    ddb   = boto3.resource("dynamodb", region_name=DDB_REGION)
    table = ddb.Table(TABLE_NAME)

    raw_body = (event.get("body") or "{}").encode("utf-8")
    body     = json.loads(raw_body)

    # Set scan region for risk card labels
    global _SCAN_REGION
    _SCAN_REGION = body.get("scanRegion") or os.environ.get("SCAN_REGION") or REGION

    purge_module_risks(table, "devops")

    # ── GitHub Webhook mode — verify signature if secret is configured ──────
    gh_event   = (event.get("headers") or {}).get("X-GitHub-Event", "")
    sig_header = (event.get("headers") or {}).get("X-Hub-Signature-256", "")

    if gh_event == "push" or sig_header:
        secret = get_webhook_secret()
        # If a webhook secret is configured, BOTH signature presence AND validity are required.
        # An absent signature header with a configured secret is treated as a forgery attempt.
        if secret:
            if not sig_header:
                logger.warning("Webhook received without X-Hub-Signature-256 header — rejecting")
                return {"statusCode": 401, "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "Missing webhook signature"})}
            if not verify_github_signature(raw_body, sig_header, secret):
                logger.warning("Webhook signature verification failed")
                return {"statusCode": 401, "headers": CORS_HEADERS,
                        "body": json.dumps({"error": "Invalid webhook signature"})}

        # Extract repo and workflow content from the push payload
        repo_name   = body.get("repository", {}).get("full_name", "unknown-repo")
        head_commit = body.get("head_commit", {})
        logger.info(f"Webhook push from {repo_name}, commit: {head_commit.get('id', '')[:8]}")

        # Prefer pipeline_config embedded in the event; otherwise fetch from GitHub API.
        pipeline_config = body.get("pipeline_config", {})
        if not pipeline_config:
            pipeline_config = _fetch_workflow_from_github(repo_name) or {"jobs": {"build": {"steps": []}}}
    else:
        # ── Manual scan mode ─────────────────────────────────────────────────
        # Priority: repoList from request > single repo_name > DEFAULT_GITHUB_REPO env
        repo_list   = body.get("repoList") or []        # ["owner/repo1", "owner/repo2", ...]
        request_pat = body.get("githubToken") or None   # PAT sent by browser for this scan only

        # Fall back to legacy single-repo mode
        if not repo_list:
            single = body.get("repo_name") or os.environ.get("DEFAULT_GITHUB_REPO", "")
            if single:
                repo_list = [single]

        if not repo_list:
            logger.warning("No repos provided and DEFAULT_GITHUB_REPO not set — cannot scan")
            no_repo_risk = build_risk(
                "(not configured)",
                "GitHub Repository Not Configured",
                "No repositories were provided in the scan request. "
                "Connect at least one GitHub repository from the DevOps module.",
                "Medium",
                remediation_steps=[
                    "Open DevOps Intelligence → Connect GitHub",
                    "Enter your GitHub org/username and Personal Access Token",
                    "Select the repositories you want to analyze",
                ]
            )
            save_risk(table, no_repo_risk)
            emit_scan_completed("devops", [no_repo_risk])
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "DevOps scan: no repository configured", "risksFound": 1}),
            }

        logger.info(f"Scanning {len(repo_list)} repo(s): {repo_list}")

        def _fetch_with_pat(path, pat):
            """Inline GitHub API GET using the PAT sent in the scan request."""
            import urllib.request as _ureq
            url = f"{GITHUB_API_BASE}{path}"
            req = _ureq.Request(url, headers={
                "Authorization":       f"token {pat}",
                "Accept":              "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            try:
                with _ureq.urlopen(req, timeout=15) as r:
                    return json.loads(r.read())
            except Exception as e:
                logger.warning(f"GitHub API call failed {path}: {e}")
                return None

        all_risks = []
        for repo_name in repo_list:
            repo_name = repo_name.strip()
            if not repo_name:
                continue
            logger.info(f"  Scanning {repo_name}")

            if request_pat:
                # Fetch workflow files directly with the request PAT
                workflow_dir = _fetch_with_pat(f"/repos/{repo_name}/contents/.github/workflows", request_pat)
                pipeline_config = {"jobs": {"build": {"steps": []}}}
                if isinstance(workflow_dir, list):
                    for f in workflow_dir:
                        name = f.get("name", "")
                        if not (name.endswith(".yml") or name.endswith(".yaml")):
                            continue
                        file_meta = _fetch_with_pat(
                            f"/repos/{repo_name}/contents/.github/workflows/{name}", request_pat
                        )
                        if not file_meta:
                            continue
                        try:
                            raw_yaml = base64.b64decode(file_meta.get("content", "")).decode("utf-8")
                        except Exception:
                            continue
                        if yaml:
                            try:
                                parsed = yaml.safe_load(raw_yaml)
                                if parsed and isinstance(parsed, dict):
                                    for job_key, job_val in parsed.get("jobs", {}).items():
                                        pipeline_config["jobs"][f"{name}/{job_key}"] = job_val
                            except Exception:
                                pass
                        else:
                            for line in raw_yaml.splitlines():
                                line = line.strip()
                                if line.startswith("run:"):
                                    pipeline_config["jobs"]["build"]["steps"].append({"run": line[4:].strip()})
            else:
                # Fall back to Secrets Manager PAT (legacy path)
                pipeline_config = _fetch_workflow_from_github(repo_name) or \
                                   {"jobs": {"build": {"steps": []}}}

            steps = flatten_steps(pipeline_config)
            all_risks += scan_for_secrets(repo_name, steps)
            all_risks += scan_for_test_steps(repo_name, steps)
            all_risks += scan_for_rollback(repo_name, steps)
            all_risks += scan_for_monitoring(repo_name, steps)
            all_risks += scan_for_unverified_actions(repo_name, pipeline_config)
            all_risks += scan_for_admin_permissions(repo_name, pipeline_config)

    for r in all_risks:
        save_risk(table, r)

    emit_scan_completed("devops", all_risks)

    # Trigger AI explainer immediately
    try:
        boto3.client("lambda", region_name=REGION).invoke(
            FunctionName=AI_EXPLAINER_FN,
            InvocationType="Event",
            Payload=json.dumps({"source": "devops-scanner", "module": "devops"}),
        )
        logger.info("ai-explainer triggered for devops")
    except Exception as e:
        logger.warning(f"Could not trigger ai-explainer (non-fatal): {e}")

    duration_ms = int((time.time() - _start) * 1000)
    try:
        cw = boto3.client("cloudwatch", region_name=REGION)
        cw.put_metric_data(
            Namespace="CloudSentinel/Performance",
            MetricData=[{"MetricName": "ScanDurationMs",
                         "Dimensions": [{"Name": "Module", "Value": "devops"}],
                         "Value": duration_ms, "Unit": "Milliseconds"}],
        )
    except Exception as e:
        logger.warning(f"CloudWatch metric write failed (non-fatal): {e}")

    logger.info(f"devops scan done — {len(all_risks)} risk(s) in {duration_ms}ms")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message":    "DevOps scan complete",
            "risksFound": len(all_risks),
            "durationMs": duration_ms,
        }),
    }

