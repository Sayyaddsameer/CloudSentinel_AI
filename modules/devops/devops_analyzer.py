import hashlib
import hmac
import json
import os
import logging
import re
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME         = os.environ["DYNAMODB_TABLE"]
REGION             = os.environ.get("AWS_REGION", "us-east-1")
WEBHOOK_SECRET_ARN = os.environ.get("WEBHOOK_SECRET_ARN", "")

# Regex patterns for secret detection
SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|token|api_key|apikey)\s*[:=]\s*["\']?\S{8,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),                   # AWS access key ID format
    re.compile(r'(?i)aws_secret_access_key\s*=\s*\S+'),
]

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": "*",
}


# ---------------------------------------------------------------------------
# Webhook signature verification
# GitHub signs every webhook payload with HMAC-SHA256 using WEBHOOK_SECRET
# ---------------------------------------------------------------------------

def get_webhook_secret():
    if not WEBHOOK_SECRET_ARN:
        return None
    try:
        sm = boto3.client("secretsmanager", region_name=REGION)
        return sm.get_secret_value(SecretId=WEBHOOK_SECRET_ARN)["SecretString"]
    except Exception as e:
        logger.error(f"Could not retrieve webhook secret: {e}")
        return None


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
    ts = datetime.now(timezone.utc).isoformat()
    safe_repo = repo_name.replace("/", "-").replace(" ", "-")
    slug = risk_type.lower().replace(" ", "-")
    return {
        "resourceId":           f"devops-{safe_repo}-{slug}",
        "riskTimestamp":        ts,
        "module":               "devops",
        "cloudProvider":        "AWS",
        "resource":             "CI/CD Pipeline",
        "resourceName":         repo_name,
        "riskType":             risk_type,
        "riskReason":           risk_reason,
        "riskPriority":         priority,
        "remediationSteps":     remediation_steps or [],
        "alternativeSolutions": alternative_solutions or [],
        "aiExplanation":        "",
        "riskCategory":         "",
        "status":               "OPEN",
        "region":               REGION,
    }


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
# Entry point — dual mode: GitHub Webhook OR manual JSON
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    logger.info("devops-analyzer invoked")
    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)

    raw_body = (event.get("body") or "{}").encode("utf-8")
    body     = json.loads(raw_body)

    # GitHub Webhook mode — verify signature if secret is configured
    gh_event = (event.get("headers") or {}).get("X-GitHub-Event", "")
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

        # Use workflow content from the push event if present, else use a generic stub
        # (full parsing would require GitHub API calls to fetch the .yml content)
        pipeline_config = body.get("pipeline_config", {})
        if not pipeline_config:
            # When the pipeline_config isn't embedded in the event,
            # run the checks against an empty pipeline so at least
            # test/rollback/monitoring gaps are surfaced.
            pipeline_config = {"jobs": {"build": {"steps": []}}}
    else:
        # Manual / demo mode — pipeline_config provided directly in the body
        repo_name       = body.get("repo_name", "CloudSentinel_AI")
        pipeline_config = body.get("pipeline_config", {
            "jobs": {
                "build": {
                    "steps": [
                        {"name": "install", "run": "pip install -r requirements.txt"},
                        {"name": "deploy",  "run": "aws lambda update-function-code --function-name cloudsentinel-cloud-scanner"},
                    ]
                }
            }
        })

    steps     = flatten_steps(pipeline_config)
    all_risks = []
    all_risks += scan_for_secrets(repo_name, steps)
    all_risks += scan_for_test_steps(repo_name, steps)
    all_risks += scan_for_rollback(repo_name, steps)
    all_risks += scan_for_monitoring(repo_name, steps)

    for r in all_risks:
        save_risk(table, r)

    logger.info(f"devops scan done — {len(all_risks)} risk(s)")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"message": "DevOps scan complete", "risksFound": len(all_risks)}),
    }
