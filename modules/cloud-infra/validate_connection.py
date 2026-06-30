"""
validate_connection.py
Lambda that validates a user's AWS account connection by attempting STS AssumeRole.
Called by the frontend before storing a connection to prevent fake account IDs.

POST /validate-connection
Body: { "module": "cloud-infra", "accountId": "123456789012", "roleArn": "arn:aws:iam::..." }
Response: { "valid": true/false, "error": "...", "accountAlias": "..." }
"""
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ["AWS_REGION"]

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
}


def _respond(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": CORS_HEADERS,
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
    # Handle CORS preflight
    if event.get("httpMethod") == "OPTIONS":
        return _respond(200, {})

    try:
        body = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        return _respond(400, {"valid": False, "error": "Invalid request body"})

    module     = body.get("module", "")
    account_id = body.get("accountId", "").strip()
    role_arn   = body.get("roleArn", "").strip()

    # ── Input validation ─────────────────────────────────────────────────────
    if not account_id or len(account_id) != 12 or not account_id.isdigit():
        return _respond(400, {
            "valid": False,
            "error": "Invalid AWS Account ID — must be exactly 12 digits.",
        })

    if not role_arn:
        role_arn = f"arn:aws:iam::{account_id}:role/cloudsentinel-scanner-role"

    logger.info("Validating connection: module=%s accountId=%s roleArn=%s",
                module, account_id, role_arn)

    # ── STS AssumeRole — the definitive test ─────────────────────────────────
    sts = boto3.client("sts", region_name=REGION)
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="cloudsentinel-validate",
            ExternalId="cloudsentinel",
            DurationSeconds=900,
        )
        assumed_account = resp["AssumedRoleUser"]["Arn"].split(":")[4]
        logger.info("AssumeRole succeeded for account %s", assumed_account)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        logger.warning("AssumeRole failed: %s — %s", code, msg)

        # Provide clear, user-friendly error messages
        if code == "AccessDenied":
            error = (
                "Access Denied: The CloudSentinel IAM role does not exist in this account "
                "or the External ID is wrong. Please deploy the CloudFormation stack first."
            )
        elif code == "NoSuchEntity":
            error = (
                "The IAM role 'cloudsentinel-scanner-role' was not found in account "
                f"{account_id}. Please deploy the CloudSentinel CloudFormation stack."
            )
        elif code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
            error = "AWS credentials error. Please check your IAM role configuration."
        else:
            error = f"Could not connect to AWS account {account_id}: {msg}"

        return _respond(200, {"valid": False, "error": error})

    # ── Try to get account alias (optional, best-effort) ─────────────────────
    account_alias = ""
    try:
        creds = resp["Credentials"]
        iam_client = boto3.client(
            "iam",
            region_name=REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        aliases = iam_client.list_account_aliases().get("AccountAliases", [])
        account_alias = aliases[0] if aliases else ""
    except Exception:
        pass  # alias is optional

    return _respond(200, {
        "valid":        True,
        "accountId":    assumed_account,
        "accountAlias": account_alias,
        "roleArn":      role_arn,
        "module":       module,
    })
