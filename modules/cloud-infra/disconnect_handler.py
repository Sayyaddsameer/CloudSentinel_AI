"""
disconnect_handler.py — Automated cloud access revocation

Called when:
  1. User clicks "Disconnect" on any module page
  2. Session expires (auto-logout) — called for all connected modules

Actions per provider:
  AWS  -> Assumes the cross-account scanner role -> deletes CloudFormation stack
          -> falls back to instructions if assume-role fails
  GCP  -> Deletes the GCP service account key secret from Secrets Manager
  ALL  -> Purges all DynamoDB risk records for the module

Request body:
  { "module": "cloud-infra", "provider": "aws"|"gcp"|"all", "roleArn": "<arn>", "stackName": "<name>" }

Returns:
  { "aws": "deleted"|"instructions"|"skipped", "gcp": "deleted"|"skipped", "risks": <n purged> }
"""

import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION        = os.environ.get("AWS_REGION", "us-east-1")
RISKS_TABLE   = os.environ["DYNAMODB_TABLE"]          # required — no hardcoded default
GCP_SECRET_PREFIX = os.environ.get("GCP_SECRET_PREFIX", "cloudsentinel-gcp-creds")  # configurable prefix
MODULE_INDEX  = "module-index"
DEFAULT_STACK = os.environ.get("DEFAULT_CFN_STACK", "CloudSentinel-Scanner")


def cors_headers():
    return {
        "Access-Control-Allow-Origin":  os.environ.get("AMPLIFY_DOMAIN", "*"),
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Content-Type": "application/json",
    }


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": cors_headers(), "body": ""}

    try:
        body       = json.loads(event.get("body") or "{}")
        module     = body.get("module", "cloud-infra")
        provider   = body.get("provider", "all").lower()   # "aws", "gcp", or "all"
        role_arn   = body.get("roleArn", "")
        stack_name = body.get("stackName", DEFAULT_STACK)

        result = {"aws": "skipped", "gcp": "skipped", "risks_purged": 0}

        # ── Revoke AWS access (delete CloudFormation stack) ──────────────
        if provider in ("aws", "all") and role_arn:
            result["aws"] = _delete_cfn_stack(role_arn, stack_name)

        # ── Revoke GCP credentials (delete Secrets Manager secret) ───────
        if provider in ("gcp", "all"):
            result["gcp"] = _delete_gcp_secret(module)

        # ── Purge DynamoDB risk records for this module ───────────────────
        modules_to_purge = (
            ["cloud-infra", "devops", "fullstack", "data-eng", "mobile"]
            if provider == "all" and module == "all"
            else [module]
        )
        total_purged = 0
        for m in modules_to_purge:
            total_purged += _purge_risks(m)
        result["risks_purged"] = total_purged

        logger.info("Disconnect result for module=%s provider=%s: %s", module, provider, result)

        return {
            "statusCode": 200,
            "headers":    cors_headers(),
            "body":       json.dumps(result),
        }

    except Exception as e:
        logger.error("Disconnect handler error: %s", str(e))
        return {
            "statusCode": 500,
            "headers":    cors_headers(),
            "body":       json.dumps({"error": str(e)}),
        }


# ── Helpers ───────────────────────────────────────────────────────────

def _delete_cfn_stack(role_arn: str, stack_name: str) -> str:
    """Assume the cross-account scanner role and delete the CloudFormation stack."""
    sts = boto3.client("sts", region_name=REGION)
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CloudSentinelDisconnect",
            ExternalId="cloudsentinel",
        )["Credentials"]

        cf = boto3.client(
            "cloudformation",
            region_name=REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        try:
            cf.describe_stacks(StackName=stack_name)
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            err_msg  = str(e)
            if err_code == "ValidationError" or "does not exist" in err_msg:
                logger.info("Stack %s already deleted or never existed.", stack_name)
                return "already_deleted"
            raise

        cf.delete_stack(StackName=stack_name)
        logger.info("Delete initiated for stack: %s in account via role %s", stack_name, role_arn)
        return "delete_initiated"

    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("AccessDenied", "AccessDeniedException"):
            logger.warning("Role %s does not permit CF delete — returning instructions.", role_arn)
            return "instructions"
        logger.error("CFN delete failed: %s", e)
        return f"error: {e}"

    except Exception as e:
        logger.error("Assume-role failed for %s: %s", role_arn, e)
        return "instructions"


def _delete_gcp_secret(module: str) -> str:
    """Delete the GCP service account key from Secrets Manager."""
    sm = boto3.client("secretsmanager", region_name=REGION)
    secret_name = f"{GCP_SECRET_PREFIX}-{module}"
    try:
        sm.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
        logger.info("Deleted GCP secret: %s", secret_name)
        return "deleted"
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ResourceNotFoundException", "InvalidRequestException"):
            return "not_found"
        logger.error("Failed to delete GCP secret %s: %s", secret_name, e)
        return f"error: {e}"


def _purge_risks(module: str) -> int:
    """Delete all DynamoDB risk records for the given module."""
    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(RISKS_TABLE)
    purged = 0
    try:
        # Paginate through ALL records for this module via GSI
        resp = table.query(
            IndexName=MODULE_INDEX,
            KeyConditionExpression="#m = :m",
            ExpressionAttributeNames={"#m": "module"},
            ExpressionAttributeValues={":m": module},
        )
        items = resp.get("Items", [])
        while "LastEvaluatedKey" in resp:
            resp = table.query(
                IndexName=MODULE_INDEX,
                KeyConditionExpression="#m = :m",
                ExpressionAttributeNames={"#m": "module"},
                ExpressionAttributeValues={":m": module},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))

        # Table key: resourceId (HASH) + riskTimestamp (RANGE)
        with table.batch_writer(overwrite_by_pkeys=["resourceId", "riskTimestamp"]) as batch:
            for item in items:
                rid = item.get("resourceId")
                rts = item.get("riskTimestamp")
                if not rid or not rts:
                    logger.warning("Skipping item with missing key: %s", item.get("resourceId"))
                    continue
                batch.delete_item(Key={"resourceId": rid, "riskTimestamp": rts})
                purged += 1

        logger.info("Purged %d risk records for module=%s", purged, module)
    except Exception as e:
        logger.error("Failed to purge risks for module=%s: %s", module, e)
        raise  # re-raise so caller surfaces the error rather than silently returning 0
    return purged
