import json
import os
import logging
import boto3
from botocore.exceptions import ClientError
from shared.schemas.risk_record import build_risk_record

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Required — raises KeyError at cold-start if not set (no silent empty-string default)
TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION     = os.environ.get("AWS_REGION", "us-east-1")

# The platform account that runs this Lambda.
# Findings whose AwsAccountId == PLATFORM_ACCOUNT_ID are OUR OWN infra,
# not the user's scanned account — exclude them to prevent contamination.
PLATFORM_ACCOUNT_ID = os.environ.get("PLATFORM_ACCOUNT_ID", "")

# Comma-separated allow-list of accounts whose SecurityHub findings should be stored.
# If empty, we only exclude the platform account (PLATFORM_ACCOUNT_ID).
# Format: "785269092008,123456789012"
ALLOWED_ACCOUNT_IDS_RAW = os.environ.get("ALLOWED_SCAN_ACCOUNT_IDS", "")
ALLOWED_ACCOUNT_IDS = set(a.strip() for a in ALLOWED_ACCOUNT_IDS_RAW.split(",") if a.strip())

def map_severity(label):
    label = str(label).upper()
    if label in ["CRITICAL", "HIGH"]:
        return "High"
    elif label in ["MEDIUM"]:
        return "Medium"
    else:
        return "Low"

def lambda_handler(event, context):
    logger.info("securityhub-handler invoked")
    
    if not TABLE_NAME:
        logger.error("DYNAMODB_TABLE environment variable not set.")
        return {"statusCode": 500, "body": "Configuration error"}

    ddb = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)
    
    detail = event.get("detail", {})
    findings = detail.get("findings", [])
    
    saved_count = 0
    for finding in findings:
        # ── Account ID filter — prevent platform-account findings polluting user scans ──
        finding_account = finding.get("AwsAccountId", "")
        if ALLOWED_ACCOUNT_IDS:
            # Strict allow-list: only store findings for explicitly allowed accounts
            if finding_account not in ALLOWED_ACCOUNT_IDS:
                logger.info("Skipping finding for account %s (not in allow-list)", finding_account)
                continue
        elif PLATFORM_ACCOUNT_ID and finding_account == PLATFORM_ACCOUNT_ID:
            # Fallback: skip our own platform-account findings
            logger.info("Skipping finding for platform account %s", finding_account)
            continue

        title = finding.get("Title", "Security Hub Finding")
        description = finding.get("Description", "")
        severity = finding.get("Severity", {}).get("Label", "MEDIUM")
        
        resources = finding.get("Resources", [])
        if not resources:
            continue
            
        resource_id = resources[0].get("Id", "Unknown")
        resource_type = resources[0].get("Type", "AwsResource")
        
        remediation_text = finding.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
        remediation_steps = [remediation_text] if remediation_text else ["Review finding in AWS Security Hub"]

        risk = build_risk_record(
            module="cloud-infra",
            resource=resource_type,
            resource_name=resource_id,
            risk_type=f"Security Hub: {title}",
            risk_reason=description,
            priority=map_severity(severity),
            remediation_steps=remediation_steps,
        )
        risk["source"] = "aws-securityhub"
        
        try:
            table.put_item(Item=risk)
            saved_count += 1
            logger.info(f"Saved Security Hub finding: {title} on {resource_id}")
        except ClientError as e:
            logger.error(f"Failed to save finding to DynamoDB: {e}")

    return {
        "statusCode": 200,
        "body": json.dumps({"message": f"Processed {len(findings)} findings, saved {saved_count} risks"})
    }
