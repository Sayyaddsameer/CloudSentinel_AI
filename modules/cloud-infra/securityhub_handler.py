import json
import os
import logging
import boto3
from botocore.exceptions import ClientError
from shared.schemas.risk_record import build_risk_record

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "")
REGION = os.environ.get("AWS_REGION", "us-east-1")

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
