"""
scan_all_handler.py
Lambda triggered by POST /scan-all from the frontend.
Starts the CloudSentinel Step Functions parallel scan orchestrator.
Returns the execution ARN so the frontend can poll status.
"""
import json
import logging
import os
import time

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION        = os.environ.get("AWS_REGION", "us-east-1")
SFN_ARN       = os.environ.get("SFN_ARN", "")
AMPLIFY_DOMAIN = os.environ.get("AMPLIFY_DOMAIN", "*")

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": AMPLIFY_DOMAIN,
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
}

sfn = boto3.client("stepfunctions", region_name=REGION)


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        body = {}

    if not SFN_ARN:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "SFN_ARN environment variable not set"}),
        }

    # Pass through scan parameters (targetRoleArn, scanRegion, providers, etc.)
    execution_name = f"scan-{int(time.time())}"

    try:
        resp = sfn.start_execution(
            stateMachineArn=SFN_ARN,
            name=execution_name,
            input=json.dumps(body),
        )
        logger.info("Started Step Functions execution: %s", resp["executionArn"])
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "executionArn": resp["executionArn"],
                "executionName": execution_name,
                "startDate": resp["startDate"].isoformat(),
                "message": "Full parallel scan started via Step Functions",
            }),
        }
    except Exception as e:
        logger.error("Failed to start Step Functions: %s", e)
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)}),
        }
