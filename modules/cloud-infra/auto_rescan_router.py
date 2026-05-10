"""
auto_rescan_router.py
Lambda triggered by EventBridge CloudTrail events.
Routes each AWS resource change to the appropriate CloudSentinel scanner Lambda(s).

Supported triggers:
  - CloudFormation CreateStack / UpdateStack → cloud-infra scanner
  - Lambda CreateFunction / UpdateFunctionCode → cloud-infra + devops scanners
  - S3 CreateBucket → cloud-infra + data-eng scanners
  - EC2 AuthorizeSecurityGroupIngress → cloud-infra scanner
  - IAM PutRolePolicy / AttachRolePolicy → cloud-infra + mobile scanners
  - API Gateway CreateRestApi / PutMethod → fullstack + mobile scanners
  - Cognito CreateUserPool → mobile scanner
  - Glue StartJobRun (failure state) → data-eng scanner
"""
import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION  = os.environ.get("AWS_REGION", "us-east-1")
PROJECT = os.environ.get("PROJECT_NAME", "cloudsentinel")

lmb = boto3.client("lambda", region_name=REGION)

# Map: (eventSource, eventName pattern) → list of scanner Lambda names
ROUTE_MAP = [
    # CloudFormation changes → cloud-infra
    ("cloudformation.amazonaws.com", "CreateStack",                 ["cloud-scanner"]),
    ("cloudformation.amazonaws.com", "UpdateStack",                 ["cloud-scanner"]),
    ("cloudformation.amazonaws.com", "DeleteStack",                 ["cloud-scanner"]),
    # Lambda function changes → cloud-infra + devops
    ("lambda.amazonaws.com",         "CreateFunction20150331",      ["cloud-scanner", "devops-analyzer"]),
    ("lambda.amazonaws.com",         "UpdateFunctionCode20150331v2",["cloud-scanner", "devops-analyzer"]),
    # S3 bucket creation → cloud-infra + data-eng
    ("s3.amazonaws.com",             "CreateBucket",                ["cloud-scanner", "data-eng-analyzer"]),
    # EC2 security group changes → cloud-infra
    ("ec2.amazonaws.com",            "AuthorizeSecurityGroupIngress",["cloud-scanner"]),
    ("ec2.amazonaws.com",            "RevokeSecurityGroupIngress",  ["cloud-scanner"]),
    # IAM policy changes → cloud-infra + mobile
    ("iam.amazonaws.com",            "PutRolePolicy",               ["cloud-scanner", "mobile-analyzer"]),
    ("iam.amazonaws.com",            "AttachRolePolicy",            ["cloud-scanner", "mobile-analyzer"]),
    ("iam.amazonaws.com",            "CreateRole",                  ["cloud-scanner", "mobile-analyzer"]),
    # API Gateway changes → fullstack + mobile
    ("apigateway.amazonaws.com",     "CreateRestApi",               ["fullstack-analyzer", "mobile-analyzer"]),
    ("apigateway.amazonaws.com",     "PutMethod",                   ["fullstack-analyzer", "mobile-analyzer"]),
    ("apigateway.amazonaws.com",     "CreateDeployment",            ["fullstack-analyzer", "mobile-analyzer"]),
    # Cognito changes → mobile
    ("cognito-idp.amazonaws.com",    "CreateUserPool",              ["mobile-analyzer"]),
    ("cognito-idp.amazonaws.com",    "UpdateUserPool",              ["mobile-analyzer"]),
    # Glue changes → data-eng
    ("glue.amazonaws.com",           "StartJobRun",                 ["data-eng-analyzer"]),
    ("glue.amazonaws.com",           "CreateJob",                   ["data-eng-analyzer"]),
    # DynamoDB changes → data-eng
    ("dynamodb.amazonaws.com",       "CreateTable",                 ["data-eng-analyzer"]),
    # GitHub Actions (DevOps) — push events go directly via webhook, no routing needed
]


def _invoke_scanner(fn_suffix: str, reason: str):
    """Asynchronously invoke a CloudSentinel scanner Lambda."""
    fn_name = f"{PROJECT}-{fn_suffix}"
    payload = json.dumps({
        "source":    "auto-rescan",
        "trigger":   "eventbridge-cloudtrail",
        "reason":    reason,
    }).encode()
    try:
        lmb.invoke(
            FunctionName=fn_name,
            InvocationType="Event",   # async — don't wait for result
            Payload=payload,
        )
        logger.info("Triggered %s (reason: %s)", fn_name, reason)
    except lmb.exceptions.ResourceNotFoundException:
        logger.warning("Lambda %s not found — skipping", fn_name)
    except Exception as e:
        logger.error("Failed to invoke %s: %s", fn_name, e)


def lambda_handler(event, context):
    logger.info("auto-rescan-router received event: %s", json.dumps(event)[:500])

    # EventBridge wraps CloudTrail events in detail
    detail       = event.get("detail", {})
    event_source = detail.get("eventSource", "")
    event_name   = detail.get("eventName", "")
    request_params = detail.get("requestParameters", {})

    logger.info("CloudTrail: source=%s event=%s", event_source, event_name)

    if not event_source or not event_name:
        logger.warning("Not a CloudTrail event — ignoring")
        return {"statusCode": 200, "body": "ignored"}

    # Find matching routes
    triggered = set()
    reason = f"{event_source}/{event_name}"

    for src, name, scanners in ROUTE_MAP:
        if event_source == src and event_name.startswith(name):
            for scanner in scanners:
                if scanner not in triggered:
                    triggered.add(scanner)
                    _invoke_scanner(scanner, reason)

    if not triggered:
        logger.info("No matching route for %s — no scan triggered", reason)
    else:
        logger.info("Triggered %d scanner(s): %s", len(triggered), list(triggered))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "triggered": list(triggered),
            "reason":    reason,
        }),
    }
