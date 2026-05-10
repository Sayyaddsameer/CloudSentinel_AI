import json
import os
import logging

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION     = os.environ.get("AWS_REGION", "us-east-1")
PAGE_LIMIT = int(os.environ.get("RISKS_PAGE_LIMIT", "100"))

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": "*",
}

# Resources that are intentionally configured in a way that would otherwise
# be flagged -- suppress these to avoid false positives on the dashboard.
IGNORED_RESOURCE_NAMES = {
    # This bucket is intentionally public so CloudFormation in external
    # accounts can download the scanner-role.yaml template.
    "cloudsentinel-cf-templates-871070087236",
}


def deduplicate(items: list) -> list:
    """Keep only the most recent entry per (resourceId, riskType) pair.
    This prevents repeated scans from inflating the risk count.
    """
    seen: dict = {}
    for item in items:
        key = (item.get("resourceId", ""), item.get("riskType", ""))
        existing = seen.get(key)
        if existing is None or item.get("riskTimestamp", "") > existing.get("riskTimestamp", ""):
            seen[key] = item
    return list(seen.values())


def filter_ignored(items: list) -> list:
    """Remove known false-positive / intentionally configured resources."""
    return [
        item for item in items
        if item.get("resourceName", "") not in IGNORED_RESOURCE_NAMES
    ]


def query_by_module(table, module):
    response = table.query(
        IndexName="module-index",
        KeyConditionExpression=Key("module").eq(module),
        ScanIndexForward=False,
        Limit=PAGE_LIMIT * 10,   # fetch more so dedup has enough to work with
    )
    return response.get("Items", [])


def scan_all(table):
    items = []
    response = table.scan()
    items.extend(response.get("Items", []))
    # Handle pagination for large tables
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
        if len(items) >= PAGE_LIMIT * 20:
            break
    return items


def lambda_handler(event, context):
    module = (event.get("queryStringParameters") or {}).get("module", "")
    priority_filter = (event.get("queryStringParameters") or {}).get("priority", "")

    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)

    try:
        if module:
            items = query_by_module(table, module)
        else:
            items = scan_all(table)
    except ClientError as e:
        logger.error(f"DynamoDB read failed: {e}")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Failed to read risks from database"}),
        }

    # Deduplicate and remove false positives
    items = deduplicate(items)
    items = filter_ignored(items)

    if priority_filter:
        items = [i for i in items if i.get("riskPriority", "").lower() == priority_filter.lower()]

    # Sort: High first, then Medium, then Low; within each priority newest timestamp first.
    # Achieved with a stable two-pass sort (Python's sort is stable):
    #   Pass 1: sort by timestamp descending (newest first)
    #   Pass 2: sort by priority ascending (High=0, Medium=1, Low=2)
    priority_order = {"High": 0, "Medium": 1, "Low": 2}
    items.sort(key=lambda x: x.get("riskTimestamp", ""), reverse=True)  # newest first
    items.sort(key=lambda x: priority_order.get(x.get("riskPriority", "Low"), 2))  # high first

    logger.info(f"Returning {len(items)} deduplicated risks")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"risks": items, "count": len(items)}),
    }
