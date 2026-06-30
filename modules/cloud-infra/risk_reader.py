import json
import os
import logging
import time

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION     = os.environ["AWS_REGION"]
PAGE_LIMIT = int(os.environ.get("RISKS_PAGE_LIMIT", "100"))

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}

# Resources that are intentionally configured in a way that would otherwise
# be flagged -- suppress these to avoid false positives on the dashboard.
# Resources intentionally excluded from risk results (e.g. deliberately-public buckets).
# Configure via env var IGNORED_RESOURCES as a comma-separated list of resource names.
# Example: IGNORED_RESOURCES=my-public-bucket-123456789012,another-resource
_ignored_raw = os.environ.get("IGNORED_RESOURCES", "")
IGNORED_RESOURCE_NAMES = {r.strip() for r in _ignored_raw.split(",") if r.strip()}


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
    qp             = event.get("queryStringParameters") or {}
    module         = qp.get("module", "")
    priority_filter = qp.get("priority", "")
    # ?status=OPEN (default) hides RESOLVED risks; ?status=ALL shows everything
    status_filter  = qp.get("status", "OPEN").upper()

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

    # Status filter: OPEN (default) = hide RESOLVED; ALL = show everything
    if status_filter != "ALL":
        items = [i for i in items if i.get("status", "OPEN").upper() != "RESOLVED"]

    if priority_filter:
        items = [i for i in items if i.get("riskPriority", "").lower() == priority_filter.lower()]

    # Sort: Critical first, then High, Medium, Low; newest within each priority.
    # Achieved with a stable two-pass sort (Python's sort is stable):
    #   Pass 1: sort by timestamp descending (newest first)
    #   Pass 2: sort by priority ascending (Critical=0, High=1, Medium=2, Low=3)
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    items.sort(key=lambda x: x.get("riskTimestamp", ""), reverse=True)  # newest first
    items.sort(key=lambda x: priority_order.get(x.get("riskPriority", "Low"), 3))  # critical first

    # --- Security Posture Score (0-100, novel metric for paper) ---
    # Weighted penalty: Critical=-20, High=-10, Medium=-5, Low=-2
    # Score starts at 100 and each finding deducts points (floor: 0)
    weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
    penalty = sum(weights.get(r.get("riskPriority", "Low"), 2) for r in items)
    posture_score = max(0, 100 - penalty)

    # Per-severity counts
    critical_count = sum(1 for r in items if r.get("riskPriority") == "Critical")
    high_count     = sum(1 for r in items if r.get("riskPriority") == "High")
    medium_count   = sum(1 for r in items if r.get("riskPriority") == "Medium")
    low_count      = sum(1 for r in items if r.get("riskPriority") == "Low")

    logger.info(
        f"Returning {len(items)} risks | Score={posture_score} "
        f"C={critical_count} H={high_count} M={medium_count} L={low_count}"
    )
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "risks":         items,
            "count":         len(items),
            "postureScore":  posture_score,
            "criticalCount": critical_count,
            "highCount":     high_count,
            "mediumCount":   medium_count,
            "lowCount":      low_count,
        }),
    }
