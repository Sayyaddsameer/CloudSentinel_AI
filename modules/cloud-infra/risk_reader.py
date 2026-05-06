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


def query_by_module(table, module):
    response = table.query(
        IndexName="module-index",
        KeyConditionExpression=Key("module").eq(module),
        ScanIndexForward=False,
        Limit=PAGE_LIMIT,
    )
    return response.get("Items", [])


def scan_all(table):
    response = table.scan(Limit=PAGE_LIMIT)
    return response.get("Items", [])


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

    if priority_filter:
        items = [i for i in items if i.get("riskPriority", "").lower() == priority_filter.lower()]

    # Sort: High first, then Medium, then Low
    priority_order = {"High": 0, "Medium": 1, "Low": 2}
    items.sort(key=lambda x: priority_order.get(x.get("riskPriority", "Low"), 2))

    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"risks": items, "count": len(items)}),
    }
