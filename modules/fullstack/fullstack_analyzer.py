import json
import os
import logging
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError
from scan_events import emit_scan_completed

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION     = os.environ.get("AWS_REGION", "us-east-1")

# Thresholds — web APIs. Ambica uses 1000ms for mobile; I use 2000ms here.
LATENCY_THRESHOLD_MS = int(os.environ.get("LATENCY_THRESHOLD_MS", "2000"))
ERROR_5XX_THRESHOLD  = int(os.environ.get("ERROR_5XX_THRESHOLD", "10"))
LOOKBACK_HOURS       = int(os.environ.get("LOOKBACK_HOURS", "1"))

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": "*",
}


def build_risk(api_name, resource_path, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None):
    ts = datetime.now(timezone.utc).isoformat()
    safe = f"{api_name}-{resource_path}".lower().replace("/", "-").replace(" ", "-")[:80]
    return {
        "resourceId":           f"fullstack-apigw-{safe}",
        "riskTimestamp":        ts,
        "module":               "fullstack",
        "cloudProvider":        "AWS",
        "resource":             "API Gateway",
        "resourceName":         f"{api_name} {resource_path}".strip(),
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
        logger.info(f"Saved: {risk['riskType']} — {risk['resourceName']}")
    except ClientError as e:
        logger.error(f"DynamoDB put_item failed: {e}")


# ---------------------------------------------------------------------------
# Check 1 — unauthenticated API endpoints
# ---------------------------------------------------------------------------

def scan_api_authentication(apigw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis: {e}")
        return found

    for api in apis:
        api_id   = api["id"]
        api_name = api.get("name", api_id)

        try:
            resources = apigw.get_resources(restApiId=api_id).get("items", [])
        except ClientError as e:
            logger.warning(f"get_resources {api_name}: {e}")
            continue

        for res in resources:
            path    = res.get("path", "/")
            methods = res.get("resourceMethods", {})
            for method_name in methods:
                if method_name == "OPTIONS":
                    continue    # OPTIONS is CORS preflight, not a real endpoint
                try:
                    method_detail = apigw.get_method(
                        restApiId=api_id,
                        resourceId=res["id"],
                        httpMethod=method_name,
                    )
                    auth_type     = method_detail.get("authorizationType", "NONE")
                    api_key_req   = method_detail.get("apiKeyRequired", False)

                    if auth_type == "NONE" and not api_key_req:
                        r = build_risk(
                            api_name, f"{method_name} {path}",
                            "Unauthenticated API Endpoint",
                            f"{method_name} {path} on '{api_name}' has no authentication. "
                            "Anyone with the URL can call this endpoint.",
                            "High",
                            remediation_steps=[
                                "Add a Cognito User Pool authorizer to the method",
                                "Or use AWS_IAM authorization and restrict caller via IAM policies",
                            ],
                            alternative_solutions=[
                                "Require an API key (less secure, but better than nothing)",
                                "Route traffic through a WAF rule that checks for an authorization header",
                            ],
                        )
                        found.append(r)
                        save_risk(table, r)
                except ClientError as e:
                    logger.warning(f"get_method {api_name} {method_name} {path}: {e}")

    return found


# ---------------------------------------------------------------------------
# Check 2 — missing rate limiting
# ---------------------------------------------------------------------------

def scan_throttling(apigw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (throttle check): {e}")
        return found

    for api in apis:
        api_id   = api["id"]
        api_name = api.get("name", api_id)
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
        except ClientError as e:
            logger.warning(f"get_stages {api_name}: {e}")
            continue

        for stage in stages:
            stage_name = stage.get("stageName", "")
            burst = (stage.get("defaultRouteSettings") or {}).get("throttlingBurstLimit")
            rate  = stage.get("defaultRouteSettings", {}).get("throttlingRateLimit") if stage.get("defaultRouteSettings") else None

            # Also check the top-level method settings
            if burst is None:
                burst = stage.get("methodSettings", {}).get("*/*", {}).get("throttlingBurstLimit")

            if burst is None:
                r = build_risk(
                    api_name, f"stage:{stage_name}",
                    "No Rate Limiting on API Stage",
                    f"Stage '{stage_name}' of API '{api_name}' has no throttling configured. "
                    "The API can be flooded or abused without any limit.",
                    "Medium",
                    remediation_steps=[
                        "Set a throttling burst limit and rate limit on the stage in API Gateway",
                        "Go to Stage > Default Route Settings > Enable throttling",
                    ],
                    alternative_solutions=[
                        "Use AWS WAF rate-based rules in front of the API",
                        "Add API usage plans and keys for consumer-level throttling",
                    ],
                )
                found.append(r)
                save_risk(table, r)

    return found


# ---------------------------------------------------------------------------
# Checks 3 & 4 — CloudWatch metrics: 5XX errors and latency
# ---------------------------------------------------------------------------

def get_cw_metric(cw, metric_name, statistic, api_name, hours):
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    try:
        resp = cw.get_metric_statistics(
            Namespace="AWS/ApiGateway",
            MetricName=metric_name,
            Dimensions=[{"Name": "ApiName", "Value": api_name}],
            StartTime=start,
            EndTime=now,
            Period=3600 * hours,
            Statistics=[statistic],
        )
        datapoints = resp.get("Datapoints", [])
        if not datapoints:
            return 0
        return datapoints[0].get(statistic, 0)
    except ClientError as e:
        logger.warning(f"CloudWatch {metric_name} for {api_name}: {e}")
        return 0


def scan_cloudwatch_metrics(apigw, cw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (cw metrics): {e}")
        return found

    for api in apis:
        api_name = api.get("name", api["id"])

        # 5XX error count
        error_count = get_cw_metric(cw, "5XXError", "Sum", api_name, LOOKBACK_HOURS)
        if error_count > ERROR_5XX_THRESHOLD:
            r = build_risk(
                api_name, "",
                "High 5XX Error Rate",
                f"API '{api_name}' recorded {int(error_count)} 5XX errors in the last {LOOKBACK_HOURS} hour(s).",
                "High",
                remediation_steps=[
                    "Check CloudWatch Logs for the Lambda function behind this API",
                    "Look for unhandled exceptions, timeouts, and memory limit errors",
                ],
            )
            found.append(r)
            save_risk(table, r)

        # Average latency
        avg_latency = get_cw_metric(cw, "Latency", "Average", api_name, LOOKBACK_HOURS)
        if avg_latency > LATENCY_THRESHOLD_MS:
            r = build_risk(
                api_name, "",
                "High API Latency",
                f"Average latency for '{api_name}' is {int(avg_latency)}ms — "
                f"above the {LATENCY_THRESHOLD_MS}ms threshold.",
                "Medium",
                remediation_steps=[
                    "Check Lambda execution time and memory allocation",
                    "Enable Lambda provisioned concurrency to eliminate cold starts",
                    "Review DynamoDB read patterns — consider adding DAX",
                ],
                alternative_solutions=[
                    "Add caching at the API Gateway stage level",
                    "Move heavy computation to an async job and respond immediately",
                ],
            )
            found.append(r)
            save_risk(table, r)

    return found


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    logger.info("fullstack-analyzer started")
    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)
    apigw = boto3.client("apigateway", region_name=REGION)
    cw    = boto3.client("cloudwatch",  region_name=REGION)

    all_risks = []
    all_risks += scan_api_authentication(apigw, table)
    all_risks += scan_throttling(apigw, table)
    all_risks += scan_cloudwatch_metrics(apigw, cw, table)

    emit_scan_completed("fullstack", all_risks)

    logger.info(f"fullstack scan complete — {len(all_risks)} risk(s)")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"message": "Full-Stack scan complete", "risksFound": len(all_risks)}),
    }
