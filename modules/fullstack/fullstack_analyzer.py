import json
import os
import logging
import time
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

from shared.scan_events import emit_scan_completed
from shared.schemas.risk_record import build_risk_record

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME  = os.environ["DYNAMODB_TABLE"]
# SCAN_REGION: where AWS services (API GW, Cognito etc.) live
REGION      = os.environ.get("SCAN_REGION") or os.environ.get("AWS_REGION", "us-east-1")
# DDB_REGION: where the DynamoDB table lives (may differ from scan region)
DDB_REGION  = os.environ.get("DDB_REGION") or os.environ.get("AWS_REGION", "ap-south-1")

# Thresholds — web APIs. Ambica uses 1000ms for mobile; I use 2000ms here.
LATENCY_THRESHOLD_MS = int(os.environ.get("LATENCY_THRESHOLD_MS", "2000"))
ERROR_5XX_THRESHOLD  = int(os.environ.get("ERROR_5XX_THRESHOLD", "10"))
LOOKBACK_HOURS       = int(os.environ.get("LOOKBACK_HOURS", "1"))

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}


def build_risk(api_name, resource_path, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None):
    # Facade over shared schema
    return build_risk_record(
        module="fullstack",
        resource="API Gateway",
        resource_name=f"{api_name} {resource_path}".strip(),
        risk_type=risk_type,
        risk_reason=risk_reason,
        priority=priority,
        remediation_steps=remediation_steps,
        alternative_solutions=alternative_solutions,
        cloud_provider="AWS",
        region=REGION,
    )


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

            # For REST APIs, throttling can be in three places:
            burst = None
            # Check defaultRouteSettings (HTTP API v2)
            if stage.get("defaultRouteSettings"):
                burst = stage["defaultRouteSettings"].get("throttlingBurstLimit")
            # Also check REST API methodSettings catch-all
            if burst is None:
                burst = stage.get("methodSettings", {}).get("*/*", {}).get("throttlingBurstLimit")
            # Also check stage-level throttle (REST API)
            if burst is None and stage.get("throttle"):
                burst = stage["throttle"].get("burstLimit")

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
# Check 5 — WAF association on API Gateway stages
# ---------------------------------------------------------------------------

def scan_waf_association(apigw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (WAF check): {e}")
        return found

    for api in apis:
        api_id   = api["id"]
        api_name = api.get("name", api_id)
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
        except ClientError as e:
            logger.warning(f"get_stages {api_name} (WAF check): {e}")
            continue

        for stage in stages:
            stage_name  = stage.get("stageName", "")
            waf_arn     = stage.get("webAclArn") or stage.get("wafWebAclArn", "")
            if not waf_arn:
                r = build_risk(
                    api_name, f"stage:{stage_name}",
                    "API Gateway Not Protected by WAF",
                    f"Stage '{stage_name}' of API '{api_name}' has no WAF WebACL associated. "
                    "The API is exposed to common web exploits and DDoS attacks.",
                    "Medium",
                    remediation_steps=[
                        "Create a WAF WebACL and associate it with the API Gateway stage",
                        "Add rate-based rules to prevent DDoS",
                    ],
                    alternative_solutions=[
                        "Use AWS Shield Advanced for DDoS protection",
                    ],
                )
                found.append(r)
                save_risk(table, r)

    return found


# ---------------------------------------------------------------------------
# Check 6 — API Gateway access & execution logging
# ---------------------------------------------------------------------------

def scan_api_logging(apigw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (logging check): {e}")
        return found

    for api in apis:
        api_id   = api["id"]
        api_name = api.get("name", api_id)
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
        except ClientError as e:
            logger.warning(f"get_stages {api_name} (logging check): {e}")
            continue

        for stage in stages:
            stage_name = stage.get("stageName", "")

            # Access logging check
            access_log_settings = stage.get("accessLogSettings")
            if not access_log_settings or not access_log_settings.get("destinationArn"):
                r = build_risk(
                    api_name, f"stage:{stage_name}",
                    "API Gateway Access Logging Not Enabled",
                    f"Stage '{stage_name}' of API '{api_name}' does not have access logging "
                    "configured. API call records will not be captured for audit or forensics.",
                    "Medium",
                    remediation_steps=[
                        "Enable access logging in Stage > Logs/Tracing > Access Logging",
                        "Set CloudWatch log group ARN",
                    ],
                )
                found.append(r)
                save_risk(table, r)

            # Execution logging check
            method_settings    = stage.get("methodSettings", {})
            catch_all_settings = method_settings.get("*/*", {})
            logging_level      = catch_all_settings.get("loggingLevel", "OFF")
            if logging_level == "OFF":
                r = build_risk(
                    api_name, f"stage:{stage_name}",
                    "API Gateway Execution Logging Disabled",
                    f"Stage '{stage_name}' of API '{api_name}' has execution logging set to OFF. "
                    "Request/response details and integration errors will not be logged.",
                    "Low",
                    remediation_steps=[
                        "Enable access logging in Stage > Logs/Tracing > Access Logging",
                        "Set CloudWatch log group ARN",
                    ],
                )
                found.append(r)
                save_risk(table, r)

    return found


# ---------------------------------------------------------------------------
# Check 7 — CloudWatch alarms for 5XX errors per API
# ---------------------------------------------------------------------------

def scan_cloudwatch_alarms(apigw, cw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (alarm check): {e}")
        return found

    for api in apis:
        api_name = api.get("name", api["id"])
        try:
            resp   = cw.describe_alarms_for_metric(
                MetricName="5XXError",
                Namespace="AWS/ApiGateway",
                Dimensions=[{"Name": "ApiName", "Value": api_name}],
            )
            alarms = resp.get("MetricAlarms", [])
        except ClientError as e:
            logger.warning(f"describe_alarms_for_metric {api_name}: {e}")
            alarms = []

        if not alarms:
            r = build_risk(
                api_name, "",
                "No Error Rate Alarm on API",
                f"No CloudWatch alarm is configured for the '5XXError' metric on API '{api_name}'. "
                "Elevated error rates will go undetected until users report issues.",
                "Low",
                remediation_steps=[
                    "Create a CloudWatch alarm on the 5XXError metric for this API",
                    "Set an appropriate threshold and link it to an SNS topic for notifications",
                ],
                alternative_solutions=[
                    "Use AWS X-Ray and CloudWatch ServiceLens for end-to-end observability",
                ],
            )
            found.append(r)
            save_risk(table, r)

    return found


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def purge_module_risks(table, module):
    try:
        resp = table.query(
            IndexName="module-index",
            KeyConditionExpression="#m = :m",
            ExpressionAttributeNames={"#m": "module"},
            ExpressionAttributeValues={":m": module},
        )
        items = resp.get("Items", [])
        while "LastEvaluatedKey" in resp:
            resp = table.query(
                IndexName="module-index",
                KeyConditionExpression="#m = :m",
                ExpressionAttributeNames={"#m": "module"},
                ExpressionAttributeValues={":m": module},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))

        with table.batch_writer(overwrite_by_pkeys=["resourceId", "riskTimestamp"]) as batch:
            for item in items:
                rid = item.get("resourceId")
                rts = item.get("riskTimestamp")
                if rid and rts:
                    batch.delete_item(Key={"resourceId": rid, "riskTimestamp": rts})
    except Exception as e:
        logger.error(f"Failed to purge old risks: {e}")

def lambda_handler(event, context):
    _start = time.time()
    logger.info("fullstack-analyzer started")
    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)
    apigw = boto3.client("apigateway", region_name=REGION)
    cw    = boto3.client("cloudwatch",  region_name=REGION)

    purge_module_risks(table, "fullstack")

    all_risks = []
    all_risks += scan_api_authentication(apigw, table)
    all_risks += scan_throttling(apigw, table)
    all_risks += scan_cloudwatch_metrics(apigw, cw, table)
    all_risks += scan_waf_association(apigw, table)
    all_risks += scan_api_logging(apigw, table)
    all_risks += scan_cloudwatch_alarms(apigw, cw, table)

    emit_scan_completed("fullstack", all_risks)

    duration_ms = int((time.time() - _start) * 1000)
    try:
        cw.put_metric_data(
            Namespace="CloudSentinel/Performance",
            MetricData=[{
                "MetricName": "ScanDurationMs",
                "Dimensions": [{"Name": "Module", "Value": "fullstack"}],
                "Value": duration_ms,
                "Unit": "Milliseconds",
            }],
        )
    except Exception as e:
        logger.warning(f"CloudWatch metric write failed: {e}")

    logger.info(f"fullstack scan complete — {len(all_risks)} risk(s) in {duration_ms}ms")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message": "Full-Stack scan complete",
            "risksFound": len(all_risks),
            "durationMs": duration_ms,
        }),
    }
