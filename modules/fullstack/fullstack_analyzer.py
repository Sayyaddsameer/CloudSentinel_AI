import json
import os
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

from shared.scan_events import emit_scan_completed
from shared.schemas.risk_record import build_risk_record

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME  = os.environ["DYNAMODB_TABLE"]
# REGION: internal Lambda deployment region (for STS + DDB)
REGION      = os.environ.get("SCAN_REGION") or os.environ.get("AWS_REGION", "us-east-1")
# DDB_REGION: where the CloudSentinel DynamoDB table lives
DDB_REGION  = os.environ.get("DDB_REGION") or os.environ.get("AWS_REGION", "ap-south-1")
AI_EXPLAINER_FN = os.environ.get("AI_EXPLAINER_FUNCTION_NAME", "cloudsentinel-ai-explainer")

# Thresholds Ã¢â‚¬â€ web APIs. Ambica uses 1000ms for mobile; I use 2000ms here.
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
        logger.info(f"Saved: {risk['riskType']} Ã¢â‚¬â€ {risk['resourceName']}")
    except ClientError as e:
        logger.error(f"DynamoDB put_item failed: {e}")


# ---------------------------------------------------------------------------
# Check 1 Ã¢â‚¬â€ unauthenticated API endpoints
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
# Check 2 Ã¢â‚¬â€ missing rate limiting
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
# Checks 3 & 4 Ã¢â‚¬â€ CloudWatch metrics: 5XX errors and latency
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
                f"Average latency for '{api_name}' is {int(avg_latency)}ms Ã¢â‚¬â€ "
                f"above the {LATENCY_THRESHOLD_MS}ms threshold.",
                "Medium",
                remediation_steps=[
                    "Check Lambda execution time and memory allocation",
                    "Enable Lambda provisioned concurrency to eliminate cold starts",
                    "Review DynamoDB read patterns Ã¢â‚¬â€ consider adding DAX",
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
# Check 5 Ã¢â‚¬â€ WAF association on API Gateway stages
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
# Check 6 Ã¢â‚¬â€ API Gateway access & execution logging
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
# Check 7 Ã¢â‚¬â€ CloudWatch alarms for 5XX errors per API
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
# Real-time HTTP tests â€” latency, rate limiting, authentication
# These make LIVE calls to the user's API endpoint from the Lambda.
# ---------------------------------------------------------------------------

_SCANNER_UA = "CloudSentinel-Scanner/1.0"


def _http_get(url, headers=None, timeout=10):
    """Single HTTP GET. Returns (status_code, elapsed_ms) or (None, None) on error."""
    req = urllib.request.Request(url, headers={"User-Agent": _SCANNER_UA, **(headers or {})})
    t0  = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            return r.status, int((time.time() - t0) * 1000)
    except urllib.error.HTTPError as e:
        return e.code, int((time.time() - t0) * 1000)
    except Exception:
        return None, None


def test_live_latency(api_base_url, table, threshold_ms):
    """Make 3 real HTTP requests and flag if average exceeds threshold."""
    found = []
    if not api_base_url:
        return found

    samples = []
    for _ in range(3):
        _, elapsed = _http_get(api_base_url)
        if elapsed is not None:
            samples.append(elapsed)
        time.sleep(0.3)

    if not samples:
        logger.warning(f"Could not reach {api_base_url} â€” skipping latency check")
        return found

    avg_ms = int(sum(samples) / len(samples))
    logger.info(f"Live latency for {api_base_url}: {samples} â†’ avg {avg_ms}ms (threshold {threshold_ms}ms)")

    if avg_ms > threshold_ms:
        r = build_risk(
            api_base_url, "",
            "High Real-Time API Latency",
            f"Live measurement: average response time is {avg_ms}ms "
            f"(samples: {samples}) â€” above the {threshold_ms}ms threshold. "
            "Users will experience slow load times.",
            "High" if avg_ms > threshold_ms * 2 else "Medium",
            remediation_steps=[
                "Check Lambda execution time and memory allocation",
                "Enable Lambda provisioned concurrency to eliminate cold starts",
                "Add API Gateway caching on frequently-requested routes",
            ],
            alternative_solutions=[
                "Move expensive computation to async jobs (SQS/Step Functions)",
                "Add a CloudFront distribution in front of the API",
            ],
        )
        found.append(r)
        save_risk(table, r)
    return found


def test_rate_limiting(api_base_url, table):
    """Burst 20 rapid requests. If no 429 is returned, rate limiting is absent."""
    found = []
    if not api_base_url:
        return found

    got_429 = False
    for i in range(20):
        status, _ = _http_get(api_base_url, timeout=5)
        if status == 429:
            got_429 = True
            logger.info(f"Rate limiting confirmed at request #{i+1} (got 429)")
            break

    if not got_429:
        r = build_risk(
            api_base_url, "",
            "No Rate Limiting Enforced",
            f"20 rapid requests to {api_base_url} produced no HTTP 429 response. "
            "The API is not enforcing rate limits and can be flooded or abused.",
            "High",
            remediation_steps=[
                "Enable throttling on the API Gateway stage (burst limit + rate limit)",
                "Set a Usage Plan and attach an API key",
            ],
            alternative_solutions=[
                "Add a WAF rate-based rule to throttle by IP",
                "Use AWS Shield Advanced for DDoS protection",
            ],
        )
        found.append(r)
        save_risk(table, r)
    return found


def test_auth_enforcement(api_base_url, table):
    """Call the API without any auth header. 401/403 = protected. 2xx = unauthenticated."""
    found = []
    if not api_base_url:
        return found

    status, _ = _http_get(api_base_url, timeout=10)
    logger.info(f"Auth check for {api_base_url}: got HTTP {status}")

    if status is not None and status not in (401, 403):
        r = build_risk(
            api_base_url, "",
            "API Accessible Without Authentication (Live Verified)",
            f"A request with no Authorization header to {api_base_url} returned HTTP {status} â€” "
            "not 401 or 403. The endpoint is publicly accessible without credentials.",
            "High",
            remediation_steps=[
                "Add a Cognito User Pool authorizer to the API Gateway method",
                "Or use AWS_IAM authorization and restrict via IAM policy",
            ],
            alternative_solutions=[
                "Require an API key as a minimum short-term measure",
                "Add a WAF rule to block requests without an Authorization header",
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


def get_clients(scan_region, role_arn=None):
    """
    Build boto3 clients scoped to scan_region.
    If role_arn is provided, assume that role first (cross-account).
    """
    if role_arn:
        sts = boto3.client("sts", region_name=REGION)
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="cloudsentinel-fullstack-scan",
            DurationSeconds=900,
        )["Credentials"]
        session_kwargs = dict(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        logger.info(f"Assumed role {role_arn}, scanning region {scan_region}")
    else:
        session_kwargs = {}
        logger.info(f"Scanning own account, region {scan_region}")

    apigw = boto3.client("apigateway", region_name=scan_region, **session_kwargs)
    cw    = boto3.client("cloudwatch",  region_name=scan_region, **session_kwargs)
    return apigw, cw


def _invoke_ai_explainer(module):
    """Fire-and-forget: trigger AI explainer Lambda so explanations are ready immediately."""
    try:
        boto3.client("lambda", region_name=REGION).invoke(
            FunctionName=AI_EXPLAINER_FN,
            InvocationType="Event",
            Payload=json.dumps({"source": f"{module}-scanner", "module": module}),
        )
        logger.info(f"ai-explainer triggered for module={module}")
    except Exception as e:
        logger.warning(f"Could not trigger ai-explainer (non-fatal): {e}")


def lambda_handler(event, context):
    _start = time.time()
    logger.info("fullstack-analyzer started")

    body         = json.loads((event.get("body") or "{}"))
    role_arn     = body.get("targetRoleArn") or None
    scan_region  = body.get("scanRegion") or os.environ.get("SCAN_REGION") or os.environ.get("AWS_REGION", "us-east-1")
    api_base_url = (body.get("apiBaseUrl") or "").rstrip("/")
    threshold_ms = int(body.get("latencyThresholdMs") or LATENCY_THRESHOLD_MS)

    ddb   = boto3.resource("dynamodb", region_name=DDB_REGION)
    table = ddb.Table(TABLE_NAME)

    try:
        apigw, cw = get_clients(scan_region, role_arn)
    except Exception as e:
        logger.error(f"Cannot assume role / build clients: {e}")
        return {
            "statusCode": 403,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": f"Cannot access AWS account: {e}"}),
        }

    purge_module_risks(table, "fullstack")

    all_risks = []

    # ── Config-based checks (cross-account API GW read) ──────────────────────
    all_risks += scan_api_authentication(apigw, table)
    all_risks += scan_throttling(apigw, table)
    all_risks += scan_waf_association(apigw, table)
    all_risks += scan_api_logging(apigw, table)
    all_risks += scan_cloudwatch_alarms(apigw, cw, table)

    # ── Historical CloudWatch metrics ─────────────────────────────────────────
    all_risks += scan_cloudwatch_metrics(apigw, cw, table)

    # ── Real-time HTTP tests (live calls from Lambda → user's API) ────────────
    if api_base_url:
        logger.info(f"Running real-time HTTP tests against {api_base_url}")
        all_risks += test_live_latency(api_base_url, table, threshold_ms)
        all_risks += test_rate_limiting(api_base_url, table)
        all_risks += test_auth_enforcement(api_base_url, table)
    else:
        logger.info("No apiBaseUrl provided — skipping real-time HTTP tests")

    emit_scan_completed("fullstack", all_risks)

    # Trigger AI explainer immediately so explanations appear without waiting for hourly schedule
    _invoke_ai_explainer("fullstack")

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

    logger.info(f"fullstack scan complete — {len(all_risks)} risk(s) in {duration_ms}ms (region={scan_region})")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message": "Full-Stack scan complete",
            "risksFound": len(all_risks),
            "durationMs": duration_ms,
        }),
    }
