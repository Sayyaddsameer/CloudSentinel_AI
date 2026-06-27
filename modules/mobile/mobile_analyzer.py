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

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION     = os.environ.get("AWS_REGION", "us-east-1")

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}


# ---------------------------------------------------------------------------
# Risk builder
# ---------------------------------------------------------------------------

def build_risk(resource, resource_name, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None):
    return build_risk_record(
        module="mobile",
        resource=resource,
        resource_name=resource_name,
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
        logger.info(f"Saved: [{risk['riskPriority']}] {risk['riskType']} — {risk['resourceName']}")
    except ClientError as e:
        logger.error(f"DynamoDB put_item failed: {e}")


# ---------------------------------------------------------------------------
# API Gateway — check for missing authorization on API routes
# ---------------------------------------------------------------------------

def scan_api_gateway(apigw, table):
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
            for res in resources:
                methods = res.get("resourceMethods", {})
                for method in methods:
                    if method == "OPTIONS":
                        continue
                    try:
                        method_detail = apigw.get_method(
                            restApiId=api_id,
                            resourceId=res["id"],
                            httpMethod=method,
                        )
                        auth = method_detail.get("authorizationType", "NONE")
                        api_key_req = method_detail.get("apiKeyRequired", False)
                        if auth == "NONE" and not api_key_req:
                            r = build_risk(
                                "API Gateway", f"{api_name}/{res.get('path', '?')}",
                                "API Route Missing Authorization",
                                f"Method {method} on '{res.get('path')}' in API '{api_name}' "
                                "has no authorization. Unauthenticated users can call this endpoint.",
                                "High",
                                remediation_steps=[
                                    "Add a Cognito User Pool Authorizer to the API Gateway method",
                                    "Or use an IAM authorizer for service-to-service calls",
                                    "Enable API keys for at minimum basic rate-limiting",
                                ],
                                alternative_solutions=[
                                    "Use AWS WAF with API Gateway to add IP-based or rate-limit rules",
                                    "Implement a Lambda authorizer for custom token validation",
                                ],
                            )
                            found.append(r)
                            save_risk(table, r)
                    except ClientError as e:
                        logger.warning(f"get_method {api_id}/{method}: {e}")
                        continue
        except ClientError as e:
            logger.warning(f"get_resources for API {api_id}: {e}")

    return found


# ---------------------------------------------------------------------------
# Cognito — check for weak password policies and MFA settings
# ---------------------------------------------------------------------------

def scan_cognito_pools(cognito, table):
    found = []
    try:
        pools = cognito.list_user_pools(MaxResults=50).get("UserPools", [])
    except ClientError as e:
        logger.error(f"list_user_pools: {e}")
        return found

    for pool in pools:
        pool_id   = pool["Id"]
        pool_name = pool.get("Name", pool_id)
        try:
            detail = cognito.describe_user_pool(UserPoolId=pool_id).get("UserPool", {})

            # MFA check
            mfa_config = detail.get("MfaConfiguration", "OFF")
            if mfa_config == "OFF":
                r = build_risk(
                    "Cognito User Pool", pool_name,
                    "MFA Not Enforced on User Pool",
                    f"User pool '{pool_name}' has MFA disabled. "
                    "Mobile users have no second factor protecting their accounts.",
                    "High",
                    remediation_steps=[
                        "Set MfaConfiguration to OPTIONAL or ON in the Cognito console",
                        "Enable TOTP (time-based one-time passwords) as the MFA method",
                        "Notify existing users to set up MFA through your app",
                    ],
                    alternative_solutions=[
                        "Use Cognito Advanced Security for adaptive authentication",
                        "Implement SMS-based MFA as a minimum second factor",
                    ],
                )
                found.append(r)
                save_risk(table, r)

            # Password policy strength check
            policy = detail.get("Policies", {}).get("PasswordPolicy", {})
            min_len = policy.get("MinimumLength", 0)
            if min_len < 12:
                r = build_risk(
                    "Cognito User Pool", pool_name,
                    "Weak Password Policy in User Pool",
                    f"User pool '{pool_name}' requires a minimum password length of only {min_len}. "
                    "Short passwords are vulnerable to brute-force attacks on mobile clients.",
                    "Medium",
                    remediation_steps=[
                        "Set minimum password length to at least 12 characters",
                        "Require uppercase, numbers, and special characters",
                        "Enable account lockout after repeated failed attempts",
                    ],
                    alternative_solutions=[
                        "Integrate password strength meter in your mobile app UI",
                        "Use Cognito's built-in compromised credentials check (Advanced Security)",
                    ],
                )
                found.append(r)
                save_risk(table, r)

        except ClientError as e:
            logger.warning(f"describe_user_pool {pool_id}: {e}")

    return found


# ---------------------------------------------------------------------------
# API Gateway — check p95 latency against mobile threshold
# ---------------------------------------------------------------------------

def scan_api_latency(apigw, cw, table, latency_threshold_ms):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (latency): {e}")
        return found

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)

    for api in apis:
        api_name = api.get("name", api["id"])
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/ApiGateway",
                MetricName="Latency",
                Dimensions=[{"Name": "ApiName", "Value": api_name}],
                StartTime=start,
                EndTime=now,
                Period=3600,
                Statistics=["p95"],
            )
            datapoints = resp.get("Datapoints", [])
            p95_latency = datapoints[0].get("p95", 0) if datapoints else 0
            if p95_latency > latency_threshold_ms:
                r = build_risk(
                    "API Gateway", api_name,
                    "High Mobile API Latency (p95)",
                    f"p95 latency for '{api_name}' is {int(p95_latency)}ms, above the {latency_threshold_ms}ms mobile threshold.",
                    "High",
                    remediation_steps=[
                        "Increase Lambda memory — this also increases CPU allocation",
                        "Enable provisioned concurrency to eliminate cold starts",
                        "Add DynamoDB DAX or ElastiCache to reduce read latency",
                    ],
                    alternative_solutions=[
                        "Use CloudFront in front of API Gateway for edge caching",
                        "Move to HTTP API v2 (lower latency than REST API)",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"CloudWatch latency for {api_name}: {e}")
    return found


# ---------------------------------------------------------------------------
# IAM — check for Lambda execution roles with overly broad permissions
# ---------------------------------------------------------------------------

def scan_iam_lambda_roles(iam, table):
    found = []
    OVERLY_BROAD_ACTIONS = {"*", "s3:*", "dynamodb:*", "lambda:*", "iam:*"}
    try:
        roles = iam.list_roles().get("Roles", [])
    except ClientError as e:
        logger.error(f"list_roles: {e}")
        return found

    for role in roles:
        role_name = role["RoleName"]
        # Focus on Lambda execution roles
        assume_doc = role.get("AssumeRolePolicyDocument", {})
        stmts = assume_doc.get("Statement", [])
        is_lambda_role = any(
            "lambda.amazonaws.com" in str(s.get("Principal", ""))
            for s in stmts
        )
        if not is_lambda_role:
            continue

        try:
            inline_policies = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            for pol_name in inline_policies:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                policy_doc = doc.get("PolicyDocument", {})
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    broad = [a for a in actions if a in OVERLY_BROAD_ACTIONS]
                    if broad:
                        r = build_risk(
                            "IAM Role", role_name,
                            "Lambda Role Has Overly Broad Permissions",
                            f"Role '{role_name}' grants broad actions {broad} in inline policy '{pol_name}'. "
                            "Compromised mobile backend Lambdas can access all account resources.",
                            "High",
                            remediation_steps=[
                                "Replace wildcard actions with specific actions the function actually needs",
                                "Apply the principle of least privilege to every Lambda execution role",
                                "Use resource-level restrictions (specific ARNs) instead of '*'",
                            ],
                            alternative_solutions=[
                                "Use AWS IAM Access Analyzer to identify and remove unused permissions",
                                "Separate Lambda roles by function — one role per Lambda with minimal perms",
                            ],
                        )
                        found.append(r)
                        save_risk(table, r)
                        break   # one risk per role is sufficient
        except ClientError as e:
            logger.warning(f"Checking inline policies for {role_name}: {e}")

    return found


# ---------------------------------------------------------------------------
# Lambda — check function timeout, memory, and reserved concurrency
# ---------------------------------------------------------------------------

def scan_lambda_health(lambda_client, table):
    found = []
    try:
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name    = fn["FunctionName"]
                timeout = fn.get("Timeout", 3)
                memory  = fn.get("MemorySize", 128)

                # Timeout check
                if timeout >= 900 or timeout < 10:
                    reason = (
                        f"Lambda '{name}' has a timeout of {timeout}s. "
                        + ("This is the maximum (no real timeout enforced), which can cause hung executions."
                           if timeout >= 900
                           else "This is too low for typical mobile backend workloads and may cause premature termination.")
                    )
                    r = build_risk(
                        "Lambda", name,
                        "Lambda Function Timeout Misconfigured",
                        reason,
                        "Medium",
                        remediation_steps=[
                            "Set a timeout between 10s and 29s for mobile-facing APIs",
                            "Profile function execution time with AWS X-Ray to find a safe upper bound",
                            "Use Step Functions for workflows that genuinely need longer execution",
                        ],
                        alternative_solutions=[
                            "Enable Lambda Insights for continuous timeout monitoring",
                            "Add CloudWatch alarms on the Lambda Errors metric for timeout detection",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)

                # Memory check
                if memory < 256:
                    r = build_risk(
                        "Lambda", name,
                        "Lambda Function Low Memory Allocation",
                        f"Lambda '{name}' has only {memory}MB of memory allocated. "
                        "Low memory also reduces CPU allocation, increasing latency for mobile backends.",
                        "Low",
                        remediation_steps=[
                            "Increase memory to at least 256MB for mobile-facing Lambda functions",
                            "Use AWS Lambda Power Tuning to find the optimal memory/cost balance",
                        ],
                        alternative_solutions=[
                            "Profile the function with AWS X-Ray to confirm memory pressure",
                            "Consider Graviton2 (arm64) architecture for better price/performance",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)

                # Reserved concurrency check
                try:
                    concurrency = lambda_client.get_function_concurrency(FunctionName=name)
                    if "ReservedConcurrentExecutions" not in concurrency:
                        r = build_risk(
                            "Lambda", name,
                            "Lambda Missing Reserved Concurrency",
                            f"Lambda '{name}' has no reserved concurrency set. "
                            "Without it the function can consume the entire account concurrency quota, "
                            "starving other mobile backend functions during traffic spikes.",
                            "Medium",
                            remediation_steps=[
                                "Set a reserved concurrency limit appropriate for the function's role",
                                "Use provisioned concurrency for latency-sensitive mobile APIs",
                                "Configure account-level concurrency limits in the Lambda console",
                            ],
                            alternative_solutions=[
                                "Use SQS as a buffer in front of Lambda to smooth traffic bursts",
                                "Implement exponential back-off with jitter in the mobile client",
                            ],
                        )
                        found.append(r)
                        save_risk(table, r)
                except ClientError as e:
                    logger.warning(f"get_function_concurrency for {name}: {e}")
    except ClientError as e:
        logger.error(f"list_functions paginator: {e}")
    return found


# ---------------------------------------------------------------------------
# API Gateway — check for missing access logging on REST API stages
# ---------------------------------------------------------------------------

def scan_api_gateway_logging(apigw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (logging): {e}")
        return found

    for api in apis:
        api_id   = api["id"]
        api_name = api.get("name", api_id)
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                stage_name = stage.get("stageName", "unknown")
                resource_label = f"{api_name}/{stage_name}"

                # Check access log settings
                access_log_settings = stage.get("accessLogSettings", {})
                logging_disabled = not access_log_settings.get("destinationArn")

                # Check method-level logging level
                method_settings  = stage.get("methodSettings", {})
                catch_all        = method_settings.get("*/*", {})
                logging_level    = catch_all.get("loggingLevel", "OFF")
                method_log_off   = logging_level == "OFF"

                if logging_disabled or method_log_off:
                    r = build_risk(
                        "API Gateway", resource_label,
                        "API Gateway Access Logging Disabled",
                        f"Stage '{stage_name}' of API '{api_name}' has access logging disabled. "
                        "Without logs, malicious or erroneous mobile requests cannot be investigated.",
                        "Medium",
                        remediation_steps=[
                            "Enable access logging in API Gateway Stage settings",
                            "Set log level to INFO or ERROR",
                        ],
                        alternative_solutions=[
                            "Ship API Gateway access logs to CloudWatch Logs Insights for querying",
                            "Enable AWS X-Ray tracing on the stage for distributed tracing",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)
        except ClientError as e:
            logger.warning(f"get_stages for API {api_id}: {e}")

    return found


# ---------------------------------------------------------------------------
# API Gateway — detect elevated 4XX error rates via CloudWatch
# ---------------------------------------------------------------------------

def scan_4xx_error_rates(apigw, cw, table):
    found = []
    try:
        apis = apigw.get_rest_apis().get("items", [])
    except ClientError as e:
        logger.error(f"get_rest_apis (4xx): {e}")
        return found

    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)

    for api in apis:
        api_name = api.get("name", api["id"])
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/ApiGateway",
                MetricName="4XXError",
                Dimensions=[{"Name": "ApiName", "Value": api_name}],
                StartTime=start,
                EndTime=now,
                Period=3600,
                Statistics=["Sum"],
            )
            datapoints = resp.get("Datapoints", [])
            total_4xx  = datapoints[0].get("Sum", 0) if datapoints else 0
            if total_4xx > 50:
                r = build_risk(
                    "API Gateway", api_name,
                    "4XX Error Rate Elevated",
                    f"API '{api_name}' recorded {int(total_4xx)} 4XX errors in the last hour. "
                    "This may indicate expired auth tokens, bad requests, or client-side issues "
                    "degrading the mobile user experience.",
                    "Medium",
                    remediation_steps=[
                        "Review API Gateway access logs for failed requests",
                        "Check client authentication token expiry",
                    ],
                    alternative_solutions=[
                        "Add a CloudWatch alarm on 4XXError to get proactive notifications",
                        "Use AWS X-Ray to trace specific failing requests end-to-end",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"CloudWatch 4XXError for {api_name}: {e}")

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
    logger.info("mobile-analyzer started")

    # Accept optional params from the frontend (API URL + custom threshold)
    latency_ms = int(os.environ.get("LATENCY_THRESHOLD_MS", "1000"))
    try:
        body = json.loads((event.get("body") or "{}"))
        custom_threshold = body.get("latencyThresholdMs")
        if custom_threshold:
            latency_ms = int(custom_threshold)
    except Exception:
        pass

    ddb     = boto3.resource("dynamodb", region_name=REGION)
    table   = ddb.Table(TABLE_NAME)
    apigw   = boto3.client("apigateway",  region_name=REGION)
    cognito = boto3.client("cognito-idp", region_name=REGION)
    iam     = boto3.client("iam",         region_name=REGION)
    cw      = boto3.client("cloudwatch",  region_name=REGION)

    purge_module_risks(table, "mobile")

    _start = time.time()

    all_risks = []
    all_risks += scan_api_gateway(apigw, table)
    all_risks += scan_cognito_pools(cognito, table)
    all_risks += scan_iam_lambda_roles(iam, table)
    all_risks += scan_api_latency(apigw, cw, table, latency_ms)

    lambda_client = boto3.client("lambda", region_name=REGION)
    all_risks += scan_lambda_health(lambda_client, table)
    all_risks += scan_api_gateway_logging(apigw, table)
    all_risks += scan_4xx_error_rates(apigw, cw, table)

    emit_scan_completed("mobile", all_risks)

    duration_ms = int((time.time() - _start) * 1000)
    try:
        cw.put_metric_data(
            Namespace="CloudSentinel/Performance",
            MetricData=[{
                "MetricName": "ScanDurationMs",
                "Dimensions": [{"Name": "Module", "Value": "mobile"}],
                "Value": duration_ms,
                "Unit": "Milliseconds",
            }],
        )
    except Exception as e:
        logger.warning(f"CloudWatch metric write failed: {e}")

    logger.info(f"mobile scan complete -- {len(all_risks)} risk(s) (latency threshold: {latency_ms}ms) in {duration_ms}ms")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message": "Mobile scan complete",
            "risksFound": len(all_risks),
            "durationMs": duration_ms,
        }),
    }
