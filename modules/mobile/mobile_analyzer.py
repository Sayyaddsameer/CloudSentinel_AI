import json
import os
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION     = os.environ.get("AWS_REGION", "us-east-1")

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": "*",
}


# ---------------------------------------------------------------------------
# Risk builder
# ---------------------------------------------------------------------------

def build_risk(resource, resource_name, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None):
    ts   = datetime.now(timezone.utc).isoformat()
    safe = resource_name.lower().replace(" ", "-").replace("/", "-")[:60]
    res  = resource.lower().replace(" ", "-")
    return {
        "resourceId":           f"mobile-{res}-{safe}",
        "riskTimestamp":        ts,
        "module":               "mobile",
        "cloudProvider":        "AWS",
        "resource":             resource,
        "resourceName":         resource_name,
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
                for method, detail in methods.items():
                    if method == "OPTIONS":
                        continue
                    auth = detail.get("authorizationType", "NONE")
                    if auth == "NONE":
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
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    logger.info("mobile-analyzer started")
    ddb     = boto3.resource("dynamodb", region_name=REGION)
    table   = ddb.Table(TABLE_NAME)
    apigw   = boto3.client("apigateway",  region_name=REGION)
    cognito = boto3.client("cognito-idp", region_name=REGION)
    iam     = boto3.client("iam",         region_name=REGION)

    all_risks = []
    all_risks += scan_api_gateway(apigw, table)
    all_risks += scan_cognito_pools(cognito, table)
    all_risks += scan_iam_lambda_roles(iam, table)

    logger.info(f"mobile scan complete — {len(all_risks)} risk(s)")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"message": "Mobile scan complete", "risksFound": len(all_risks)}),
    }
