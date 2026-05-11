import json
import os
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from scan_events import emit_scan_completed

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
REGION = os.environ.get("AWS_REGION", "us-east-1")
TARGET_ROLE_ARN = os.environ.get("TARGET_ROLE_ARN", "")
GCP_SECRET_NAME = os.environ.get("GCP_SECRET_NAME", "")


# ---------------------------------------------------------------------------
# STS helper -- if TARGET_ROLE_ARN is set, all clients use assumed-role creds
# ---------------------------------------------------------------------------

def get_aws_clients(role_arn=None):
    effective_role = role_arn or TARGET_ROLE_ARN
    if effective_role:
        sts = boto3.client("sts", region_name=REGION)
        creds = sts.assume_role(
            RoleArn=effective_role,
            RoleSessionName="cloudsentinel-scan",
            ExternalId="cloudsentinel",
            DurationSeconds=900,
        )["Credentials"]
        kwargs = {
            "aws_access_key_id":     creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token":     creds["SessionToken"],
            "region_name":           REGION,
        }
        logger.info(f"Using assumed role: {effective_role}")
    else:
        kwargs = {"region_name": REGION}

    return {
        "s3":     boto3.client("s3",     **kwargs),
        "ec2":    boto3.client("ec2",    **kwargs),
        "iam":    boto3.client("iam",    **kwargs),
        "config": boto3.client("config", **kwargs),
    }


# ---------------------------------------------------------------------------
# Risk record builder -- shared schema
# ---------------------------------------------------------------------------

def build_risk(module, resource, resource_name, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None,
               cloud_provider="AWS"):
    ts = datetime.now(timezone.utc).isoformat()
    safe = resource_name.lower().replace(" ", "-").replace("/", "-")[:60]
    res_key = resource.lower().replace(" ", "-")
    return {
        "resourceId":           f"{module}-{res_key}-{safe}",
        "riskTimestamp":        ts,
        "module":               module,
        "cloudProvider":        cloud_provider,
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
        logger.info(f"Saved: [{risk['riskPriority']}] {risk['riskType']} -- {risk['resourceName']}")
    except ClientError as e:
        logger.error(f"DynamoDB put_item failed: {e}")


# ---------------------------------------------------------------------------
# AWS -- S3
# ---------------------------------------------------------------------------

def scan_s3_buckets(clients, table):
    s3 = clients["s3"]
    found = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.error(f"list_buckets: {e}")
        return found

    for b in buckets:
        name = b["Name"]

        # public access block
        try:
            cfg = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            all_blocked = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                r = build_risk(
                    "cloud-infra", "S3 Bucket", name,
                    "S3 Public Access Not Fully Blocked",
                    "One or more Block Public Access settings are disabled on this bucket.",
                    "High",
                    remediation_steps=[
                        "Open S3 > Bucket > Permissions > Block Public Access",
                        "Enable all four settings",
                        "Review and remove bucket policies that grant public access",
                    ],
                    alternative_solutions=[
                        "Use pre-signed URLs for temporary controlled access",
                        "Serve static content through CloudFront with Origin Access Control",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                r = build_risk(
                    "cloud-infra", "S3 Bucket", name,
                    "S3 No Public Access Block Configured",
                    "No public access block configuration exists for this bucket.",
                    "High",
                    remediation_steps=["Enable Block Public Access on the bucket from the console or CLI."],
                )
                found.append(r)
                save_risk(table, r)
            else:
                logger.warning(f"get_public_access_block {name}: {e}")

        # encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ServerSideEncryptionConfigurationNotFoundError",):
                r = build_risk(
                    "cloud-infra", "S3 Bucket", name,
                    "S3 Bucket Encryption Not Configured",
                    "Server-side encryption is not enabled on this bucket.",
                    "Medium",
                    remediation_steps=[
                        "Go to S3 > Bucket > Properties > Default encryption",
                        "Enable SSE-S3 or SSE-KMS",
                    ],
                    alternative_solutions=[
                        "Apply a bucket policy denying unencrypted PutObject requests (aws:SecureTransport)"
                    ],
                )
                found.append(r)
                save_risk(table, r)
            else:
                logger.warning(f"get_bucket_encryption {name}: {e}")

    return found


# ---------------------------------------------------------------------------
# AWS -- EC2 Security Groups
# ---------------------------------------------------------------------------

def scan_security_groups(clients, table):
    ec2 = clients["ec2"]
    found = []
    watch_ports = {22: "SSH", 3389: "RDP"}

    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except ClientError as e:
        logger.error(f"describe_security_groups: {e}")
        return found

    for sg in sgs:
        sg_id   = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        for rule in sg.get("IpPermissions", []):
            from_p = rule.get("FromPort", 0)
            to_p   = rule.get("ToPort",   65535)
            for cidr_entry in rule.get("IpRanges", []):
                if cidr_entry.get("CidrIp") != "0.0.0.0/0":
                    continue
                for port, label in watch_ports.items():
                    if from_p <= port <= to_p:
                        r = build_risk(
                            "cloud-infra", "EC2 Security Group", sg_name,
                            f"Security Group Open {label} to Internet",
                            f"Security group {sg_name} allows inbound {label} (port {port}) from 0.0.0.0/0.",
                            "High",
                            remediation_steps=[
                                f"Restrict port {port} to specific trusted IP ranges",
                                "Use AWS Systems Manager Session Manager instead of open SSH",
                            ],
                            alternative_solutions=[
                                "Place EC2 instances behind a bastion host with restricted access",
                                "Enable AWS Client VPN for private access",
                            ],
                        )
                        found.append(r)
                        save_risk(table, r)
                        break

    return found


# ---------------------------------------------------------------------------
# AWS -- IAM Password Policy
# ---------------------------------------------------------------------------

def scan_iam_password_policy(clients, table):
    iam = clients["iam"]
    found = []
    MIN_LENGTH = 14

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        length = policy.get("MinimumPasswordLength", 0)
        if length < MIN_LENGTH:
            r = build_risk(
                "cloud-infra", "IAM", "account-password-policy",
                "IAM Password Policy Too Weak",
                f"Minimum password length is {length}, which is below the recommended {MIN_LENGTH}.",
                "Medium",
                remediation_steps=[
                    f"Set minimum password length to {MIN_LENGTH} or more",
                    "Require uppercase letters, numbers, and symbols",
                    "Enable password expiration (90 days)",
                ],
            )
            found.append(r)
            save_risk(table, r)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            r = build_risk(
                "cloud-infra", "IAM", "account-password-policy",
                "No IAM Password Policy Set",
                "No account-level password policy is configured. Users can set any password.",
                "High",
                remediation_steps=[
                    "Go to IAM > Account settings > Create account password policy",
                    "Set minimum length 14, require uppercase, numbers, symbols",
                    "Enable password expiration at 90 days",
                ],
            )
            found.append(r)
            save_risk(table, r)
        else:
            logger.error(f"get_account_password_policy: {e}")

    return found


# ---------------------------------------------------------------------------
# AWS Config -- pull non-compliant managed rule evaluations
# ---------------------------------------------------------------------------

MANAGED_CONFIG_RULES = [
    "s3-bucket-public-read-prohibited",
    "restricted-ssh",
    "iam-password-policy",
]


def scan_aws_config_findings(clients, table):
    config = clients["config"]
    found = []

    for rule_name in MANAGED_CONFIG_RULES:
        try:
            paginator = config.get_paginator("get_compliance_details_by_config_rule")
            for page in paginator.paginate(
                ConfigRuleName=rule_name,
                ComplianceTypes=["NON_COMPLIANT"],
            ):
                for result in page.get("EvaluationResults", []):
                    qualifier    = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
                    resource_id  = qualifier["ResourceId"]
                    resource_type = qualifier["ResourceType"]
                    r = build_risk(
                        "cloud-infra", resource_type, resource_id,
                        f"AWS Config Non-Compliant: {rule_name}",
                        f"Resource is non-compliant with Config rule '{rule_name}'.",
                        "High",
                        remediation_steps=[
                            f"Review the resource flagged by Config rule: {rule_name}",
                            "Fix the misconfiguration and re-evaluate the rule",
                        ],
                    )
                    r["source"] = "aws-config"
                    found.append(r)
                    save_risk(table, r)
        except ClientError as e:
            # Rule may not be enabled in this account -- skip silently
            logger.info(f"Config rule '{rule_name}' not available: {e}")

    return found


# ---------------------------------------------------------------------------
# GCP -- GCS buckets + Firewall rules
# Credentials from AWS Secrets Manager (service account JSON key)
# ---------------------------------------------------------------------------

def scan_gcp_resources(table):
    found = []
    if not GCP_SECRET_NAME:
        logger.info("GCP_SECRET_NAME not configured -- skipping GCP scan")
        return found

    try:
        from google.oauth2 import service_account
        from google.cloud import storage as gcs_lib
        import googleapiclient.discovery
    except ImportError:
        logger.error("GCP libraries missing. Add google-cloud-storage and google-api-python-client to requirements.txt")
        return found

    # Fetch service account JSON from Secrets Manager
    try:
        sm = boto3.client("secretsmanager", region_name=REGION)
        secret = sm.get_secret_value(SecretId=GCP_SECRET_NAME)
        sa_info = json.loads(secret["SecretString"])
        project_id = sa_info.get("project_id", "")
    except Exception as e:
        logger.error(f"Failed to load GCP credentials from Secrets Manager '{GCP_SECRET_NAME}': {e}")
        return found

    credentials = service_account.Credentials.from_service_account_info(
        sa_info,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    # GCS bucket scan -- check for public ACLs
    try:
        gcs_client = gcs_lib.Client(credentials=credentials, project=project_id)
        for bucket in gcs_client.list_buckets():
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                public = {"allUsers", "allAuthenticatedUsers"}
                is_public = any(
                    m in binding.get("members", [])
                    for binding in policy.bindings
                    for m in public
                )
                if is_public:
                    r = build_risk(
                        "cloud-infra", "GCS Bucket", bucket.name,
                        "GCP GCS Bucket Publicly Accessible",
                        f"Bucket {bucket.name} grants access to allUsers or allAuthenticatedUsers.",
                        "High",
                        remediation_steps=[
                            "Remove allUsers / allAuthenticatedUsers from the bucket IAM policy",
                            "Enable Uniform Bucket-Level Access to disable legacy ACLs",
                        ],
                        alternative_solutions=["Use signed URLs for time-limited controlled access"],
                        cloud_provider="GCP",
                    )
                    found.append(r)
                    save_risk(table, r)
            except Exception as e:
                logger.warning(f"GCS IAM policy check for {bucket.name}: {e}")
    except Exception as e:
        logger.warning(f"GCS bucket list failed: {e}")

    # GCP Firewall rules -- check for wide-open ingress
    try:
        compute = googleapiclient.discovery.build("compute", "v1", credentials=credentials)
        rules = compute.firewalls().list(project=project_id).execute().get("items", [])
        risky_ports = {"22", "3389"}
        for rule in rules:
            if rule.get("direction") != "INGRESS":
                continue
            if "0.0.0.0/0" not in rule.get("sourceRanges", []):
                continue
            for allowed in rule.get("allowed", []):
                for port in allowed.get("ports", []):
                    if str(port) in risky_ports:
                        r = build_risk(
                            "cloud-infra", "GCP Firewall Rule", rule["name"],
                            "GCP Firewall Open Port to Internet",
                            f"Firewall rule '{rule['name']}' allows port {port} from 0.0.0.0/0.",
                            "High",
                            remediation_steps=[
                                f"Restrict the firewall rule to specific source IP ranges",
                                "Use Identity-Aware Proxy (IAP) instead of open firewall access",
                            ],
                            cloud_provider="GCP",
                        )
                        found.append(r)
                        save_risk(table, r)
    except Exception as e:
        logger.warning(f"GCP firewall scan failed: {e}")

    return found


# ---------------------------------------------------------------------------
# Azure -- Scaffolding for Future Scope
# ---------------------------------------------------------------------------

def scan_azure_resources(table):
    """
    Placeholder for future Azure integration.
    Will check Azure Resource Manager for open ports and public blobs.
    """
    found = []
    logger.info("Azure scanning not yet implemented (v2 scope).")
    return found


# ---------------------------------------------------------------------------
# Graph Topology -- Scaffolding for Future Scope
# ---------------------------------------------------------------------------

def generate_graph_topology():
    """
    Placeholder for future Graph Topology mapping.
    Will map relationships between resources (e.g. S3 -> IAM -> EC2) to
    identify complex attack paths.
    """
    logger.info("Graph topology mapping not yet implemented (v2 scope).")
    return None

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def purge_module_risks(table, module):
    """Delete all existing risk records for this module before a new scan."""
    try:
        resp = table.query(
            IndexName="module-index",
            KeyConditionExpression="module = :m",
            ExpressionAttributeValues={":m": module},
        )
        items = resp.get("Items", [])
        while "LastEvaluatedKey" in resp:
            resp = table.query(
                IndexName="module-index",
                KeyConditionExpression="module = :m",
                ExpressionAttributeValues={":m": module},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))

        with table.batch_writer() as batch:
            for item in items:
                rid = item.get("resourceId")
                rts = item.get("riskTimestamp")
                if rid and rts:
                    batch.delete_item(Key={"resourceId": rid, "riskTimestamp": rts})
        logger.info(f"Purged {len(items)} old risks for module {module}")
    except Exception as e:
        logger.error(f"Failed to purge old risks: {e}")

def lambda_handler(event, context):
    logger.info("cloud-scanner started")
    ddb = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)

    # Accept targetRoleArn from request body for cross-account scanning
    target_role_arn = None
    try:
        body = json.loads(event.get("body") or "{}")
        target_role_arn = body.get("targetRoleArn") or None
    except Exception:
        pass

    if target_role_arn:
        logger.info(f"Cross-account scan requested for role: {target_role_arn}")

    # Purge old risks before scanning
    purge_module_risks(table, "cloud-infra")

    clients = get_aws_clients(role_arn=target_role_arn)
    all_risks = []

    all_risks += scan_s3_buckets(clients, table)
    all_risks += scan_security_groups(clients, table)
    all_risks += scan_iam_password_policy(clients, table)
    all_risks += scan_aws_config_findings(clients, table)
    all_risks += scan_gcp_resources(table)
    all_risks += scan_azure_resources(table)  # Future scope

    generate_graph_topology()  # Future scope

    # Emit ScanCompleted event so EventBridge triggers notification_handler
    emit_scan_completed("cloud-infra", all_risks)

    logger.info(f"Scan complete -- {len(all_risks)} risk(s) found")
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({"message": "Scan complete", "risksFound": len(all_risks)}),
    }
