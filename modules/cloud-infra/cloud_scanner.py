import json
import os
import logging
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from shared.scan_events import emit_scan_completed
from shared.schemas.risk_record import build_risk_record

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

def build_risk(*args, **kwargs):
    # This acts as a facade over the shared schema so we don't have to change the call sites
    return build_risk_record(*args, **kwargs)


# ---------------------------------------------------------------------------
# CloudWatch helper -- write scan timing metrics for benchmarking (paper Table II)
# ---------------------------------------------------------------------------

def _write_cloudwatch_metric(metric_name, value_ms, module="cloud-infra"):
    """Write a duration metric to CloudWatch namespace CloudSentinel/Performance."""
    try:
        cw = boto3.client("cloudwatch", region_name=REGION)
        cw.put_metric_data(
            Namespace="CloudSentinel/Performance",
            MetricData=[{
                "MetricName": metric_name,
                "Dimensions":  [{"Name": "Module", "Value": module}],
                "Value":       value_ms,
                "Unit":        "Milliseconds",
            }],
        )
    except Exception as e:
        logger.warning(f"CloudWatch metric write failed (non-fatal): {e}")


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
            # IPv6 check -- ::/0 is also fully open to the internet
            for cidr6 in rule.get("Ipv6Ranges", []):
                if cidr6.get("CidrIpv6") != "::/0":
                    continue
                for port, label in watch_ports.items():
                    if from_p <= port <= to_p:
                        r = build_risk(
                            "cloud-infra", "EC2 Security Group", sg_name,
                            f"Security Group Open {label} to Internet (IPv6)",
                            f"Security group {sg_name} allows inbound {label} (port {port}) from ::/0 (all IPv6 addresses).",
                            "High",
                            remediation_steps=[
                                f"Restrict port {port} to specific trusted IPv6 ranges",
                                "Use AWS Systems Manager Session Manager instead of open SSH",
                            ],
                            alternative_solutions=[
                                "Place EC2 instances behind a bastion host",
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
# AWS -- IAM Root Account MFA (Critical severity)
# ---------------------------------------------------------------------------

def scan_root_mfa(clients, table):
    """Critical -- root account must always have MFA enabled.
    Root compromise gives an attacker unrestricted, unaudited access to all AWS resources.
    """
    iam = clients["iam"]
    found = []
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            r = build_risk(
                "cloud-infra", "IAM", "root-account",
                "Root Account MFA Not Enabled",
                "The AWS root account does not have multi-factor authentication enabled. "
                "Root compromise gives an attacker unrestricted access to all AWS resources "
                "including billing, IAM, and all services.",
                "Critical",
                remediation_steps=[
                    "Sign in as root user → My Security Credentials → Activate MFA",
                    "Use a hardware MFA token (YubiKey) or virtual MFA (Google Authenticator)",
                    "Never use root credentials for day-to-day operations",
                    "Create an IAM admin user with least-privilege permissions instead",
                ],
                alternative_solutions=[
                    "Enable AWS Organizations SCP to mandate MFA for all member accounts",
                    "Use AWS IAM Identity Center (SSO) and disable root login entirely",
                ],
            )
            found.append(r)
            save_risk(table, r)
    except ClientError as e:
        logger.warning(f"get_account_summary: {e}")
    return found


# ---------------------------------------------------------------------------
# AWS Config -- pull non-compliant managed rule evaluations
# ---------------------------------------------------------------------------

MANAGED_CONFIG_RULES = [
    "s3-bucket-public-read-prohibited",
    "restricted-ssh",
    "iam-password-policy",
    "cloudtrail-enabled",
    "ebs-optimized-instance",
    "rds-instance-public-access-check",
    "iam-root-access-key-check",
    "mfa-enabled-for-iam-console-access",
    "s3-bucket-server-side-encryption-enabled",
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
# AWS -- IAM Users: Access Key Rotation & Console MFA
# ---------------------------------------------------------------------------

def scan_iam_users(clients, table):
    """Check IAM users for:
    - Access keys older than 90 days (High)
    - Console access (LoginProfile) without MFA (High)
    """
    iam = clients["iam"]
    found = []
    KEY_MAX_AGE_DAYS = 90

    try:
        users = iam.list_users().get("Users", [])
    except ClientError as e:
        logger.warning(f"list_users: {e}")
        return found

    for user in users:
        username = user["UserName"]

        # --- Access key age check ---
        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key.get("Status") != "Active":
                    continue
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age_days > KEY_MAX_AGE_DAYS:
                    r = build_risk(
                        "cloud-infra", "IAM User", username,
                        "IAM Access Key Not Rotated",
                        f"Access key {key['AccessKeyId']} for user '{username}' is {age_days} days old "
                        f"(threshold: {KEY_MAX_AGE_DAYS} days).",
                        "High",
                        remediation_steps=[
                            f"Rotate or delete the old access key for IAM user '{username}'",
                            "Create a new access key, update applications, then deactivate the old key",
                            "Enable IAM Access Analyzer to monitor key usage",
                        ],
                        alternative_solutions=[
                            "Use IAM roles instead of long-lived access keys wherever possible",
                            "Enforce key rotation via AWS Config rule 'access-keys-rotated'",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)
        except ClientError as e:
            logger.warning(f"list_access_keys for '{username}': {e}")

        # --- Console access without MFA check ---
        has_console = False
        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                logger.warning(f"get_login_profile for '{username}': {e}")

        if has_console:
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfa_devices:
                    r = build_risk(
                        "cloud-infra", "IAM User", username,
                        "IAM User Console Access Without MFA",
                        f"IAM user '{username}' has AWS Console access but no MFA device configured.",
                        "High",
                        remediation_steps=[
                            f"Require MFA for IAM user '{username}' via IAM > Users > Security credentials",
                            "Attach an IAM policy that enforces MFA (aws:MultiFactorAuthPresent condition)",
                            "Consider migrating users to AWS IAM Identity Center (SSO) with MFA enforced",
                        ],
                        alternative_solutions=[
                            "Enable the 'mfa-enabled-for-iam-console-access' AWS Config rule",
                            "Use AWS Organizations SCP to deny console access without MFA",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)
            except ClientError as e:
                logger.warning(f"list_mfa_devices for '{username}': {e}")

    return found


# ---------------------------------------------------------------------------
# AWS -- S3 Versioning & Access Logging
# ---------------------------------------------------------------------------

def scan_s3_logging_versioning(clients, table):
    """Check each S3 bucket for:
    - Versioning not enabled (Medium)
    - Access logging not enabled (Low)
    """
    s3 = clients["s3"]
    found = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.warning(f"list_buckets (versioning/logging scan): {e}")
        return found

    for b in buckets:
        name = b["Name"]

        # --- Versioning check ---
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                r = build_risk(
                    "cloud-infra", "S3 Bucket", name,
                    "S3 Bucket Versioning Disabled",
                    f"S3 bucket '{name}' does not have versioning enabled. "
                    "Accidental deletions or overwrites cannot be recovered.",
                    "Medium",
                    remediation_steps=[
                        f"Enable versioning on bucket '{name}' via S3 > Bucket > Properties > Bucket Versioning",
                        "Enable MFA Delete for additional protection on versioned objects",
                    ],
                    alternative_solutions=[
                        "Use S3 Replication with versioning for cross-region durability",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"get_bucket_versioning for '{name}': {e}")

        # --- Access logging check ---
        try:
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                r = build_risk(
                    "cloud-infra", "S3 Bucket", name,
                    "S3 Bucket Access Logging Disabled",
                    f"S3 bucket '{name}' does not have server access logging enabled. "
                    "Access activity cannot be audited.",
                    "Low",
                    remediation_steps=[
                        f"Enable server access logging on bucket '{name}' via S3 > Bucket > Properties > Server access logging",
                        "Specify a target bucket and prefix for log delivery",
                    ],
                    alternative_solutions=[
                        "Use AWS CloudTrail data events for S3 object-level API logging",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"get_bucket_logging for '{name}': {e}")

    return found


# ---------------------------------------------------------------------------
# AWS -- CloudTrail Enabled
# ---------------------------------------------------------------------------

def scan_cloudtrail(clients, table):
    """Check whether CloudTrail is enabled and actively logging (Critical if not)."""
    found = []
    try:
        cloudtrail = boto3.client("cloudtrail", region_name=REGION)
        trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            r = build_risk(
                "cloud-infra", "CloudTrail", "account-level",
                "CloudTrail Not Enabled",
                "No CloudTrail trails are configured in this region. "
                "All API activity is unaudited and cannot be investigated after a security incident.",
                "Critical",
                remediation_steps=[
                    "Create a CloudTrail trail in the AWS console: CloudTrail > Create trail",
                    "Enable logging to an S3 bucket with server-side encryption",
                    "Enable CloudWatch Logs integration for real-time alerting",
                ],
                alternative_solutions=[
                    "Use an organization-level trail in AWS Organizations to cover all member accounts",
                ],
            )
            found.append(r)
            save_risk(table, r)
        else:
            for trail in trails:
                trail_arn = trail.get("TrailARN", trail.get("Name", "unknown"))
                try:
                    status = cloudtrail.get_trail_status(Name=trail_arn)
                    if not status.get("IsLogging", False):
                        r = build_risk(
                            "cloud-infra", "CloudTrail", trail.get("Name", trail_arn),
                            "CloudTrail Not Enabled",
                            f"CloudTrail trail '{trail.get('Name', trail_arn)}' exists but is not actively logging. "
                            "API events are not being captured.",
                            "Critical",
                            remediation_steps=[
                                f"Start logging for trail '{trail.get('Name')}' via the CloudTrail console or CLI: "
                                "aws cloudtrail start-logging --name <trail-name>",
                                "Verify the S3 bucket policy allows CloudTrail to write logs",
                            ],
                            alternative_solutions=[
                                "Set up an EventBridge rule to alert when CloudTrail logging is stopped",
                            ],
                        )
                        found.append(r)
                        save_risk(table, r)
                except ClientError as e:
                    logger.warning(f"get_trail_status for '{trail_arn}': {e}")
    except ClientError as e:
        logger.warning(f"describe_trails: {e}")

    return found


# ---------------------------------------------------------------------------
# AWS -- EBS Volume Encryption
# ---------------------------------------------------------------------------

def scan_ebs_encryption(clients, table):
    """Check all EBS volumes for encryption-at-rest (Medium if unencrypted)."""
    ec2 = clients["ec2"]
    found = []

    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                if not volume.get("Encrypted", False):
                    vol_id = volume["VolumeId"]
                    r = build_risk(
                        "cloud-infra", "EBS Volume", vol_id,
                        "EBS Volume Not Encrypted",
                        f"EBS volume '{vol_id}' is not encrypted at rest. "
                        "Data stored on this volume is vulnerable if the underlying hardware is compromised.",
                        "Medium",
                        remediation_steps=[
                            f"Create an encrypted snapshot of volume '{vol_id}' and restore it as an encrypted volume",
                            "Enable EBS default encryption for the account: EC2 > Settings > EBS Encryption",
                            "Replace the unencrypted volume with an encrypted one and update the instance attachment",
                        ],
                        alternative_solutions=[
                            "Enable EBS default encryption to ensure all future volumes are encrypted automatically",
                            "Use KMS customer-managed keys (CMK) for additional control over encryption",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)
    except ClientError as e:
        logger.warning(f"describe_volumes: {e}")

    return found


# ---------------------------------------------------------------------------
# AWS -- RDS Public Accessibility
# ---------------------------------------------------------------------------

def scan_rds_public(clients, table):
    """Check RDS DB instances for public accessibility (High if publicly accessible)."""
    found = []
    try:
        rds = boto3.client("rds", region_name=REGION)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                if instance.get("PubliclyAccessible", False):
                    db_id = instance["DBInstanceIdentifier"]
                    engine = instance.get("Engine", "unknown")
                    r = build_risk(
                        "cloud-infra", "RDS Instance", db_id,
                        "RDS Instance Publicly Accessible",
                        f"RDS instance '{db_id}' (engine: {engine}) is publicly accessible from the internet. "
                        "Database endpoints should never be exposed publicly.",
                        "High",
                        remediation_steps=[
                            f"Modify the RDS instance '{db_id}': disable 'Publicly Accessible' in the connectivity settings",
                            "Place the RDS instance in a private subnet with no internet gateway route",
                            "Use a bastion host or AWS Systems Manager Session Manager for database access",
                        ],
                        alternative_solutions=[
                            "Use RDS Proxy to manage connections without exposing the database endpoint",
                            "Enable VPC security groups to restrict inbound access to known application IPs only",
                        ],
                    )
                    found.append(r)
                    save_risk(table, r)
    except ClientError as e:
        logger.warning(f"describe_db_instances: {e}")

    return found


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def purge_module_risks(table, module):
    """Delete all existing risk records for this module before a new scan."""
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
        logger.info(f"Purged {len(items)} old risks for module {module}")
    except Exception as e:
        logger.error(f"Failed to purge old risks: {e}")

def lambda_handler(event, context):
    _start = time.time()
    logger.info("cloud-scanner started")
    ddb = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)

    # Accept targetRoleArn and providers from request body
    target_role_arn = None
    providers = ["aws", "gcp"]  # default to both if not specified
    try:
        body = json.loads(event.get("body") or "{}")
        target_role_arn = body.get("targetRoleArn") or None
        if "providers" in body:
            providers = body["providers"]
    except Exception:
        pass

    if target_role_arn:
        logger.info(f"Cross-account scan requested for role: {target_role_arn}")

    # Purge old risks before scanning
    purge_module_risks(table, "cloud-infra")

    all_risks = []

    if "aws" in providers:
        clients = get_aws_clients(role_arn=target_role_arn)
        all_risks += scan_root_mfa(clients, table)           # Critical severity check
        all_risks += scan_s3_buckets(clients, table)
        all_risks += scan_security_groups(clients, table)
        all_risks += scan_iam_password_policy(clients, table)
        all_risks += scan_iam_users(clients, table)
        all_risks += scan_s3_logging_versioning(clients, table)
        all_risks += scan_cloudtrail(clients, table)
        all_risks += scan_ebs_encryption(clients, table)
        all_risks += scan_rds_public(clients, table)
        # Re-enable Config with expanded rules
        all_risks += scan_aws_config_findings(clients, table)

    if "gcp" in providers:
        all_risks += scan_gcp_resources(table)

    # Azure scanning is future scope (v2) — only call if provider explicitly requested
    if "azure" in providers:
        all_risks += scan_azure_resources(table)

    # Emit ScanCompleted event so EventBridge triggers notification_handler
    emit_scan_completed("cloud-infra", all_risks)

    # Record execution timing for benchmarking (paper Table II)
    duration_ms = int((time.time() - _start) * 1000)
    _write_cloudwatch_metric("ScanDurationMs", duration_ms, module="cloud-infra")
    logger.info(f"Scan complete -- {len(all_risks)} risk(s) in {duration_ms}ms")

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
        },
        "body": json.dumps({
            "message":    "Scan complete",
            "risksFound": len(all_risks),
            "module":     "cloud-infra",
            "durationMs": duration_ms,
        }),
    }

