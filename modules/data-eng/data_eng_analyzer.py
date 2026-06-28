import json
import os
import logging
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

from shared.scan_events import emit_scan_completed
from shared.schemas.risk_record import build_risk_record

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME  = os.environ["DYNAMODB_TABLE"]
# SCAN_REGION overrides the Lambda-injected AWS_REGION so we can scan a
# different region (e.g. us-east-1 resources from an ap-south-1 Lambda).
REGION      = os.environ.get("SCAN_REGION") or os.environ.get("AWS_REGION", "us-east-1")
GLUE_FAIL_THRESHOLD = int(os.environ.get("GLUE_FAIL_THRESHOLD", "2"))
GLUE_RUNS_WINDOW    = int(os.environ.get("GLUE_RUNS_WINDOW", "5"))

# Keywords that suggest sensitive data — based on naming conventions
SENSITIVE_PATTERNS = [
    "user", "customer", "client", "patient", "payment",
    "financial", "pii", "medical", "health", "ssn",
    "credit", "password", "secret", "private", "personal",
]

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}


def is_sensitive_name(name):
    name_lower = name.lower()
    return any(p in name_lower for p in SENSITIVE_PATTERNS)


def build_risk(resource, resource_name, risk_type, risk_reason, priority,
               remediation_steps=None, alternative_solutions=None):
    return build_risk_record(
        module="data-eng",
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
# S3 — public access block + encryption, with sensitivity-based priority
# ---------------------------------------------------------------------------

def scan_s3_data_buckets(s3, table):
    found = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.error(f"list_buckets: {e}")
        return found

    for b in buckets:
        name      = b["Name"]
        sensitive = is_sensitive_name(name)
        priority  = "High" if sensitive else "Medium"
        suffix    = " (sensitive bucket name detected)" if sensitive else ""

        # Public access block
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
                    "Data Storage", name,
                    "Data Bucket Public Access Not Fully Blocked",
                    f"Bucket '{name}' has incomplete public access blocking{suffix}.",
                    priority,
                    remediation_steps=[
                        "Enable all four Block Public Access settings on the bucket",
                        "Audit the bucket policy for any public grants",
                    ],
                    alternative_solutions=[
                        "Move data to a private bucket and access through a backend API",
                        "Use signed URLs for any content that needs to be temporarily shareable",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                r = build_risk(
                    "Data Storage", name,
                    "Data Bucket No Public Access Block",
                    f"No public access block configuration set on bucket '{name}'{suffix}.",
                    priority,
                    remediation_steps=["Enable Block Public Access immediately from the S3 console."],
                )
                found.append(r)
                save_risk(table, r)
            else:
                logger.warning(f"get_public_access_block {name}: {e}")

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                r = build_risk(
                    "Data Storage", name,
                    "Data Bucket Encryption Missing",
                    f"Bucket '{name}' has no server-side encryption configured{suffix}.",
                    priority,
                    remediation_steps=[
                        "Enable SSE-S3 (AES-256) or SSE-KMS in bucket Properties > Default encryption",
                    ],
                    alternative_solutions=[
                        "Apply a bucket policy that denies unencrypted uploads (s3:PutObject without encryption header)",
                    ],
                )
                found.append(r)
                save_risk(table, r)
            else:
                logger.warning(f"get_bucket_encryption {name}: {e}")

    return found


# ---------------------------------------------------------------------------
# DynamoDB — encryption check
# ---------------------------------------------------------------------------

def scan_dynamodb_tables(dynamodb_client, table):
    found = []
    paginator = dynamodb_client.get_paginator("list_tables")
    table_names = []
    try:
        for page in paginator.paginate():
            table_names.extend(page.get("TableNames", []))
    except ClientError as e:
        logger.error(f"list_tables: {e}")
        return found

    for t_name in table_names:
        try:
            desc = dynamodb_client.describe_table(TableName=t_name).get("Table", {})
            sse  = desc.get("SSEDescription", {})
            # DISABLED means no SSE — AWS-owned key by default exists for new tables
            # but older tables or explicitly-disabled ones show DISABLED
            if sse.get("Status") == "DISABLED":
                r = build_risk(
                    "DynamoDB Table", t_name,
                    "DynamoDB Table Encryption Disabled",
                    f"Table '{t_name}' has server-side encryption explicitly disabled. "
                    "This does not meet GDPR or HIPAA encryption requirements.",
                    "Medium",
                    remediation_steps=[
                        "Enable SSE using an AWS-managed or customer-managed KMS key",
                        "In the DynamoDB console: Table > Additional settings > Encryption",
                    ],
                    alternative_solutions=[
                        "Migrate data to a new table with encryption enabled from the start",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"describe_table {t_name}: {e}")

    return found


# ---------------------------------------------------------------------------
# Glue — repeated ETL job failures
# ---------------------------------------------------------------------------

def scan_glue_jobs(glue, table):
    found = []
    try:
        jobs = glue.get_jobs().get("Jobs", [])
    except ClientError as e:
        logger.error(f"get_jobs: {e}")
        return found

    for job in jobs:
        job_name = job["Name"]
        try:
            runs = glue.get_job_runs(
                JobName=job_name,
                MaxResults=GLUE_RUNS_WINDOW,
            ).get("JobRuns", [])

            failures = sum(1 for r in runs if r.get("JobRunState") == "FAILED")
            if failures >= GLUE_FAIL_THRESHOLD:
                last_error = ""
                for run in runs:
                    if run.get("JobRunState") == "FAILED":
                        last_error = run.get("ErrorMessage", "")
                        break

                r = build_risk(
                    "Glue ETL Job", job_name,
                    "Repeated ETL Job Failures",
                    f"Job '{job_name}' failed {failures} time(s) in its last {len(runs)} run(s). "
                    f"Last error: {last_error[:200] if last_error else 'no message'}.",
                    "High",
                    remediation_steps=[
                        "Check Glue job logs in CloudWatch for the specific error message",
                        "Verify the source data format and S3 path are correct",
                        "Review IAM permissions on the Glue job role",
                    ],
                    alternative_solutions=[
                        "Add retry logic to the Glue job (set max retries > 0)",
                        "Set up a CloudWatch alarm on the Glue job failure metric",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"get_job_runs {job_name}: {e}")

    return found


# ---------------------------------------------------------------------------
# S3 — versioning & access logging
# ---------------------------------------------------------------------------

def scan_s3_versioning_logging(s3, table):
    found = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.error(f"list_buckets (versioning/logging scan): {e}")
        return found

    for b in buckets:
        name      = b["Name"]
        sensitive = is_sensitive_name(name)
        suffix    = " (sensitive bucket name detected)" if sensitive else ""

        # --- Versioning ---
        try:
            ver_resp = s3.get_bucket_versioning(Bucket=name)
            if ver_resp.get("Status") != "Enabled":
                priority = "High" if sensitive else "Medium"
                r = build_risk(
                    "Data Storage", name,
                    "Data Bucket Versioning Disabled",
                    f"Bucket '{name}' does not have versioning enabled{suffix}. "
                    "Without versioning, accidental deletions or overwrites cannot be recovered.",
                    priority,
                    remediation_steps=[
                        "Enable versioning in S3 > Bucket > Properties > Bucket Versioning",
                    ],
                    alternative_solutions=[
                        "Enable S3 Object Lock for WORM (write-once-read-many) protection on critical buckets",
                        "Set up cross-region replication as an additional durability layer",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"get_bucket_versioning {name}: {e}")

        # --- Access Logging ---
        try:
            log_resp = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in log_resp:
                priority = "High" if sensitive else "Low"
                r = build_risk(
                    "Data Storage", name,
                    "Data Bucket Access Logging Disabled",
                    f"Bucket '{name}' does not have server access logging enabled{suffix}. "
                    "Access logs are essential for auditing and incident investigation.",
                    priority,
                    remediation_steps=[
                        "Enable server access logging for audit trail",
                        "In S3 console: Bucket > Properties > Server access logging > Enable",
                    ],
                    alternative_solutions=[
                        "Use AWS CloudTrail S3 data events as an alternative audit mechanism",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"get_bucket_logging {name}: {e}")

    return found


# ---------------------------------------------------------------------------
# DynamoDB — Point-in-Time Recovery (PITR)
# ---------------------------------------------------------------------------

def scan_dynamodb_pitr(dynamodb_client, table):
    found = []
    paginator = dynamodb_client.get_paginator("list_tables")
    table_names = []
    try:
        for page in paginator.paginate():
            table_names.extend(page.get("TableNames", []))
    except ClientError as e:
        logger.error(f"list_tables (PITR scan): {e}")
        return found

    for t_name in table_names:
        try:
            resp = dynamodb_client.describe_continuous_backups(TableName=t_name)
            cb   = resp.get("ContinuousBackupsDescription", {})
            cb_status   = cb.get("ContinuousBackupsStatus", "DISABLED")
            pitr_desc   = cb.get("PointInTimeRecoveryDescription", {})
            pitr_status = pitr_desc.get("PointInTimeRecoveryStatus", "DISABLED")

            if cb_status != "ENABLED" or pitr_status != "ENABLED":
                r = build_risk(
                    "DynamoDB Table", t_name,
                    "DynamoDB Point-in-Time Recovery Not Enabled",
                    f"Table '{t_name}' does not have Point-in-Time Recovery (PITR) enabled "
                    f"(ContinuousBackupsStatus={cb_status}, PointInTimeRecoveryStatus={pitr_status}). "
                    "Without PITR, accidental writes or deletes cannot be rolled back.",
                    "Medium",
                    remediation_steps=[
                        "Enable PITR in DynamoDB > Table > Backups > Point-in-time recovery",
                    ],
                    alternative_solutions=[
                        "Schedule on-demand DynamoDB backups via AWS Backup as a supplemental measure",
                    ],
                )
                found.append(r)
                save_risk(table, r)
        except ClientError as e:
            logger.warning(f"describe_continuous_backups {t_name}: {e}")

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
    logger.info("data-eng-analyzer started")
    ddb          = boto3.resource("dynamodb", region_name=REGION)
    table        = ddb.Table(TABLE_NAME)
    s3           = boto3.client("s3",       region_name=REGION)
    ddb_client   = boto3.client("dynamodb", region_name=REGION)
    glue         = boto3.client("glue",     region_name=REGION)

    purge_module_risks(table, "data-eng")

    all_risks = []
    all_risks += scan_s3_data_buckets(s3, table)
    all_risks += scan_dynamodb_tables(ddb_client, table)
    all_risks += scan_glue_jobs(glue, table)
    all_risks += scan_s3_versioning_logging(s3, table)
    all_risks += scan_dynamodb_pitr(ddb_client, table)

    emit_scan_completed("data-eng", all_risks)

    logger.info(f"data-eng scan complete — {len(all_risks)} risk(s)")
    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"message": "Data Engineering scan complete", "risksFound": len(all_risks)}),
    }
