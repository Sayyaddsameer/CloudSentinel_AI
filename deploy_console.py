"""
deploy_console.py — CloudSentinel console-based deployer (no Terraform required).

Usage:
    python deploy_console.py
    python deploy_console.py --dry-run

Configuration:
    Set the variables below via a deploy.env file or environment variables
    prefixed with CS_*. The script prompts for any missing required values.
"""

import argparse
import json
import logging
import os
import sys
import time
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cloudsentinel-deploy")

# ---------------------------------------------------------------------------
# Project root (script lives at repo root)
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.resolve()
MODULES_DIR = ROOT / "modules" / "cloud-infra"
IAM_POLICY   = ROOT / "infrastructure" / "iam" / "lambda_policy.json"

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

def _load_env_file(path: Path) -> None:
    """Load key=value pairs from a deploy.env file into os.environ."""
    if not path.exists():
        return
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


def _require(env_key: str, prompt: str, secret: bool = False) -> str:
    value = os.environ.get(env_key, "").strip()
    if not value:
        try:
            import getpass
            value = getpass.getpass(f"  {prompt}: ") if secret else input(f"  {prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            log.error("Aborted by user.")
            sys.exit(1)
    if not value:
        log.error("Required value '%s' was not provided. Aborting.", env_key)
        sys.exit(1)
    return value


def load_config() -> dict:
    _load_env_file(ROOT / "deploy.env")

    log.info("Loading deployment configuration ...")
    cfg = {
        "region":                 os.environ.get("CS_REGION", "us-east-1"),
        "project":                os.environ.get("CS_PROJECT", "cloudsentinel"),
        "environment":            os.environ.get("CS_ENVIRONMENT", "dev"),
        "alert_email":            _require("CS_ALERT_EMAIL",           "Alert email address"),
        "app_url":                os.environ.get("CS_APP_URL", ""),
        "bedrock_model_id":       os.environ.get("CS_BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0"),
        "notification_threshold": os.environ.get("CS_NOTIFICATION_THRESHOLD", "High"),
        "max_tokens":             os.environ.get("CS_MAX_TOKENS", "400"),
        "max_risks_per_run":      os.environ.get("CS_MAX_RISKS_PER_RUN", "50"),
        "risks_page_limit":       os.environ.get("CS_RISKS_PAGE_LIMIT", "100"),
        "chatbot_context_risks":  os.environ.get("CS_CHATBOT_CONTEXT_RISKS", "20"),
        "gcp_secret_name":        os.environ.get("CS_GCP_SECRET_NAME", ""),
        "target_role_arn":        os.environ.get("CS_TARGET_ROLE_ARN", ""),
    }
    return cfg


# ---------------------------------------------------------------------------
# Dry-run wrapper
# ---------------------------------------------------------------------------

class Step:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run

    def run(self, description: str, fn, *args, **kwargs):
        if self.dry_run:
            log.info("[DRY-RUN] %s", description)
            return None
        log.info("%s", description)
        return fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# Deployment steps
# ---------------------------------------------------------------------------

def create_dynamodb_table(ddb, cfg: dict, step: Step) -> str:
    table_name = f"{cfg['project']}-risks"

    def _create():
        try:
            ddb.create_table(
                TableName=table_name,
                BillingMode="PAY_PER_REQUEST",
                KeySchema=[
                    {"AttributeName": "resourceId",    "KeyType": "HASH"},
                    {"AttributeName": "riskTimestamp", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "resourceId",    "AttributeType": "S"},
                    {"AttributeName": "riskTimestamp", "AttributeType": "S"},
                    {"AttributeName": "module",        "AttributeType": "S"},
                    {"AttributeName": "riskPriority",  "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "module-index",
                        "KeySchema": [
                            {"AttributeName": "module",        "KeyType": "HASH"},
                            {"AttributeName": "riskTimestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                    {
                        "IndexName": "priority-index",
                        "KeySchema": [
                            {"AttributeName": "riskPriority",  "KeyType": "HASH"},
                            {"AttributeName": "riskTimestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    },
                ],
                Tags=[
                    {"Key": "Project",     "Value": cfg["project"]},
                    {"Key": "Environment", "Value": cfg["environment"]},
                    {"Key": "ManagedBy",   "Value": "deploy_console.py"},
                ],
            )
            waiter = ddb.meta.client.get_waiter("table_exists")
            waiter.wait(TableName=table_name)
            log.info("DynamoDB table '%s' is active.", table_name)
        except ddb.meta.client.exceptions.ResourceInUseException:
            log.info("DynamoDB table '%s' already exists — skipping.", table_name)

    step.run(f"Create DynamoDB table: {table_name}", _create)
    return table_name


def create_s3_bucket(s3, account_id: str, cfg: dict, step: Step) -> str:
    bucket_name = f"{cfg['project']}-artifacts-{account_id}"
    region      = cfg["region"]

    def _create():
        try:
            kwargs = {"Bucket": bucket_name}
            if region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
            s3.create_bucket(**kwargs)
        except s3.exceptions.BucketAlreadyOwnedByYou:
            log.info("S3 bucket '%s' already exists — skipping creation.", bucket_name)

        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        log.info("S3 bucket '%s' configured: private, versioned, encrypted.", bucket_name)

    step.run(f"Create S3 artifacts bucket: {bucket_name}", _create)
    return bucket_name


def create_iam_role(iam, cfg: dict, step: Step) -> str:
    role_name   = f"{cfg['project']}-lambda-role"
    policy_text = IAM_POLICY.read_text()

    def _create():
        assume = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect":    "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action":    "sts:AssumeRole",
            }],
        })
        try:
            resp = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume,
                Description="CloudSentinel shared Lambda execution role",
                Tags=[
                    {"Key": "Project",     "Value": cfg["project"]},
                    {"Key": "Environment", "Value": cfg["environment"]},
                ],
            )
            role_arn = resp["Role"]["Arn"]
        except iam.exceptions.EntityAlreadyExistsException:
            role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
            log.info("IAM role '%s' already exists — skipping creation.", role_name)

        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{cfg['project']}-lambda-inline",
            PolicyDocument=policy_text,
        )
        time.sleep(10)  # allow IAM propagation before Lambda creation
        return role_arn

    return step.run(f"Create IAM role: {role_name}", _create) or f"arn:aws:iam::000000000000:role/{role_name}"


def create_cognito(cognito_idp, cfg: dict, step: Step) -> tuple:
    pool_name = f"{cfg['project']}-users"

    def _create():
        pool = cognito_idp.create_user_pool(
            PoolName=pool_name,
            Policies={"PasswordPolicy": {
                "MinimumLength":                 8,
                "RequireUppercase":              True,
                "RequireNumbers":                True,
                "RequireSymbols":                False,
                "TemporaryPasswordValidityDays": 7,
            }},
            AutoVerifiedAttributes=["email"],
            UsernameAttributes=["email"],
            UserPoolTags={"Project": cfg["project"], "Environment": cfg["environment"]},
        )
        pool_id = pool["UserPool"]["Id"]

        client = cognito_idp.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=f"{cfg['project']}-web-client",
            GenerateSecret=False,
            ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            PreventUserExistenceErrors="ENABLED",
        )
        client_id = client["UserPoolClient"]["ClientId"]
        log.info("Cognito pool '%s' created: %s", pool_name, pool_id)
        return pool_id, client_id

    result = step.run(f"Create Cognito User Pool: {pool_name}", _create)
    return result if result else ("dry-run-pool-id", "dry-run-client-id")


def _zip_lambda(source_file: Path, zip_path: Path) -> Path:
    """Package a single Python file plus all *.py in its directory into a ZIP."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for py_file in source_file.parent.glob("*.py"):
            zf.write(py_file, py_file.name)
    return zip_path


def _upsert_lambda(lmb, function_name: str, zip_bytes: bytes, handler: str,
                   role_arn: str, timeout: int, memory: int,
                   env_vars: dict, tags: dict) -> str:
    try:
        lmb.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler=handler,
            Code={"ZipFile": zip_bytes},
            Timeout=timeout,
            MemorySize=memory,
            Environment={"Variables": env_vars},
            Tags=tags,
        )
        log.info("Lambda '%s' created.", function_name)
    except lmb.exceptions.ResourceConflictException:
        lmb.update_function_code(FunctionName=function_name, ZipFile=zip_bytes)
        waiter = lmb.get_waiter("function_updated")
        waiter.wait(FunctionName=function_name)
        
        lmb.update_function_configuration(
            FunctionName=function_name,
            Handler=handler,
            Timeout=timeout,
            MemorySize=memory,
            Environment={"Variables": env_vars},
        )
        log.info("Lambda '%s' updated.", function_name)

    waiter = lmb.get_waiter("function_updated")
    waiter.wait(FunctionName=function_name)
    return lmb.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]


def create_lambdas(lmb, cfg: dict, table_name: str, role_arn: str,
                   sns_topic_arn: str, step: Step) -> dict:
    project = cfg["project"]
    tags    = {"Project": project, "Environment": cfg["environment"], "ManagedBy": "deploy_console.py"}

    zip_path = MODULES_DIR / "_deploy_package.zip"
    _zip_lambda(MODULES_DIR / "cloud_scanner.py", zip_path)
    zip_bytes = zip_path.read_bytes()

    lambdas_def = [
        {
            "name":    f"{project}-cloud-scanner",
            "handler": "cloud_scanner.lambda_handler",
            "timeout": 300, "memory": 256,
            "env": {
                "DYNAMODB_TABLE":  table_name,
                "GCP_SECRET_NAME": cfg["gcp_secret_name"],
                "TARGET_ROLE_ARN": cfg["target_role_arn"],
            },
        },
        {
            "name":    f"{project}-ai-explainer",
            "handler": "ai_explainer.lambda_handler",
            "timeout": 300, "memory": 256,
            "env": {
                "DYNAMODB_TABLE":    table_name,
                "BEDROCK_MODEL_ID":  cfg["bedrock_model_id"],
                "MAX_TOKENS":        cfg["max_tokens"],
                "MAX_RISKS_PER_RUN": cfg["max_risks_per_run"],
            },
        },
        {
            "name":    f"{project}-chatbot-handler",
            "handler": "chatbot_handler.lambda_handler",
            "timeout": 60, "memory": 256,
            "env": {
                "DYNAMODB_TABLE":      table_name,
                "BEDROCK_MODEL_ID":    cfg["bedrock_model_id"],
                "MAX_TOKENS":          cfg["max_tokens"],
                "CHATBOT_CONTEXT_RISKS": cfg["chatbot_context_risks"],
            },
        },
        {
            "name":    f"{project}-risk-reader",
            "handler": "risk_reader.lambda_handler",
            "timeout": 30, "memory": 128,
            "env": {
                "DYNAMODB_TABLE":  table_name,
                "RISKS_PAGE_LIMIT": cfg["risks_page_limit"],
            },
        },
        {
            "name":    f"{project}-notification-handler",
            "handler": "notification_handler.lambda_handler",
            "timeout": 30, "memory": 256,
            "env": {
                "DYNAMODB_TABLE":         table_name,
                "SNS_TOPIC_ARN":          sns_topic_arn,
                "NOTIFICATION_THRESHOLD": cfg["notification_threshold"],
                "APP_URL":                cfg["app_url"],
            },
        },
    ]

    arns = {}
    for ld in lambdas_def:
        def _deploy(ld=ld):
            return _upsert_lambda(
                lmb, ld["name"], zip_bytes, ld["handler"],
                role_arn, ld["timeout"], ld["memory"], ld["env"], tags,
            )
        arn = step.run(f"Deploy Lambda: {ld['name']}", _deploy)
        arns[ld["name"]] = arn or f"arn:aws:lambda:{cfg['region']}:000000000000:function:{ld['name']}"

    zip_path.unlink(missing_ok=True)
    return arns


def create_sns_topic(sns_client, cfg: dict, step: Step) -> str:
    topic_name = f"{cfg['project']}-alerts"

    def _create():
        resp = sns_client.create_topic(
            Name=topic_name,
            Tags=[
                {"Key": "Project",     "Value": cfg["project"]},
                {"Key": "Environment", "Value": cfg["environment"]},
            ],
        )
        arn = resp["TopicArn"]
        sns_client.subscribe(TopicArn=arn, Protocol="email", Endpoint=cfg["alert_email"])
        log.info("SNS topic '%s' created. Subscription confirmation sent to '%s'.",
                 topic_name, cfg["alert_email"])
        return arn

    return step.run(f"Create SNS topic: {topic_name}", _create) or "arn:aws:sns:us-east-1:000000000000:dry-run"


def create_api_gateway(apigw, lmb, account_id: str, cfg: dict,
                       lambda_arns: dict, step: Step) -> str:
    project = cfg["project"]
    region  = cfg["region"]

    def _create():
        api = apigw.create_rest_api(
            name=f"{project}-api",
            description="CloudSentinel multi-module API",
            endpointConfiguration={"types": ["REGIONAL"]},
            tags={"Project": project},
        )
        api_id    = api["id"]
        root_id   = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

        routes = [
            ("risks",      "GET",  f"{project}-risk-reader"),
            ("chat",       "POST", f"{project}-chatbot-handler"),
            ("scan-cloud", "POST", f"{project}-cloud-scanner"),
        ]

        for path_part, method, fn_name in routes:
            resource = apigw.create_resource(
                restApiId=api_id, parentId=root_id, pathPart=path_part
            )
            resource_id = resource["id"]
            fn_arn = lambda_arns[fn_name]

            apigw.put_method(
                restApiId=api_id, resourceId=resource_id,
                httpMethod=method, authorizationType="NONE",
            )
            apigw.put_integration(
                restApiId=api_id, resourceId=resource_id,
                httpMethod=method, integrationHttpMethod="POST",
                type="AWS_PROXY",
                uri=f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations",
            )
            try:
                lmb.add_permission(
                    FunctionName=fn_name,
                    StatementId=f"AllowAPIGW-{path_part}-{method}",
                    Action="lambda:InvokeFunction",
                    Principal="apigateway.amazonaws.com",
                    SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*",
                )
            except lmb.exceptions.ResourceConflictException:
                pass

            # --- CORS preflight (OPTIONS) ---
            try:
                apigw.put_method(
                    restApiId=api_id, resourceId=resource_id,
                    httpMethod="OPTIONS", authorizationType="NONE",
                )
            except apigw.exceptions.ConflictException:
                pass
            apigw.put_integration(
                restApiId=api_id, resourceId=resource_id,
                httpMethod="OPTIONS", type="MOCK",
                requestTemplates={"application/json": '{"statusCode":200}'},
            )
            apigw.put_method_response(
                restApiId=api_id, resourceId=resource_id,
                httpMethod="OPTIONS", statusCode="200",
                responseParameters={
                    "method.response.header.Access-Control-Allow-Headers": False,
                    "method.response.header.Access-Control-Allow-Methods": False,
                    "method.response.header.Access-Control-Allow-Origin":  False,
                },
            )
            apigw.put_integration_response(
                restApiId=api_id, resourceId=resource_id,
                httpMethod="OPTIONS", statusCode="200",
                responseParameters={
                    "method.response.header.Access-Control-Allow-Headers": "'Content-Type,Authorization,X-Amz-Date,X-Api-Key'",
                    "method.response.header.Access-Control-Allow-Methods": f"'{method},OPTIONS'",
                    "method.response.header.Access-Control-Allow-Origin":  "'*'",
                },
            )

        deployment = apigw.create_deployment(restApiId=api_id)
        apigw.create_stage(
            restApiId=api_id,
            deploymentId=deployment["id"],
            stageName="dev",
            tags={"Project": project},
        )
        url = f"https://{api_id}.execute-api.{region}.amazonaws.com/dev"
        log.info("API Gateway deployed: %s", url)
        return url

    return step.run(f"Create API Gateway: {project}-api", _create) or "https://dry-run.execute-api.us-east-1.amazonaws.com/dev"


def create_cfn_template_bucket(s3, account_id: str, cfg: dict, step: Step) -> str:
    """Create the S3 bucket that hosts the scanner-role.yaml CloudFormation template
    and upload the template so users can deploy cross-account roles with one click."""
    cfn_bucket = f"{cfg['project']}-cf-templates-{account_id}"
    template_src = ROOT / "infrastructure" / "cloudformation" / "scanner_role.yaml"

    def _create():
        # Create bucket (skip if already exists)
        try:
            kwargs = {"Bucket": cfn_bucket}
            if cfg["region"] != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": cfg["region"]}
            s3.create_bucket(**kwargs)
            log.info("S3 CFN bucket '%s' created.", cfn_bucket)
        except s3.exceptions.BucketAlreadyOwnedByYou:
            log.info("S3 CFN bucket '%s' already exists — skipping.", cfn_bucket)
        except Exception as exc:
            if "BucketAlreadyExists" in type(exc).__name__:
                log.warning("Bucket name '%s' already taken globally. Skipping.", cfn_bucket)
                return
            raise

        # Step 1: Lift the account-level block so a bucket policy can take effect
        s3.put_public_access_block(
            Bucket=cfn_bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       False,
                "IgnorePublicAcls":      False,
                "BlockPublicPolicy":     False,
                "RestrictPublicBuckets": False,
            },
        )

        # Step 2: Apply a bucket policy granting public s3:GetObject on all objects
        # This is required so CloudFormation running in ANY external account can
        # fetch the template URL without authentication errors.
        public_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid":       "PublicReadCFNTemplate",
                "Effect":    "Allow",
                "Principal": "*",
                "Action":    "s3:GetObject",
                "Resource":  f"arn:aws:s3:::{cfn_bucket}/*",
            }],
        })
        s3.put_bucket_policy(Bucket=cfn_bucket, Policy=public_policy)
        log.info("Public-read bucket policy applied to '%s'.", cfn_bucket)

        # Step 3: Upload the CloudFormation template
        if template_src.exists():
            s3.upload_file(
                str(template_src),
                cfn_bucket,
                "scanner-role.yaml",
                ExtraArgs={"ContentType": "application/x-yaml"},
            )
            log.info("scanner-role.yaml uploaded to s3://%s/scanner-role.yaml", cfn_bucket)
        else:
            log.warning("scanner_role.yaml not found at %s — skipping upload.", template_src)

    step.run(f"Create CFN template bucket and upload scanner-role.yaml: {cfn_bucket}", _create)
    return f"https://{cfn_bucket}.s3.amazonaws.com/scanner-role.yaml"


def create_eventbridge_rules(events, lmb, cfg: dict, lambda_arns: dict, step: Step) -> None:
    project = cfg["project"]

    def _create_hourly():
        rule = events.put_rule(
            Name=f"{project}-ai-explainer-hourly",
            ScheduleExpression="rate(1 hour)",
            Description="Runs the AI explainer Lambda hourly to process new risks",
            State="ENABLED",
            Tags=[{"Key": "Project", "Value": project}],
        )
        rule_arn = rule["RuleArn"]
        fn_name  = f"{project}-ai-explainer"
        events.put_targets(
            Rule=f"{project}-ai-explainer-hourly",
            Targets=[{"Id": "AIExplainerLambda", "Arn": lambda_arns[fn_name]}],
        )
        try:
            lmb.add_permission(
                FunctionName=fn_name,
                StatementId="AllowEventBridgeAIExplainer",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )
        except lmb.exceptions.ResourceConflictException:
            pass
        log.info("EventBridge hourly rule created for ai-explainer.")

    def _create_scan_complete():
        rule = events.put_rule(
            Name=f"{project}-scan-complete",
            EventPattern=json.dumps({
                "source":      ["cloudsentinel.scanner"],
                "detail-type": ["ScanCompleted"],
                "detail":      {"status": ["COMPLETED"]},
            }),
            Description="Triggers notification Lambda when a scan completes",
            State="ENABLED",
            Tags=[{"Key": "Project", "Value": project}],
        )
        rule_arn = rule["RuleArn"]
        fn_name  = f"{project}-notification-handler"
        events.put_targets(
            Rule=f"{project}-scan-complete",
            Targets=[{"Id": "NotificationHandler", "Arn": lambda_arns[fn_name]}],
        )
        try:
            lmb.add_permission(
                FunctionName=fn_name,
                StatementId="AllowEventBridgeNotify",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )
        except lmb.exceptions.ResourceConflictException:
            pass
        log.info("EventBridge scan-complete rule created for notification-handler.")

    step.run("Create EventBridge hourly rule (AI explainer)", _create_hourly)
    step.run("Create EventBridge scan-complete rule (notifications)", _create_scan_complete)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deploy CloudSentinel to AWS without Terraform."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print all steps without making any AWS API calls.",
    )
    args = parser.parse_args()

    cfg  = load_config()
    step = Step(dry_run=args.dry_run)

    region  = cfg["region"]
    session = boto3.Session(region_name=region)

    if not args.dry_run:
        try:
            sts        = session.client("sts")
            identity   = sts.get_caller_identity()
            account_id = identity["Account"]
            log.info("AWS identity verified: account=%s region=%s", account_id, region)
        except Exception as exc:
            log.error("AWS credentials are not configured or invalid: %s", exc)
            sys.exit(1)
    else:
        account_id = "123456789012"
        log.info("[DRY-RUN] Using placeholder account ID: %s", account_id)

    ddb        = session.resource("dynamodb")
    s3         = session.client("s3")
    iam        = session.client("iam")
    lmb        = session.client("lambda")
    cognito    = session.client("cognito-idp")
    sns_client = session.client("sns")
    apigw      = session.client("apigateway")
    events     = session.client("events")

    log.info("=" * 60)
    log.info("CloudSentinel Deployment Starting")
    log.info("Project   : %s", cfg["project"])
    log.info("Region    : %s", region)
    log.info("Env       : %s", cfg["environment"])
    log.info("Dry-run   : %s", args.dry_run)
    log.info("=" * 60)

    table_name    = create_dynamodb_table(ddb, cfg, step)
    _bucket_name  = create_s3_bucket(s3, account_id, cfg, step)
    role_arn      = create_iam_role(iam, cfg, step)
    pool_id, client_id = create_cognito(cognito, cfg, step)
    sns_topic_arn = create_sns_topic(sns_client, cfg, step)
    lambda_arns   = create_lambdas(lmb, cfg, table_name, role_arn, sns_topic_arn, step)
    api_url          = create_api_gateway(apigw, lmb, account_id, cfg, lambda_arns, step)
    create_eventbridge_rules(events, lmb, cfg, lambda_arns, step)
    cfn_template_url = create_cfn_template_bucket(s3, account_id, cfg, step)

    log.info("=" * 60)
    log.info("Deployment Complete")
    log.info("=" * 60)
    log.info("API Gateway URL    : %s", api_url)
    log.info("Cognito Pool ID    : %s", pool_id)
    log.info("Cognito Client ID  : %s", client_id)
    log.info("DynamoDB Table     : %s", table_name)
    log.info("SNS Topic ARN      : %s", sns_topic_arn)
    log.info("CFN Template URL   : %s", cfn_template_url)
    log.info("")
    log.info("ACTION REQUIRED: Confirm the SNS email subscription sent to '%s'.", cfg["alert_email"])
    log.info("")

    # Auto-write env.js so the frontend is wired without manual editing
    env_js_path = ROOT / "modules" / "frontend" / "js" / "env.js"
    env_js_content = f"""\
/**
 * env.js — Runtime environment configuration for CloudSentinel
 *
 * Auto-generated by deploy_console.py on {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
 * Re-run deploy_console.py to regenerate this file after infrastructure changes.
 *
 * NEVER commit real credentials or secrets here.
 * These are non-secret deployment outputs safe to store in source control.
 */

window.ENV_COGNITO_POOL_ID   = "{pool_id}";
window.ENV_COGNITO_CLIENT_ID = "{client_id}";
window.ENV_API_URL            = "{api_url}";
window.ENV_REGION             = "{region}";
window.ENV_CFN_TEMPLATE_URL   = "{cfn_template_url}";
window.ENV_LAMBDA_ROLE_ARN    = "{role_arn}";
"""
    if not args.dry_run:
        env_js_path.write_text(env_js_content, encoding="utf-8")
        log.info("env.js written to: %s", env_js_path)
    else:
        log.info("[DRY-RUN] Would write env.js with all deployment values.")

    log.info("=" * 60)


if __name__ == "__main__":
    main()

