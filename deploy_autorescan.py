"""
deploy_autorescan.py
Deploys the auto_rescan_router Lambda and all EventBridge rules for
automatic CloudSentinel rescanning on AWS resource changes.

Usage:
    python deploy_autorescan.py

Prerequisites:
    - AWS CLI configured with sufficient permissions
    - The cloud-infra Lambda ZIP already exists (run deploy_console.py first)
"""
import sys
import boto3
import json
import zipfile
import os
import io
import time

REST_API_ID = 'ojekcmosgj'
REGION      = 'us-east-1'
ACCOUNT_ID  = '871070087236'
PROJECT     = 'cloudsentinel'
ROLE_ARN    = f'arn:aws:iam::{ACCOUNT_ID}:role/cloudsentinel-lambda-role'
TABLE_NAME  = 'cloudsentinel-risks'

lmb    = boto3.client('lambda',              region_name=REGION)
events = boto3.client('events',              region_name=REGION)
apigw  = boto3.client('apigateway',          region_name=REGION)

CLOUD_INFRA_DIR = os.path.join(os.path.dirname(__file__),
                               'modules', 'cloud-infra')

# ── 1. Build ZIP from cloud-infra directory ──────────────────────────────────
print('Building Lambda ZIP from modules/cloud-infra...')
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    for fname in os.listdir(CLOUD_INFRA_DIR):
        if fname.endswith('.py'):
            zf.write(os.path.join(CLOUD_INFRA_DIR, fname), fname)
zip_bytes = buf.getvalue()
print(f'  ZIP size: {len(zip_bytes):,} bytes')


def deploy_lambda(fn_name, handler, env_vars, timeout=60, memory=128):
    """Create or update a Lambda function."""
    try:
        lmb.get_function(FunctionName=fn_name)
        # Update existing
        lmb.update_function_code(FunctionName=fn_name, ZipFile=zip_bytes)
        time.sleep(2)
        lmb.update_function_configuration(
            FunctionName=fn_name,
            Handler=handler,
            Timeout=timeout,
            MemorySize=memory,
            Environment={'Variables': env_vars},
        )
        print(f'  [UPDATE] {fn_name}')
    except lmb.exceptions.ResourceNotFoundException:
        lmb.create_function(
            FunctionName=fn_name,
            Runtime='python3.11',
            Role=ROLE_ARN,
            Handler=handler,
            Code={'ZipFile': zip_bytes},
            Timeout=timeout,
            MemorySize=memory,
            Environment={'Variables': env_vars},
        )
        print(f'  [CREATE] {fn_name}')


def add_eventbridge_permission(fn_name, rule_arn, stmt_id):
    """Grant EventBridge permission to invoke a Lambda function."""
    try:
        lmb.add_permission(
            FunctionName=fn_name,
            StatementId=stmt_id,
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=rule_arn,
        )
    except lmb.exceptions.ResourceConflictException:
        pass   # already granted


def put_rule_and_target(rule_name, description, event_pattern, fn_name):
    """Create or update an EventBridge rule and wire it to a Lambda target."""
    resp    = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State='ENABLED',
        Description=description,
    )
    rule_arn = resp['RuleArn']
    fn_arn   = f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{fn_name}'

    events.put_targets(
        Rule=rule_name,
        Targets=[{'Id': 'RouterTarget', 'Arn': fn_arn}],
    )
    add_eventbridge_permission(fn_name, rule_arn, f'allow-{rule_name}')
    print(f'  [RULE] {rule_name}')
    return rule_arn


# ── 2. Deploy auto_rescan_router Lambda ──────────────────────────────────────
print('\n-- Deploying auto-rescan-router Lambda...')
ROUTER_NAME = f'{PROJECT}-auto-rescan-router'
deploy_lambda(
    ROUTER_NAME,
    handler='auto_rescan_router.lambda_handler',
    env_vars={'PROJECT_NAME': PROJECT},
    timeout=60, memory=128,
)

# ── 3. Deploy validate_connection Lambda ─────────────────────────────────────
print('\n-- Deploying validate-connection Lambda...')
VALIDATE_NAME = f'{PROJECT}-validate-connection'
deploy_lambda(
    VALIDATE_NAME,
    handler='validate_connection.lambda_handler',
    env_vars={},
    timeout=30, memory=128,
)

# ── 4. Add /validate-connection API Gateway route ────────────────────────────
print('\n-- Adding /validate-connection route to API Gateway...')
resources  = apigw.get_resources(restApiId=REST_API_ID)['items']
existing   = {r.get('pathPart'): r['id'] for r in resources if 'pathPart' in r}
root_id    = next(r['id'] for r in resources if r.get('path') == '/')
fn_arn_val = f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{VALIDATE_NAME}'

if 'validate-connection' not in existing:
    resource    = apigw.create_resource(restApiId=REST_API_ID, parentId=root_id, pathPart='validate-connection')
    resource_id = resource['id']
    print(f'  Created resource /validate-connection (id={resource_id})')
else:
    resource_id = existing['validate-connection']
    print(f'  Resource /validate-connection already exists (id={resource_id})')

for method in ('POST', 'OPTIONS'):
    try:
        apigw.put_method(restApiId=REST_API_ID, resourceId=resource_id,
                         httpMethod=method, authorizationType='NONE')
    except apigw.exceptions.ConflictException:
        pass

# POST integration → validate_connection Lambda
uri = f'arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{fn_arn_val}/invocations'
try:
    apigw.put_integration(restApiId=REST_API_ID, resourceId=resource_id,
                          httpMethod='POST', integrationHttpMethod='POST',
                          type='AWS_PROXY', uri=uri)
except apigw.exceptions.ConflictException:
    pass

# CORS OPTIONS
try:
    apigw.put_integration(restApiId=REST_API_ID, resourceId=resource_id,
                          httpMethod='OPTIONS', type='MOCK',
                          requestTemplates={'application/json': '{"statusCode":200}'})
    apigw.put_method_response(restApiId=REST_API_ID, resourceId=resource_id,
                              httpMethod='OPTIONS', statusCode='200',
                              responseParameters={
                                  'method.response.header.Access-Control-Allow-Headers': False,
                                  'method.response.header.Access-Control-Allow-Methods': False,
                                  'method.response.header.Access-Control-Allow-Origin':  False,
                              })
    apigw.put_integration_response(restApiId=REST_API_ID, resourceId=resource_id,
                                   httpMethod='OPTIONS', statusCode='200',
                                   responseParameters={
                                       'method.response.header.Access-Control-Allow-Headers': "'Content-Type,Authorization'",
                                       'method.response.header.Access-Control-Allow-Methods': "'POST,OPTIONS'",
                                       'method.response.header.Access-Control-Allow-Origin':  "'*'",
                                   })
except Exception as e:
    print(f'  CORS OPTIONS: {e}')

# Lambda permission
try:
    lmb.add_permission(FunctionName=VALIDATE_NAME, StatementId=f'AllowAPIGW-validate',
                       Action='lambda:InvokeFunction', Principal='apigateway.amazonaws.com',
                       SourceArn=f'arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:{REST_API_ID}/*/*')
except lmb.exceptions.ResourceConflictException:
    pass
print('  /validate-connection route configured')

# ── 5. Create EventBridge rules ──────────────────────────────────────────────
print('\n-- Creating EventBridge auto-rescan rules...')

RULES = [
    (f'{PROJECT}-cfn-changes',     'CloudFormation changes trigger cloud-infra rescan',
     {'source': ['aws.cloudformation'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['cloudformation.amazonaws.com'],
                 'eventName': ['CreateStack', 'UpdateStack', 'DeleteStack']}}),

    (f'{PROJECT}-lambda-changes',  'Lambda function changes trigger cloud-infra + devops rescan',
     {'source': ['aws.lambda'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['lambda.amazonaws.com'],
                 'eventName': ['CreateFunction20150331', 'UpdateFunctionCode20150331v2']}}),

    (f'{PROJECT}-s3-changes',      'S3 bucket changes trigger cloud-infra + data-eng rescan',
     {'source': ['aws.s3'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['s3.amazonaws.com'],
                 'eventName': ['CreateBucket', 'PutBucketPolicy', 'PutBucketAcl']}}),

    (f'{PROJECT}-ec2-sg-changes',  'EC2 SG changes trigger cloud-infra rescan',
     {'source': ['aws.ec2'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['ec2.amazonaws.com'],
                 'eventName': ['AuthorizeSecurityGroupIngress', 'CreateSecurityGroup']}}),

    (f'{PROJECT}-iam-changes',     'IAM changes trigger cloud-infra + mobile rescan',
     {'source': ['aws.iam'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['iam.amazonaws.com'],
                 'eventName': ['PutRolePolicy', 'AttachRolePolicy', 'CreateRole']}}),

    (f'{PROJECT}-apigw-changes',   'API Gateway changes trigger fullstack + mobile rescan',
     {'source': ['aws.apigateway'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['apigateway.amazonaws.com'],
                 'eventName': ['CreateRestApi', 'PutMethod', 'CreateDeployment']}}),

    (f'{PROJECT}-cognito-changes', 'Cognito changes trigger mobile rescan',
     {'source': ['aws.cognito-idp'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['cognito-idp.amazonaws.com'],
                 'eventName': ['CreateUserPool', 'UpdateUserPool']}}),

    (f'{PROJECT}-glue-changes',    'Glue changes trigger data-eng rescan',
     {'source': ['aws.glue'], 'detail-type': ['AWS API Call via CloudTrail'],
      'detail': {'eventSource': ['glue.amazonaws.com'],
                 'eventName': ['CreateJob', 'UpdateJob', 'StartJobRun']}}),
]

for rule_name, description, event_pattern in RULES:
    put_rule_and_target(rule_name, description, event_pattern, ROUTER_NAME)

# ── 6. Scheduled rescan every 6 hours ───────────────────────────────────────
print('\n-- Setting up scheduled 6-hour full rescan...')
sched_rule = events.put_rule(
    Name=f'{PROJECT}-scheduled-rescan',
    ScheduleExpression='rate(6 hours)',
    State='ENABLED',
    Description='Full CloudSentinel rescan every 6 hours',
)
events.put_targets(
    Rule=f'{PROJECT}-scheduled-rescan',
    Targets=[{
        'Id': 'ScheduledRouter',
        'Arn': f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{ROUTER_NAME}',
        'Input': json.dumps({
            'source': 'scheduled-rescan',
            'detail': {'eventSource': 'all', 'eventName': 'ScheduledFullScan'},
        }),
    }],
)
add_eventbridge_permission(ROUTER_NAME, sched_rule['RuleArn'], 'allow-scheduled-rescan')
print(f'  [RULE] {PROJECT}-scheduled-rescan (every 6 hours)')

# ── 7. Redeploy API Gateway ──────────────────────────────────────────────────
print('\n-- Redeploying API Gateway...')
dep = apigw.create_deployment(restApiId=REST_API_ID, stageName='dev',
                              description='Add auto-rescan router + validate-connection routes')
print(f'  Deployed (id: {dep["id"]})')

print('\n[OK] Auto-rescan infrastructure deployed successfully!')
print(f'  Router Lambda:     {ROUTER_NAME}')
print(f'  Validation Lambda: {VALIDATE_NAME}')
print(f'  EventBridge rules: {len(RULES)} + 1 scheduled')
print(f'  Validate endpoint: POST https://{REST_API_ID}.execute-api.{REGION}.amazonaws.com/dev/validate-connection')
