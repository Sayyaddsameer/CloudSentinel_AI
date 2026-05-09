"""
deploy_disconnect.py — Deploys disconnect_handler Lambda and wires it to API Gateway /disconnect
"""
import boto3, zipfile, io, json
from pathlib import Path

REGION        = 'us-east-1'
REST_API_ID   = 'ojekcmosgj'
STAGE         = 'dev'
ACCOUNT_ID    = '871070087236'
LAMBDA_ROLE   = f'arn:aws:iam::{ACCOUNT_ID}:role/cloudsentinel-lambda-role'
FN_NAME       = 'cloudsentinel-disconnect-handler'
AUTHORIZER_ID = 'zpur1f'   # Cognito authorizer created earlier
MODULE_DIR    = Path(r'd:\project_related\CloudSentinel_AI\modules\cloud-infra')

lmb   = boto3.client('lambda',     region_name=REGION)
apigw = boto3.client('apigateway', region_name=REGION)

# ── Build zip of all python files in cloud-infra module ────────────
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    for py in MODULE_DIR.glob('*.py'):
        zf.write(py, py.name)
buf.seek(0)
zip_bytes = buf.read()

# ── Create or update Lambda ─────────────────────────────────────────
try:
    lmb.get_function(FunctionName=FN_NAME)
    lmb.update_function_code(FunctionName=FN_NAME, ZipFile=zip_bytes)
    lmb.get_waiter('function_updated').wait(FunctionName=FN_NAME)
    lmb.update_function_configuration(
        FunctionName=FN_NAME,
        Timeout=30,
        Environment={'Variables': {
            'RISKS_TABLE': 'CloudSentinelRisks',
            'AWS_ACCOUNT_ID': ACCOUNT_ID,
        }},
    )
    print(f'Updated Lambda: {FN_NAME}')
except lmb.exceptions.ResourceNotFoundException:
    lmb.create_function(
        FunctionName=FN_NAME,
        Runtime='python3.11',
        Role=LAMBDA_ROLE,
        Handler='disconnect_handler.lambda_handler',
        Code={'ZipFile': zip_bytes},
        Timeout=30,
        MemorySize=256,
        Environment={'Variables': {
            'RISKS_TABLE': 'CloudSentinelRisks',
            'AWS_ACCOUNT_ID': ACCOUNT_ID,
        }},
    )
    lmb.get_waiter('function_active').wait(FunctionName=FN_NAME)
    print(f'Created Lambda: {FN_NAME}')

fn_arn = lmb.get_function_configuration(FunctionName=FN_NAME)['FunctionArn']
print(f'Function ARN: {fn_arn}')

# ── Attach IAM policy to allow sts:AssumeRole and secretsmanager:DeleteSecret ──
# (These actions may already be on the Lambda role — just ensure they're present)
iam = boto3.client('iam', region_name=REGION)
try:
    iam.put_role_policy(
        RoleName='cloudsentinel-lambda-role',
        PolicyName='cloudsentinel-disconnect-policy',
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole"],
                    "Resource": "arn:aws:iam::*:role/CloudSentinel-ScannerRole*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:DeleteSecret",
                        "secretsmanager:DescribeSecret"
                    ],
                    "Resource": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:cloudsentinel-gcp-creds-*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:Query",
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem"
                    ],
                    "Resource": [
                        f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/CloudSentinelRisks",
                        f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/CloudSentinelRisks/index/*"
                    ]
                }
            ]
        })
    )
    print('IAM inline policy updated')
except Exception as e:
    print(f'IAM policy note: {e}')

# ── Add /disconnect resource to API Gateway ─────────────────────────
resources = apigw.get_resources(restApiId=REST_API_ID)['items']
root_id  = next(r['id'] for r in resources if r['path'] == '/')

# Check if /disconnect already exists
disconnect_res = next((r for r in resources if r.get('path') == '/disconnect'), None)

if not disconnect_res:
    disconnect_res = apigw.create_resource(
        restApiId=REST_API_ID, parentId=root_id, pathPart='disconnect'
    )
    print('Created /disconnect resource')
else:
    print('Reusing existing /disconnect resource')

res_id = disconnect_res['id']

# ── POST method with Cognito auth ───────────────────────────────────
uri = f'arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{fn_arn}/invocations'

for existing_method in disconnect_res.get('resourceMethods', {}).keys():
    if existing_method == 'POST':
        apigw.delete_method(restApiId=REST_API_ID, resourceId=res_id, httpMethod='POST')

apigw.put_method(
    restApiId=REST_API_ID, resourceId=res_id,
    httpMethod='POST',
    authorizationType='COGNITO_USER_POOLS',
    authorizerId=AUTHORIZER_ID,
)
apigw.put_integration(
    restApiId=REST_API_ID, resourceId=res_id,
    httpMethod='POST', integrationHttpMethod='POST',
    type='AWS_PROXY', uri=uri,
)
print('POST /disconnect -> Lambda (Cognito auth)')

# ── OPTIONS CORS ─────────────────────────────────────────────────────
try:
    apigw.delete_method(restApiId=REST_API_ID, resourceId=res_id, httpMethod='OPTIONS')
except Exception:
    pass

apigw.put_method(restApiId=REST_API_ID, resourceId=res_id, httpMethod='OPTIONS', authorizationType='NONE')
apigw.put_integration(restApiId=REST_API_ID, resourceId=res_id, httpMethod='OPTIONS',
    type='MOCK', requestTemplates={'application/json': '{"statusCode":200}'})
apigw.put_method_response(restApiId=REST_API_ID, resourceId=res_id, httpMethod='OPTIONS', statusCode='200',
    responseParameters={
        'method.response.header.Access-Control-Allow-Headers': False,
        'method.response.header.Access-Control-Allow-Methods': False,
        'method.response.header.Access-Control-Allow-Origin': False,
    })
apigw.put_integration_response(restApiId=REST_API_ID, resourceId=res_id, httpMethod='OPTIONS', statusCode='200',
    responseParameters={
        'method.response.header.Access-Control-Allow-Headers': "'Content-Type,Authorization,X-Amz-Date'",
        'method.response.header.Access-Control-Allow-Methods': "'POST,OPTIONS'",
        'method.response.header.Access-Control-Allow-Origin': "'*'",
    })
print('OPTIONS /disconnect -> CORS')

# ── Lambda permission ────────────────────────────────────────────────
try:
    lmb.remove_permission(FunctionName=FN_NAME, StatementId=f'AllowAPIGW-{REST_API_ID}-disconnect-POST')
except Exception:
    pass
lmb.add_permission(
    FunctionName=FN_NAME,
    StatementId=f'AllowAPIGW-{REST_API_ID}-disconnect-POST',
    Action='lambda:InvokeFunction',
    Principal='apigateway.amazonaws.com',
    SourceArn=f'arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:{REST_API_ID}/*/*',
)
print('Lambda permission added')

# ── Redeploy ─────────────────────────────────────────────────────────
apigw.create_deployment(
    restApiId=REST_API_ID,
    stageName=STAGE,
    description='Add /disconnect endpoint with Cognito auth',
)
print(f'Deployed to stage: {STAGE}')
print(f'Endpoint: https://{REST_API_ID}.execute-api.{REGION}.amazonaws.com/{STAGE}/disconnect')
