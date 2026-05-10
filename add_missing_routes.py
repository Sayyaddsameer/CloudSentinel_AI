"""
add_missing_routes.py
Adds the missing /disconnect and /notify API Gateway routes to the existing
CloudSentinel API, then redeploys to the dev stage.

Run with:  python add_missing_routes.py
"""
import sys
import boto3

# Force UTF-8 output on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

REST_API_ID  = 'ojekcmosgj'
STAGE        = 'dev'
REGION       = 'us-east-1'
ACCOUNT_ID   = '871070087236'
PROJECT      = 'cloudsentinel'

apigw  = boto3.client('apigateway', region_name=REGION)
lmb    = boto3.client('lambda',     region_name=REGION)

# Routes to add: (path_part, HTTP_method, lambda_function_name)
NEW_ROUTES = [
    ('disconnect', 'POST', f'{PROJECT}-disconnect-handler'),
    ('notify',     'POST', f'{PROJECT}-notification-handler'),
]

# Get root resource ID
resources   = apigw.get_resources(restApiId=REST_API_ID)['items']
existing    = {r.get('pathPart'): r['id'] for r in resources if 'pathPart' in r}
root_id     = next(r['id'] for r in resources if r.get('path') == '/')

print(f"Existing resources: {list(existing.keys())}")

for path_part, method, fn_name in NEW_ROUTES:
    print(f"\n-- Adding route: {method} /{path_part} -> {fn_name}")

    # 1. Get Lambda ARN
    try:
        fn_config = lmb.get_function(FunctionName=fn_name)['Configuration']
        fn_arn    = fn_config['FunctionArn']
        print(f"   Lambda ARN: {fn_arn}")
    except lmb.exceptions.ResourceNotFoundException:
        print(f"   [WARN] Lambda '{fn_name}' not found -- skipping this route.")
        continue

    # 2. Create resource (skip if already exists)
    if path_part in existing:
        resource_id = existing[path_part]
        print(f"   Resource /{path_part} already exists (id={resource_id})")
    else:
        resource    = apigw.create_resource(
            restApiId=REST_API_ID, parentId=root_id, pathPart=path_part
        )
        resource_id = resource['id']
        print(f"   Created resource /{path_part} (id={resource_id})")

    # 3. Put method (skip if already exists)
    try:
        apigw.put_method(
            restApiId=REST_API_ID, resourceId=resource_id,
            httpMethod=method, authorizationType='NONE',
        )
        print(f"   Created method {method}")
    except apigw.exceptions.ConflictException:
        print(f"   Method {method} already exists")

    # 4. Put Lambda proxy integration
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    try:
        apigw.put_integration(
            restApiId=REST_API_ID, resourceId=resource_id,
            httpMethod=method, integrationHttpMethod='POST',
            type='AWS_PROXY', uri=uri,
        )
        print(f"   Integration set -> {fn_arn}")
    except apigw.exceptions.ConflictException:
        print(f"   Integration already exists")

    # 5. Grant API Gateway permission to invoke the Lambda
    stmt_id = f"AllowAPIGW-{REST_API_ID}-{path_part}-{method}"
    try:
        lmb.add_permission(
            FunctionName=fn_name,
            StatementId=stmt_id,
            Action='lambda:InvokeFunction',
            Principal='apigateway.amazonaws.com',
            SourceArn=f"arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:{REST_API_ID}/*/*",
        )
        print(f"   Lambda permission granted (StatementId={stmt_id})")
    except lmb.exceptions.ResourceConflictException:
        print(f"   Lambda permission already exists")

    # 6. CORS preflight (OPTIONS)
    try:
        apigw.put_method(
            restApiId=REST_API_ID, resourceId=resource_id,
            httpMethod='OPTIONS', authorizationType='NONE',
        )
    except apigw.exceptions.ConflictException:
        pass

    try:
        apigw.put_integration(
            restApiId=REST_API_ID, resourceId=resource_id,
            httpMethod='OPTIONS', type='MOCK',
            requestTemplates={'application/json': '{"statusCode":200}'},
        )
        apigw.put_method_response(
            restApiId=REST_API_ID, resourceId=resource_id,
            httpMethod='OPTIONS', statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Headers': False,
                'method.response.header.Access-Control-Allow-Methods': False,
                'method.response.header.Access-Control-Allow-Origin':  False,
            },
        )
        apigw.put_integration_response(
            restApiId=REST_API_ID, resourceId=resource_id,
            httpMethod='OPTIONS', statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Headers': "'Content-Type,Authorization,X-Amz-Date,X-Api-Key'",
                'method.response.header.Access-Control-Allow-Methods': f"'{method},OPTIONS'",
                'method.response.header.Access-Control-Allow-Origin':  "'*'",
            },
        )
        print(f"   CORS OPTIONS configured")
    except Exception as e:
        print(f"   CORS OPTIONS skipped: {e}")

# Redeploy to dev stage
print(f"\n-- Redeploying to '{STAGE}' stage...")
deployment = apigw.create_deployment(
    restApiId=REST_API_ID,
    stageName=STAGE,
    description='Add /disconnect and /notify routes',
)
print(f"   Deployed (deployment id: {deployment['id']})")
print(f"\n[OK] Done. New routes are live at:")
print(f"   POST https://{REST_API_ID}.execute-api.{REGION}.amazonaws.com/{STAGE}/disconnect")
print(f"   POST https://{REST_API_ID}.execute-api.{REGION}.amazonaws.com/{STAGE}/notify")
