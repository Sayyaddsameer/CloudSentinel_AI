"""
add_jwt_authorizer.py
Creates a Cognito User Pool authorizer on the CloudSentinel API Gateway
and attaches it to all non-OPTIONS methods.
"""
import boto3, json, time

REST_API_ID   = 'ojekcmosgj'
STAGE         = 'dev'
REGION        = 'us-east-1'
POOL_ID       = 'us-east-1_6O8s8U592'
CLIENT_ID     = '3bljg42108cec2ajj70h21mcnn'
AUTHORIZER_NAME = 'CloudSentinelCognito'

apigw = boto3.client('apigateway', region_name=REGION)

# ── 1. Check for existing authorizer or create ──────────────────────
existing = apigw.get_authorizers(restApiId=REST_API_ID)['items']
auth_id = None
for a in existing:
    if a['name'] == AUTHORIZER_NAME:
        auth_id = a['id']
        print(f'Reusing existing authorizer: {auth_id}')
        break

if not auth_id:
    resp = apigw.create_authorizer(
        restApiId=REST_API_ID,
        name=AUTHORIZER_NAME,
        type='COGNITO_USER_POOLS',
        providerARNs=[f'arn:aws:cognito-idp:{REGION}:871070087236:userpool/{POOL_ID}'],
        identitySource='method.request.header.Authorization',
        authorizerResultTtlInSeconds=300,
    )
    auth_id = resp['id']
    print(f'Created authorizer: {auth_id}  ({AUTHORIZER_NAME})')

# ── 2. Apply to all non-OPTIONS methods ─────────────────────────────
resources = apigw.get_resources(restApiId=REST_API_ID)['items']
updated = 0
skipped = 0

for r in sorted(resources, key=lambda x: x.get('path','/')):
    path = r.get('path', '/')
    for method in list(r.get('resourceMethods', {}).keys()):
        if method == 'OPTIONS':
            skipped += 1
            continue  # CORS preflight must remain unauthenticated

        m = apigw.get_method(restApiId=REST_API_ID, resourceId=r['id'], httpMethod=method)
        current_auth = m.get('authorizationType', 'NONE')
        current_id   = m.get('authorizerId', '')

        if current_auth == 'COGNITO_USER_POOLS' and current_id == auth_id:
            print(f'  [skip] {method:<7} {path}  already has Cognito auth')
            skipped += 1
            continue

        apigw.update_method(
            restApiId=REST_API_ID,
            resourceId=r['id'],
            httpMethod=method,
            patchOperations=[
                {'op': 'replace', 'path': '/authorizationType',      'value': 'COGNITO_USER_POOLS'},
                {'op': 'replace', 'path': '/authorizerId',           'value': auth_id},
            ],
        )
        print(f'  [OK]   {method:<7} {path}  -> COGNITO_USER_POOLS (authorizer={auth_id})')
        updated += 1

# ── 3. Redeploy to dev stage ────────────────────────────────────────
print()
print('Redeploying to dev stage...')
apigw.create_deployment(
    restApiId=REST_API_ID,
    stageName=STAGE,
    description='Add Cognito JWT authorizer to all protected endpoints',
)
print('Deployed.')
print()
print(f'Summary: {updated} methods secured, {skipped} skipped (OPTIONS + already secured)')
print(f'Authorizer ID: {auth_id}')
print(f'Pool: arn:aws:cognito-idp:{REGION}:871070087236:userpool/{POOL_ID}')
