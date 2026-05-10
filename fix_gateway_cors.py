"""
fix_gateway_cors.py
Adds CORS headers to ALL API Gateway error responses (401, 403, 404, 500, etc.)
so the browser receives proper HTTP status codes instead of TypeError: Failed to fetch.

Root cause: API Gateway strips CORS headers from Cognito authorizer rejections (401/403).
The browser sees a response with no CORS header and throws TypeError: Failed to fetch.

Run: python fix_gateway_cors.py
"""
import boto3, json

API_ID  = 'ojekcmosgj'
REGION  = 'us-east-1'
STAGE   = 'dev'

apigw = boto3.client('apigateway', region_name=REGION)

CORS_HEADERS = {
    'gatewayresponse.header.Access-Control-Allow-Origin':  "'*'",
    'gatewayresponse.header.Access-Control-Allow-Headers': "'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token'",
    'gatewayresponse.header.Access-Control-Allow-Methods': "'GET,POST,OPTIONS'",
}

# These are the Gateway Response types that need CORS headers
RESPONSE_TYPES = [
    'DEFAULT_4XX',      # catches ALL 4xx including Cognito 401/403
    'DEFAULT_5XX',      # catches ALL 5xx
    'UNAUTHORIZED',     # explicit 401 from authorizer
    'ACCESS_DENIED',    # explicit 403
    'EXPIRED_TOKEN',    # expired JWT
    'INVALID_SIGNATURE',# bad JWT signature
    'BAD_REQUEST_BODY', # 400
    'QUOTA_EXCEEDED',   # 429
    'THROTTLED',        # 429
    'RESOURCE_NOT_FOUND', # 404
]

print(f'Fixing Gateway Responses for API: {API_ID}')
print('-' * 60)

for resp_type in RESPONSE_TYPES:
    try:
        apigw.put_gateway_response(
            restApiId=API_ID,
            responseType=resp_type,
            responseParameters=CORS_HEADERS,
            responseTemplates={
                'application/json': '{"message": $context.error.messageString}'
            }
        )
        print(f'  [OK] {resp_type}')
    except Exception as e:
        print(f'  [ERR] {resp_type}: {e}')

# Redeploy the stage so changes take effect immediately
print()
print('Redeploying stage to apply changes...')
deployment = apigw.create_deployment(
    restApiId=API_ID,
    stageName=STAGE,
    description='fix: add CORS headers to all gateway error responses'
)
print(f'  [OK] Deployed: {deployment["id"]}')

# Verify the fix
print()
print('Verifying fix...')
import urllib.request, urllib.error, time
time.sleep(5)  # wait for propagation

url = f'https://{API_ID}.execute-api.{REGION}.amazonaws.com/{STAGE}/scan-cloud-infra'
req = urllib.request.Request(url, data=b'{}', method='POST')
req.add_header('Content-Type',  'application/json')
req.add_header('Authorization', 'invalid-token')
req.add_header('Origin', 'http://cloudsentinel-frontend-871070087236.s3-website-us-east-1.amazonaws.com')
try:
    urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as e:
    acao = e.headers.get('Access-Control-Allow-Origin', 'MISSING')
    print(f'  Status: {e.code}')
    print(f'  Access-Control-Allow-Origin: {acao}')
    if acao != 'MISSING':
        print()
        print('  SUCCESS: 401 now includes CORS headers.')
        print('  Browser will correctly receive 401 instead of TypeError: Failed to fetch.')
        print('  The auto token-refresh in apiFetch() will handle this gracefully.')
    else:
        print('  CORS header still missing - may need more propagation time.')
except Exception as ex:
    print(f'  Error: {ex}')
