"""
diagnose_token.py
Tests which Cognito token type (accessToken vs idToken) the API Gateway authorizer accepts.
"""
import boto3, json, urllib.request, urllib.error

REGION      = 'us-east-1'
API_BASE    = 'https://ojekcmosgj.execute-api.us-east-1.amazonaws.com/dev'

# Get these from env.js
CLIENT_ID   = None  # will be read from env.js
POOL_ID     = None

# Read env.js to get Cognito config
import re, os
env_path = r'd:\project_related\CloudSentinel_AI\modules\frontend\js\env.js'
with open(env_path) as f:
    content = f.read()

client_match = re.search(r"ENV_COGNITO_CLIENT_ID\s*=\s*['\"]([^'\"]+)['\"]", content)
pool_match   = re.search(r"ENV_COGNITO_POOL_ID\s*=\s*['\"]([^'\"]+)['\"]", content)

if client_match: CLIENT_ID = client_match.group(1)
if pool_match:   POOL_ID   = pool_match.group(1)

print(f'Cognito Pool ID:   {POOL_ID}')
print(f'Cognito Client ID: {CLIENT_ID}')

if not CLIENT_ID or CLIENT_ID.startswith('%%'):
    print('ERROR: Cognito not configured in env.js')
    exit(1)

# Authenticate with Cognito to get fresh tokens
EMAIL    = 'sayyadsameersaddiqui@gmail.com'
PASSWORD = 'Sameer@M3S2A1'

print(f'\nAuthenticating as {EMAIL}...')
cognito_url = f'https://cognito-idp.{REGION}.amazonaws.com/'
auth_body = json.dumps({
    'AuthFlow': 'USER_PASSWORD_AUTH',
    'ClientId': CLIENT_ID,
    'AuthParameters': {'USERNAME': EMAIL, 'PASSWORD': PASSWORD},
}).encode()

req = urllib.request.Request(cognito_url, data=auth_body, method='POST')
req.add_header('Content-Type', 'application/x-amz-json-1.1')
req.add_header('X-Amz-Target', 'AWSCognitoIdentityProviderService.InitiateAuth')

try:
    with urllib.request.urlopen(req, timeout=10) as r:
        data   = json.loads(r.read())
        result = data['AuthenticationResult']
        ACCESS = result['AccessToken']
        ID     = result['IdToken']
        print('  Auth successful')
        print(f'  AccessToken (first 40): {ACCESS[:40]}...')
        print(f'  IdToken     (first 40): {ID[:40]}...')
except Exception as e:
    print(f'  Auth FAILED: {e}')
    exit(1)

# Test both token types against /risks
def test_token(label, token):
    url = f'{API_BASE}/risks?module=cloud-infra'
    req = urllib.request.Request(url, method='GET')
    req.add_header('Authorization', token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read())
            count = len(body) if isinstance(body, list) else body.get('count', '?')
            print(f'  [{label}] STATUS 200  risks={count}  <- WORKS')
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:100]
        print(f'  [{label}] STATUS {e.code}  {body}  <- REJECTED')
        return False
    except Exception as ex:
        print(f'  [{label}] ERROR: {ex}')
        return False

print()
print('Testing which token type the API Gateway authorizer accepts:')
print('-' * 60)
access_ok = test_token('accessToken', ACCESS)
id_ok     = test_token('idToken    ', ID)
print('-' * 60)
print()

if id_ok and not access_ok:
    print('RESULT: Authorizer requires idToken, NOT accessToken.')
    print('FIX:    Change getToken() in auth.js to return user.idToken')
elif access_ok and not id_ok:
    print('RESULT: Authorizer correctly accepts accessToken.')
    print('ISSUE:  Something else is wrong (stale cached JS?)')
elif access_ok and id_ok:
    print('RESULT: Both tokens work.')
elif not access_ok and not id_ok:
    print('RESULT: NEITHER token works. Authorizer config issue.')
    print('Check: API Gateway -> Authorizer -> Token source')
