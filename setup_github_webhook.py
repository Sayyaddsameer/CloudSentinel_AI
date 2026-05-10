"""
setup_github_webhook.py
Registers a GitHub webhook on your repository so that every push to the
main branch automatically triggers the CloudSentinel DevOps scanner.

Usage:
    python setup_github_webhook.py

Requires: A GitHub Personal Access Token with 'admin:repo_hook' scope.
"""
import sys
import json
import urllib.request
import urllib.error
import secrets
import boto3

REGION      = 'us-east-1'
ACCOUNT_ID  = '871070087236'
PROJECT     = 'cloudsentinel'
REST_API_ID = 'ojekcmosgj'
DEVOPS_ENDPOINT = f'https://{REST_API_ID}.execute-api.{REGION}.amazonaws.com/dev/scan-devops'

# ---------------------------------------------------------------------------

def github_request(method, path, token, body=None):
    url = f'https://api.github.com{path}'
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header('Authorization', f'token {token}')
    req.add_header('Accept', 'application/vnd.github+json')
    req.add_header('X-GitHub-Api-Version', '2022-11-28')
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        return body, e.code


print('CloudSentinel GitHub Webhook Setup')
print('=' * 40)
print()
print('This will register a webhook on your GitHub repo so every push')
print('automatically triggers the CloudSentinel DevOps scanner.')
print()

# ── Input ────────────────────────────────────────────────────────────────────
repo  = input('GitHub repo (e.g. Sayyaddsameer/CloudSentinel_AI): ').strip()
token = input('Personal Access Token (needs admin:repo_hook scope): ').strip()
if not repo or not token:
    print('[ERROR] Repository and token are required.')
    sys.exit(1)

# Validate token
user_data, status = github_request('GET', '/user', token)
if status != 200:
    print(f'[ERROR] Token validation failed ({status}): {user_data.get("message")}')
    sys.exit(1)
print(f'  Authenticated as: {user_data["login"]}')

# ── Generate webhook secret and store in Secrets Manager ────────────────────
webhook_secret = secrets.token_hex(32)
secret_name    = f'{PROJECT}-github-webhook-secret'

sm = boto3.client('secretsmanager', region_name=REGION)
try:
    sm.create_secret(Name=secret_name, SecretString=webhook_secret)
    print(f'  Webhook secret stored in Secrets Manager: {secret_name}')
except sm.exceptions.ResourceExistsException:
    sm.put_secret_value(SecretId=secret_name, SecretString=webhook_secret)
    print(f'  Webhook secret updated in Secrets Manager: {secret_name}')

secret_arn = sm.describe_secret(SecretId=secret_name)['ARN']

# ── Update devops-analyzer Lambda env var ────────────────────────────────────
lmb     = boto3.client('lambda', region_name=REGION)
fn_name = f'{PROJECT}-devops-analyzer'
try:
    current = lmb.get_function_configuration(FunctionName=fn_name)
    env     = current.get('Environment', {}).get('Variables', {})
    env['WEBHOOK_SECRET_ARN'] = secret_arn
    lmb.update_function_configuration(FunctionName=fn_name, Environment={'Variables': env})
    print(f'  Updated {fn_name} WEBHOOK_SECRET_ARN = {secret_arn}')
except lmb.exceptions.ResourceNotFoundException:
    print(f'  [WARN] Lambda {fn_name} not found -- skipping env var update')

# ── Register webhook on GitHub ───────────────────────────────────────────────
print(f'\nRegistering webhook on {repo}...')

# List existing webhooks to avoid duplicates
hooks, status = github_request('GET', f'/repos/{repo}/hooks', token)
if status == 404:
    print(f'[ERROR] Repo "{repo}" not found or token lacks "repo" scope.')
    sys.exit(1)

existing_hook = None
if isinstance(hooks, list):
    for h in hooks:
        if DEVOPS_ENDPOINT in h.get('config', {}).get('url', ''):
            existing_hook = h
            break

if existing_hook:
    # Update existing hook
    data, status = github_request('PATCH', f'/repos/{repo}/hooks/{existing_hook["id"]}', token, {
        'config': {
            'url':          DEVOPS_ENDPOINT,
            'content_type': 'json',
            'secret':       webhook_secret,
            'insecure_ssl': '0',
        },
        'events': ['push'],
        'active': True,
    })
    action = 'Updated'
else:
    # Create new hook
    data, status = github_request('POST', f'/repos/{repo}/hooks', token, {
        'name':   'web',
        'active': True,
        'events': ['push'],
        'config': {
            'url':          DEVOPS_ENDPOINT,
            'content_type': 'json',
            'secret':       webhook_secret,
            'insecure_ssl': '0',
        },
    })
    action = 'Created'

if status not in (200, 201):
    print(f'[ERROR] Webhook registration failed ({status}): {data.get("message")}')
    sys.exit(1)

hook_id = data['id']
print(f'  {action} webhook (id: {hook_id})')
print(f'  Webhook URL: {DEVOPS_ENDPOINT}')

# ── Trigger a test ping ──────────────────────────────────────────────────────
print('\nSending test ping...')
_, ping_status = github_request('POST', f'/repos/{repo}/hooks/{hook_id}/pings', token)
print(f'  Ping status: {ping_status}')

print()
print('[OK] GitHub webhook setup complete!')
print()
print('How it works:')
print('  Every push to any branch of your repo will automatically trigger')
print('  the CloudSentinel DevOps scanner to re-analyze your CI/CD pipelines.')
print()
print(f'  Webhook endpoint: {DEVOPS_ENDPOINT}')
print(f'  Secret stored at: {secret_name} (Secrets Manager)')
