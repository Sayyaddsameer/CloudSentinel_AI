import boto3, json

apigw = boto3.client('apigateway', region_name='us-east-1')
lmb   = boto3.client('lambda',     region_name='us-east-1')

# ── All routes ────────────────────────────────────────────────────────────────
print('=== All API Gateway routes (REST API: ojekcmosgj) ===')
resources = apigw.get_resources(restApiId='ojekcmosgj', limit=100).get('items', [])
for r in sorted(resources, key=lambda x: x.get('path', '')):
    path    = r.get('path', '')
    methods = list(r.get('resourceMethods', {}).keys())
    print(f'  {path:<45} {methods}')

chat_exists   = any(r.get('path') == '/chat'          for r in resources)
scan_exists   = any(r.get('path') == '/scan-cloud-infra' for r in resources)
notify_exists = any(r.get('path') == '/notify'        for r in resources)
print()
print('/chat exists:             ', chat_exists)
print('/scan-cloud-infra exists: ', scan_exists)
print('/notify exists:           ', notify_exists)

# ── Check scan-cloud-infra integration ────────────────────────────────────────
print()
print('=== /scan-cloud-infra integration ===')
for r in resources:
    if r.get('path') == '/scan-cloud-infra':
        rid = r['id']
        try:
            integ = apigw.get_integration(restApiId='ojekcmosgj', resourceId=rid, httpMethod='POST')
            print('  type:  ', integ.get('type'))
            uri = integ.get('uri', '')
            print('  uri:   ', uri[:120])
        except Exception as e:
            print(f'  Error: {e}')

# ── Chatbot Lambda ─────────────────────────────────────────────────────────────
print()
print('=== Chatbot / AI Lambda search ===')
for suffix in ['chatbot', 'chatbot-handler', 'chat-handler', 'ai-explainer', 'chatbot-api']:
    fn_name = f'cloudsentinel-{suffix}'
    try:
        c = lmb.get_function_configuration(FunctionName=fn_name)
        h = c.get('Handler', '?')
        print(f'  FOUND:     {fn_name}  handler={h}')
    except lmb.exceptions.ResourceNotFoundException:
        print(f'  NOT FOUND: {fn_name}')

# ── Test /scan-cloud-infra endpoint directly with fake token ──────────────────
import urllib.request, urllib.error
print()
print('=== Testing POST /scan-cloud-infra (expect 401) ===')
url = 'https://ojekcmosgj.execute-api.us-east-1.amazonaws.com/dev/scan-cloud-infra'
try:
    req = urllib.request.Request(url, data=b'{}', method='POST')
    req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=10) as r:
        print(f'  Status: {r.status}  (no auth - unexpected 200)')
except urllib.error.HTTPError as e:
    body = e.read().decode()[:200]
    print(f'  Status: {e.code}  body: {body}')
    if e.code == 401:
        print('  -> JWT authorizer is blocking (expected)')
    elif e.code == 403:
        print('  -> 403 Forbidden - check authorizer or CORS')
    elif e.code == 500:
        print('  -> 500 Internal Server Error - Lambda crash')
except Exception as e:
    print(f'  Network error: {e}')
