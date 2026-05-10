"""
deep_diagnose.py — Checks every possible failure point in the scan flow.
Run: python deep_diagnose.py
"""
import boto3, json, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta

REGION      = 'us-east-1'
API_BASE    = 'https://ojekcmosgj.execute-api.us-east-1.amazonaws.com/dev'
TABLE_NAME  = 'cloudsentinel-risks'
ACCOUNT_ID  = '871070087236'

ddb  = boto3.client('dynamodb',   region_name=REGION)
lmb  = boto3.client('lambda',     region_name=REGION)
apigw= boto3.client('apigateway', region_name=REGION)
logs = boto3.client('logs',       region_name=REGION)

PASS = '  [PASS]'
FAIL = '  [FAIL]'
WARN = '  [WARN]'
INFO = '  [INFO]'

print('=' * 60)
print('  CloudSentinel Full Scan-Flow Diagnostic')
print('=' * 60)

# ── 1. DynamoDB table health ──────────────────────────────────
print('\n[1] DynamoDB Table')
try:
    t = ddb.describe_table(TableName=TABLE_NAME)['Table']
    status = t['TableStatus']
    count  = t.get('ItemCount', 0)
    print(f'{PASS} Table exists: {TABLE_NAME}  status={status}  items={count}')

    # Count by module
    modules = ['cloud-infra', 'fullstack', 'devops', 'mobile', 'data-eng']
    for mod in modules:
        resp = ddb.query(
            TableName=TABLE_NAME,
            IndexName='module-index',
            KeyConditionExpression='#m = :m',
            ExpressionAttributeNames={'#m': 'module'},
            ExpressionAttributeValues={':m': {'S': mod}},
            Select='COUNT',
        )
        cnt = resp['Count']
        mark = PASS if cnt > 0 else WARN
        print(f'{mark} Module {mod:<20} {cnt} risk records in DynamoDB')
except Exception as e:
    print(f'{FAIL} DynamoDB error: {e}')

# ── 2. API endpoints reachable ────────────────────────────────
print('\n[2] API Gateway Endpoints')
ENDPOINTS = [
    ('/risks',               'GET',  None),
    ('/scan-cloud-infra',    'POST', '{}'),
    ('/validate-connection', 'POST', '{"module":"cloud-infra","accountId":"000000000000"}'),
    ('/notify',              'POST', '{"module":"cloud-infra"}'),
    ('/disconnect',          'POST', '{"module":"cloud-infra","resourceType":"all"}'),
]

for path, method, body in ENDPOINTS:
    url = API_BASE + path
    try:
        data = body.encode() if body else None
        req  = urllib.request.Request(url, data=data, method=method)
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=8) as r:
            print(f'{PASS} {method:6} {path:<30} → {r.status}')
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print(f'{PASS} {method:6} {path:<30} → {e.code} (auth required - expected)')
        elif e.code == 200:
            print(f'{PASS} {method:6} {path:<30} → {e.code}')
        else:
            body_text = e.read().decode()[:200]
            print(f'{FAIL} {method:6} {path:<30} → {e.code} {body_text}')
    except Exception as e:
        print(f'{FAIL} {method:6} {path:<30} → {e}')

# ── 3. Lambda configs ─────────────────────────────────────────
print('\n[3] Lambda Functions')
LAMBDAS = [
    ('cloudsentinel-cloud-scanner',      'cloud_scanner.lambda_handler'),
    ('cloudsentinel-validate-connection','validate_connection.lambda_handler'),
    ('cloudsentinel-notification-handler','notification_handler.lambda_handler'),
    ('cloudsentinel-risk-reader',        'risk_reader.lambda_handler'),
    ('cloudsentinel-mobile-analyzer',    'mobile_analyzer.lambda_handler'),
    ('cloudsentinel-fullstack-analyzer', 'fullstack_analyzer.lambda_handler'),
    ('cloudsentinel-devops-analyzer',    'devops_analyzer.lambda_handler'),
    ('cloudsentinel-data-eng-analyzer',  'data_eng_analyzer.lambda_handler'),
]

for fn_name, expected_handler in LAMBDAS:
    try:
        c = lmb.get_function_configuration(FunctionName=fn_name)
        handler = c.get('Handler', '')
        status  = c.get('LastUpdateStatus', '?')
        env     = c.get('Environment', {}).get('Variables', {})

        issues = []
        if handler != expected_handler:
            issues.append(f'handler mismatch: got {handler}')
        if 'DYNAMODB_TABLE' not in env:
            issues.append('missing DYNAMODB_TABLE env var')
        if status != 'Successful':
            issues.append(f'update status={status}')

        if issues:
            print(f'{FAIL} {fn_name}')
            for i in issues:
                print(f'         > {i}')
        else:
            ddb_val = env.get('DYNAMODB_TABLE', '?')
            print(f'{PASS} {fn_name:<45} handler OK  DYNAMODB_TABLE={ddb_val}')
    except lmb.exceptions.ResourceNotFoundException:
        print(f'{FAIL} {fn_name} — NOT FOUND')
    except Exception as e:
        print(f'{WARN} {fn_name}: {e}')

# ── 4. Recent scan errors ─────────────────────────────────────
print('\n[4] Recent Errors in CloudWatch (last 6 hours)')
since_ms = int((datetime.now(timezone.utc) - timedelta(hours=6)).timestamp() * 1000)
SCAN_GROUPS = [
    '/aws/lambda/cloudsentinel-cloud-scanner',
    '/aws/lambda/cloudsentinel-mobile-analyzer',
    '/aws/lambda/cloudsentinel-fullstack-analyzer',
    '/aws/lambda/cloudsentinel-devops-analyzer',
    '/aws/lambda/cloudsentinel-data-eng-analyzer',
    '/aws/lambda/cloudsentinel-validate-connection',
]
for lg in SCAN_GROUPS:
    fn_short = lg.split('/')[-1]
    try:
        streams = logs.describe_log_streams(
            logGroupName=lg, orderBy='LastEventTime', descending=True, limit=1
        ).get('logStreams', [])
        if not streams:
            print(f'{INFO} {fn_short}: no invocations yet')
            continue
        events = logs.get_log_events(
            logGroupName=lg,
            logStreamName=streams[0]['logStreamName'],
            startTime=since_ms, limit=80
        ).get('events', [])
        errors = [e['message'].strip() for e in events
                  if any(w in e['message'] for w in ('ERROR', 'Exception', 'Error', 'FAILED', 'Traceback'))]
        if errors:
            print(f'{FAIL} {fn_short}: {len(errors)} error(s)')
            for err in errors[-5:]:
                print(f'         > {err[:120]}')
        else:
            print(f'{PASS} {fn_short}: no errors in last 6 hours ({len(events)} log lines)')
    except logs.exceptions.ResourceNotFoundException:
        print(f'{INFO} {fn_short}: never invoked (no log group)')
    except Exception as e:
        print(f'{WARN} {fn_short}: {e}')

# ── 5. S3 frontend — check key JS files have right content ────
print('\n[5] Frontend JS on S3')
S3_BUCKET = f'cloudsentinel-frontend-{ACCOUNT_ID}'
JS_CHECKS = ['js/app.js', 'js/cloud.js', 'js/mobile.js']
s3c = boto3.client('s3', region_name=REGION)
for key in JS_CHECKS:
    try:
        obj = s3c.get_object(Bucket=S3_BUCKET, Key=key)
        content = obj['Body'].read().decode()
        modified = obj['LastModified'].strftime('%Y-%m-%d %H:%M UTC')

        checks = {
            'js/app.js':    ('validateAwsConnection', 'userEmail'),
            'js/cloud.js':  ('validateAwsConnection', 'Validating AWS access'),
            'js/mobile.js': ('latencyThresholdMs', 'Validating AWS access'),
        }
        required = checks.get(key, [])
        missing = [r for r in required if r not in content]
        if missing:
            print(f'{FAIL} {key} (modified {modified}) — missing: {missing}')
        else:
            print(f'{PASS} {key} (modified {modified}) — all patches present')
    except Exception as e:
        print(f'{FAIL} {key}: {e}')

print()
print('=' * 60)
print('  Diagnostic complete')
print('=' * 60)
