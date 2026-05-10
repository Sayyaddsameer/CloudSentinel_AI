"""
deploy_all_changes.py
One-command deployment of ALL CloudSentinel changes:
  1. Update backend Lambda functions (all modules)
  2. Sync frontend JS/HTML/CSS to S3

Run:
    python deploy_all_changes.py

What it deploys:
  Lambdas:
    - cloudsentinel-notification-handler  (notification_handler.py fixed)
    - cloudsentinel-mobile-analyzer       (mobile_analyzer.py fixed)
    - cloudsentinel-auto-rescan-router    (already deployed, refresh code)
    - cloudsentinel-validate-connection   (already deployed, refresh code)
    - cloudsentinel-cloud-scanner         (refresh with latest cloud-infra/)
    - cloudsentinel-risk-reader           (refresh)
    - cloudsentinel-disconnect-handler    (refresh)
    - cloudsentinel-fullstack-analyzer    (refresh)
    - cloudsentinel-devops-analyzer       (refresh)
    - cloudsentinel-data-eng-analyzer     (refresh)

  Frontend:
    - All files in modules/frontend/ -> S3 cloudsentinel-frontend-871070087236
"""
import sys
import os
import io
import zipfile
import mimetypes
import time
import boto3
from botocore.exceptions import ClientError

# ── Config ───────────────────────────────────────────────────────────────────
REGION     = 'us-east-1'
ACCOUNT_ID = '871070087236'
PROJECT    = 'cloudsentinel'
ROLE_ARN   = f'arn:aws:iam::{ACCOUNT_ID}:role/cloudsentinel-lambda-role'
S3_BUCKET  = f'cloudsentinel-frontend-{ACCOUNT_ID}'

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODULES    = os.path.join(BASE_DIR, 'modules')

lmb = boto3.client('lambda', region_name=REGION)
s3  = boto3.client('s3',     region_name=REGION)

# ── Colors for terminal output ────────────────────────────────────────────────
OK  = '[OK]  '
UPD = '[UPD] '
SKP = '[SKIP]'
ERR = '[ERR] '
HDR = '\n' + '=' * 60 + '\n'

# ── Build Lambda ZIP from a source directory ──────────────────────────────────
def build_zip(source_dir: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fname in os.listdir(source_dir):
            if fname.endswith('.py'):
                zf.write(os.path.join(source_dir, fname), fname)
    return buf.getvalue()


# ── Update a Lambda function's code (create if missing) ──────────────────────
def update_lambda(fn_name: str, zip_bytes: bytes, handler: str = None,
                  env_vars: dict = None, timeout: int = None, memory: int = None):
    try:
        lmb.update_function_code(FunctionName=fn_name, ZipFile=zip_bytes)
        # Small wait for the update to settle before updating config
        time.sleep(2)
        if handler or env_vars or timeout or memory:
            cfg = {}
            if handler:   cfg['Handler']    = handler
            if timeout:   cfg['Timeout']    = timeout
            if memory:    cfg['MemorySize'] = memory
            if env_vars is not None:
                # Merge with existing env vars instead of overwriting
                cur = lmb.get_function_configuration(FunctionName=fn_name)
                merged = cur.get('Environment', {}).get('Variables', {})
                merged.update(env_vars)
                cfg['Environment'] = {'Variables': merged}
            if cfg:
                lmb.update_function_configuration(FunctionName=fn_name, **cfg)
        print(f'{UPD} {fn_name}')
        return True
    except lmb.exceptions.ResourceNotFoundException:
        print(f'{SKP} {fn_name}  (not deployed yet -- skipping)')
        return False
    except ClientError as e:
        print(f'{ERR} {fn_name}: {e}')
        return False


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Backend Lambdas
# ─────────────────────────────────────────────────────────────────────────────
print(HDR + 'PHASE 1: Updating Lambda Functions' + HDR)

# ── 1a. Cloud-Infra bundle (notification, disconnect, cloud-scanner, risk-reader,
#         auto-rescan-router, validate-connection) ─────────────────────────────
cloud_dir  = os.path.join(MODULES, 'cloud-infra')
cloud_zip  = build_zip(cloud_dir)
print(f'Built cloud-infra ZIP  ({len(cloud_zip):,} bytes)')

cloud_lambdas = [
    # (fn_suffix,              handler,                              timeout, memory, extra_env)
    ('cloud-scanner',          'cloud_scanner.lambda_handler',        300,    256,   None),
    ('risk-reader',            'risk_reader.lambda_handler',          30,     128,   None),
    ('notification-handler',   'notification_handler.lambda_handler', 30,     256,   None),
    ('disconnect-handler',     'disconnect_handler.lambda_handler',   60,     128,   None),
    ('auto-rescan-router',     'auto_rescan_router.lambda_handler',   60,     128,   {'PROJECT_NAME': PROJECT}),
    ('validate-connection',    'validate_connection.lambda_handler',  30,     128,   None),
]

for suffix, handler, timeout, memory, extra_env in cloud_lambdas:
    fn_name = f'{PROJECT}-{suffix}'
    update_lambda(fn_name, cloud_zip, handler=handler,
                  env_vars=extra_env, timeout=timeout, memory=memory)

# ── 1b. Mobile Analyzer ───────────────────────────────────────────────────────
mobile_dir = os.path.join(MODULES, 'mobile')
mobile_zip = build_zip(mobile_dir)
print(f'\nBuilt mobile ZIP       ({len(mobile_zip):,} bytes)')
update_lambda(f'{PROJECT}-mobile-analyzer', mobile_zip,
              handler='mobile_analyzer.lambda_handler', timeout=120, memory=256)

# ── 1c. Fullstack Analyzer ────────────────────────────────────────────────────
fs_dir  = os.path.join(MODULES, 'fullstack')
fs_zip  = build_zip(fs_dir)
print(f'Built fullstack ZIP    ({len(fs_zip):,} bytes)')
update_lambda(f'{PROJECT}-fullstack-analyzer', fs_zip,
              handler='fullstack_analyzer.lambda_handler', timeout=120, memory=256)

# ── 1d. DevOps Analyzer ───────────────────────────────────────────────────────
devops_dir = os.path.join(MODULES, 'devops')
devops_zip = build_zip(devops_dir)
print(f'Built devops ZIP       ({len(devops_zip):,} bytes)')
update_lambda(f'{PROJECT}-devops-analyzer', devops_zip,
              handler='devops_analyzer.lambda_handler', timeout=120, memory=256)

# ── 1e. Data Engineering Analyzer ────────────────────────────────────────────
data_dir = os.path.join(MODULES, 'data-eng')
data_zip = build_zip(data_dir)
print(f'Built data-eng ZIP     ({len(data_zip):,} bytes)')
update_lambda(f'{PROJECT}-data-eng-analyzer', data_zip,
              handler='data_eng_analyzer.lambda_handler', timeout=120, memory=256)

print('\nAll Lambda functions updated.')

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Frontend to S3
# ─────────────────────────────────────────────────────────────────────────────
print(HDR + 'PHASE 2: Syncing Frontend to S3' + HDR)

frontend_dir = os.path.join(MODULES, 'frontend')
EXTENSIONS   = {'.html', '.css', '.js', '.png', '.jpg', '.jpeg',
                '.svg', '.ico', '.json', '.webp', '.woff', '.woff2', '.txt'}

# Ensure bucket exists and is configured for static hosting
try:
    s3.head_bucket(Bucket=S3_BUCKET)
    print(f'Bucket exists: s3://{S3_BUCKET}')
except ClientError as e:
    if e.response['Error']['Code'] in ('404', 'NoSuchBucket'):
        s3.create_bucket(Bucket=S3_BUCKET)
        print(f'Created bucket: s3://{S3_BUCKET}')
    else:
        print(f'{ERR} head_bucket: {e}')

# Disable Block Public Access (needed for static website hosting)
try:
    s3.put_public_access_block(
        Bucket=S3_BUCKET,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls':       False,
            'IgnorePublicAcls':      False,
            'BlockPublicPolicy':     False,
            'RestrictPublicBuckets': False,
        }
    )
except ClientError as e:
    print(f'{ERR} put_public_access_block: {e}')

# Public read policy
import json as _json
policy = _json.dumps({
    'Version': '2012-10-17',
    'Statement': [{
        'Effect':    'Allow',
        'Principal': '*',
        'Action':    's3:GetObject',
        'Resource':  f'arn:aws:s3:::{S3_BUCKET}/*',
    }]
})
try:
    s3.put_bucket_policy(Bucket=S3_BUCKET, Policy=policy)
except ClientError as e:
    print(f'{ERR} put_bucket_policy: {e}')

# Static website config
try:
    s3.put_bucket_website(
        Bucket=S3_BUCKET,
        WebsiteConfiguration={
            'IndexDocument': {'Suffix': 'landing.html'},
            'ErrorDocument': {'Key':    'index.html'},
        }
    )
except ClientError as e:
    print(f'{ERR} put_bucket_website: {e}')

# Upload all frontend files
uploaded = 0
errors   = 0

for root, dirs, files in os.walk(frontend_dir):
    # Skip node_modules or any hidden directories
    dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
    for fname in files:
        fpath = os.path.join(root, fname)
        ext   = os.path.splitext(fname)[1].lower()
        if ext not in EXTENSIONS:
            continue
        # S3 key relative to frontend_dir, using forward slashes
        key = os.path.relpath(fpath, frontend_dir).replace('\\', '/')
        content_type, _ = mimetypes.guess_type(fpath)
        content_type = content_type or 'application/octet-stream'
        # Override for JS so browsers don't cache aggressively
        cache_control = 'no-cache' if ext in ('.js', '.css', '.html') else 'max-age=86400'
        try:
            s3.upload_file(
                fpath, S3_BUCKET, key,
                ExtraArgs={
                    'ContentType':  content_type,
                    'CacheControl': cache_control,
                }
            )
            print(f'  {OK} {key}')
            uploaded += 1
        except ClientError as e:
            print(f'  {ERR} {key}: {e}')
            errors += 1

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
print(HDR + 'DEPLOYMENT COMPLETE' + HDR)
print(f'  Lambda functions: {len(cloud_lambdas) + 4} updated')
print(f'  Frontend files:   {uploaded} uploaded, {errors} errors')
print()
print('  Live URLs:')
print(f'    Landing : http://{S3_BUCKET}.s3-website-{REGION}.amazonaws.com/landing.html')
print(f'    Sign In : http://{S3_BUCKET}.s3-website-{REGION}.amazonaws.com/index.html')
print(f'    Dashboard: http://{S3_BUCKET}.s3-website-{REGION}.amazonaws.com/dashboard.html')
print()
print('  API Base: https://ojekcmosgj.execute-api.us-east-1.amazonaws.com/dev')
print()
if errors:
    print(f'[WARN] {errors} file(s) failed to upload — check errors above.')
else:
    print('[OK] All files deployed successfully!')
