"""
sync_frontend.py — Upload all frontend files to S3 with website hosting.
Creates bucket if needed, enables public static website hosting.
"""
import boto3, mimetypes, os
from pathlib import Path

BUCKET   = 'cloudsentinel-frontend-871070087236'
REGION   = 'us-east-1'
FRONTEND = Path(r'd:\project_related\CloudSentinel_AI\modules\frontend')

s3 = boto3.client('s3', region_name=REGION)

# ── Create bucket if missing ────────────────────────────────────────
try:
    s3.head_bucket(Bucket=BUCKET)
    print(f'Bucket exists: {BUCKET}')
except:
    s3.create_bucket(Bucket=BUCKET)
    print(f'Created bucket: {BUCKET}')

# ── Disable Block Public Access ─────────────────────────────────────
s3.put_public_access_block(
    Bucket=BUCKET,
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False,
    }
)

# ── Bucket policy — public read ─────────────────────────────────────
import json
policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*"
    }]
})
s3.put_bucket_policy(Bucket=BUCKET, Policy=policy)

# ── Enable website hosting ──────────────────────────────────────────
s3.put_bucket_website(
    Bucket=BUCKET,
    WebsiteConfiguration={
        'IndexDocument': {'Suffix': 'landing.html'},
        'ErrorDocument': {'Key': 'index.html'},
    }
)

# ── Upload all files ────────────────────────────────────────────────
EXTENSIONS = {'.html', '.css', '.js', '.png', '.jpg', '.svg', '.ico', '.json', '.webp', '.woff', '.woff2'}
uploaded = 0
skipped  = 0

for fpath in FRONTEND.rglob('*'):
    if fpath.is_dir():
        continue
    if fpath.suffix.lower() not in EXTENSIONS:
        skipped += 1
        continue
    # Relative key preserving subdirectory structure
    key = fpath.relative_to(FRONTEND).as_posix()
    content_type, _ = mimetypes.guess_type(str(fpath))
    content_type = content_type or 'application/octet-stream'
    try:
        s3.upload_file(
            str(fpath), BUCKET, key,
            ExtraArgs={'ContentType': content_type}
        )
        print(f'  [UP] {key}')
        uploaded += 1
    except Exception as e:
        print(f'  [ERR] {key}: {e}')

print()
print(f'Uploaded: {uploaded} files, Skipped: {skipped} files')
print()
print(f'Website URL: http://{BUCKET}.s3-website-{REGION}.amazonaws.com/landing.html')
print(f'Sign In URL: http://{BUCKET}.s3-website-{REGION}.amazonaws.com/index.html')
