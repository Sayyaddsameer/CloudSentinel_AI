"""
update_notification_lambda.py
Updates the deployed cloudsentinel-notification-handler Lambda with the
fixed code and ensures the SNS_TOPIC_ARN environment variable is set.

Usage:
    python update_notification_lambda.py
"""
import boto3
import zipfile
import os
import io
import json
import time

REGION     = 'us-east-1'
ACCOUNT_ID = '871070087236'
PROJECT    = 'cloudsentinel'
FN_NAME    = f'{PROJECT}-notification-handler'

CLOUD_INFRA_DIR = os.path.join(os.path.dirname(__file__), 'modules', 'cloud-infra')

lmb = boto3.client('lambda', region_name=REGION)
sns = boto3.client('sns',    region_name=REGION)

# ── 1. Find the SNS topic ARN ────────────────────────────────────────────────
print('Looking up SNS topic ARN...')
topics = sns.list_topics().get('Topics', [])
topic_arn = None
for t in topics:
    if f'{PROJECT}-alerts' in t['TopicArn']:
        topic_arn = t['TopicArn']
        break

if not topic_arn:
    print('[WARN] SNS topic not found! Creating cloudsentinel-alerts topic...')
    resp      = sns.create_topic(Name=f'{PROJECT}-alerts', Attributes={'DisplayName': 'CloudSentinel Risk Alerts'})
    topic_arn = resp['TopicArn']
    print(f'  Created topic: {topic_arn}')
    print()
    print('[ACTION REQUIRED] Enter your email to subscribe to SNS alerts:')
    email = input('  Alert email address: ').strip()
    if email:
        sns.subscribe(TopicArn=topic_arn, Protocol='email', Endpoint=email)
        print(f'  Subscription created. CHECK YOUR EMAIL and click "Confirm subscription"!')
else:
    print(f'  Found topic: {topic_arn}')

# ── 2. Check subscription confirmation ──────────────────────────────────────
subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn).get('Subscriptions', [])
confirmed = [s for s in subs if s.get('SubscriptionArn', '').startswith('arn:')]
pending   = [s for s in subs if s.get('SubscriptionArn') == 'PendingConfirmation']

if confirmed:
    print(f'  Confirmed subscriptions: {[s["Endpoint"] for s in confirmed]}')
elif pending:
    print()
    print('[WARNING] SNS subscription is PENDING CONFIRMATION!')
    print(f'  Pending for: {[s["Endpoint"] for s in pending]}')
    print('  Check your email and click "Confirm subscription" before alerts will work.')
else:
    print('[WARN] No email subscriptions found on this topic.')

# ── 3. Build updated ZIP ─────────────────────────────────────────────────────
print('\nBuilding updated Lambda ZIP...')
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    for fname in os.listdir(CLOUD_INFRA_DIR):
        if fname.endswith('.py'):
            zf.write(os.path.join(CLOUD_INFRA_DIR, fname), fname)
zip_bytes = buf.getvalue()
print(f'  ZIP size: {len(zip_bytes):,} bytes')

# ── 4. Update Lambda code ────────────────────────────────────────────────────
print(f'\nUpdating Lambda function: {FN_NAME}...')
try:
    lmb.update_function_code(FunctionName=FN_NAME, ZipFile=zip_bytes)
    time.sleep(3)   # wait for update to propagate
    print('  Code updated.')
except lmb.exceptions.ResourceNotFoundException:
    print(f'[ERROR] Lambda {FN_NAME} not found. Run deploy_console.py first.')
    exit(1)

# ── 5. Update environment variables ─────────────────────────────────────────
print('Updating environment variables...')
# Get current env vars to preserve existing ones
current = lmb.get_function_configuration(FunctionName=FN_NAME)
env     = current.get('Environment', {}).get('Variables', {})

# Determine threshold (ask user if not already set)
current_threshold = env.get('NOTIFICATION_THRESHOLD', 'High')
print(f'  Current NOTIFICATION_THRESHOLD: {current_threshold}')
print('  Options: High | Medium | All')
threshold = input(f'  Set threshold [{current_threshold}]: ').strip() or current_threshold
if threshold not in ('High', 'Medium', 'All'):
    threshold = 'High'

# Determine APP_URL
current_url = env.get('APP_URL', '')
app_url = input(f'  Amplify APP_URL (press Enter to keep [{current_url}]): ').strip() or current_url

env.update({
    'SNS_TOPIC_ARN':          topic_arn,
    'NOTIFICATION_THRESHOLD': threshold,
    'APP_URL':                app_url,
})

lmb.update_function_configuration(
    FunctionName=FN_NAME,
    Environment={'Variables': env},
)
print('  Environment variables updated.')

print()
print('[OK] Notification Lambda updated successfully!')
print(f'  Function:  {FN_NAME}')
print(f'  SNS Topic: {topic_arn}')
print(f'  Threshold: {threshold} (alerts sent for {threshold}-priority risks and above)')
if pending:
    print()
    print('[IMPORTANT] Still waiting for SNS email confirmation!')
    print('  No alerts will be delivered until you click the confirmation link.')
