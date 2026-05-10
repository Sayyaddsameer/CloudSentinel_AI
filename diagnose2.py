import boto3, json

REGION = 'us-east-1'
lmb = boto3.client('lambda', region_name=REGION)
iam = boto3.client('iam',    region_name=REGION)

# ── 1. Invoke validate-connection Lambda directly ─────────────────────────────
print('=== Testing validate-connection Lambda directly ===')
payload = json.dumps({
    'module':    'cloud-infra',
    'accountId': '871070087236',
    'roleArn':   'arn:aws:iam::871070087236:role/cloudsentinel-scanner-role',
}).encode()
resp   = lmb.invoke(FunctionName='cloudsentinel-validate-connection', Payload=payload)
result = json.loads(resp['Payload'].read())
print('Lambda raw response:')
print(json.dumps(result, indent=2))

# Parse body if it's a string
if isinstance(result.get('body'), str):
    body = json.loads(result['body'])
    print()
    print('Parsed body:')
    print(json.dumps(body, indent=2))

# ── 2. Check scanner role existence ──────────────────────────────────────────
print()
print('=== Checking IAM roles ===')
try:
    role  = iam.get_role(RoleName='cloudsentinel-scanner-role')
    trust = role['Role']['AssumeRolePolicyDocument']
    print('cloudsentinel-scanner-role EXISTS')
    print('Trust policy:', json.dumps(trust, indent=2))
except iam.exceptions.NoSuchEntityException:
    print('cloudsentinel-scanner-role DOES NOT EXIST in this account!')
    print()
    print('Listing all roles with cloudsentinel or scanner:')
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for r in page['Roles']:
            name = r['RoleName']
            if 'cloudsentinel' in name.lower() or 'scanner' in name.lower():
                print(' ', name)

# ── 3. Lambda role permissions ────────────────────────────────────────────────
print()
print('=== cloudsentinel-lambda-role permissions ===')
LAMBDA_ROLE = 'cloudsentinel-lambda-role'
try:
    policies = iam.list_role_policies(RoleName=LAMBDA_ROLE).get('PolicyNames', [])
    attached = iam.list_attached_role_policies(RoleName=LAMBDA_ROLE).get('AttachedPolicies', [])
    print('Inline policies:', policies)
    print('Attached policies:', [p['PolicyName'] for p in attached])

    # Check for sts:AssumeRole permission
    for pname in policies:
        doc = iam.get_role_policy(RoleName=LAMBDA_ROLE, PolicyName=pname)
        policy_doc = doc['PolicyDocument']
        doc_str = json.dumps(policy_doc)
        if 'AssumeRole' in doc_str or 'sts' in doc_str:
            print(f'  Policy {pname} contains sts:AssumeRole - OK')
        else:
            print(f'  Policy {pname} does NOT mention sts:AssumeRole')
        print(json.dumps(policy_doc, indent=2))
except Exception as e:
    print('Error:', e)
