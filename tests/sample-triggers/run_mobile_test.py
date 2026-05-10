#!/usr/bin/env python3
"""
run_mobile_test.py
Creates insecure mobile backend resources on AWS to test the Mobile module.

Creates:
  - Cognito User Pool (MFA OFF, weak password)  → HIGH risk
  - Overly broad Lambda IAM role                 → HIGH risk
  - Unprotected API Gateway endpoint             → HIGH risk

Usage:
    python run_mobile_test.py
    python run_mobile_test.py --cleanup
"""
import sys
import json
import boto3
import time

REGION   = 'us-east-1'
ACCOUNT  = boto3.client('sts', region_name=REGION).get_caller_identity()['Account']

cognito  = boto3.client('cognito-idp', region_name=REGION)
iam      = boto3.client('iam',         region_name=REGION)
apigw    = boto3.client('apigateway',  region_name=REGION)

POOL_NAME  = 'cloudsentinel-test-mobile-pool'
ROLE_NAME  = 'cloudsentinel-test-overly-broad-role'
API_NAME   = 'cloudsentinel-test-mobile-api'


def create_resources():
    print('Creating insecure mobile backend resources...')
    print()

    # ── 1. Cognito Pool with MFA OFF + weak password ─────────────────────────
    print('1. Creating Cognito User Pool (MFA OFF, weak password)...')
    pool = cognito.create_user_pool(
        PoolName=POOL_NAME,
        MfaConfiguration='OFF',                        # HIGH RISK
        Policies={
            'PasswordPolicy': {
                'MinimumLength':        6,             # MEDIUM RISK: should be >= 12
                'RequireUppercase':     False,
                'RequireNumbers':       False,
                'RequireSymbols':       False,
            }
        },
        UserPoolTags={'Purpose': 'CloudSentinel-Test', 'DeleteMe': 'true'},
    )
    pool_id = pool['UserPool']['Id']
    print(f'   Pool ID: {pool_id}  → RISK: MFA disabled + weak password policy')

    # ── 2. Overly broad IAM role ──────────────────────────────────────────────
    print('2. Creating overly broad Lambda IAM role...')
    try:
        iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect':    'Allow',
                    'Principal': {'Service': 'lambda.amazonaws.com'},
                    'Action':    'sts:AssumeRole',
                }]
            }),
            Tags=[{'Key': 'Purpose', 'Value': 'CloudSentinel-Test'}],
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print('   Role already exists, updating policy...')

    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName='too-broad',
        PolicyDocument=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{
                'Effect':   'Allow',
                'Action':   '*',           # HIGH RISK: wildcard permissions
                'Resource': '*',
            }]
        }),
    )
    print(f'   Role: {ROLE_NAME}  → RISK: wildcard Action:* Resource:*')

    # ── 3. API Gateway with no auth ───────────────────────────────────────────
    print('3. Creating API Gateway with unauthenticated endpoint...')
    api = apigw.create_rest_api(
        name=API_NAME,
        description='CloudSentinel test - no auth',
    )
    api_id  = api['id']
    root_id = apigw.get_resources(restApiId=api_id)['items'][0]['id']

    resource = apigw.create_resource(
        restApiId=api_id, parentId=root_id, pathPart='users'
    )
    apigw.put_method(
        restApiId=api_id,
        resourceId=resource['id'],
        httpMethod='GET',
        authorizationType='NONE',          # HIGH RISK: no authentication
    )
    print(f'   API ID: {api_id}  → RISK: GET /users has authorizationType: NONE')

    print()
    print('Resources created. Now scan the Mobile module to see the findings.')
    print()
    print('CLEANUP (run after testing):')
    print(f'  python run_mobile_test.py --cleanup')
    print()
    print(f'Cognito Pool ID:  {pool_id}')
    print(f'IAM Role:         {ROLE_NAME}')
    print(f'API Gateway ID:   {api_id}')

    # Save IDs for cleanup
    with open('.cs-mobile-test-ids.json', 'w') as f:
        json.dump({'pool_id': pool_id, 'api_id': api_id}, f)


def cleanup_resources():
    print('Cleaning up CloudSentinel mobile test resources...')

    ids = {}
    try:
        with open('.cs-mobile-test-ids.json') as f:
            ids = json.load(f)
    except FileNotFoundError:
        pass

    # Cognito pool
    pool_id = ids.get('pool_id')
    if not pool_id:
        pools = cognito.list_user_pools(MaxResults=10).get('UserPools', [])
        pool_id = next((p['Id'] for p in pools if p['Name'] == POOL_NAME), None)
    if pool_id:
        cognito.delete_user_pool(UserPoolId=pool_id)
        print(f'  Deleted Cognito pool: {pool_id}')
    else:
        print('  Cognito pool not found')

    # IAM role
    try:
        iam.delete_role_policy(RoleName=ROLE_NAME, PolicyName='too-broad')
        iam.delete_role(RoleName=ROLE_NAME)
        print(f'  Deleted IAM role: {ROLE_NAME}')
    except iam.exceptions.NoSuchEntityException:
        print('  IAM role not found')

    # API Gateway
    api_id = ids.get('api_id')
    if not api_id:
        apis = apigw.get_rest_apis()['items']
        api_id = next((a['id'] for a in apis if a['name'] == API_NAME), None)
    if api_id:
        apigw.delete_rest_api(restApiId=api_id)
        print(f'  Deleted API Gateway: {api_id}')
    else:
        print('  API Gateway not found')

    import os
    try:
        os.remove('.cs-mobile-test-ids.json')
    except FileNotFoundError:
        pass

    print('Cleanup complete.')


if __name__ == '__main__':
    if '--cleanup' in sys.argv:
        cleanup_resources()
    else:
        create_resources()
