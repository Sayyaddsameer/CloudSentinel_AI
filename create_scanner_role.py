"""
create_scanner_role.py
Creates the cloudsentinel-scanner-role IAM role in the current AWS account.
This role is required for CloudSentinel to validate and scan AWS resources.

Run: python create_scanner_role.py
"""
import boto3, json

REGION     = 'us-east-1'
ACCOUNT_ID = boto3.client('sts', region_name=REGION).get_caller_identity()['Account']
LAMBDA_ROLE_ACCOUNT = '871070087236'   # CloudSentinel platform account

iam = boto3.client('iam', region_name=REGION)

ROLE_NAME = 'cloudsentinel-scanner-role'

# Trust policy: allow CloudSentinel Lambda role to assume this role
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":    "AllowCloudSentinelLambda",
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{LAMBDA_ROLE_ACCOUNT}:role/cloudsentinel-lambda-role"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "cloudsentinel"
                }
            }
        }
    ]
}

# Permissions the scanner needs (read-only)
SCANNER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3Read",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketPolicy",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EC2Read",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeRegions"
            ],
            "Resource": "*"
        },
        {
            "Sid": "IAMRead",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:GetUser",
                "iam:ListAccountAliases",
                "iam:ListRoles",
                "iam:GetRole",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CognitoRead",
            "Effect": "Allow",
            "Action": [
                "cognito-idp:ListUserPools",
                "cognito-idp:DescribeUserPool",
                "cognito-idp:GetUserPoolMfaConfig"
            ],
            "Resource": "*"
        },
        {
            "Sid": "APIGatewayRead",
            "Effect": "Allow",
            "Action": [
                "apigateway:GET"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DynamoDBRead",
            "Effect": "Allow",
            "Action": [
                "dynamodb:ListTables",
                "dynamodb:DescribeTable"
            ],
            "Resource": "*"
        },
        {
            "Sid": "GlueRead",
            "Effect": "Allow",
            "Action": [
                "glue:GetJobs",
                "glue:GetJobRuns",
                "glue:ListJobs"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchRead",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:GetMetricData",
                "cloudwatch:ListMetrics"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AWSConfig",
            "Effect": "Allow",
            "Action": [
                "config:DescribeConfigRules",
                "config:GetComplianceDetailsByConfigRule"
            ],
            "Resource": "*"
        },
        {
            "Sid": "STSIdentity",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}

print(f'Creating {ROLE_NAME} in account {ACCOUNT_ID}...')

# Create the role
try:
    resp = iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description='CloudSentinel read-only scanner role. Allows CloudSentinel to audit your AWS resources.',
        MaxSessionDuration=3600,
        Tags=[
            {'Key': 'Purpose',    'Value': 'CloudSentinel'},
            {'Key': 'ManagedBy',  'Value': 'cloudsentinel-platform'},
        ]
    )
    role_arn = resp['Role']['Arn']
    print(f'  [CREATED] Role ARN: {role_arn}')
except iam.exceptions.EntityAlreadyExistsException:
    role_arn = f'arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}'
    print(f'  [EXISTS] Role already exists: {role_arn}')
    # Update trust policy in case it changed
    iam.update_assume_role_policy(
        RoleName=ROLE_NAME,
        PolicyDocument=json.dumps(TRUST_POLICY)
    )
    print('  Trust policy updated.')

# Attach scanner permissions as inline policy
iam.put_role_policy(
    RoleName=ROLE_NAME,
    PolicyName='cloudsentinel-scanner-policy',
    PolicyDocument=json.dumps(SCANNER_POLICY)
)
print('  [OK] Scanner permissions attached.')

# Verify the role can be assumed
import time
print()
print('Waiting 10 seconds for IAM to propagate...')
time.sleep(10)

sts = boto3.client('sts', region_name=REGION)
try:
    test = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='cloudsentinel-test',
        ExternalId='cloudsentinel',
        DurationSeconds=900,
    )
    test_account = test['AssumedRoleUser']['Arn'].split(':')[4]
    print(f'  [OK] AssumeRole succeeded! Account: {test_account}')
except Exception as e:
    print(f'  [WARN] AssumeRole test failed: {e}')
    print('  This may resolve within 1-2 minutes due to IAM propagation delay.')

print()
print('Done! The cloudsentinel-scanner-role is ready.')
print(f'Role ARN: {role_arn}')
print()
print('Use this Role ARN when connecting in the CloudSentinel website.')
print(f'Account ID: {ACCOUNT_ID}')
