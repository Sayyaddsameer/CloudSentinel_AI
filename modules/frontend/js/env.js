/**
 * env.js — Runtime environment configuration for CloudSentinel
 *
 * All values here are injected by the deployment script (deploy_console.py)
 * or set manually after running: python deploy_console.py
 *
 * Required variables:
 *   COGNITO_POOL_ID    — Cognito User Pool ID
 *   COGNITO_CLIENT_ID  — Cognito App Client ID (no secret)
 *   API_URL            — API Gateway invoke URL
 *   REGION             — AWS region
 *   CFN_TEMPLATE_URL   — Public S3 URL for the scanner CloudFormation template
 *   LAMBDA_ROLE_ARN    — ARN of the CloudSentinel Lambda execution role
 *                        (pre-fills the CloudFormation trust policy parameter)
 *
 * NEVER commit real credentials or secrets here.
 * These non-secret deployment outputs are safe to store here.
 */

window.ENV_COGNITO_POOL_ID   = "us-east-1_nsa2fJTq6";
window.ENV_COGNITO_CLIENT_ID = "2oic9j2thbd97o9phnj2fuuh1l";
window.ENV_API_URL            = "https://cbrg5o4rv9.execute-api.us-east-1.amazonaws.com/dev";
window.ENV_REGION             = "us-east-1";
window.ENV_CFN_TEMPLATE_URL   = "https://cloudsentinel-cf-templates-871070087236.s3.amazonaws.com/scanner-role.yaml";
window.ENV_LAMBDA_ROLE_ARN    = "arn:aws:iam::871070087236:role/cloudsentinel-lambda-role";
