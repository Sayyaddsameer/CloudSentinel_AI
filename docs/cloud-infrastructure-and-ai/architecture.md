# Cloud Infrastructure Intelligence -- Architecture

## Overview

The Cloud Infrastructure module is the primary scanner module of CloudSentinel AI.
It connects to an AWS account via a read-only cross-account IAM role deployed
through CloudFormation, and optionally to GCP via a service account key stored
in AWS Secrets Manager.

---

## Components

### Lambda Functions

| Function | Handler | Trigger | Purpose |
|----------|---------|---------|---------|
| `cloudsentinel-cloud-scanner` | `cloud_scanner.lambda_handler` | API Gateway POST /scan-cloud-infra | Scans AWS/GCP resources for misconfigurations |
| `cloudsentinel-risk-reader` | `risk_reader.lambda_handler` | API Gateway GET /risks | Reads risk records from DynamoDB |
| `cloudsentinel-chatbot-handler` | `chatbot_handler.lambda_handler` | API Gateway POST /chat | AI chatbot with Bedrock + rule-based fallback |
| `cloudsentinel-ai-explainer` | `ai_explainer.lambda_handler` | EventBridge (hourly) | Enriches risks with AI explanations |
| `cloudsentinel-notification-handler` | `notification_handler.lambda_handler` | EventBridge (ScanCompleted) | Sends SNS email alerts for High risks |
| `cloudsentinel-disconnect-handler` | `disconnect_handler.lambda_handler` | API Gateway POST /disconnect | Revokes access: deletes CFN stack, GCP secret, DynamoDB risks |

---

## Data Flow

```
1. User connects AWS account
   Frontend --> CloudFormation one-click URL --> creates CloudSentinel-ScannerRole in user account

2. User clicks "Scan Now"
   Frontend --> POST /scan-cloud-infra (Cognito JWT required)
   --> cloud-scanner Lambda
         --> STS AssumeRole (into user account)
         --> Boto3 clients: iam, s3, ec2, config
         --> Scan checks run in parallel
         --> Each finding: build_risk() --> DynamoDB put_item

3. AI Enrichment (async, hourly)
   EventBridge --> ai-explainer Lambda
   --> Query DynamoDB for risks with empty aiExplanation
   --> Bedrock InvokeModel (Claude 3 Haiku)
   --> Update DynamoDB item with AI explanation

4. Display results
   Frontend --> GET /risks?module=cloud-infra (Cognito JWT required)
   --> risk-reader Lambda
   --> DynamoDB Query on ModuleIndex GSI
   --> Deduplicated, sorted by timestamp

5. User disconnects
   Frontend --> POST /disconnect (Cognito JWT required)
   --> disconnect-handler Lambda
         --> STS AssumeRole --> cloudformation:DeleteStack
         --> Secrets Manager: delete GCP credentials
         --> DynamoDB: batch delete all risk records for module

6. Session expiry
   session.js: _doAutoLogout()
   --> autoDisconnectAll() for every connected module
   --> Same as step 5, runs for each module
   --> Redirect to sign-in page
```

---

## Scan Checks

### AWS Checks

| Check | Resource | Priority |
|-------|----------|----------|
| Missing IAM account password policy | IAM account | High |
| Short IAM password policy (< 8 chars) | IAM account | Medium |
| S3 bucket with public access not fully blocked | S3 bucket | High |
| EC2 security group with SSH (22) open to 0.0.0.0/0 | EC2 security group | High |
| EC2 security group with RDP (3389) open to 0.0.0.0/0 | EC2 security group | High |
| AWS Config not enabled | AWS Config | Medium |

### GCP Checks

| Check | Resource | Priority |
|-------|----------|----------|
| Firewall rule allowing SSH (22) from 0.0.0.0/0 | GCP Firewall | High |
| Firewall rule allowing RDP (3389) from 0.0.0.0/0 | GCP Firewall | High |

---

## Risk Record Schema

```json
{
  "resourceId":          "cloud-infra-S3 Bucket-my-bucket-<uuid>",
  "riskTimestamp":       "2026-05-09T20:23:17Z",
  "module":              "cloud-infra",
  "cloudProvider":       "AWS",
  "resource":            "S3 Bucket",
  "resourceName":        "my-bucket",
  "riskType":            "S3 Public Access Not Fully Blocked",
  "riskReason":          "One or more Block Public Access settings are disabled.",
  "riskPriority":        "High",
  "remediationSteps":    ["Enable Block Public Access at bucket level", "..."],
  "alternativeSolutions":["Use bucket policy to restrict access instead"],
  "aiExplanation":       "This bucket could expose sensitive data to the internet...",
  "riskCategory":        "Storage",
  "status":              "OPEN",
  "region":              "us-east-1"
}
```

---

## Chatbot Intelligence

The chatbot has two response modes:

1. **Bedrock (Claude 3)** -- used when Anthropic model access is granted in the AWS account.
   Receives the full list of detected risks as context and generates a natural language response.

2. **Rule-based fallback** -- used when Bedrock is unavailable.
   Handles questions about risk priority, remediation, comparison, and platform guidance.
   Platform-level questions ("What does CloudSentinel do?", "Which module first?") are
   answered without requiring any scan data.

---

## Security Controls

| Control | Implementation |
|---------|---------------|
| API authorization | Cognito JWT required on all endpoints |
| Cross-account access | Read-only IAM role only (no write permissions) |
| GCP credentials | Stored in Secrets Manager with KMS encryption |
| Risk deduplication | resourceId collision detection at write time |
| Credential revocation | Automated on disconnect via disconnect_handler |
| Session management | Login-time based timer; auto-logout revokes all credentials |
