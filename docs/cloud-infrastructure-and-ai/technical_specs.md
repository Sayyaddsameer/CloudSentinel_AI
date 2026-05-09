# Technical Specs — My Lambdas
## Sayyad Sameer

Quick reference for all the Lambda functions I own. Useful for when I need to update them or debug something during integration.

---

## cloud-scanner

- **Function name:** `cloudsentinel-cloud-scanner`
- **Runtime:** Python 3.11
- **Handler:** `cloud_scanner.lambda_handler`
- **Timeout:** 300 seconds — it scans all S3 buckets + security groups so can take a while
- **Memory:** 256 MB
- **Trigger:** API Gateway POST /scan-cloud
- **Env:** `DYNAMODB_TABLE=cloudsentinel-risks`

Input: just an empty `{}` — it reads everything directly from AWS APIs using the execution role

Output:
```json
{ "statusCode": 200, "body": "{\"message\": \"Scan complete\", \"risksFound\": 5}" }
```

APIs I call:
- `s3.list_buckets()` → iterate each bucket
- `s3.get_public_access_block(Bucket=name)` → if this raises NoSuchPublicAccessBlockConfiguration, that itself is a High risk
- `s3.get_bucket_encryption(Bucket=name)` → if ServerSideEncryptionConfigurationNotFoundError, Medium risk
- `ec2.describe_security_groups()` → check IpPermissions for 0.0.0.0/0 rules
- `iam.get_account_password_policy()` → catches exception if no policy exists

I wrap each resource scan in try/except so one bad bucket doesn't crash the whole scan.

---

## ai-explainer

- **Function name:** `cloudsentinel-ai-explainer`
- **Runtime:** Python 3.11
- **Handler:** `ai_explainer.lambda_handler`
- **Timeout:** 300 seconds
- **Memory:** 256 MB
- **Trigger:** Manual or EventBridge (TODO: set up the schedule)
- **Env:** `DYNAMODB_TABLE=cloudsentinel-risks`

Flow: scan DynamoDB for items where `status=OPEN` and `aiExplanation=""`, build a prompt for each, call Bedrock, update the item.

Bedrock model I use: `anthropic.claude-3-haiku-20240307-v1:0`

Prompt structure that works well:
```
You are a cloud security expert explaining risks to a junior developer.

Resource: {resource} called {resourceName}
Risk: {riskType}
Why it matters: {riskReason}
Priority: {riskPriority}

Write under 200 words. Cover: what this means, why it's dangerous, and one action to fix it.
```

Bedrock request body format — have to include `anthropic_version` or it throws an error:
```json
{
  "anthropic_version": "bedrock-2023-05-31",
  "max_tokens": 400,
  "messages": [{"role": "user", "content": "<prompt>"}]
}
```

---

## chatbot-handler

- **Function name:** `cloudsentinel-chatbot-handler`
- **Timeout:** 60 seconds
- **Trigger:** POST /chat

Input:
```json
{ "question": "what are my high priority risks?", "module": "cloud-infra" }
```

Output:
```json
{ "statusCode": 200, "body": "{\"answer\": \"...\"}" }
```

It fetches the top 20 risks for the given module from DynamoDB and passes them as context when calling Bedrock. That's what makes the chatbot actually useful — it knows the user's specific risks, not just generic cloud security info.

---

## risk-reader

- **Function name:** `cloudsentinel-risk-reader`
- **Timeout:** 30 seconds
- **Memory:** 128 MB — lightweight, just reads DynamoDB
- **Trigger:** GET /risks?module=cloud-infra

If `module` param is given → query `module-index` GSI
If no param → full table scan (limit 100)

Always includes CORS header `Access-Control-Allow-Origin: *` in the response so Akash's frontend doesn't hit CORS errors.

---

## DynamoDB schema (for reference)

Every module writes records in this format. The `aiExplanation` starts empty — my ai-explainer fills it in.

```
resourceId       → partition key, format: {module}-{resource-type}-{name}
riskTimestamp    → sort key, ISO 8601
module           → which team member's engine detected it
cloudProvider    → AWS (GCP planned for v2)
resource         → e.g., "S3 Bucket", "EC2 Security Group"
resourceName     → the actual name
riskType         → short label
riskReason       → explanation of why it's risky
riskPriority     → High / Medium / Low
remediationSteps → list of strings
alternativeSolutions → list of strings
aiExplanation    → filled by ai-explainer Lambda
status           → OPEN / IN_PROGRESS / RESOLVED
region           → us-east-1
```

---

## .gitignore additions I added

```
terraform.tfstate
terraform.tfstate.backup
.terraform/
*.zip
__pycache__/
package/
.env
```
