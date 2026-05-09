# CloudSentinel AI -- Deployment Guide

Two deployment paths are supported. Path A uses Terraform and is recommended
for team or production deployments. Path B is a Python script that does the
same thing without requiring Terraform.

| Path | Best For | Prerequisites |
|------|----------|---------------|
| A -- Terraform | Team or production deployments | Terraform >= 1.6, AWS CLI, Python 3.11 |
| B -- Console Script | Personal or demo deployments | Python >= 3.9, AWS CLI |

---

## Prerequisites (Both Paths)

### AWS CLI and Credentials

```bash
aws --version           # verify installed
aws configure           # set Access Key, Secret, Region, Output
```

Your IAM user/role needs: Lambda, DynamoDB, S3, IAM, Cognito, API Gateway, SNS,
EventBridge, STS, Secrets Manager, and CloudFormation permissions.
For a dev environment, AdministratorAccess is the quickest option.

### Amazon Bedrock Model Access

The AI explanation feature requires manual model activation:

1. Open the [AWS Console](https://console.aws.amazon.com/bedrock/)
2. Go to **Bedrock > Model access > Manage model access**
3. Enable **Anthropic Claude 3 Haiku**
4. Wait until status shows **Access granted**

If Bedrock access is not yet granted, the platform falls back to the built-in
rule-based chatbot. All other features work normally.

---

## Path A -- Terraform

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars -- fill in alert_email and environment at minimum

# Windows
..\deploy_terraform.ps1

# Linux / macOS
bash ../deploy_terraform.sh
```

**Required variables:**

| Variable | Description |
|----------|-------------|
| `alert_email` | Email for SNS risk alert notifications |
| `environment` | `dev`, `staging`, or `prod` |

**Optional variables:**

| Variable | Description |
|----------|-------------|
| `bedrock_model_id` | Bedrock model ID (default: Claude 3 Haiku) |
| `gcp_secret_name` | Secrets Manager name for GCP service account key |
| `target_role_arn` | Cross-account IAM role ARN for scanning |
| `app_url` | Frontend URL included in alert emails |

**Teardown:**
```bash
..\deploy_terraform.ps1 -Destroy   # Windows
bash ../deploy_terraform.sh --destroy  # Linux
```

---

## Path B -- Console Script

```bash
pip install boto3
cp deploy.env.example deploy.env
# Edit deploy.env -- fill in CS_ALERT_EMAIL and CS_REGION

python deploy_console.py --dry-run   # preview without making AWS calls
python deploy_console.py             # deploy all resources
```

The script creates in order:
1. DynamoDB table `CloudSentinelRisks` with `ModuleIndex` GSI
2. S3 artifacts bucket (private, versioned, encrypted)
3. Lambda execution IAM role
4. Cognito User Pool and App Client
5. SNS topic and email subscription
6. All Lambda functions (9 total)
7. API Gateway with Cognito JWT authorizer on all protected routes
8. EventBridge scheduled rules
9. CloudFormation template bucket (for cross-account scanner role)

---

## Post-Deploy: Attach Cognito JWT Authorizer

If you are using an existing API Gateway that was deployed without JWT auth,
run this once to secure all endpoints:

```bash
python add_jwt_authorizer.py
```

This creates a `COGNITO_USER_POOLS` authorizer and attaches it to all 8
protected methods. `OPTIONS` routes remain open for CORS preflight.

---

## Post-Deploy: Disconnect Lambda

The `/disconnect` endpoint automates credential revocation when a user
disconnects a cloud provider or their session expires. Deploy it with:

```bash
python deploy_disconnect.py
```

This creates the `cloudsentinel-disconnect-handler` Lambda and wires it to
`POST /disconnect` with Cognito JWT authorization.

---

## Frontend Deployment

After any backend change, update the frontend config in `modules/frontend/js/env.js`:

```javascript
window.ENV_COGNITO_POOL_ID   = "us-east-1_XXXXXXXXX";
window.ENV_COGNITO_CLIENT_ID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX";
window.ENV_API_URL            = "https://XXXX.execute-api.us-east-1.amazonaws.com/dev";
window.ENV_REGION             = "us-east-1";
```

Then sync all frontend files to S3:

```bash
python sync_frontend.py
```

This uploads all HTML, CSS, and JS files to the S3 static website bucket
and configures public read access with HTTPS.

**Live URLs after sync:**
```
Landing page:  http://cloudsentinel-frontend-<accountid>.s3-website-us-east-1.amazonaws.com/landing.html
Sign In:       http://cloudsentinel-frontend-<accountid>.s3-website-us-east-1.amazonaws.com/index.html
```

---

## Verifying the Deployment

```bash
API_URL="https://XXXX.execute-api.us-east-1.amazonaws.com/dev"
TOKEN="<id-token-from-cognito-login>"

# GET /risks requires auth -- should return empty list on fresh deployment
curl -s -H "Authorization: $TOKEN" "$API_URL/risks" | python -m json.tool

# POST /scan-cloud-infra requires auth and optionally a cross-account role
curl -s -X POST -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"targetRoleArn":"arn:aws:iam::123456789:role/CloudSentinel-ScannerRole"}' \
  "$API_URL/scan-cloud-infra" | python -m json.tool

# Without auth -- should return 401
curl -s "$API_URL/risks"
# Expected: {"message":"Unauthorized"}
```

---

## API Gateway Routes Reference

| Method | Path | Auth | Lambda |
|--------|------|------|--------|
| POST | /scan-cloud-infra | Cognito JWT | cloudsentinel-cloud-scanner |
| POST | /scan-devops | Cognito JWT | cloudsentinel-devops-analyzer |
| POST | /scan-fullstack | Cognito JWT | cloudsentinel-fullstack-analyzer |
| POST | /scan-data-eng | Cognito JWT | cloudsentinel-data-eng-analyzer |
| POST | /scan-mobile | Cognito JWT | cloudsentinel-mobile-analyzer |
| GET | /risks | Cognito JWT | cloudsentinel-risk-reader |
| POST | /chat | Cognito JWT | cloudsentinel-chatbot-handler |
| POST | /disconnect | Cognito JWT | cloudsentinel-disconnect-handler |
| OPTIONS | /* | NONE | MOCK (CORS preflight) |

---

## Environment Variables Reference

All Lambda environment variables are documented in `.env.example`.
No function has hardcoded values.

To change a value after deploying, update the Lambda environment variable
in the AWS Console under the function's **Configuration > Environment variables** tab.

---

## Troubleshooting

| Symptom | Resolution |
|---------|-----------|
| `ExpiredTokenException` | Run `aws configure` or refresh SSO session |
| `AccessDeniedException` | Ensure IAM has all required service permissions |
| API returns 401 on all routes | Run `python add_jwt_authorizer.py` to attach Cognito auth |
| Bedrock `ModelNotReadyException` | Grant model access in the Bedrock console |
| SNS alerts not arriving | Click the confirmation link sent to your email |
| `ResourceConflictException` on Lambda | Already exists; the script updates it automatically |
| Disconnect Lambda missing | Run `python deploy_disconnect.py` |
| Frontend shows old version | Run `python sync_frontend.py` to re-sync all files to S3 |
| Session timer resets constantly | Ensure `js/session.js` is the latest version (login-time based) |
