# Deployment Guide

Two ways to deploy. Pick the one that fits your setup.

| | Terraform | Console Script |
|--|-----------|---------------|
| Best for | Clean deployments, team environments | Quick personal setup, no Terraform needed |
| Needs | Terraform >= 1.6, AWS CLI, Python 3.11 | Python >= 3.9, AWS CLI |
| Teardown | One command | Manual cleanup |

---

## Before you start (both paths)

### AWS CLI

```bash
aws --version      # make sure it's installed
aws configure      # enter access key, secret, region (us-east-1), output format
```

Your IAM user or role needs permissions for: Lambda, DynamoDB, S3, IAM, Cognito, API Gateway, SNS, EventBridge, STS, Secrets Manager, Step Functions, and CloudFormation. For a personal dev account, `AdministratorAccess` is the fastest option.

### Enable Claude 3 Haiku on Bedrock

The AI explainer and chatbot won't work until you manually activate the model — AWS doesn't enable it by default.

1. Go to the [Bedrock console](https://console.aws.amazon.com/bedrock/)
2. Click **Model access** → **Manage model access**
3. Find **Anthropic Claude 3 Haiku** and enable it
4. Wait for status to show **Access granted** (usually a few minutes)

If you skip this step, the platform still works — scans run, risks are stored, alerts fire. The AI explanations and chatbot just fall back to basic responses.

---

## Path A — Terraform

This is the recommended way. Terraform handles all the resource dependencies in the right order and makes teardown clean.

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
```

Open `terraform.tfvars` and fill in at least these two:

| Variable | What to set |
|----------|-------------|
| `alert_email` | Where SNS risk alerts should go. You'll get a confirmation email — click it or alerts won't deliver. |
| `environment` | `dev`, `staging`, or `prod` |

Optional but useful:

| Variable | What it does |
|----------|-------------|
| `gcp_secret_name` | Name of the Secrets Manager secret holding your GCP service account key. Omit if you're only scanning AWS. |
| `target_role_arn` | Cross-account IAM role ARN if you want to scan a different AWS account. Leave empty to scan the same account. |
| `default_github_repo` | GitHub repo for the DevOps scanner in `owner/repo` format. |
| `ignored_resources` | Comma-separated resource names to suppress from the dashboard (e.g. a bucket that's intentionally public). |
| `bedrock_model_id` | Defaults to Claude 3 Haiku. Change if you want to try a different model. |

Then run:

```bash
# Windows
..\deploy_terraform.ps1

# Linux / macOS
bash ../deploy_terraform.sh
```

**To tear everything down:**
```bash
..\deploy_terraform.ps1 -Destroy      # Windows
bash ../deploy_terraform.sh --destroy  # Linux
```

---

## Path B — Console Script

If you don't want to install Terraform, the Python deploy script does the same thing using boto3 API calls.

```bash
pip install boto3
cp deploy.env.example deploy.env
# Edit deploy.env — set CS_ALERT_EMAIL and CS_REGION at minimum
python deploy_console.py --dry-run   # see what it would create without actually doing it
python deploy_console.py             # deploy everything
```

The script creates resources in this order:
1. DynamoDB table (with module-index and priority-index GSIs)
2. S3 artifacts bucket
3. Lambda execution IAM role
4. Cognito User Pool and App Client
5. SNS topic + email subscription
6. All Lambda functions
7. API Gateway with Cognito JWT authorizer on all protected routes
8. EventBridge scheduled rules (hourly AI explainer, daily full scan)
9. CloudFormation template bucket (for cross-account scanner role)

---

## After deploy: configure the frontend

The frontend reads its config from `modules/frontend/js/env.js`. After deployment, copy the example file and fill in the values from your terraform outputs or the AWS console:

```bash
cp modules/frontend/js/env.js.example modules/frontend/js/env.js
```

Then edit `env.js`:
```javascript
window.ENV_COGNITO_POOL_ID    = "us-east-1_XXXXXXXXX";      // Cognito → User pools → Pool ID
window.ENV_COGNITO_CLIENT_ID  = "xxxxxxxxxxxxxxxxxxxx";      // Cognito → App clients → Client ID
window.ENV_API_URL             = "https://XXXX.execute-api.us-east-1.amazonaws.com/dev";
window.ENV_REGION              = "us-east-1";
window.ENV_CFN_TEMPLATE_URL    = "https://your-bucket.s3.amazonaws.com/scanner-role.yaml";
window.ENV_LAMBDA_ROLE_ARN     = "arn:aws:iam::ACCOUNT_ID:role/cloudsentinel-lambda-role";
```

Then sync the frontend to S3:
```bash
python sync_frontend.py
```

Don't commit `env.js` — it's in `.gitignore`. The `.example` file is what's tracked.

---

## Verify the deployment

After everything is up, do a quick sanity check:

```bash
API_URL="https://XXXX.execute-api.us-east-1.amazonaws.com/dev"
TOKEN="<id-token from signing in to the portal>"

# Should return an empty list on a fresh deploy
curl -s -H "Authorization: $TOKEN" "$API_URL/risks" | python -m json.tool

# Without a token — should get 401 back
curl -s "$API_URL/risks"
# Expected: {"message":"Unauthorized"}

# Trigger a scan
curl -s -X POST -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{}' "$API_URL/scan-cloud-infra" | python -m json.tool
```

---

## API routes reference

| Method | Route | Auth | Lambda |
|--------|-------|------|--------|
| POST | /scan-cloud-infra | Cognito JWT | cloudsentinel-cloud-scanner |
| POST | /scan-devops | Cognito JWT | cloudsentinel-devops-analyzer |
| POST | /scan-fullstack | Cognito JWT | cloudsentinel-fullstack-analyzer |
| POST | /scan-data-eng | Cognito JWT | cloudsentinel-data-eng-analyzer |
| POST | /scan-mobile | Cognito JWT | cloudsentinel-mobile-analyzer |
| GET | /risks | Cognito JWT | cloudsentinel-risk-reader |
| POST | /generate-report | Cognito JWT | cloudsentinel-pdf-generator |
| POST | /chat | Cognito JWT | cloudsentinel-chatbot-handler |
| POST | /disconnect | Cognito JWT | cloudsentinel-disconnect-handler |
| OPTIONS | /* | None | CORS preflight (MOCK) |

---

## Environment variables

All Lambda environment variables are configured through Terraform (or the console script). None of the functions have hardcoded values. If you need to change something after deploy — say, increase `MAX_TOKENS` for the AI explainer — go to the Lambda in the AWS Console → Configuration → Environment variables.

Key variables per function:

| Function | Key Variables |
|----------|--------------|
| cloud-scanner | `DYNAMODB_TABLE`, `GCP_SECRET_NAME`, `TARGET_ROLE_ARN` |
| ai-explainer | `DYNAMODB_TABLE`, `AI_MODEL`, `AI_API_KEY`, `MAX_RISKS_PER_RUN` |
| risk-reader | `DYNAMODB_TABLE`, `RISKS_PAGE_LIMIT`, `IGNORED_RESOURCES` |
| devops-analyzer | `DYNAMODB_TABLE`, `GITHUB_PAT_SECRET_ARN`, `DEFAULT_GITHUB_REPO` |
| pdf-generator | `DYNAMODB_TABLE`, `REPORTS_BUCKET`, `PRESIGNED_URL_EXPIRY` |
| disconnect-handler | `DYNAMODB_TABLE`, `GCP_SECRET_PREFIX`, `DEFAULT_CFN_STACK` |
| chatbot-handler | `DYNAMODB_TABLE`, `AI_MODEL`, `AI_API_KEY`, `IGNORED_RESOURCES` |

---

## Common issues

| What happened | What to do |
|---------------|------------|
| `ExpiredTokenException` | Run `aws configure` again or refresh your SSO session |
| `AccessDeniedException` | Your IAM user is missing permissions for one of the services |
| All API routes return 401 | Run `python add_jwt_authorizer.py` to attach the Cognito authorizer |
| Bedrock `ModelNotReadyException` | You haven't enabled Claude 3 Haiku in the Bedrock console yet |
| SNS alerts not arriving | Click the confirmation link in the subscription email |
| `ResourceConflictException` on Lambda deploy | The function already exists — the script will update it automatically |
| Frontend shows outdated config | Re-run `python sync_frontend.py` after updating `env.js` |
| Session timer resets on every page load | Check that `js/session.js` is using the login-time-based approach, not page-load-based |
