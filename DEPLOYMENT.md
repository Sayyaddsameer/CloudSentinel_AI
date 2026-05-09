# CloudSentinel — Deployment Guide

There are two ways to deploy CloudSentinel. Pick whichever matches your setup.
Path A uses Terraform and is the one we recommend for team or production deployments.
Path B is a Python script that does the same thing without needing Terraform installed.

| Path | Best For | Prerequisites |
|---|---|---|
| A — Terraform | Team deployments, repeatable infrastructure | Terraform >= 1.6, AWS CLI |
| B — Console Script | Personal use, no Terraform installed | Python >= 3.9, AWS CLI |

---

## Prerequisites (Both Paths)

### AWS CLI and Credentials

```bash
# Verify AWS CLI is installed
aws --version

# Configure credentials (one-time)
aws configure
# Provide: Access Key ID, Secret Access Key, Default Region, Output format
```

Your IAM user or role needs permissions to create Lambda, DynamoDB, S3, IAM, Cognito,
API Gateway, SNS, EventBridge, and AWS Config resources. If you are using the deployer
account for the first time, AdministratorAccess is the quickest option for a dev environment.

### Amazon Bedrock Model Access

Before deploying, make sure you have access to the Claude model in Bedrock.
It does not work automatically even if you have an AWS account.

1. Open the [AWS Console](https://console.aws.amazon.com/bedrock/)
2. Go to **Bedrock > Model access**
3. Click **Manage model access**, find **Anthropic Claude 3 Haiku**, enable it
4. Wait a minute or two until status shows **Access granted**

---

## Path A — Terraform Deployment

### Prerequisites

```bash
# Verify Terraform is installed
terraform version
# Must be >= 1.6.0

# Install if missing: https://developer.hashicorp.com/terraform/install
```

### Step 1 — Configure Variables

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
```

Open `terraform.tfvars` and fill in every value.
Required values:

| Variable | Description |
|---|---|
| `alert_email` | Email address for risk alert notifications |
| `bedrock_model_id` | Bedrock model ID (default is Claude 3 Haiku) |
| `environment` | `dev`, `staging`, or `prod` |

Optional values (leave as empty string `""` to disable the feature):

| Variable | Description |
|---|---|
| `github_token` | Required only for Amplify frontend deployment |
| `gcp_secret_name` | Required only for GCP scanning |
| `target_role_arn` | Required only for cross-account scanning |
| `app_url` | Frontend URL included in alert emails |

### Step 2 — Deploy (Windows)

```powershell
# From the repository root
.\deploy_terraform.ps1
```

### Step 2 — Deploy (Linux / macOS)

```bash
# From the repository root
bash deploy_terraform.sh
```

### Step 3 — Confirm Email Subscription

After deployment, AWS will send a confirmation email to your `alert_email` address.
Click the confirmation link before notifications can be delivered.

### Step 4 — Update Frontend Configuration

After `terraform apply` completes, the output will display:

```
api_invoke_url       = "https://XXXX.execute-api.us-east-1.amazonaws.com/dev"
cognito_client_id    = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
cognito_user_pool_id = "us-east-1_XXXXXXXXX"
dynamodb_table       = "cloudsentinel-risks"
```

Set these values in each frontend HTML file:

```javascript
window.ENV_API_URL           = "https://XXXX.execute-api.us-east-1.amazonaws.com/dev";
window.ENV_COGNITO_POOL_ID   = "us-east-1_XXXXXXXXX";
window.ENV_COGNITO_CLIENT_ID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX";
window.ENV_REGION            = "us-east-1";
```

### Teardown

When you want to remove everything:

```powershell
# Windows
.\deploy_terraform.ps1 -Destroy

# Linux / macOS
bash deploy_terraform.sh --destroy
```

This destroys all AWS resources created by Terraform. DynamoDB data is deleted.
Make sure you have exported anything you need before running this.

---

## Path B — Console Script (No Terraform)

### Prerequisites

```bash
# Verify Python is installed
python --version
# Must be >= 3.9

# Install boto3 (AWS SDK)
pip install boto3
```

### Step 1 — Configure

```bash
# Copy the example configuration file
cp deploy.env.example deploy.env
```

Open `deploy.env` and fill in the values. Every `CS_*` variable can
alternatively be exported as a shell environment variable.

Required:

| Variable | Description |
|---|---|
| `CS_ALERT_EMAIL` | Email address for SNS risk alerts |
| `CS_REGION` | AWS region to deploy into |

All other variables have working defaults for a standard deployment.

### Step 2 — Dry Run (Recommended)

Preview all deployment steps without making any AWS API calls:

```bash
python deploy_console.py --dry-run
```

### Step 3 — Deploy

```bash
python deploy_console.py
```

The script will:
1. Verify your AWS credentials
2. Create the DynamoDB risks table with both GSIs
3. Create the S3 artifacts bucket (private, versioned, encrypted)
4. Create the Lambda IAM execution role
5. Create the Cognito user pool and app client
6. Create the SNS alerts topic and email subscription
7. Package and deploy all five Lambda functions
8. Create the API Gateway REST API with all routes
9. Create EventBridge rules for scheduled AI explanation and scan notifications
10. Print the final output summary

### Step 4 — Confirm Email and Update Frontend

Same as Path A, Steps 3 and 4 above. The console script prints the required
values at the end of the deployment run.

---

## Verifying the Deployment

Once deployed, this is the quickest way to confirm everything is working:

```bash
# Replace with your actual API URL from the deployment output
API_URL="https://XXXX.execute-api.us-east-1.amazonaws.com/dev"

# The risks endpoint should return an empty list on a fresh deployment
curl -s "${API_URL}/risks" | python -m json.tool
# Expected: {"risks": [], "count": 0}

# Trigger a cloud scan manually
curl -s -X POST "${API_URL}/scan-cloud" | python -m json.tool
# Expected: {"message": "Scan complete", "risksFound": <number>}
```

---

## Environment Variables Reference

All Lambda environment variables are documented in `.env.example` at the project root.
No function has hardcoded values — everything is set during deployment.
If you need to change a threshold or model ID after deploying, update the Lambda
environment variable in the AWS Console under the function's Configuration tab.

---

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `ExpiredTokenException` | Run `aws configure` or refresh your SSO session |
| `AccessDeniedException` | Ensure your IAM user/role has the required permissions listed above |
| Bedrock returns `ModelNotReadyException` | Request model access in the Bedrock console |
| SNS alerts not arriving | Confirm the subscription link sent to your email |
| Terraform error `duplicate provider` | Ensure you are running `terraform` from `infrastructure/terraform/` |
| `ResourceConflictException` on Lambda | The function already exists; the script will update it automatically |

---

## Architecture Overview

```
EventBridge (hourly)
      |
      v
 ai-explainer Lambda
      |
      v
 DynamoDB (cloudsentinel-risks)
      |
      +---> module-index GSI
      |
      v
 risk-reader Lambda  <-- API Gateway GET /risks
 chatbot-handler     <-- API Gateway POST /chat
 cloud-scanner       <-- API Gateway POST /scan-cloud
 notification-handler <-- EventBridge (ScanCompleted event)
      |
      v
    SNS --> Email
```
