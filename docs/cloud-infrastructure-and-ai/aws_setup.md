# My Setup Notes — AWS + Terraform
## Sayyad Sameer | Cloud Infra + AI

These are my personal setup notes for the core infrastructure. I'm handling everything that the other modules depend on — DynamoDB, Cognito, API Gateway, IAM role, Bedrock. Everyone else needs to wait for me to finish this before they can deploy their Lambdas.

---

## AWS Account Setup (first time only)

Created the account at aws.amazon.com. Used my college email. Picked Basic Support (free obviously). 

After signup:
- Enable MFA on root immediately — I used Google Authenticator
- Create an IAM admin user `cloudsentinel-admin` and never use root again
- Download the CSV with the access keys, store it somewhere safe (NOT in the repo)

To configure the CLI:
```
aws configure
```
enter the key ID and secret from the CSV, region `us-east-1`, format `json`.

Quick check that it's working:
```
aws sts get-caller-identity
```

---

## Option 1 — Console Setup (No Terraform)

### DynamoDB

Created the table manually:
- Table name: `cloudsentinel-risks`
- Partition key: `resourceId` (String)
- Sort key: `riskTimestamp` (String)
- Billing: On-demand (no capacity planning needed for our project)

After creating I added two GSIs because the frontend needs to query by module and by priority:
- **module-index**: partition key `module`, sort key `riskTimestamp`, projected: All
- **priority-index**: partition key `riskPriority`, sort key `riskTimestamp`, projected: All

Takes a minute or two for the indexes to become Active.

### S3 Bucket

Created `cloudsentinel-artifacts-<my-account-id>`. Found my account ID in the top right of any console page.

Settings:
- Block all public access ✓
- Versioning enabled
- SSE-S3 encryption

### Lambda IAM Role

IAM > Roles > Create role > AWS Service > Lambda

Name: `cloudsentinel-lambda-role`

Started with `AWSLambdaBasicExecutionRole` then added an inline policy with DynamoDB, S3, EC2, IAM, Bedrock permissions. Shared the role ARN with the rest of the team on Slack — everyone uses the same role.

The inline policy JSON is in `infrastructure/iam/` folder if anyone needs to reference it.

### Cognito

Created `cloudsentinel-users` pool. Settings I used:
- Sign-in by email
- Password: at least 8 chars, uppercase, numbers required
- No MFA (would complicate the demo)
- App client: `cloudsentinel-web-client`, public (no secret), with USER_PASSWORD_AUTH flow

After creating I sent Akash the User Pool ID and Client ID in #frontend channel.

### Bedrock

Search for Amazon Bedrock > Model access > Modify model access.
Request access to **Claude 3 Haiku** under Anthropic. Takes about 10 minutes.
Status goes from "In Progress" → "Access granted". Do this ASAP when you first set up the account.

### API Gateway

Created `cloudsentinel-api` as a REST API (Regional endpoint).

Resources I added:
| Path | Method | Lambda |
|------|--------|--------|
| /scan-cloud | POST | cloudsentinel-cloud-scanner |
| /scan-devops | POST | cloudsentinel-devops-analyzer |
| /scan-fullstack | POST | cloudsentinel-fullstack-analyzer |
| /scan-data-eng | POST | cloudsentinel-data-eng-analyzer |
| /scan-mobile | POST | cloudsentinel-mobile-analyzer |
| /risks | GET | cloudsentinel-risk-reader |
| /chat | POST | cloudsentinel-chatbot-handler |

All use Lambda Proxy integration. After adding all routes, deployed to a stage called `dev`. The invoke URL I sent to Akash for the frontend.

**NOTE:** After each new Lambda is connected, need to re-deploy the API for the route to be live.

### Deploying My Lambdas

I have 4 Lambda functions to deploy: cloud-scanner, ai-explainer, chatbot-handler, and risk-reader.

Packing each one (example for cloud-scanner):
```
cd modules/cloud-infra
pip install boto3 -t package/
copy cloud_scanner.py package\
cd package
Compress-Archive -Path * -DestinationPath ..\cloud_scanner.zip -Force
cd ..\..
```

Then in Lambda console:
1. Create function, Author from scratch, Python 3.11
2. Use existing role: `cloudsentinel-lambda-role`
3. Upload the zip
4. Set env variable: `DYNAMODB_TABLE` = `cloudsentinel-risks`
5. Timeout: 5 minutes for scanner and explainer, 1 min for chatbot and reader

---

## Option 2 — Terraform

I prefer doing it with Terraform so I can rebuild everything quickly if something goes wrong. The main file is `infrastructure/terraform/main.tf`.

```
cd infrastructure/terraform
terraform init
terraform plan   # review what it will create
terraform apply  # type yes
```

After apply it prints outputs — I copy those values immediately:
- `cognito_user_pool_id` and `cognito_client_id` → sent to Akash
- `lambda_role_arn` → shared with everyone else
- `dynamodb_table` name → everyone uses this

For my Lambda functions there's a separate file `cloud_infra_lambdas.tf`. I run it the same way.

**IMPORTANT:** Don't commit `terraform.tfstate` to git ever. I added it to `.gitignore`.

**TODO:** Set up EventBridge to run ai-explainer Lambda automatically every hour so risks get AI explanations without manual triggering.
