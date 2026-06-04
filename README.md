# CloudSentinel AI

**Multi-Cloud Security Intelligence — AWS Serverless + AI**

[![CI](https://github.com/Sayyaddsameer/CloudSentinel_AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Sayyaddsameer/CloudSentinel_AI/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11-3776AB)
![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900)
![License](https://img.shields.io/badge/License-Academic-blue)

---

## What is this?

CloudSentinel AI is our final year project. We built a platform that continuously scans cloud infrastructure for security misconfigurations and explains every finding in plain English using AI — not generic alerts, but actual explanations tailored to the specific resource that was flagged.

The idea came from a frustration we all had: existing security tools dump a list of issues with no context. You get `S3 bucket public access not blocked` with no explanation of why that matters or what to actually do about it. If you are a junior developer who has never thought about security before, that is not helpful.

We split the problem across five domains — each teammate owns one:
- **Cloud Infrastructure** (Sameer) — AWS S3, EC2, IAM, GCP buckets and firewalls
- **DevOps Intelligence** (Vivek) — GitHub Actions CI/CD pipelines
- **Full-Stack APIs** (Gowrish) — API Gateway authentication, throttling, error rates
- **Data Engineering** (Ayyan) — DynamoDB encryption, sensitive S3 buckets, Glue jobs
- **Mobile Backend** (Ambica) — Cognito MFA, Lambda errors, mobile API latency

Akash built the frontend.

---

## How it works

When you connect your AWS account and trigger a scan, AWS Step Functions kicks off all five scanners simultaneously. Instead of running one after another (which would take around 10 minutes), they all run in parallel and finish in 2–3 minutes.

Each scanner writes risk records into DynamoDB. An AI explainer Lambda runs on a schedule, picks up records that haven't been explained yet, and calls Amazon Bedrock (Claude 3 Haiku) to write a plain-English explanation and concrete remediation steps for each one. Amazon Comprehend classifies the risk type. If anything Critical or High comes up, Amazon SNS fires an email alert to whoever set up the account.

The frontend is a static site hosted on AWS Amplify, authenticated with Amazon Cognito. Every module page has its own risk dashboard and an AI chatbot where you can ask follow-up questions about what was found.

---

## Architecture overview

```
Browser (landing.html → sign in → dashboard)
  └── Amazon Cognito  (JWT tokens, 30-min expiry, forgot password flow)
  └── Amazon API Gateway  (ALL routes require a valid Cognito token)
        ├── POST /validate-connection  →  cloudsentinel-validate-connection
        ├── POST /scan-cloud-infra     →  cloudsentinel-cloud-scanner
        ├── POST /scan-devops          →  cloudsentinel-devops-analyzer
        ├── POST /scan-fullstack       →  cloudsentinel-fullstack-analyzer
        ├── POST /scan-data-eng        →  cloudsentinel-data-eng-analyzer
        ├── POST /scan-mobile          →  cloudsentinel-mobile-analyzer
        ├── GET  /risks                →  cloudsentinel-risk-reader
        ├── POST /generate-report      →  cloudsentinel-pdf-generator
        ├── POST /chat                 →  cloudsentinel-chatbot-handler
        └── POST /disconnect           →  cloudsentinel-disconnect-handler

Scan flow:
  API Gateway → Step Functions (parallel) → 5 scanners → DynamoDB
  EventBridge (hourly) → cloudsentinel-ai-explainer → Amazon Bedrock (Claude 3 Haiku)
                                                     → Amazon Comprehend (risk classification)
  High/Critical risks → cloudsentinel-notification-handler → Amazon SNS → Email

GCP scanning (optional, set GCP_SECRET_NAME):
  cloud-scanner → Secrets Manager (GCP service account JSON key)
    ├── Google Cloud Storage: checks bucket IAM for allUsers/allAuthenticatedUsers
    └── GCP Compute Engine: checks firewall rules open to 0.0.0.0/0

On disconnect / session expiry:
  disconnect-handler → STS AssumeRole → CloudFormation DeleteStack
                     → Secrets Manager ForceDeleteWithoutRecovery (GCP key)
                     → DynamoDB batch delete (all risks for that module)
```

Full architecture with sequence diagrams and the risk data schema: [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Tech stack

| Layer | What we used |
|-------|-------------|
| Frontend | HTML/CSS/JS — hosted on AWS Amplify |
| Auth | Amazon Cognito (JWT, forgot password, 30-min token expiry) |
| API security | API Gateway + Cognito JWT authorizer on every route |
| Compute | AWS Lambda (Python 3.11) |
| AI explanations | Amazon Bedrock — Claude 3 Haiku |
| Risk classification | Amazon Comprehend |
| Storage | Amazon DynamoDB (with GSIs for module and priority filtering) |
| PDF reports | AWS Lambda + fpdf2 (presigned S3 download URL) |
| GCP credentials | AWS Secrets Manager |
| Cross-account scanning | STS AssumeRole + CloudFormation (read-only scanner role) |
| Alerts | Amazon SNS |
| Scheduling | Amazon EventBridge |
| Metrics | Amazon CloudWatch (scan timing, AI latency) |
| IaC | Terraform >= 1.6 |
| CI/CD | GitHub Actions |

---

## What we scan

| Module | Checks |
|--------|--------|
| Cloud Infrastructure | S3 public access, S3 encryption, EC2 open security groups, IAM password policy, GCP firewall, GCP bucket exposure, root account MFA |
| DevOps | Hardcoded secrets in YAML, missing test step, no rollback, no post-deploy monitoring |
| Full-Stack | Unauthenticated API endpoints, no throttling, 5XX error rate, high latency |
| Data Engineering | DynamoDB encryption off, sensitive bucket names publicly accessible, repeated Glue job failures |
| Mobile Backend | Cognito MFA disabled, weak password policy, Lambda error rate, API response time > 1 second |

---

## Security properties

We tried to be thoughtful about this:

- Every API endpoint requires a Cognito JWT — no endpoint is publicly accessible
- Tokens expire in 30 minutes, enforced server-side by Cognito and API Gateway (not just a frontend timer)
- GCP service account keys never touch the frontend — they go straight to Secrets Manager
- Cross-account AWS scanning uses a read-only CloudFormation-deployed IAM role, not long-lived access keys
- When you disconnect a provider or your session expires, we automatically delete the CloudFormation stack, purge the GCP secret, and clear all DynamoDB risk records for that module

---

## Repo structure

```
CloudSentinel_AI/
├── .github/workflows/ci.yml          # CI: unit tests + Bandit security linting + Terraform validate
├── docs/
│   ├── cloud-infrastructure-and-ai/  # Sameer's architecture, AWS setup, research notes, specs
│   ├── devops-intelligence/          # Vivek's docs
│   ├── frontend-portal/              # Akash's docs
│   ├── fullstack-intelligence/       # Gowrish's docs
│   ├── data-engineering-intelligence/# Ayyan's docs
│   └── mobile-backend-intelligence/  # Ambica's docs
├── infrastructure/
│   ├── cloudformation/               # Scanner IAM role template (deployed to client accounts)
│   ├── iam/lambda_policy.json        # Least-privilege Lambda execution policy
│   └── terraform/                    # Full IaC for all AWS resources
├── modules/
│   ├── cloud-infra/                  # Cloud scanner, AI explainer, chatbot, risk reader Lambdas
│   ├── devops/                       # DevOps analyzer Lambda
│   ├── fullstack/                    # Full-stack analyzer Lambda
│   ├── data-eng/                     # Data engineering analyzer Lambda
│   ├── mobile/                       # Mobile backend analyzer Lambda
│   ├── reporting/                    # PDF report generator Lambda
│   ├── benchmarking/                 # Benchmarking Lambda (for paper Table II/III data)
│   └── frontend/                     # Static web portal
│       ├── landing.html              # Public landing page (dark/light mode toggle)
│       ├── index.html                # Sign in + forgot password
│       ├── signup.html               # Account registration
│       ├── dashboard.html            # Main dashboard with AI chatbot
│       ├── cloud.html / devops.html / fullstack.html / data.html / mobile.html
│       ├── js/env.js.example         # Config template (copy to env.js and fill in after deploy)
│       ├── js/auth.js                # Cognito sign in / sign up / forgot password
│       ├── js/session.js             # 30-min session timer, auto-disconnect on expiry
│       └── js/app.js                 # Shared API helpers, disconnect flow
├── shared/schemas/                   # Risk record JSON schema
├── tests/                            # Unit tests for all 5 modules (pytest + moto)
│   └── conftest.py                   # Shared fixtures, mocked AWS, sys.path setup
├── pytest.ini
├── deploy_console.py                 # Full deployment without Terraform (Python only)
├── ARCHITECTURE.md                   # Full design doc
├── DEPLOYMENT.md                     # Step-by-step setup guide
└── README.md                         # This file
```

---

## Getting started

You need: an AWS account with CLI configured, Python 3.11, and Git. That's it.

**Quick deploy with Terraform (recommended for a clean environment):**
```bash
git clone https://github.com/Sayyaddsameer/CloudSentinel_AI.git
cd CloudSentinel_AI/infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — at minimum set alert_email and environment
terraform init && terraform apply
```

**Quick deploy without Terraform:**
```bash
pip install boto3
python deploy_console.py
```

**Access the portal after deploy:**
```
http://cloudsentinel-frontend-<your-account-id>.s3-website-us-east-1.amazonaws.com/landing.html
```

Full setup instructions including Bedrock model activation and GCP integration: [DEPLOYMENT.md](./DEPLOYMENT.md)

---

## Running tests

```bash
pip install boto3 "moto[all]" pytest pytest-cov
pytest tests/ -v
pytest tests/ -v --cov=modules --cov-report=term-missing
```

No real AWS credentials needed — the test suite mocks all AWS services with moto.

---

## Team

This is a six-person academic project at Aditya University.

| Name | Module |
|------|--------|
| Sayyad Sameer | Cloud Infrastructure + AI Layer + Platform Lead |
| Kantipudi Vivek Vardhan | DevOps Intelligence |
| Janapareddy Dyns Gowrish | Full-Stack Intelligence |
| Bikkavolu Srivallisa Sai Veerabhadra Ayyan | Data Engineering Intelligence |
| Muramalla Ambica Sai Ram | Mobile Backend Intelligence |
| Bogavalli Akash | Frontend Portal |

---

## License

Academic project — Aditya University. All rights reserved by the team members listed above.
