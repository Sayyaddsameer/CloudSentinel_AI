# CloudSentinel

**AI-Powered Multi-Cloud Engineering Risk Intelligence Platform**

[![CI](https://github.com/Sayyaddsameer/CloudSentinel_AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Sayyaddsameer/CloudSentinel_AI/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900?logo=amazon-aws&logoColor=white)
![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform&logoColor=white)

---

## Overview

Most cloud monitoring tools tell you something is wrong but not what it actually means or what to do about it. Engineers end up with dashboards full of alerts and no clear path forward.

We built CloudSentinel to fix that. Connect your cloud environment, run a scan, and get back a prioritised list of risks — each one with an AI-generated explanation in plain English, concrete remediation steps, and alternative configurations you can actually use.

The platform covers five areas we deal with day to day: cloud infrastructure, DevOps pipelines, full-stack APIs, data engineering, and mobile backends. There is a built-in AI chatbot that answers questions about your specific detected risks, so you do not have to go back to the docs during an incident.

---

## Platform Modules

| Module | Primary Detections |
|--------|--------------------|
| Cloud Infrastructure | Publicly accessible S3 buckets, open EC2 security groups, missing IAM password policy, GCP firewall exposure |
| DevOps Intelligence | Hardcoded credentials in pipeline files, no test step, no rollback strategy, no post-deploy monitoring |
| Full-Stack Application | Unauthenticated API endpoints, missing rate limiting, high 5XX error rate, high API latency |
| Data Engineering | Unencrypted data buckets, DynamoDB SSE disabled, publicly accessible datasets, repeated Glue job failures |
| Mobile Backend | API latency above threshold, Lambda error spikes, missing CORS headers, high 4XX error rate |

---

## System Architecture

```
User
 └── AWS Amplify (Web Portal)
       └── Amazon Cognito (Authentication)
       └── Amazon API Gateway
             ├── POST /scan-cloud       -->  cloudsentinel-cloud-scanner
             ├── POST /scan-devops      -->  cloudsentinel-devops-analyzer
             ├── POST /scan-fullstack   -->  cloudsentinel-fullstack-analyzer
             ├── POST /scan-data-eng    -->  cloudsentinel-data-eng-analyzer
             ├── POST /scan-mobile      -->  cloudsentinel-mobile-analyzer
             ├── GET  /risks            -->  cloudsentinel-risk-reader
             └── POST /chat             -->  cloudsentinel-chatbot-handler

All scanners write to:
 └── Amazon DynamoDB  (cloudsentinel-risks)
       └── AWS Step Functions (scan orchestration)
             └── cloudsentinel-ai-explainer
                   └── Amazon Bedrock -- Claude 3 Haiku
                         └── AI explanations written back to DynamoDB
                               └── Amazon SNS  --> email alert to user (High risks)
```

Full architecture diagrams, module-level flows, sequence diagrams, and the risk data model are in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Tech Stack

| Layer | Service |
|-------|---------|
| Frontend hosting | AWS Amplify |
| Authentication | Amazon Cognito |
| API layer | Amazon API Gateway |
| Scan orchestration | AWS Step Functions (Express workflow) |
| Serverless compute | AWS Lambda (Python 3.11) |
| AI reasoning | Amazon Bedrock (Claude 3 Haiku) |
| Risk classification | Amazon Comprehend |
| Risk storage | Amazon DynamoDB |
| Alert delivery | Amazon SNS |
| Artifact storage | Amazon S3 |
| Monitoring | Amazon CloudWatch + AWS X-Ray |
| Event scheduling | Amazon EventBridge |
| Cross-account scanning | AWS STS |
| Secrets management | AWS Secrets Manager |
| Governance | AWS Config |
| Infrastructure as Code | Terraform >= 1.6 |
| CI/CD | GitHub Actions |

---

## Repository Structure

```
CloudSentinel_AI/
├── .github/
│   └── workflows/ci.yml          # CI pipeline - tests + Bandit security scan
├── docs/
│   ├── cloud-infrastructure-and-ai/
│   ├── devops-intelligence/
│   ├── frontend-portal/
│   ├── fullstack-intelligence/
│   ├── data-engineering-intelligence/
│   └── mobile-backend-intelligence/
├── infrastructure/
│   ├── cloudformation/           # Scanner IAM role for cross-account access
│   ├── iam/                      # Lambda execution policy
│   └── terraform/                # Full infrastructure as code
├── modules/
│   ├── cloud-infra/              # Cloud Infrastructure and AI Layer
│   ├── devops/                   # DevOps Intelligence
│   ├── fullstack/                # Full-Stack Intelligence
│   ├── data-eng/                 # Data Engineering Intelligence
│   ├── mobile/                   # Mobile Backend Intelligence
│   └── frontend/                 # Frontend Portal
├── shared/schemas/               # Risk record JSON schema
├── tests/                        # Unit tests per module
├── ARCHITECTURE.md               # Full architecture and design documentation
├── DEPLOYMENT.md                 # Step-by-step deployment guide
└── README.md
```

---

## Getting Started

**Prerequisites:** AWS account, AWS CLI v2, Python 3.11, Terraform >= 1.6, Git.

See [DEPLOYMENT.md](./DEPLOYMENT.md) for the complete deployment guide — both Terraform (automated) and AWS Console (manual) paths are covered.

**Quick setup:**
```bash
git clone https://github.com/Sayyaddsameer/CloudSentinel_AI.git
cd CloudSentinel_AI/infrastructure/terraform
terraform init && terraform plan && terraform apply
```

---

## Team

| Name | GitHub | Module |
|------|--------|--------|
| Sayyad Sameer | [@Sayyaddsameer](https://github.com/Sayyaddsameer) | Cloud Infrastructure, AI Layer |
| Kantipudi Vivek Vardhan | [@vivekkantipudi](https://github.com/vivekkantipudi) | DevOps Intelligence |
| Janapareddy Dyns Gowrish | [@gowrishjanapareddy](https://github.com/gowrishjanapareddy) | Full-Stack Intelligence |
| Bikkavolu Srivallisa Sai Veerabhadra Ayyan | [@23P31A0506](https://github.com/23P31A0506) | Data Engineering Intelligence |
| Muramalla Ambica Sai Ram | [@AmbicaSairam](https://github.com/AmbicaSairam) | Mobile Backend Intelligence |
| Bogavalli Akash | [@Akashbogavalli69](https://github.com/Akashbogavalli69) | Frontend Portal |

---

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production — merged via pull request only |
| `develop` | Integration — all feature branches merge here |
| `feature/cloud-infra` | Cloud Infrastructure and AI Layer |
| `feature/devops` | DevOps Intelligence |
| `feature/fullstack` | Full-Stack Intelligence |
| `feature/data-eng` | Data Engineering Intelligence |
| `feature/mobile` | Mobile Backend Intelligence |
| `feature/frontend` | Frontend Portal |

---

## License

This project is developed as part of an academic engineering initiative. All rights reserved by the contributing team members.
