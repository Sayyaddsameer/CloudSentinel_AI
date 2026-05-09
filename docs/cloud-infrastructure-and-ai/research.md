# Research Notes — Cloud Infra + AI
## Sayyad Sameer

Dumping my research notes here so I can reference them later and also explain my decisions if anyone asks during the demo.

---

## Why this module exists

The biggest source of real-world cloud breaches isn't zero-day exploits — it's misconfigured infrastructure. Stuff like S3 buckets left public, security groups with port 22 open to 0.0.0.0/0, and IAM accounts with no password policy. I know this from reading about the Capital One breach and a few other big ones. These are all things that can be detected programmatically by just calling AWS APIs — no agent needed, no install required.

So the cloud-infra module basically automates what a security engineer would do manually when auditing an account.

---

## What risks I chose to detect and why

I went through the CIS AWS Foundations Benchmark to pick the most impactful checks. Didn't implement all 50+ — just the ones that are commonly misconfigured and easy to demo:

| Check | Why I picked it |
|-------|----------------|
| S3 public access block | Probably the most famous source of data breaches |
| S3 encryption missing | Compliance baseline — GDPR, HIPAA both require it |
| EC2 security group open to 0.0.0.0/0 | Classic lateral movement entry point |
| IAM no password policy | Weak/no policy = easy brute force |
| IAM short password | Common oversight in small teams |

I looked at Prowler (open source CSPM tool) to see what categories matter most. Used it as a reference, not as a dependency.

---

## AI model — why Claude 3 Haiku

This was actually a decision I spent time on. Options I compared:

**Claude 3 Haiku** — fast (~1s), cheap ($0.00025/1K tokens), good quality explanations. AWS-native through Bedrock so no external API keys. This is what I went with.

**Claude 3 Sonnet** — much better quality but 12x more expensive. Not worth it for just explaining risks.

**Amazon Titan** — native AWS, cheap, but I tested it and the explanations were too generic. Didn't feel helpful enough.

**GPT-4o mini (OpenAI)** — I actually tried this first via the OpenAI API and the output quality was great. But it adds an external API key dependency and our whole stack is AWS. Dropped it.

Bedrock also has no cold start problem for invoking models which matters because the AI explainer Lambda processes multiple risks in a loop.

---

## Prompt engineering — what works

Took a few iterations to get the AI output right. Early versions were too long and too technical. What works:
- Tell it the audience is a junior developer
- Keep response under 200 words
- Ask for: what it means + why it matters + one concrete fix
- Give it the actual resource name and risk type, not just generic descriptions

The chatbot prompt is different — I inject the actual risk records from DynamoDB as context so it answers specifically about the user's environment.

---

## Things I looked at

- CIS AWS Foundations Benchmark v2.0 — used as the primary reference for which checks matter
- Prowler (github.com/prowler-cloud/prowler) — open source CSPM, good for understanding risk categories
- AWS Security Hub documentation — looked at its finding format for inspiration on the risk schema
- Amazon Bedrock developer guide — for the API call format and model IDs
- Boto3 docs — for S3, EC2, IAM API calls
