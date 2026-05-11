import json
import os
import logging

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME    = os.environ["DYNAMODB_TABLE"]
REGION        = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
CONTEXT_LIMIT = int(os.environ.get("CHATBOT_CONTEXT_RISKS", "20"))
MAX_TOKENS    = int(os.environ.get("MAX_TOKENS", "600"))

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": "*",
}

# Resources that are intentionally public -- exclude from chatbot context
IGNORED_RESOURCE_NAMES = {"cloudsentinel-cf-templates-871070087236"}


def fetch_all_risks(table):
    """Scan entire table and return deduplicated risks, newest first per resource."""
    items = []
    try:
        resp = table.scan()
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
    except ClientError as e:
        logger.error(f"DynamoDB scan failed: {e}")
        return []

    # Filter ignored resources
    items = [i for i in items if i.get("resourceName", "") not in IGNORED_RESOURCE_NAMES]

    # Deduplicate -- keep newest per (resourceId, riskType)
    seen = {}
    for item in items:
        key = (item.get("resourceId", ""), item.get("riskType", ""))
        existing = seen.get(key)
        if existing is None or item.get("riskTimestamp", "") > existing.get("riskTimestamp", ""):
            seen[key] = item

    # Sort: High first, newest first
    priority_order = {"High": 0, "Medium": 1, "Low": 2}
    result = sorted(seen.values(), key=lambda x: (
        priority_order.get(x.get("riskPriority", "Low"), 2),
        x.get("riskTimestamp", ""),
    ))
    return result[:CONTEXT_LIMIT]


def fetch_module_risks(table, module):
    """Query the module-index GSI for risks in a specific module."""
    try:
        response = table.query(
            IndexName="module-index",
            KeyConditionExpression=Key("module").eq(module),
            ScanIndexForward=False,
            Limit=CONTEXT_LIMIT * 5,
        )
        items = [i for i in response.get("Items", [])
                 if i.get("resourceName", "") not in IGNORED_RESOURCE_NAMES]
        # Deduplicate
        seen = {}
        for item in items:
            key = (item.get("resourceId", ""), item.get("riskType", ""))
            existing = seen.get(key)
            if existing is None or item.get("riskTimestamp", "") > existing.get("riskTimestamp", ""):
                seen[key] = item
        return list(seen.values())[:CONTEXT_LIMIT]
    except ClientError as e:
        logger.error(f"DynamoDB query failed for module '{module}': {e}")
        return []


def build_chat_prompt(question, risks, module):
    context_lines = []
    for r in risks:
        line = (
            f"- [{r.get('riskPriority', '?')}] {r.get('riskType', '?')} "
            f"on {r.get('resourceName', '?')}: {r.get('riskReason', '')}"
        )
        context_lines.append(line)

    context = "\n".join(context_lines) if context_lines else "No risks detected yet for this module."

    return (
        f"You are CloudSentinel's AI security assistant. The user is currently viewing the {module} module.\n\n"
        f"Here are the latest detected risks in this module (deduplicated, High priority first):\n{context}\n\n"
        f"User question: {question}\n\n"
        "Instructions:\n"
        "1. If the user asks a general question about CloudSentinel, the website, or how to use it, answer helpfully and accurately.\n"
        f"2. If the user asks what this module ({module}) does, explain its purpose and what kind of risks it scans for.\n"
        "3. If the user asks about their risks, answer specifically based on the risks shown above.\n"
        "Keep your answer under 300 words. Format remediation steps as a numbered list where applicable."
    )


def call_bedrock(bedrock_client, prompt):
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    })
    try:
        resp = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL,
            contentType="application/json",
            accept="application/json",
            body=body,
        )
        result = json.loads(resp["body"].read())
        return result["content"][0]["text"].strip(), True
    except Exception as e:
        logger.error(f"Bedrock invoke failed: {e}")
        return str(e), False


def rule_based_response(question: str, risks: list, module: str) -> str:
    """Fallback rule-based response when Bedrock is unavailable."""
    q = question.lower()

    # ── Generic Conversational ──────────────────────────────────
    if any(kw in q.split() for kw in ["hi", "hello", "hey", "greetings", "hola", "sup"]):
        return (
            "Hello! I am CloudSentinel AI, your security assistant.\n\n"
            "You can ask me about the platform, how to connect your AWS/GCP accounts, "
            "or to summarize and explain the security risks detected in your environment."
        )

    if any(kw in q for kw in ["thanks", "thank you", "awesome", "great", "ok", "okay"]):
        return "You're welcome! Let me know if you need help analyzing or fixing any other security risks."

    if any(kw in q for kw in ["how are you", "who are you", "what are you"]):
        return "I'm CloudSentinel AI, an automated assistant here to help you secure your cloud infrastructure. How can I assist you today?"

    # ── Platform-level guidance (no risk data needed) ───────────
    if any(kw in q for kw in ["what is", "what does", "what can", "cloudsentinel", "platform", "about", "project", "this app", "purpose"]):
        if module == "devops" and "devops" in q:
            return "The DevOps module analyzes your CI/CD pipelines (like GitHub Actions) to detect hardcoded secrets, missing test steps, and missing rollback strategies."
        if module == "fullstack" and "fullstack" in q:
            return "The Full-Stack module analyzes API Gateway and CloudWatch metrics to detect unauthenticated API routes, missing rate limits, and latency/error spikes."
        if module == "data-eng" and "data" in q:
            return "The Data Engineering module scans S3, DynamoDB, and Glue to detect unencrypted tables, public buckets, and failing ETL jobs."
        if module == "mobile" and "mobile" in q:
            return "The Mobile Backend module scans Cognito and API Gateway to detect weak password policies, missing MFA, and unauthenticated routes."
        if module == "cloud-infra" and "cloud" in q:
            return "The Cloud Infrastructure module scans core AWS/GCP resources like S3 buckets, EC2 security groups, and IAM policies for misconfigurations."

        return (
            "**CloudSentinel AI** is a cloud security intelligence platform that scans your AWS and GCP "
            "environments for misconfigurations, IAM vulnerabilities, and compliance gaps.\n\n"
            "It has **5 specialized modules:**\n"
            "1. **Cloud Infrastructure** -- S3, EC2 security groups, IAM, AWS Config\n"
            "2. **DevOps** -- CI/CD pipelines, secrets in code, missing test steps\n"
            "3. **Full-Stack** -- API Gateway auth, CORS, Lambda permissions\n"
            "4. **Data Engineering** -- DynamoDB encryption, S3 data buckets, Glue jobs\n"
            "5. **Mobile Backend** -- Cognito MFA, API route auth, IAM execution roles\n\n"
            "Each scan stores results in DynamoDB and shows actionable remediation steps on the dashboard."
        )

    if any(kw in q for kw in ["this module", "what module", "current module", "do here"]):
        module_descriptions = {
            "cloud-infra": "You are currently in the **Cloud Infrastructure** module. It scans S3, EC2 security groups, and IAM policies for misconfigurations.",
            "devops": "You are currently in the **DevOps** module. It scans CI/CD pipelines for hardcoded secrets, missing tests, and deployment issues.",
            "fullstack": "You are currently in the **Full-Stack** module. It analyzes API Gateway configurations and CloudWatch metrics.",
            "data-eng": "You are currently in the **Data Engineering** module. It focuses on S3 data buckets, DynamoDB encryption, and AWS Glue ETL jobs.",
            "mobile": "You are currently in the **Mobile Backend** module. It scans Cognito user pools for MFA and password policies, and API Gateway for route authorization."
        }
        return module_descriptions.get(module, "You are in a CloudSentinel module that detects security risks.")

    if any(kw in q for kw in ["start", "first", "begin", "which"]):
        return (
            "**Start with the Cloud Infrastructure module** -- it's the foundation.\n\n"
            "1. Go to **Cloud Infrastructure** -> Connect your AWS account (takes 60 seconds via CloudFormation)\n"
            "2. Click **Rescan Now** to detect misconfigurations in S3, EC2, and IAM\n"
            "3. Then explore **DevOps**, **Full-Stack**, **Data Engineering**, and **Mobile Backend** for specialized scans\n\n"
            "Each module page has its own **Scan** button and **AI chatbot** for module-specific questions."
        )

    if any(kw in q for kw in ["connect", "aws", "account", "cloudformation", "setup"]):
        return (
            "**Connecting your AWS account is easy and read-only:**\n\n"
            "1. Go to the **Cloud Infrastructure** page\n"
            "2. Click **Manage Connections** -> **Connect AWS**\n"
            "3. Choose CloudFormation (recommended) -- one-click stack deployment\n"
            "4. The stack creates a read-only IAM role -- CloudSentinel can **never modify** your resources\n"
            "5. Click **Confirm** and run your first scan!\n\n"
            "For GCP: Upload a Viewer-role service account JSON key. It's stored encrypted in AWS Secrets Manager."
        )

    # NOTE: deliberately excluding 'risk' and 'scan' here -- those are handled
    # by the risk-data branch below so "Highest risk right now?" doesn't get caught here
    if any(kw in q for kw in ["what risks", "can you detect", "what can it find", "what does it find",
                               "what does cloudsentinel check", "what vulnerabilit"]):
        return (
            "CloudSentinel detects **security risks across your entire cloud stack:**\n\n"
            "**Cloud Infrastructure:**\n"
            "- S3 buckets with public access enabled\n"
            "- EC2 security groups with port 22/3389 open to 0.0.0.0/0\n"
            "- Missing IAM account password policy\n\n"
            "**DevOps:** Hardcoded secrets, missing tests, no rollback strategy\n\n"
            "**Full-Stack:** Unauthenticated API routes, permissive CORS, unencrypted Lambdas\n\n"
            "**Data Engineering:** Unencrypted DynamoDB tables, public data buckets, Glue failures\n\n"
            "**Mobile:** Cognito without MFA, weak password policies, over-permissioned Lambda roles"
        )

    high = [r for r in risks if r.get("riskPriority") == "High"]
    medium = [r for r in risks if r.get("riskPriority") == "Medium"]
    total = len(risks)

    if not risks:
        return (
            "No risks have been detected yet. Run a scan from any module page first, "
            "then ask me about the results!\n\n"
            "**Quick start:** Go to Cloud Infrastructure -> Connect AWS -> Rescan Now"
        )

    if any(kw in q for kw in ["highest", "top", "worst", "critical", "priority", "most"]):
        if high:
            top = high[0]
            others = f" (+{len(high)-1} more High risks)" if len(high) > 1 else ""
            return (
                f"Your highest risk right now is:\n\n"
                f"[HIGH] **{top.get('riskType')}** on `{top.get('resourceName')}`\n"
                f"{top.get('riskReason', '')}\n\n"
                f"**Remediation:** {'; '.join(top.get('remediationSteps', ['See AWS documentation.']))}"
                f"{others}"
            )
        return f"No High priority risks detected. You have {len(medium)} Medium risks."

    if any(kw in q for kw in ["fix", "remediate", "resolve", "how"]):
        if high:
            r = high[0]
            steps = r.get("remediationSteps", [])
            steps_str = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps else "Review the risk details on the dashboard."
            return (
                f"To fix **{r.get('riskType')}** on `{r.get('resourceName')}`:\n\n"
                f"{steps_str}\n\n"
                f"{'Alternative: ' + r.get('alternativeSolutions', [''])[0] if r.get('alternativeSolutions') else ''}"
            )

    if any(kw in q for kw in ["compare", "breakdown", "summary", "overview", "count", "how many"]):
        return (
            f"Here's your current risk breakdown:\n\n"
            f"[HIGH] High: {len(high)}\n"
            f"[MED] Medium: {len(medium)}\n"
            f"[LOW] Low: {total - len(high) - len(medium)}\n"
            f" Total: {total}\n\n"
            f"Top concern: {high[0].get('riskType', 'N/A') if high else 'None -- great job!'}"
        )

    if any(kw in q for kw in ["best", "practice", "recommend", "should", "advice"]):
        return (
            "Based on your current scan results, here are the top security best practices to apply:\n\n"
            "1. **Restrict SSH (port 22)** -- Never allow 0.0.0.0/0 on security groups. Use SSM Session Manager instead.\n"
            "2. **Set an IAM Password Policy** -- Require 14+ chars, uppercase, numbers, and 90-day expiry.\n"
            "3. **Enable S3 Block Public Access** -- Enable all 4 settings on every bucket.\n"
            "4. **Add API authorization** -- Use Cognito or IAM auth on all API Gateway endpoints.\n"
            "5. **Enable MFA** -- Enforce MFA for all IAM users and Cognito user pools."
        )

    # Default: summarize all risks
    lines = [f"[HIGH] {r.get('riskType')} on `{r.get('resourceName')}`" for r in high[:5]]
    summary = "\n".join(lines)
    return (
        f"You have **{total} unique risks** detected ({len(high)} High, {len(medium)} Medium).\n\n"
        f"Top High-priority risks:\n{summary}\n\n"
        "Ask me about a specific risk, how to fix it, or for a full breakdown!"
    )


def lambda_handler(event, context):
    logger.info("chatbot-handler invoked")

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {"statusCode": 400, "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Invalid JSON body"})}

    question = body.get("question", "").strip()
    module   = body.get("module", "cloud-infra").strip()

    if not question:
        return {"statusCode": 400, "headers": CORS_HEADERS,
                "body": json.dumps({"error": "question field is required"})}

    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)

    # Fetch risks: always scoped to the current module so chatbot context
    # matches exactly what the user sees on the dashboard page
    if module:
        risks = fetch_module_risks(table, module)
    else:
        risks = fetch_all_risks(table)

    # Try Bedrock first; fall back to rule-based if not available
    bedrock = boto3.client("bedrock-runtime", region_name=REGION)
    prompt  = build_chat_prompt(question, risks, module)
    answer, used_ai = call_bedrock(bedrock, prompt)

    if not used_ai:
        logger.info("Bedrock unavailable -- using rule-based fallback")
        answer = rule_based_response(question, risks, module)

    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "answer":       answer,
            "contextRisks": len(risks),
            "aiPowered":    used_ai,
        }),
    }
