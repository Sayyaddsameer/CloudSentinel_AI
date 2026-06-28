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

# --- LLM provider: Groq by default; Amazon Bedrock (Claude 3 Haiku) interchangeable ---
import urllib.request
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "groq").lower()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL     = os.environ.get("GROQ_URL", "https://api.groq.com/openai/v1/chat/completions")

# Initialize clients outside the handler for connection reuse across invocations (reduces cold-starts)
ddb   = boto3.resource("dynamodb", region_name=REGION)
table = ddb.Table(TABLE_NAME)
bedrock = boto3.client("bedrock-runtime", region_name=REGION)

# Use environment variable for CORS domain, fallback to * if not set to avoid breaking dev
AMPLIFY_DOMAIN = os.environ.get("AMPLIFY_DOMAIN", "*")
CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": AMPLIFY_DOMAIN,
}

# Resources that are intentionally public -- exclude from chatbot context
# Resources intentionally excluded from risk reporting (comma-separated env var).
# Example: IGNORED_RESOURCES=cloudsentinel-cf-templates-123456789012
_ignored_raw = os.environ.get("IGNORED_RESOURCES", "")
IGNORED_RESOURCE_NAMES = {r.strip() for r in _ignored_raw.split(",") if r.strip()}


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
        "1. If the user says a conversational greeting (like 'hi', 'hello', etc.), reply politely and briefly introduce yourself as the CloudSentinel AI assistant.\n"
        "2. If the user asks a general question about CloudSentinel, the website, or how to use it, answer helpfully and accurately.\n"
        f"3. If the user asks what this module ({module}) does, explain its purpose and what kind of risks it scans for.\n"
        "4. If the user asks about their risks, answer specifically based on the risks shown above.\n"
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


def call_groq(prompt):
    """Groq OpenAI-compatible chat call (stdlib only). Returns (text, used_ai)."""
    body = json.dumps({
        "model": GROQ_MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        GROQ_URL, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {GROQ_API_KEY}",
                 "User-Agent": "python-requests/2.31.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"].strip(), True
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", "replace")
        logger.error(f"Groq HTTP {e.code}: {body_text}")
        return body_text, False
    except Exception as e:
        logger.error(f"Groq invoke failed: {type(e).__name__}: {e}")
        return str(e), False


def call_llm(prompt, bedrock_client=None):
    """Default: Groq. Set LLM_PROVIDER=bedrock to use Amazon Bedrock (Claude 3 Haiku)."""
    if LLM_PROVIDER == "bedrock":
        return call_bedrock(bedrock_client, prompt)
    return call_groq(prompt)


def _graceful_fallback(risks: list, module: str) -> str:
    """
    Structured fallback returned when Bedrock is unavailable.

    Returns a concise, data-driven summary built from the live DynamoDB risk
    list instead of trying to guess user intent through keyword matching.
    This is intentionally narrow in scope: it tells the user what is known,
    acknowledges the AI is offline, and directs them to re-ask later.

    Args:
        risks:  Risk dicts already fetched from DynamoDB for this module.
        module: CloudSentinel module name shown in the dashboard.
    """
    high   = [r for r in risks if r.get("riskPriority") == "High"]
    medium = [r for r in risks if r.get("riskPriority") == "Medium"]
    low    = [r for r in risks if r.get("riskPriority") == "Low"]

    header = (
        "⚠️ **AI assistant temporarily unavailable** — the AI model could not be "
        "reached. Here is a data-driven summary of your current security posture instead:\n\n"
    )

    if not risks:
        return (
            header
            + f"No risks have been detected yet for the **{module}** module. "
            + "Run a scan from the dashboard, then ask your question again once the AI is back online."
        )

    top_lines = "\n".join(
        f"  • [{r.get('riskPriority', '?')}] **{r.get('riskType', 'Unknown')}** "
        f"on `{r.get('resourceName', 'N/A')}` — {r.get('riskReason', '')}"
        for r in (high + medium)[:5]
    )

    return (
        header
        + f"**Module:** {module}  |  "
        + f"🔴 High: {len(high)}  🟡 Medium: {len(medium)}  🟢 Low: {len(low)}  "
        + f"(Total: {len(risks)})\n\n"
        + (f"**Top risks:**\n{top_lines}\n\n" if top_lines else "")
        + "Please retry your question in a moment — the AI assistant will respond "
        + "with a full explanation when the AI service becomes available again."
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

    # Fetch risks: always scoped to the current module so chatbot context
    # matches exactly what the user sees on the dashboard page
    if module:
        risks = fetch_module_risks(table, module)
    else:
        risks = fetch_all_risks(table)

    # Try Bedrock first; fall back to rule-based if not available
    prompt  = build_chat_prompt(question, risks, module)
    answer, used_ai = call_llm(prompt, bedrock)

    if not used_ai:
        logger.info("AI provider unavailable -- using graceful fallback")
        answer = _graceful_fallback(risks, module)

    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "answer":       answer,
            "contextRisks": len(risks),
            "aiPowered":    used_ai,
        }),
    }
