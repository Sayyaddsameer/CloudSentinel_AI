import json
import os
import logging
import time
import re
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME  = os.environ["DYNAMODB_TABLE"]
REGION      = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
MAX_TOKENS  = int(os.environ.get("MAX_TOKENS", "400"))
MAX_RISKS   = int(os.environ.get("MAX_RISKS_PER_RUN", "50"))

# --- LLM provider selection ---------------------------------------------------
# Groq is used by default for the reasoning layer (no model-access/billing gate,
# does not train on submitted data, brief retention). Amazon Bedrock (Claude 3
# Haiku) is an interchangeable alternative: set LLM_PROVIDER=bedrock to use it.
import urllib.request
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "groq").lower()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL     = os.environ.get("GROQ_URL", "https://api.groq.com/openai/v1/chat/completions")

# NOTE: clients are initialized inside lambda_handler (not globally) so that
# unit-test patches applied via unittest.mock.patch("boto3.client") are effective.
# A module-level client is created before any test patch is active and bypasses mocks.


# ---------------------------------------------------------------------------
# Bedrock -- generate a developer-friendly explanation for a risk
# ---------------------------------------------------------------------------

def build_bedrock_prompt(risk, strict=False):
    """Grounded prompt. Strict rules forbid inventing IPs/ARNs/resource names and
    require a fixed three-section output that validate_output() can check."""
    rules = (
        "You are a senior cloud security auditor. Use ONLY the facts in the finding data below. "
        "Do NOT invent IP addresses, ARNs, port numbers, resource names, or dates. "
        "Reference the exact resource name from the finding. "
        "Reply in plain text (no markdown) as exactly three labelled sections, 130-250 words total:\n"
        "IMPACT: <paragraph>\nTECHNICAL CONTEXT: <paragraph>\nPRIORITY JUSTIFICATION: <one sentence>\n\n"
    )
    if strict:
        rules = "STRICT MODE. " + rules + "If a detail is not in the finding data, omit it. Invent nothing.\n\n"
    return (
        rules +
        "--- FINDING DATA ---\n"
        f"Resource type : {risk.get('resource', '')}\n"
        f"Resource name : {risk.get('resourceName', '')}\n"
        f"Finding       : {risk.get('riskType', '')}\n"
        f"Why it failed : {risk.get('riskReason', '')}\n"
        f"Priority      : {risk.get('riskPriority', '')}\n"
        "--- END FINDING DATA ---\n"
        "Write the IMPACT, TECHNICAL CONTEXT, and PRIORITY JUSTIFICATION now."
    )


def call_bedrock(bedrock_client, prompt, temperature=0.1):
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    })
    try:
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL,
            contentType="application/json",
            accept="application/json",
            body=body,
        )
        result = json.loads(response["body"].read())
        return result["content"][0]["text"].strip()
    except Exception as e:
        logger.error(f"Bedrock invoke failed: {e}")
        return ""


def call_groq(prompt, temperature=0.1):
    """Call Groq's OpenAI-compatible chat endpoint (stdlib only, no extra deps)."""
    body = json.dumps({
        "model": GROQ_MODEL,
        "max_tokens": MAX_TOKENS,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        GROQ_URL, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {GROQ_API_KEY}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.error(f"Groq invoke failed: {e}")
        return ""


def call_llm(prompt, bedrock_client=None, temperature=0.1):
    """Provider-agnostic reasoning call. Default: Groq.
    Set LLM_PROVIDER=bedrock to route through Amazon Bedrock (Claude 3 Haiku) instead."""
    if LLM_PROVIDER == "bedrock":
        return call_bedrock(bedrock_client, prompt, temperature)
    return call_groq(prompt, temperature)


SAFE_FALLBACK = ("IMPACT: Automated analysis is temporarily unavailable for this finding. "
    "TECHNICAL CONTEXT: Refer to the remediation steps below for guidance. "
    "PRIORITY JUSTIFICATION: This finding has been flagged for manual review.")


def validate_output(text, risk):
    """Anti-hallucination guardrail. Rejects outputs that omit the required sections,
    are the wrong length, fail to reference the real resource, or invent IP addresses
    or ARNs not present in the finding. Returns (is_valid, reason)."""
    if not text:
        return False, "empty"
    for header in ("IMPACT:", "TECHNICAL CONTEXT:", "PRIORITY JUSTIFICATION:"):
        if header not in text:
            return False, "missing section " + header
    wc = len(text.split())
    if wc < 80:
        return False, "too short"
    if wc > 400:
        return False, "too long"
    rname = str(risk.get("resourceName", "")).strip()
    if rname and rname not in text:
        return False, "resource name not referenced"
    src = json.dumps(risk)
    bad_ips = [ip for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", text) if ip not in src]
    if bad_ips:
        return False, "invented IP " + str(bad_ips)
    bad_arns = [a for a in re.findall(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d+:[^\s]+", text) if a not in src]
    if bad_arns:
        return False, "invented ARN " + str(bad_arns)
    return True, "ok"


# ---------------------------------------------------------------------------
# Comprehend -- classify risk into a category using key phrase extraction
# Detected key phrases are mapped to: SECURITY | PERFORMANCE | RELIABILITY | COMPLIANCE
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS = {
    "SECURITY":     {"public", "exposed", "open", "unauthenticated", "credential",
                     "secret", "iam", "firewall", "password", "access", "acl", "permission"},
    "PERFORMANCE":  {"latency", "slow", "timeout", "response time", "throughput"},
    "RELIABILITY":  {"error", "failure", "crash", "unavailable", "rollback", "retry", "downtime"},
    "COMPLIANCE":   {"encryption", "gdpr", "hipaa", "pci", "ssn", "pii", "unencrypted", "audit"},
}


def classify_risk_with_comprehend(comprehend_client, risk_text):
    try:
        response = comprehend_client.detect_key_phrases(
            Text=risk_text[:4500],   # Comprehend has a 5 KB limit per call
            LanguageCode="en",
        )
        phrases = {p["Text"].lower() for p in response.get("KeyPhrases", [])}
        phrases.add(risk_text.lower())   # also check the full text

        scores = {cat: 0 for cat in CATEGORY_KEYWORDS}
        for cat, keywords in CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if any(kw in phrase for phrase in phrases):
                    scores[cat] += 1

        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "SECURITY"
    except Exception as e:
        logger.warning(f"Comprehend classify failed: {e}")
        return "SECURITY"


# ---------------------------------------------------------------------------
# DynamoDB -- fetch unprocessed risks and write back
# ---------------------------------------------------------------------------

def fetch_open_risks(table):
    """Scan for OPEN risks that have no AI explanation yet."""
    try:
        response = table.scan(
            FilterExpression=(
                Attr("status").eq("OPEN") &
                (Attr("aiExplanation").eq("") | Attr("aiExplanation").not_exists())
            )
        )
        items = response.get("Items", [])[:MAX_RISKS]
        return items
    except ClientError as e:
        logger.error(f"DynamoDB scan failed: {e}")
        return []


def update_risk(table, risk, explanation, category):
    try:
        table.update_item(
            Key={
                "resourceId":    risk["resourceId"],
                "riskTimestamp": risk["riskTimestamp"],
            },
            UpdateExpression="SET aiExplanation = :ex, riskCategory = :cat",
            ExpressionAttributeValues={
                ":ex":  explanation,
                ":cat": category,
            },
        )
    except ClientError as e:
        logger.error(f"update_item failed for {risk.get('resourceId')}: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    logger.info("ai-explainer started")

    # Initialize clients here (not globally) so test mocks are effective
    ddb     = boto3.resource("dynamodb", region_name=REGION)
    table   = ddb.Table(TABLE_NAME)
    bedrock = boto3.client("bedrock-runtime", region_name=REGION)
    comp    = boto3.client("comprehend",       region_name=REGION)

    risks = fetch_open_risks(table)
    logger.info(f"{len(risks)} risk(s) need AI explanation")

    processed = 0
    latencies_ms = []          # per-finding LLM latency (paper Q2)
    first_pass_valid = 0       # passed the guardrail on attempt 1
    rescued = 0                # passed only after the strict retry (temp 0.05)
    fallback_used = 0          # both attempts failed the guardrail

    for risk in risks:
        _t0 = time.time()
        explanation = call_llm(build_bedrock_prompt(risk), bedrock, temperature=0.1)
        latency_ms = int((time.time() - _t0) * 1000)

        valid, reason = validate_output(explanation, risk)
        if valid:
            first_pass_valid += 1
        else:
            logger.info(f"guardrail rejected attempt 1 ({reason}); retrying strict")
            retry = call_llm(build_bedrock_prompt(risk, strict=True), bedrock, temperature=0.05)
            rvalid, _ = validate_output(retry, risk)
            if rvalid:
                explanation = retry; rescued += 1
            else:
                explanation = SAFE_FALLBACK; fallback_used += 1

        latencies_ms.append(latency_ms)
        logger.info(f"LLM ({LLM_PROVIDER}) latency: {latency_ms}ms for '{risk.get('riskType', '')}'")

        risk_text = f"{risk.get('riskType', '')} {risk.get('riskReason', '')}"
        category  = classify_risk_with_comprehend(comp, risk_text)

        update_risk(table, risk, explanation, category)
        logger.info(f"Updated {risk['resourceId']} -- category: {category}")
        processed += 1

    # Compute latency statistics for the paper (Table III)
    avg_latency = int(sum(latencies_ms) / len(latencies_ms)) if latencies_ms else 0
    max_latency = max(latencies_ms) if latencies_ms else 0
    min_latency = min(latencies_ms) if latencies_ms else 0

    # Write aggregate metric to CloudWatch for benchmarking
    if avg_latency > 0:
        try:
            cw = boto3.client("cloudwatch", region_name=REGION)
            cw.put_metric_data(
                Namespace="CloudSentinel/Performance",
                MetricData=[{
                    "MetricName": "AvgBedrockLatencyMs",
                    "Dimensions":  [{"Name": "Module", "Value": "ai-explainer"}],
                    "Value":       avg_latency,
                    "Unit":        "Milliseconds",
                }],
            )
        except Exception as e:
            logger.warning(f"CloudWatch metric write failed (non-fatal): {e}")

    logger.info(
        f"AI explain complete -- processed={processed} "
        f"avg={avg_latency}ms max={max_latency}ms min={min_latency}ms"
    )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "message":      "AI explanation run complete",
            "processed":    processed,
            "firstPassValid": first_pass_valid,
            "rescued":      rescued,
            "fallback":     fallback_used,
            "avgLatencyMs": avg_latency,
            "maxLatencyMs": max_latency,
            "minLatencyMs": min_latency,
        }),
    }

