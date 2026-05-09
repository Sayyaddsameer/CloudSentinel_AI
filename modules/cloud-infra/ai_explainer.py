import json
import os
import logging
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


# ---------------------------------------------------------------------------
# Bedrock -- generate a developer-friendly explanation for a risk
# ---------------------------------------------------------------------------

def build_bedrock_prompt(risk):
    return (
        "You are a cloud security expert writing for a junior developer.\n\n"
        f"Resource type: {risk.get('resource', '')}\n"
        f"Resource name: {risk.get('resourceName', '')}\n"
        f"Risk: {risk.get('riskType', '')}\n"
        f"Why it is risky: {risk.get('riskReason', '')}\n"
        f"Priority: {risk.get('riskPriority', '')}\n\n"
        "In under 200 words, explain: what this risk means, why it is dangerous, "
        "and one concrete step to fix it. Write in plain English."
    )


def call_bedrock(bedrock_client, prompt):
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS,
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
            FilterExpression=Attr("status").eq("OPEN") & Attr("aiExplanation").eq(""),
            Limit=MAX_RISKS,
        )
        return response.get("Items", [])
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
    ddb      = boto3.resource("dynamodb", region_name=REGION)
    table    = ddb.Table(TABLE_NAME)
    bedrock  = boto3.client("bedrock-runtime", region_name=REGION)
    comp     = boto3.client("comprehend", region_name=REGION)

    risks = fetch_open_risks(table)
    logger.info(f"{len(risks)} risk(s) need AI explanation")

    processed = 0
    for risk in risks:
        prompt      = build_bedrock_prompt(risk)
        explanation = call_bedrock(bedrock, prompt)
        if not explanation:
            continue

        risk_text   = f"{risk.get('riskType', '')} {risk.get('riskReason', '')}"
        category    = classify_risk_with_comprehend(comp, risk_text)

        update_risk(table, risk, explanation, category)
        logger.info(f"Updated {risk['resourceId']} -- category: {category}")
        processed += 1

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "AI explanation run complete", "processed": processed}),
    }
