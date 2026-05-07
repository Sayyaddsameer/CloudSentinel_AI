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


def fetch_module_risks(table, module):
    """Query the module-index GSI for the most recent risks in a given module."""
    try:
        response = table.query(
            IndexName="module-index",
            KeyConditionExpression=Key("module").eq(module),
            ScanIndexForward=False,         # newest first
            Limit=CONTEXT_LIMIT,
        )
        return response.get("Items", [])
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
        f"You are CloudSentinel's AI assistant. The user is asking about their {module} environment.\n\n"
        f"Here are the latest detected risks:\n{context}\n\n"
        f"User question: {question}\n\n"
        "Answer helpfully and specifically based on the risks shown above. "
        "If the question is general, relate it to the risks. Keep your answer under 300 words."
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
        return result["content"][0]["text"].strip()
    except Exception as e:
        logger.error(f"Bedrock invoke failed: {e}")
        return "Sorry, I could not generate a response right now. Please try again."


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

    ddb    = boto3.resource("dynamodb", region_name=REGION)
    table  = ddb.Table(TABLE_NAME)
    risks  = fetch_module_risks(table, module)

    prompt  = build_chat_prompt(question, risks, module)
    bedrock = boto3.client("bedrock-runtime", region_name=REGION)
    answer  = call_bedrock(bedrock, prompt)

    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({"answer": answer, "contextRisks": len(risks)}),
    }
