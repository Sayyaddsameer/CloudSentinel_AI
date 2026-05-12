"""
notification_handler.py

Lambda function triggered by EventBridge when a CloudSentinel scan completes.
Queries DynamoDB for open risks above the configured priority threshold and
sends a structured HTML summary email via SNS.

Environment Variables (all required unless marked optional):
    DYNAMODB_TABLE         -- Name of the DynamoDB risks table
    SNS_TOPIC_ARN          -- ARN of the SNS topic for email alerts
    NOTIFICATION_THRESHOLD -- Minimum priority to notify: High | Medium | All
    APP_URL                -- Public URL of the Amplify frontend (optional)
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration -- sourced entirely from Lambda environment variables
# ---------------------------------------------------------------------------

DYNAMODB_TABLE         = os.environ["DYNAMODB_TABLE"]
SNS_TOPIC_ARN          = os.environ["SNS_TOPIC_ARN"]
NOTIFICATION_THRESHOLD = os.environ.get("NOTIFICATION_THRESHOLD", "High")
APP_URL                = os.environ.get("APP_URL", "")

_THRESHOLD_PRIORITIES = {
    "High":   ["High"],
    "Medium": ["High", "Medium"],
    "All":    ["High", "Medium", "Low"],
}

dynamodb = boto3.resource("dynamodb")
sns      = boto3.client("sns")
table    = dynamodb.Table(DYNAMODB_TABLE)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    """
    Dual-mode handler:
    Mode A (API Gateway / frontend): POST /notify with body {module, highCount}
    Mode B (EventBridge): {module, userId, userEmail, scanId, ...}
    In both modes, sends SNS alert if there are High-priority open risks.
    """
    # ── Parse event (API Gateway or EventBridge) ──────────────────────────────
    if event.get("body") is not None:
        # API Gateway call from frontend's triggerSnsAlert()
        try:
            body = json.loads(event.get("body") or "{}")
        except Exception:
            body = {}
        module     = body.get("module", "unknown")
        user_email = body.get("userEmail", "")  # optional
        scan_id    = body.get("scanId", "")
    else:
        # Direct EventBridge invocation
        module     = event.get("module", "unknown")
        user_email = event.get("userEmail", "")
        scan_id    = event.get("scanId", "")

    if not SNS_TOPIC_ARN:
        logger.error("SNS_TOPIC_ARN environment variable is not set -- cannot send notification")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*")},
            "body": "Configuration error: SNS_TOPIC_ARN is not set",
        }

    # ── Fetch risks for this module ───────────────────────────────────────────
    risks = _fetch_risks_for_scan(module, scan_id)

    notify_priorities = _THRESHOLD_PRIORITIES.get(NOTIFICATION_THRESHOLD, ["High"])
    notify_risks = [r for r in risks if r.get("riskPriority") in notify_priorities]

    if not notify_risks:
        logger.info(
            "No risks at threshold '%s' found for module=%s",
            NOTIFICATION_THRESHOLD, module,
        )
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*")},
            "body": json.dumps({"status": "no_risks", "module": module}),
        }

    high   = sum(1 for r in notify_risks if r.get("riskPriority") == "High")
    medium = sum(1 for r in notify_risks if r.get("riskPriority") == "Medium")
    low    = sum(1 for r in notify_risks if r.get("riskPriority") == "Low")

    subject = f"[CloudSentinel] {high} High-priority risk(s) detected in {_module_display_name(module)}"
    html    = _build_html_email(module, notify_risks, high, medium, low, scan_id)
    text    = _build_text_email(module, notify_risks, high, medium, low)

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=text,
            MessageStructure="raw" if not user_email else "raw",
        )
        logger.info(
            "SNS notification sent: risks=%d module=%s",
            len(notify_risks), module,
        )
    except ClientError as exc:
        logger.error("SNS publish failed: %s", exc)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*")},
            "body": json.dumps({"error": str(exc)}),
        }

    _mark_risks_notified(notify_risks)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*")},
        "body": json.dumps({"notified": len(notify_risks), "module": module, "high": high}),
    }


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _fetch_risks_for_scan(module, scan_id):
    """
    Query the module-index GSI for OPEN risks in a given module, then filter
    by scanId in memory. This avoids requiring a separate userId-module-index
    GSI that is not declared in the table schema.
    """
    try:
        response = table.query(
            IndexName="module-index",
            KeyConditionExpression=Key("module").eq(module),
            FilterExpression=Attr("status").eq("OPEN"),
        )
        items = response.get("Items", [])
        if scan_id:
            items = [r for r in items if r.get("scanId") == scan_id]
        return items
    except ClientError as exc:
        logger.error("DynamoDB query failed for module='%s': %s", module, exc)
        return []


def _mark_risks_notified(risks):
    """Update each risk record to record that a notification was sent."""
    now = datetime.now(timezone.utc).isoformat()
    for risk in risks:
        resource_id    = risk.get("resourceId")
        risk_timestamp = risk.get("riskTimestamp")
        if not resource_id or not risk_timestamp:
            continue
        try:
            table.update_item(
                Key={"resourceId": resource_id, "riskTimestamp": risk_timestamp},
                UpdateExpression="SET notified = :t, notifiedAt = :ts",
                ExpressionAttributeValues={":t": True, ":ts": now},
            )
        except ClientError as exc:
            logger.warning("Could not mark risk '%s' as notified: %s", resource_id, exc)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _module_display_name(module: str) -> str:
    names = {
        "cloud-infra": "Cloud Infrastructure",
        "devops":      "DevOps",
        "fullstack":   "Full-Stack Application",
        "data-eng":    "Data Engineering",
        "mobile":      "Mobile Backend",
    }
    return names.get(module, module)


# ---------------------------------------------------------------------------
# Email builders
# ---------------------------------------------------------------------------

def _build_html_email(module, risks, high, medium, low, scan_id):
    rows = ""
    for r in risks[:20]:
        priority = r.get("riskPriority", "Unknown")
        color    = {"High": "#e53e3e", "Medium": "#d69e2e", "Low": "#38a169"}.get(priority, "#718096")
        rows += (
            f"<tr>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #1e2840;"
            f"font-size:13px;color:#e2e8f5\">{r.get('riskType', '')}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #1e2840;"
            f"font-size:13px;color:#8892aa\">{r.get('resourceName', '')}</td>"
            f"<td style=\"padding:10px 12px;border-bottom:1px solid #1e2840\">"
            f"<span style=\"font-size:11px;font-weight:700;color:{color};"
            f"background:rgba(255,255,255,.08);padding:3px 8px;border-radius:4px\">"
            f"{priority}</span></td>"
            f"</tr>"
        )

    truncated = ""
    if len(risks) > 20:
        truncated = (
            f"<p style=\"color:#8892aa;font-size:12px;text-align:center\">"
            f"... and {len(risks) - 20} additional risk(s) not shown</p>"
        )

    scan_ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_ref = scan_id[:8] if scan_id else "N/A"
    dashboard_url = f"{APP_URL}/{module.replace('-', '')}.html" if APP_URL else "#"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>CloudSentinel Risk Alert</title></head>
<body style="margin:0;padding:0;background:#080c1a;font-family:Inter,system-ui,sans-serif">
  <table width="100%" style="max-width:640px;margin:32px auto;background:#111628;
    border:1px solid #1e2840;border-radius:12px;overflow:hidden">
    <tr><td style="background:linear-gradient(135deg,#2b6cb0,#553c9a);padding:28px 32px">
      <div style="font-size:22px;font-weight:800;color:#fff;letter-spacing:-.03em">
        CloudSentinel
      </div>
      <div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:4px">
        AI-Powered Multi-Cloud Risk Intelligence
      </div>
    </td></tr>
    <tr><td style="padding:28px 32px">
      <h2 style="font-size:18px;color:#e2e8f5;margin:0 0 8px">
        New risks detected in {_module_display_name(module)}
      </h2>
      <p style="color:#8892aa;font-size:14px;margin:0 0 24px">
        Scan completed at {scan_ts}
      </p>
      <table width="100%" style="border-collapse:separate;border-spacing:8px;margin-bottom:24px">
        <tr>
          <td style="background:#4a0f18;border:1px solid rgba(229,62,62,.3);
            border-radius:8px;padding:14px;text-align:center;width:33%">
            <div style="font-size:28px;font-weight:700;color:#e53e3e">{high}</div>
            <div style="font-size:12px;color:#8892aa;margin-top:4px">High Priority</div>
          </td>
          <td style="background:#3d2200;border:1px solid rgba(214,158,46,.3);
            border-radius:8px;padding:14px;text-align:center;width:33%">
            <div style="font-size:28px;font-weight:700;color:#d69e2e">{medium}</div>
            <div style="font-size:12px;color:#8892aa;margin-top:4px">Medium Priority</div>
          </td>
          <td style="background:#0b3320;border:1px solid rgba(56,161,105,.3);
            border-radius:8px;padding:14px;text-align:center;width:33%">
            <div style="font-size:28px;font-weight:700;color:#38a169">{low}</div>
            <div style="font-size:12px;color:#8892aa;margin-top:4px">Low Priority</div>
          </td>
        </tr>
      </table>
      <table width="100%" style="border-collapse:collapse;background:#0d1225;
        border-radius:8px;overflow:hidden">
        <thead>
          <tr style="background:#161d35">
            <th style="padding:10px 12px;text-align:left;font-size:11px;font-weight:600;
              color:#4a5577;text-transform:uppercase;letter-spacing:.07em">Risk</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;font-weight:600;
              color:#4a5577;text-transform:uppercase;letter-spacing:.07em">Resource</th>
            <th style="padding:10px 12px;text-align:left;font-size:11px;font-weight:600;
              color:#4a5577;text-transform:uppercase;letter-spacing:.07em">Priority</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      {truncated}
      <div style="margin-top:28px;text-align:center">
        <a href="{dashboard_url}"
          style="display:inline-block;padding:14px 28px;
          background:linear-gradient(135deg,#2b6cb0,#553c9a);
          color:#fff;text-decoration:none;border-radius:8px;
          font-size:14px;font-weight:600">
          View Risk Dashboard
        </a>
      </div>
    </td></tr>
    <tr><td style="padding:18px 32px;background:#0d1225;
      border-top:1px solid #1e2840;text-align:center">
      <p style="font-size:12px;color:#4a5577;margin:0">
        CloudSentinel -- Scan reference: {scan_ref}
      </p>
      <p style="font-size:11px;color:#4a5577;margin:4px 0 0">
        To adjust alert settings, sign in to your dashboard.
      </p>
    </td></tr>
  </table>
</body>
</html>"""


def _build_text_email(module, risks, high, medium, low):
    separator = "-" * 60
    lines = [
        "CloudSentinel Risk Alert",
        separator,
        f"Module  : {_module_display_name(module)}",
        f"Summary : {high} High | {medium} Medium | {low} Low",
        separator,
        "Detected Risks:",
        "",
    ]
    for r in risks[:20]:
        lines.append(
            f"  [{r.get('riskPriority', '?'):6}] {r.get('riskType', '')} "
            f"-- {r.get('resourceName', '')}"
        )
    if len(risks) > 20:
        lines.append(f"  ... and {len(risks) - 20} additional risk(s) not shown.")
    lines.extend([
        "",
        "Sign in to your CloudSentinel dashboard to view full remediation steps.",
        separator,
    ])
    return "\n".join(lines)
