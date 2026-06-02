"""
pdf_generator.py — CloudSentinel AI Reporting Lambda

Generates a branded, multi-page PDF audit report from DynamoDB findings.
Includes Security Posture Score, severity breakdown, AI-generated remediation
explanations, and a presigned S3 download URL.

Ported and significantly enhanced from the CloudSentinel Agency commercial
version to produce academic-quality, reproducible audit artifacts.

Environment Variables:
    DYNAMODB_TABLE      -- DynamoDB risks table name
    REPORTS_BUCKET      -- S3 bucket to store generated PDFs
    AWS_REGION          -- AWS region (default: us-east-1)
    PRESIGNED_URL_EXPIRY -- Presigned URL lifetime in seconds (default: 3600)
    AMPLIFY_DOMAIN      -- Allowed CORS origin
"""

import json
import os
import io
import logging
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME      = os.environ["DYNAMODB_TABLE"]
REPORTS_BUCKET  = os.environ.get("REPORTS_BUCKET", "")
REGION          = os.environ.get("AWS_REGION", "us-east-1")
URL_EXPIRY      = int(os.environ.get("PRESIGNED_URL_EXPIRY", "3600"))

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}

# ---------------------------------------------------------------------------
# Colour palette (matches Agency visual identity)
# ---------------------------------------------------------------------------

COLOUR_CRITICAL = (159,  18,  57)   # Deep crimson
COLOUR_HIGH     = (220,  38,  38)   # Red
COLOUR_MEDIUM   = (217, 119,   6)   # Amber
COLOUR_LOW      = ( 59, 130, 246)   # Steel blue
COLOUR_DARK     = ( 15,  17,  25)   # Near-black background
COLOUR_CARD_BG  = ( 22,  27,  50)   # Card background
COLOUR_BLUE     = ( 74, 126, 255)   # Accent blue
COLOUR_WHITE    = (240, 245, 255)   # Off-white text

PRIORITY_COLOURS = {
    "Critical": COLOUR_CRITICAL,
    "High":     COLOUR_HIGH,
    "Medium":   COLOUR_MEDIUM,
    "Low":      COLOUR_LOW,
}

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

MODULE_NAMES = {
    "cloud-infra": "Cloud Infrastructure",
    "devops":      "DevOps & CI/CD",
    "fullstack":   "Full-Stack Application",
    "data-eng":    "Data Engineering",
    "mobile":      "Mobile Backend",
}


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def fetch_all_risks(table):
    """Scan all OPEN risks, deduplicate, and sort by severity."""
    items = []
    try:
        resp = table.scan(FilterExpression=Attr("status").eq("OPEN"))
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = table.scan(
                FilterExpression=Attr("status").eq("OPEN"),
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))
    except ClientError as e:
        logger.error(f"DynamoDB scan failed: {e}")
        return []

    # Deduplicate: keep newest per (resourceId, riskType)
    seen = {}
    for item in items:
        key = (item.get("resourceId", ""), item.get("riskType", ""))
        existing = seen.get(key)
        if not existing or item.get("riskTimestamp", "") > existing.get("riskTimestamp", ""):
            seen[key] = item

    result = list(seen.values())
    result.sort(key=lambda r: (PRIORITY_ORDER.get(r.get("riskPriority", "Low"), 3), r.get("riskTimestamp", "")))
    return result


def fetch_risks_by_module(table, module):
    """Fetch risks for a specific module via the GSI."""
    try:
        resp = table.query(
            IndexName="module-index",
            KeyConditionExpression=Key("module").eq(module),
            FilterExpression=Attr("status").eq("OPEN"),
            ScanIndexForward=False,
        )
        items = resp.get("Items", [])
        items.sort(key=lambda r: (PRIORITY_ORDER.get(r.get("riskPriority", "Low"), 3), r.get("riskTimestamp", "")))
        return items
    except ClientError as e:
        logger.error(f"DynamoDB module query failed: {e}")
        return []


def compute_posture_score(risks):
    """
    Compute a 0–100 security posture score using a weighted penalty model.
    Critical=-20, High=-10, Medium=-5, Low=-2.
    This is a novel quantitative metric introduced in this system.
    """
    weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
    penalty = sum(weights.get(r.get("riskPriority", "Low"), 2) for r in risks)
    return max(0, 100 - penalty)


# ---------------------------------------------------------------------------
# PDF Generation
# ---------------------------------------------------------------------------

def generate_pdf(risks, scan_metadata):
    """
    Build a multi-page PDF report and return the bytes.

    Page 1: Title page with branding, scan metadata, and posture score
    Page 2: Executive summary — severity metric cards, bar chart, posture gauge
    Page 3+: Detailed findings — sorted Critical→High→Medium→Low
    """
    try:
        from fpdf import FPDF
    except ImportError:
        logger.error("fpdf2 library not available. Add it as a Lambda layer.")
        return None

    scan_date = datetime.now(timezone.utc).strftime("%B %d, %Y")
    scan_time = datetime.now(timezone.utc).strftime("%H:%M UTC")
    total     = len(risks)

    critical_count = sum(1 for r in risks if r.get("riskPriority") == "Critical")
    high_count     = sum(1 for r in risks if r.get("riskPriority") == "High")
    medium_count   = sum(1 for r in risks if r.get("riskPriority") == "Medium")
    low_count      = sum(1 for r in risks if r.get("riskPriority") == "Low")
    posture_score  = compute_posture_score(risks)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Page 1: Title Page ────────────────────────────────────────────────
    pdf.add_page()

    # Dark header banner
    pdf.set_fill_color(*COLOUR_DARK)
    pdf.rect(0, 0, 210, 60, "F")

    # Title
    pdf.set_xy(15, 15)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*COLOUR_BLUE)
    pdf.cell(0, 10, "CloudSentinel AI", ln=True)

    pdf.set_x(15)
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(*COLOUR_WHITE)
    pdf.cell(0, 8, "Multi-Cloud Security Intelligence Report", ln=True)

    # Report type badge
    pdf.set_xy(15, 45)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(180, 190, 220)
    pdf.cell(0, 8, "AI-Powered | Generative Remediation | Serverless Architecture", ln=True)

    # Posture Score box (right side of title)
    score_colour = COLOUR_LOW if posture_score >= 80 else COLOUR_MEDIUM if posture_score >= 50 else COLOUR_HIGH
    pdf.set_fill_color(*score_colour)
    pdf.set_xy(155, 12)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*COLOUR_WHITE)
    pdf.cell(40, 14, str(posture_score), align="C", ln=False, fill=True)
    pdf.set_xy(155, 28)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(40, 6, "POSTURE SCORE", align="C", ln=True)

    # Scan metadata block
    pdf.set_fill_color(*COLOUR_CARD_BG)
    pdf.rect(15, 70, 180, 55, "F")

    pdf.set_xy(20, 76)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*COLOUR_BLUE)
    pdf.cell(0, 7, "Scan Information", ln=True)

    meta_items = [
        ("Report Date",    scan_date),
        ("Scan Time",      scan_time),
        ("Total Findings", str(total)),
        ("Modules Scanned", scan_metadata.get("modules", "All modules")),
        ("Cloud Providers", scan_metadata.get("providers", "AWS, GCP")),
    ]
    for label, value in meta_items:
        pdf.set_x(20)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(180, 190, 220)
        pdf.cell(50, 6, label + ":", ln=False)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*COLOUR_WHITE)
        pdf.cell(0, 6, value, ln=True)

    # Disclaimer
    pdf.set_xy(15, 140)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 130, 160)
    pdf.multi_cell(
        180, 5,
        "DISCLAIMER: This report is generated by CloudSentinel AI, an automated multi-cloud "
        "security scanning system. Findings represent point-in-time security posture assessments. "
        "AI-generated remediation guidance should be reviewed by a qualified security professional "
        "before implementation. This report is confidential.",
    )

    # ── Page 2: Executive Summary ─────────────────────────────────────────
    pdf.add_page()

    pdf.set_fill_color(*COLOUR_DARK)
    pdf.rect(0, 0, 210, 20, "F")
    pdf.set_xy(15, 5)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*COLOUR_WHITE)
    pdf.cell(0, 10, "Executive Summary", ln=True)

    # Posture score explanation
    pdf.set_xy(15, 25)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 70, 100)
    posture_label = "Good" if posture_score >= 80 else "Needs Attention" if posture_score >= 50 else "Critical"
    pdf.multi_cell(
        180, 6,
        f"Security posture score: {posture_score}/100 ({posture_label}). "
        f"Total findings: {total} ({critical_count} Critical, {high_count} High, "
        f"{medium_count} Medium, {low_count} Low). "
        f"Score is computed using a weighted penalty model: Critical=−20pts, "
        f"High=−10pts, Medium=−5pts, Low=−2pts."
    )

    # 4 Severity Metric Cards
    card_configs = [
        ("CRITICAL", critical_count, COLOUR_CRITICAL),
        ("HIGH",     high_count,     COLOUR_HIGH),
        ("MEDIUM",   medium_count,   COLOUR_MEDIUM),
        ("LOW",      low_count,      COLOUR_LOW),
    ]
    card_x = 15
    card_y = 55
    card_w = 42
    card_h = 30
    for label, count, colour in card_configs:
        pdf.set_fill_color(*colour)
        pdf.rect(card_x, card_y, card_w, 4, "F")
        pdf.set_fill_color(*COLOUR_CARD_BG)
        pdf.rect(card_x, card_y + 4, card_w, card_h - 4, "F")

        pdf.set_xy(card_x, card_y + 6)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(*colour)
        pdf.cell(card_w, 12, str(count), align="C", ln=False)

        pdf.set_xy(card_x, card_y + 18)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(160, 170, 200)
        pdf.cell(card_w, 6, label, align="C", ln=False)

        card_x += card_w + 4

    # Risk Distribution bar chart
    pdf.set_xy(15, 95)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*COLOUR_DARK)
    pdf.cell(0, 8, "Risk Distribution", ln=True)

    bar_data = [
        ("Critical", critical_count, COLOUR_CRITICAL),
        ("High",     high_count,     COLOUR_HIGH),
        ("Medium",   medium_count,   COLOUR_MEDIUM),
        ("Low",      low_count,      COLOUR_LOW),
    ]
    max_count = max((c for _, c, _ in bar_data), default=1) or 1
    bar_y = 107
    bar_max_w = 120
    for label, count, colour in bar_data:
        bar_w = max(2, int((count / max_count) * bar_max_w)) if count > 0 else 0
        pdf.set_fill_color(*colour)
        if bar_w > 0:
            pdf.rect(45, bar_y, bar_w, 7, "F")

        pdf.set_xy(15, bar_y)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 70, 100)
        pdf.cell(28, 7, label, ln=False)

        pdf.set_xy(45 + bar_w + 3, bar_y)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*colour)
        pdf.cell(20, 7, str(count), ln=True)
        bar_y += 11

    # Top findings overview
    pdf.set_xy(15, bar_y + 5)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*COLOUR_DARK)
    pdf.cell(0, 8, "Top Findings Overview", ln=True)

    for i, risk in enumerate(risks[:8]):
        priority = risk.get("riskPriority", "Low")
        colour   = PRIORITY_COLOURS.get(priority, COLOUR_LOW)
        pdf.set_x(15)
        pdf.set_fill_color(*colour)
        pdf.rect(15, pdf.get_y(), 3, 6, "F")
        pdf.set_xy(21, pdf.get_y())
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*colour)
        pdf.cell(20, 6, f"[{priority}]", ln=False)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(60, 70, 100)
        risk_type = risk.get("riskType", "Unknown risk")[:70]
        pdf.cell(0, 6, risk_type, ln=True)

    # ── Page 3+: Detailed Findings ────────────────────────────────────────
    for i, risk in enumerate(risks):
        priority   = risk.get("riskPriority", "Low")
        colour     = PRIORITY_COLOURS.get(priority, COLOUR_LOW)
        risk_type  = risk.get("riskType", "Unknown Risk")
        resource   = risk.get("resourceName", "N/A")
        res_type   = risk.get("resource", "Unknown")
        module     = MODULE_NAMES.get(risk.get("module", ""), risk.get("module", ""))
        reason     = risk.get("riskReason", "")
        ai_expl    = risk.get("aiExplanation", "")
        remediation= risk.get("remediationSteps", [])
        timestamp  = risk.get("riskTimestamp", "")[:19].replace("T", " ") if risk.get("riskTimestamp") else ""

        # New page for each finding (or start after summary)
        if i == 0 or pdf.get_y() > 220:
            pdf.add_page()
            # Page header
            pdf.set_fill_color(*COLOUR_DARK)
            pdf.rect(0, 0, 210, 15, "F")
            pdf.set_xy(15, 3)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*COLOUR_WHITE)
            pdf.cell(0, 9, "Detailed Security Findings", ln=True)
        elif pdf.get_y() > 200:
            pdf.add_page()
            pdf.set_fill_color(*COLOUR_DARK)
            pdf.rect(0, 0, 210, 15, "F")
            pdf.set_xy(15, 3)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*COLOUR_WHITE)
            pdf.cell(0, 9, "Detailed Security Findings (continued)", ln=True)

        # Coloured left-edge severity bar
        y = pdf.get_y() + 3
        pdf.set_fill_color(*colour)
        pdf.rect(10, y, 4, 40, "F")

        # Finding header
        pdf.set_xy(17, y)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*COLOUR_DARK)
        pdf.cell(130, 7, f"#{i+1}  {risk_type[:60]}", ln=False)

        # Priority badge
        pdf.set_fill_color(*colour)
        pdf.set_text_color(*COLOUR_WHITE)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(25, 7, f"  {priority.upper()}  ", align="C", fill=True, ln=True)

        # Metadata row
        pdf.set_x(17)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 110, 140)
        pdf.cell(0, 6, f"Resource: {resource}  |  Type: {res_type}  |  Module: {module}  |  {timestamp}", ln=True)

        # Description block
        pdf.set_x(17)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*COLOUR_DARK)
        pdf.cell(0, 6, "DESCRIPTION", ln=True)
        pdf.set_x(17)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 70, 100)
        pdf.multi_cell(175, 5, reason[:400] if reason else "No description available.")

        # AI Explanation block (if available from Bedrock)
        if ai_expl:
            pdf.set_x(17)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*COLOUR_BLUE)
            pdf.cell(0, 6, "AI SECURITY ANALYSIS  (Generated by Amazon Bedrock)", ln=True)
            pdf.set_x(17)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(80, 90, 130)
            pdf.multi_cell(175, 5, ai_expl[:500])

        # Remediation steps
        if remediation:
            pdf.set_x(17)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*COLOUR_DARK)
            pdf.cell(0, 6, "REMEDIATION STEPS", ln=True)
            steps = remediation if isinstance(remediation, list) else [remediation]
            for j, step in enumerate(steps[:5], 1):
                pdf.set_x(17)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(60, 70, 100)
                pdf.multi_cell(175, 5, f"{j}. {step}")

        # Separator line
        pdf.set_draw_color(200, 210, 230)
        pdf.line(10, pdf.get_y() + 3, 200, pdf.get_y() + 3)
        pdf.set_y(pdf.get_y() + 6)

    # ── Footer on last page ───────────────────────────────────────────────
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 160, 190)
    pdf.cell(0, 5, f"CloudSentinel AI  |  Generated: {scan_date} {scan_time}  |  {total} findings  |  Posture Score: {posture_score}/100", align="C")

    return pdf.output(dest="S").encode("latin-1")


# ---------------------------------------------------------------------------
# S3 Upload + Presigned URL
# ---------------------------------------------------------------------------

def upload_to_s3(pdf_bytes, scan_id):
    """Upload PDF to S3 and return a presigned download URL."""
    if not REPORTS_BUCKET:
        logger.warning("REPORTS_BUCKET not configured — skipping S3 upload")
        return None

    s3 = boto3.client("s3", region_name=REGION)
    date_str   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    object_key = f"reports/{scan_id}/CloudSentinel_Report_{scan_id}_{date_str}.pdf"

    try:
        s3.put_object(
            Bucket=REPORTS_BUCKET,
            Key=object_key,
            Body=pdf_bytes,
            ContentType="application/pdf",
            ContentDisposition=f'attachment; filename="CloudSentinel_Report_{scan_id}.pdf"',
        )
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": REPORTS_BUCKET, "Key": object_key},
            ExpiresIn=URL_EXPIRY,
        )
        logger.info(f"PDF uploaded to s3://{REPORTS_BUCKET}/{object_key}")
        return url
    except ClientError as e:
        logger.error(f"S3 upload failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    logger.info("pdf-generator invoked")

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        body = {}

    scan_id = body.get("scanId", datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    module  = body.get("module", "")  # optional: filter by module

    ddb   = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.Table(TABLE_NAME)

    # Fetch risks
    if module:
        risks = fetch_risks_by_module(table, module)
    else:
        risks = fetch_all_risks(table)

    if not risks:
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "No open risks found — nothing to report", "riskCount": 0}),
        }

    scan_metadata = {
        "modules":   body.get("modules", "All modules"),
        "providers": body.get("providers", "AWS, GCP"),
    }

    # Generate PDF
    pdf_bytes = generate_pdf(risks, scan_metadata)
    if not pdf_bytes:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "PDF generation failed (fpdf2 may not be available as a Lambda Layer)"}),
        }

    # Upload to S3 and get presigned URL
    download_url = upload_to_s3(pdf_bytes, scan_id)

    posture_score  = compute_posture_score(risks)
    critical_count = sum(1 for r in risks if r.get("riskPriority") == "Critical")
    high_count     = sum(1 for r in risks if r.get("riskPriority") == "High")
    medium_count   = sum(1 for r in risks if r.get("riskPriority") == "Medium")
    low_count      = sum(1 for r in risks if r.get("riskPriority") == "Low")

    logger.info(f"PDF generated — {len(risks)} findings, score={posture_score}")

    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message":       "Report generated successfully",
            "downloadUrl":   download_url,
            "riskCount":     len(risks),
            "postureScore":  posture_score,
            "criticalCount": critical_count,
            "highCount":     high_count,
            "mediumCount":   medium_count,
            "lowCount":      low_count,
            "scanId":        scan_id,
        }),
    }
