"""
scan_events.py — shared EventBridge event emitter for CloudSentinel scanners.

Every scanner Lambda calls emit_scan_completed() after saving risks to DynamoDB.
This event is matched by the aws_cloudwatch_event_rule.scan_complete rule in sns.tf,
which routes it to the notification_handler Lambda for SNS email alerting.

Event shape:
  source      : "cloudsentinel.scanner"
  detail-type : "ScanCompleted"
  detail : {
    "module"       : "<module-name>",
    "status"       : "COMPLETED",
    "risksFound"   : <int>,
    "highCount"    : <int>,
    "mediumCount"  : <int>,
    "lowCount"     : <int>,
    "scanId"       : "<ISO-timestamp>",
    "region"       : "<aws-region>"
  }
"""
import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

REGION = os.environ.get("AWS_REGION", "us-east-1")


def emit_scan_completed(module: str, risks: list) -> None:
    """
    Emit a ScanCompleted EventBridge event.
    Non-fatal — a failure here must never break the scan response.

    Args:
        module: CloudSentinel module name, e.g. "cloud-infra", "devops"
        risks:  List of risk dicts written to DynamoDB during this scan run.
    """
    high   = sum(1 for r in risks if r.get("riskPriority") == "High")
    medium = sum(1 for r in risks if r.get("riskPriority") == "Medium")
    low    = sum(1 for r in risks if r.get("riskPriority") == "Low")
    scan_id = datetime.now(timezone.utc).isoformat()

    detail = {
        "module":      module,
        "status":      "COMPLETED",
        "risksFound":  len(risks),
        "highCount":   high,
        "mediumCount": medium,
        "lowCount":    low,
        "scanId":      scan_id,
        "region":      REGION,
    }

    try:
        eb = boto3.client("events", region_name=REGION)
        response = eb.put_events(Entries=[{
            "Source":       "cloudsentinel.scanner",
            "DetailType":   "ScanCompleted",
            "Detail":       json.dumps(detail),
            "EventBusName": "default",
        }])
        failed = response.get("FailedEntryCount", 0)
        if failed:
            logger.warning("EventBridge put_events: %d entr(ies) failed — %s",
                           failed, response.get("Entries"))
        else:
            logger.info("ScanCompleted event emitted: module=%s risks=%d high=%d",
                        module, len(risks), high)
    except ClientError as exc:
        logger.warning("Could not emit ScanCompleted event (non-fatal): %s", exc)
    except Exception as exc:
        logger.warning("Unexpected error emitting ScanCompleted event (non-fatal): %s", exc)
