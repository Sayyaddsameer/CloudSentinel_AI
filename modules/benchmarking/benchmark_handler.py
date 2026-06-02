"""
benchmark_handler.py — CloudSentinel AI Performance Benchmarking Lambda

Measures the wall-clock execution time of the Step Functions parallel scan
versus an estimated sequential baseline, computes a speedup ratio, and
publishes all metrics to CloudWatch namespace CloudSentinel/Performance.

This Lambda is NOT part of the production scan workflow.
It is invoked manually to collect benchmarking data for the paper.

Usage:
    POST /benchmark
    Body: {"runs": 3, "payload": {...}}   # runs: number of repeat measurements

Returns:
    {
        "runs": 3,
        "results": [
            {"run": 1, "parallelMs": 12450, "speedupRatio": 3.2},
            ...
        ],
        "avgParallelMs": 12800,
        "avgSpeedupRatio": 3.1
    }
"""

import json
import os
import time
import logging
import statistics

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION  = os.environ.get("AWS_REGION", "us-east-1")
SFN_ARN = os.environ.get("SFN_ARN", "")

# Estimated sequential baseline (sum of individual scanner durations at P50).
# These values are updated after each benchmarking run from CloudWatch.
# Initial values based on design estimates; replaced by measured values.
SEQUENTIAL_BASELINE_ESTIMATES_MS = {
    "cloud-infra": 8000,
    "devops":       5000,
    "fullstack":    4000,
    "data-eng":     4500,
    "mobile":       3500,
}
SEQUENTIAL_BASELINE_MS = sum(SEQUENTIAL_BASELINE_ESTIMATES_MS.values())  # ~25,000ms

CORS_HEADERS = {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": os.environ.get("AMPLIFY_DOMAIN", "*"),
}


def _start_sfn_execution(sfn_client, payload):
    """Start a Step Functions execution and return the executionArn."""
    resp = sfn_client.start_execution(
        stateMachineArn=SFN_ARN,
        input=json.dumps(payload),
    )
    return resp["executionArn"]


def _wait_for_execution(sfn_client, execution_arn, timeout_s=300):
    """Poll until execution completes; return (status, duration_ms)."""
    t0 = time.time()
    while True:
        elapsed = time.time() - t0
        if elapsed > timeout_s:
            return "TIMEOUT", int(elapsed * 1000)
        desc = sfn_client.describe_execution(executionArn=execution_arn)
        status = desc["status"]
        if status not in ("RUNNING",):
            duration_ms = int(elapsed * 1000)
            logger.info(f"Execution {execution_arn[-8:]} finished: {status} in {duration_ms}ms")
            return status, duration_ms
        time.sleep(2)


def _fetch_module_durations_from_cloudwatch():
    """
    Read the most recent ScanDurationMs metric from CloudWatch for each module
    to build a data-driven sequential baseline (rather than using estimates).
    Returns a dict {module: latest_ms} or empty dict on failure.
    """
    cw = boto3.client("cloudwatch", region_name=REGION)
    modules = ["cloud-infra", "devops", "fullstack", "data-eng", "mobile"]
    durations = {}
    now = time.time()
    for module in modules:
        try:
            resp = cw.get_metric_statistics(
                Namespace="CloudSentinel/Performance",
                MetricName="ScanDurationMs",
                Dimensions=[{"Name": "Module", "Value": module}],
                StartTime=now - 86400,   # last 24 hours
                EndTime=now,
                Period=86400,
                Statistics=["Average"],
            )
            datapoints = resp.get("Datapoints", [])
            if datapoints:
                avg = datapoints[-1]["Average"]
                durations[module] = int(avg)
                logger.info(f"CloudWatch {module}: avg={avg:.0f}ms")
        except Exception as e:
            logger.warning(f"Could not fetch CloudWatch data for {module}: {e}")
    return durations


def _write_benchmark_metrics(parallel_ms, sequential_ms, speedup):
    """Publish benchmark results to CloudWatch."""
    try:
        cw = boto3.client("cloudwatch", region_name=REGION)
        cw.put_metric_data(
            Namespace="CloudSentinel/Performance",
            MetricData=[
                {"MetricName": "ParallelScanDurationMs",   "Value": parallel_ms,   "Unit": "Milliseconds"},
                {"MetricName": "SequentialBaselineMs",     "Value": sequential_ms, "Unit": "Milliseconds"},
                {"MetricName": "ParallelSpeedupRatio",     "Value": speedup,       "Unit": "None"},
            ],
        )
    except Exception as e:
        logger.warning(f"CloudWatch benchmark write failed: {e}")


def lambda_handler(event, context):
    logger.info("benchmark-handler invoked")

    if not SFN_ARN:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "SFN_ARN environment variable not set"}),
        }

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        body = {}

    num_runs    = min(int(body.get("runs", 1)), 5)   # Cap at 5 runs
    sfn_payload = body.get("payload", {})

    sfn = boto3.client("stepfunctions", region_name=REGION)

    # Fetch data-driven sequential baseline from CloudWatch (if available)
    cw_durations = _fetch_module_durations_from_cloudwatch()
    sequential_ms = sum(cw_durations.values()) if cw_durations else SEQUENTIAL_BASELINE_MS
    logger.info(f"Sequential baseline: {sequential_ms}ms (from {'CloudWatch' if cw_durations else 'estimates'})")

    results = []
    for run in range(1, num_runs + 1):
        logger.info(f"Starting benchmark run {run}/{num_runs}")
        exec_arn = _start_sfn_execution(sfn, sfn_payload)
        status, parallel_ms = _wait_for_execution(sfn, exec_arn)
        speedup = round(sequential_ms / parallel_ms, 2) if parallel_ms > 0 else 0
        _write_benchmark_metrics(parallel_ms, sequential_ms, speedup)

        results.append({
            "run":          run,
            "status":       status,
            "parallelMs":   parallel_ms,
            "sequentialMs": sequential_ms,
            "speedupRatio": speedup,
        })
        logger.info(f"Run {run}: parallel={parallel_ms}ms sequential={sequential_ms}ms speedup={speedup}x")

        if run < num_runs:
            time.sleep(5)   # Brief pause between runs

    # Aggregate stats
    parallel_times  = [r["parallelMs"] for r in results]
    speedup_ratios  = [r["speedupRatio"] for r in results]

    summary = {
        "runs":              num_runs,
        "results":           results,
        "sequentialBaselineMs": sequential_ms,
        "avgParallelMs":     int(statistics.mean(parallel_times)),
        "minParallelMs":     min(parallel_times),
        "maxParallelMs":     max(parallel_times),
        "avgSpeedupRatio":   round(statistics.mean(speedup_ratios), 2),
        "baselineSource":    "CloudWatch" if cw_durations else "design_estimates",
    }

    logger.info(f"Benchmark complete: avg={summary['avgParallelMs']}ms speedup={summary['avgSpeedupRatio']}x")

    return {
        "statusCode": 200,
        "headers": CORS_HEADERS,
        "body": json.dumps(summary),
    }
