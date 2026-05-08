/*
 * step_functions.tf — AWS Step Functions orchestration for CloudSentinel
 * Orchestrates the full scan → AI explain → notify workflow
 * Vivek Kantipudi — DevOps module
 */

locals {
  sfn_name = "CloudSentinelScanOrchestrator"
}

# ── IAM Role for Step Functions ───────────────────────────────
resource "aws_iam_role" "step_functions_exec" {
  name = "cloudsentinel-sfn-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Project = "CloudSentinel", ManagedBy = "Terraform" }
}

resource "aws_iam_role_policy" "sfn_lambda_invoke" {
  name   = "cloudsentinel-sfn-lambda-invoke"
  role   = aws_iam_role.step_functions_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeScanners"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.cloud_scanner.arn,
          aws_lambda_function.devops_scanner.arn,
          aws_lambda_function.fullstack_scanner.arn,
          aws_lambda_function.data_scanner.arn,
          aws_lambda_function.mobile_scanner.arn,
          aws_lambda_function.ai_explainer.arn,
          aws_lambda_function.notification_handler.arn,
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup", "logs:CreateLogDelivery",
          "logs:PutLogEvents", "logs:GetLogDelivery",
          "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries", "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "XRayTracing"
        Effect = "Allow"
        Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
        Resource = "*"
      }
    ]
  })
}

# ── CloudWatch log group for Step Functions ───────────────────
resource "aws_cloudwatch_log_group" "sfn_logs" {
  name              = "/aws/states/CloudSentinelScanOrchestrator"
  retention_in_days = 30

  tags = { Project = "CloudSentinel" }
}

# ── State Machine definition ───────────────────────────────────
resource "aws_sfn_state_machine" "scan_orchestrator" {
  name     = local.sfn_name
  role_arn = aws_iam_role.step_functions_exec.arn

  # Express workflow for low-latency, high-throughput scans
  type = "EXPRESS"

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn_logs.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  definition = jsonencode({
    Comment = "CloudSentinel scan orchestration: run all module scanners in parallel, then AI explain and notify"
    StartAt = "ValidateInput"

    States = {

      # ── 1. Validate Input ─────────────────────────────────────
      ValidateInput = {
        Type    = "Pass"
        Comment = "Normalize and validate scan request parameters"
        Result  = { scanStartedAt = "$$.Execution.StartTime" }
        ResultPath = "$.meta"
        Next    = "RunAllScanners"
      }

      # ── 2. Parallel Module Scanners ───────────────────────────
      RunAllScanners = {
        Type    = "Parallel"
        Comment = "Run all five module scanners simultaneously"
        Branches = [
          {
            StartAt = "ScanCloudInfra"
            States  = {
              ScanCloudInfra = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.cloud_scanner.arn
                  "Payload.$"  = "$"
                }
                Retry = [{
                  ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
                  IntervalSeconds = 2
                  MaxAttempts     = 3
                  BackoffRate     = 2.0
                }]
                Catch = [{
                  ErrorEquals = ["States.ALL"]
                  Next        = "CloudScanFailed"
                  ResultPath  = "$.error"
                }]
                ResultPath = "$.cloudScan"
                End        = true
              }
              CloudScanFailed = {
                Type   = "Pass"
                Result = { status = "FAILED", module = "cloud-infra" }
                ResultPath = "$.cloudScan"
                End    = true
              }
            }
          },
          {
            StartAt = "ScanDevOps"
            States  = {
              ScanDevOps = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.devops_scanner.arn
                  "Payload.$"  = "$"
                }
                Retry = [{
                  ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
                  IntervalSeconds = 2
                  MaxAttempts     = 3
                  BackoffRate     = 2.0
                }]
                Catch = [{ ErrorEquals = ["States.ALL"], Next = "DevOpsScanFailed", ResultPath = "$.error" }]
                ResultPath = "$.devopsScan"
                End        = true
              }
              DevOpsScanFailed = {
                Type = "Pass"
                Result = { status = "FAILED", module = "devops" }
                ResultPath = "$.devopsScan"
                End = true
              }
            }
          },
          {
            StartAt = "ScanFullStack"
            States  = {
              ScanFullStack = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.fullstack_scanner.arn
                  "Payload.$"  = "$"
                }
                Retry = [{ ErrorEquals = ["Lambda.ServiceException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2.0 }]
                Catch = [{ ErrorEquals = ["States.ALL"], Next = "FullStackScanFailed", ResultPath = "$.error" }]
                ResultPath = "$.fullstackScan"
                End        = true
              }
              FullStackScanFailed = {
                Type = "Pass"
                Result = { status = "FAILED", module = "fullstack" }
                ResultPath = "$.fullstackScan"
                End = true
              }
            }
          },
          {
            StartAt = "ScanDataEng"
            States  = {
              ScanDataEng = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.data_scanner.arn
                  "Payload.$"  = "$"
                }
                Retry = [{ ErrorEquals = ["Lambda.ServiceException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2.0 }]
                Catch = [{ ErrorEquals = ["States.ALL"], Next = "DataScanFailed", ResultPath = "$.error" }]
                ResultPath = "$.dataScan"
                End        = true
              }
              DataScanFailed = {
                Type = "Pass"
                Result = { status = "FAILED", module = "data-eng" }
                ResultPath = "$.dataScan"
                End = true
              }
            }
          },
          {
            StartAt = "ScanMobile"
            States  = {
              ScanMobile = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = aws_lambda_function.mobile_scanner.arn
                  "Payload.$"  = "$"
                }
                Retry = [{ ErrorEquals = ["Lambda.ServiceException"], IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2.0 }]
                Catch = [{ ErrorEquals = ["States.ALL"], Next = "MobileScanFailed", ResultPath = "$.error" }]
                ResultPath = "$.mobileScan"
                End        = true
              }
              MobileScanFailed = {
                Type = "Pass"
                Result = { status = "FAILED", module = "mobile" }
                ResultPath = "$.mobileScan"
                End = true
              }
            }
          }
        ]

        ResultPath = "$.scanResults"
        Next       = "RunAIExplainer"
      }

      # ── 3. AI Explanation ─────────────────────────────────────
      RunAIExplainer = {
        Type    = "Task"
        Comment = "Send detected risks to Bedrock for AI explanations and priority recommendations"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.ai_explainer.arn
          "Payload.$"  = "$"
        }
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "ThrottlingException"]
          IntervalSeconds = 5
          MaxAttempts     = 3
          BackoffRate     = 2.0
          JitterStrategy  = "FULL"
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "NotifyUser"
          ResultPath  = "$.aiError"
          Comment     = "AI explain failure is non-fatal — proceed to notify with raw data"
        }]
        ResultPath = "$.aiResults"
        Next       = "CheckHighRisks"
      }

      # ── 4. Check if High risks found (decide whether to notify) ─
      CheckHighRisks = {
        Type    = "Choice"
        Comment = "Only send email notification if High-priority risks were found"
        Choices = [{
          Variable      = "$.aiResults.Payload.highRiskCount"
          NumericGreaterThan = 0
          Next          = "NotifyUser"
        }]
        Default = "ScanComplete"
      }

      # ── 5. Notify User via SNS ────────────────────────────────
      NotifyUser = {
        Type    = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.notification_handler.arn
          "Payload.$"  = "$"
        }
        Retry = [{ ErrorEquals = ["Lambda.ServiceException"], IntervalSeconds = 3, MaxAttempts = 2, BackoffRate = 1.5 }]
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "ScanComplete", ResultPath = "$.notifyError" }]
        ResultPath = "$.notifyResult"
        Next       = "ScanComplete"
      }

      # ── 6. Terminal state ─────────────────────────────────────
      ScanComplete = {
        Type = "Succeed"
        Comment = "Scan orchestration completed successfully"
      }
    }
  })

  tags = {
    Project     = "CloudSentinel"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "Vivek Kantipudi"
  }
}

# ── Outputs ───────────────────────────────────────────────────
output "step_function_arn" {
  description = "ARN of the CloudSentinel scan orchestrator Step Function"
  value       = aws_sfn_state_machine.scan_orchestrator.arn
}

output "step_function_name" {
  description = "Name of the Step Function state machine"
  value       = aws_sfn_state_machine.scan_orchestrator.name
}
