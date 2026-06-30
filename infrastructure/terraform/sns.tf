# ---------------------------------------------------------------------------
# sns.tf — SNS topic, email subscription, and notification Lambda
# Managed by: Terraform
# ---------------------------------------------------------------------------

# SNS topic for risk alert email notifications
resource "aws_sns_topic" "alerts" {
  name         = "${var.project}-alerts"
  display_name = "CloudSentinel Risk Alerts"

  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Email subscription — recipient must confirm the subscription link before
# alerts are delivered. The alert_email variable must be set in tfvars.
resource "aws_sns_topic_subscription" "admin_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SNS topic resource policy — restricts topic access to this AWS account only.
# NOTE: SNS resource policies do NOT support Service principals (e.g. lambda.amazonaws.com).
# Lambda publish access is granted via the inline IAM role policy below instead.
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountOwner"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "SNS:Publish",
          "SNS:Subscribe",
          "SNS:GetTopicAttributes",
          "SNS:SetTopicAttributes",
          "SNS:ListSubscriptionsByTopic",
          "SNS:DeleteTopic"
        ]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# Inline IAM policy — allows the shared Lambda role to publish to this topic
resource "aws_iam_role_policy" "lambda_sns_publish" {
  name = "${var.project}-lambda-sns-publish"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowSNSPublish"
      Effect   = "Allow"
      Action   = ["sns:Publish", "sns:ListSubscriptionsByTopic"]
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

# ---------------------------------------------------------------------------
# Notification Lambda — triggered by EventBridge on scan completion
# ---------------------------------------------------------------------------

data "archive_file" "notification_handler_zip" {
  type        = "zip"
  source_file = "${path.module}/../../modules/cloud-infra/notification_handler.py"
  output_path = "${path.module}/../../modules/cloud-infra/notification_handler.zip"
}

resource "aws_lambda_function" "notification_handler" {
  function_name    = "${var.project}-notification-handler"
  runtime          = "python3.11"
  handler          = "notification_handler.lambda_handler"
  role             = aws_iam_role.lambda_role.arn
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.notification_handler_zip.output_path
  source_code_hash = data.archive_file.notification_handler_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE         = aws_dynamodb_table.risks.name
      SNS_TOPIC_ARN          = aws_sns_topic.alerts.arn
      NOTIFICATION_THRESHOLD = var.notification_threshold
      APP_URL                = var.app_url
    }
  }

  depends_on = [aws_iam_role_policy.lambda_sns_publish]

  tags = {
    Project     = var.project
    Environment = var.environment
    Module      = "notifications"
    ManagedBy   = "Terraform"
  }
}

# EventBridge rule — trigger notification handler when a scan completes
resource "aws_cloudwatch_event_rule" "scan_complete" {
  name        = "${var.project}-scan-complete"
  description = "Triggers the notification Lambda when a CloudSentinel scan completes"

  event_pattern = jsonencode({
    source      = ["cloudsentinel.scanner"]
    detail-type = ["ScanCompleted"]
    detail = {
      status = ["COMPLETED"]
    }
  })

  tags = {
    Project = var.project
  }
}

resource "aws_cloudwatch_event_target" "notify_on_scan" {
  rule      = aws_cloudwatch_event_rule.scan_complete.name
  target_id = "NotificationHandler"
  arn       = aws_lambda_function.notification_handler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_notify" {
  statement_id  = "AllowEventBridgeInvokeNotify"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.notification_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_complete.arn
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "sns_alerts_topic_arn" {
  description = "ARN of the CloudSentinel risk alerts SNS topic"
  value       = aws_sns_topic.alerts.arn
}

output "notification_lambda_arn" {
  description = "ARN of the notification handler Lambda function"
  value       = aws_lambda_function.notification_handler.arn
}
