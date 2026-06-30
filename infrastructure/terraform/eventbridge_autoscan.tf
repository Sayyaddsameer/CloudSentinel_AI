# ---------------------------------------------------------------------------
# eventbridge_autoscan.tf
# EventBridge rules for automatic rescanning on AWS resource changes.
# Each CloudTrail event routes to the auto_rescan_router Lambda,
# which then invokes the appropriate scanner Lambda(s).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Auto-Rescan Router Lambda
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "auto_rescan_router" {
  filename         = data.archive_file.auto_rescan_router_zip.output_path
  function_name    = "${var.project}-auto-rescan-router"
  role             = aws_iam_role.lambda_role.arn
  handler          = "auto_rescan_router.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 128
  source_code_hash = data.archive_file.auto_rescan_router_zip.output_base64sha256

  environment {
    variables = {
      PROJECT_NAME = var.project
    }
  }

  tags = { Project = var.project, Module = "auto-rescan" }
}

resource "aws_lambda_permission" "allow_eventbridge_autoscan" {
  statement_id  = "AllowEventBridgeAutoScan"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_rescan_router.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/*"
}

# ---------------------------------------------------------------------------
# IAM — allow router to invoke scanner Lambdas
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "router_invoke_scanners" {
  name = "${var.project}-router-invoke-scanners"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "InvokeScanners"
      Effect = "Allow"
      Action = ["lambda:InvokeFunction"]
      Resource = [
        "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.project}-*"
      ]
    }]
  })
}

# ---------------------------------------------------------------------------
# CloudTrail-based EventBridge rules
# Note: CloudTrail must be enabled and CloudWatch Logs must be set up.
# These rules match management events for each AWS service.
# ---------------------------------------------------------------------------

# ── CloudFormation changes → cloud-infra scanner ─────────────────────────
resource "aws_cloudwatch_event_rule" "cfn_changes" {
  name        = "${var.project}-cfn-changes"
  description = "Triggers cloud-infra rescan on CloudFormation stack changes"

  event_pattern = jsonencode({
    source      = ["aws.cloudformation"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudformation.amazonaws.com"]
      eventName   = ["CreateStack", "UpdateStack", "DeleteStack"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "cfn_to_router" {
  rule      = aws_cloudwatch_event_rule.cfn_changes.name
  target_id = "AutoRescanRouter"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── Lambda function changes → cloud-infra + devops scanners ──────────────
resource "aws_cloudwatch_event_rule" "lambda_changes" {
  name        = "${var.project}-lambda-changes"
  description = "Triggers cloud-infra + devops rescan on Lambda function changes"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["lambda.amazonaws.com"]
      eventName   = ["CreateFunction20150331", "UpdateFunctionCode20150331v2", "DeleteFunction20150331"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "lambda_to_router" {
  rule      = aws_cloudwatch_event_rule.lambda_changes.name
  target_id = "AutoRescanRouterLambda"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── S3 bucket changes → cloud-infra + data-eng scanners ──────────────────
resource "aws_cloudwatch_event_rule" "s3_changes" {
  name        = "${var.project}-s3-changes"
  description = "Triggers cloud-infra + data-eng rescan on S3 bucket changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["CreateBucket", "DeleteBucket", "PutBucketPolicy", "PutBucketAcl"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "s3_to_router" {
  rule      = aws_cloudwatch_event_rule.s3_changes.name
  target_id = "AutoRescanRouterS3"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── EC2 security group changes → cloud-infra scanner ─────────────────────
resource "aws_cloudwatch_event_rule" "ec2_sg_changes" {
  name        = "${var.project}-ec2-sg-changes"
  description = "Triggers cloud-infra rescan on EC2 security group changes"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "CreateSecurityGroup"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "ec2_sg_to_router" {
  rule      = aws_cloudwatch_event_rule.ec2_sg_changes.name
  target_id = "AutoRescanRouterEC2"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── IAM policy changes → cloud-infra + mobile scanners ───────────────────
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.project}-iam-changes"
  description = "Triggers cloud-infra + mobile rescan on IAM role/policy changes"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["PutRolePolicy", "AttachRolePolicy", "CreateRole", "DeleteRolePolicy", "DetachRolePolicy"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "iam_to_router" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "AutoRescanRouterIAM"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── API Gateway changes → fullstack + mobile scanners ────────────────────
resource "aws_cloudwatch_event_rule" "apigw_changes" {
  name        = "${var.project}-apigw-changes"
  description = "Triggers fullstack + mobile rescan on API Gateway changes"

  event_pattern = jsonencode({
    source      = ["aws.apigateway"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["apigateway.amazonaws.com"]
      eventName   = ["CreateRestApi", "PutMethod", "CreateDeployment", "DeleteRestApi"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "apigw_to_router" {
  rule      = aws_cloudwatch_event_rule.apigw_changes.name
  target_id = "AutoRescanRouterAPIGW"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── Cognito changes → mobile scanner ─────────────────────────────────────
resource "aws_cloudwatch_event_rule" "cognito_changes" {
  name        = "${var.project}-cognito-changes"
  description = "Triggers mobile rescan on Cognito user pool changes"

  event_pattern = jsonencode({
    source      = ["aws.cognito-idp"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cognito-idp.amazonaws.com"]
      eventName   = ["CreateUserPool", "UpdateUserPool", "DeleteUserPool"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "cognito_to_router" {
  rule      = aws_cloudwatch_event_rule.cognito_changes.name
  target_id = "AutoRescanRouterCognito"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── Glue changes → data-eng scanner ──────────────────────────────────────
resource "aws_cloudwatch_event_rule" "glue_changes" {
  name        = "${var.project}-glue-changes"
  description = "Triggers data-eng rescan on Glue job changes"

  event_pattern = jsonencode({
    source      = ["aws.glue"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["glue.amazonaws.com"]
      eventName   = ["CreateJob", "UpdateJob", "StartJobRun"]
    }
  })

  tags = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "glue_to_router" {
  rule      = aws_cloudwatch_event_rule.glue_changes.name
  target_id = "AutoRescanRouterGlue"
  arn       = aws_lambda_function.auto_rescan_router.arn
}

# ── Scheduled full rescan — every 6 hours ────────────────────────────────
resource "aws_cloudwatch_event_rule" "scheduled_rescan" {
  name                = "${var.project}-scheduled-rescan"
  description         = "Runs all CloudSentinel scanners every 6 hours"
  schedule_expression = "rate(6 hours)"
  tags                = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "scheduled_rescan_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_rescan.name
  target_id = "ScheduledAutoRescan"
  arn       = aws_lambda_function.auto_rescan_router.arn

  input = jsonencode({
    source    = "scheduled-rescan"
    trigger   = "eventbridge-schedule"
    detail = {
      eventSource = "all"
      eventName   = "ScheduledFullScan"
    }
  })
}
