data "archive_file" "securityhub_handler_zip" {
  type        = "zip"
  source_file = "${path.module}/../../modules/cloud-infra/securityhub_handler.py"
  output_path = "${path.module}/../../modules/cloud-infra/securityhub_handler.zip"
}

resource "aws_lambda_function" "securityhub_handler" {
  filename         = data.archive_file.securityhub_handler_zip.output_path
  function_name    = "${var.project}-securityhub-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "securityhub_handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 128
  source_code_hash = data.archive_file.securityhub_handler_zip.output_base64sha256
  layers           = [aws_lambda_layer_version.scan_events.arn]

  environment {
    variables = {
      DYNAMODB_TABLE          = aws_dynamodb_table.risks.name
      # Dynamically resolved — no hardcoding of account IDs
      PLATFORM_ACCOUNT_ID     = data.aws_caller_identity.current.account_id
      # Leave blank to auto-filter only the platform account.
      # Populate with comma-separated target account IDs for strict allow-listing.
      ALLOWED_SCAN_ACCOUNT_IDS = var.allowed_scan_account_ids
    }
  }

  tags = { Project = var.project, Module = "cloud-infra" }
}

resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "${var.project}-securityhub-findings"
  description = "Capture AWS Security Hub findings and route to DynamoDB"
  
  event_pattern = jsonencode({
    source = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_target" "securityhub_handler" {
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  target_id = "SecurityHubHandler"
  arn       = aws_lambda_function.securityhub_handler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_securityhub" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHub"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.securityhub_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_findings.arn
}
