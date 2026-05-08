# Sameer's Lambda functions: cloud-scanner, ai-explainer, chatbot-handler, risk-reader

# ---------------------------------------------------------------------------
# cloud-scanner
# ---------------------------------------------------------------------------

data "archive_file" "cloud_scanner_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/cloud-infra"
  output_path = "${path.module}/../../modules/cloud-infra/cloud_scanner.zip"
}

resource "aws_lambda_function" "cloud_scanner" {
  filename         = data.archive_file.cloud_scanner_zip.output_path
  function_name    = "${var.project}-cloud-scanner"
  role             = aws_iam_role.lambda_role.arn
  handler          = "cloud_scanner.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 256
  source_code_hash = data.archive_file.cloud_scanner_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE  = aws_dynamodb_table.risks.name
      GCP_SECRET_NAME = var.gcp_secret_name
      TARGET_ROLE_ARN = var.target_role_arn
    }
  }

  tags = { Project = var.project, Module = "cloud-infra", Owner = "sameer" }
}

resource "aws_lambda_permission" "cloud_scanner_apigw" {
  statement_id  = "AllowAPIGatewayCloudScanner"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloud_scanner.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------
# ai-explainer
# ---------------------------------------------------------------------------

data "archive_file" "ai_explainer_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/cloud-infra"
  output_path = "${path.module}/../../modules/cloud-infra/ai_explainer.zip"
}

resource "aws_lambda_function" "ai_explainer" {
  filename         = data.archive_file.ai_explainer_zip.output_path
  function_name    = "${var.project}-ai-explainer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "ai_explainer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 256
  source_code_hash = data.archive_file.ai_explainer_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE    = aws_dynamodb_table.risks.name
      BEDROCK_MODEL_ID  = var.bedrock_model_id
      MAX_TOKENS        = tostring(var.max_tokens)
      MAX_RISKS_PER_RUN = tostring(var.max_risks_per_run)
    }
  }

  tags = { Project = var.project, Module = "cloud-infra", Owner = "sameer" }
}

resource "aws_lambda_permission" "ai_explainer_events" {
  statement_id  = "AllowEventBridgeAIExplainer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai_explainer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ai_explainer_schedule.arn
}

# ---------------------------------------------------------------------------
# chatbot-handler
# ---------------------------------------------------------------------------

data "archive_file" "chatbot_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/cloud-infra"
  output_path = "${path.module}/../../modules/cloud-infra/chatbot_handler.zip"
}

resource "aws_lambda_function" "chatbot_handler" {
  filename         = data.archive_file.chatbot_zip.output_path
  function_name    = "${var.project}-chatbot-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "chatbot_handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256
  source_code_hash = data.archive_file.chatbot_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE        = aws_dynamodb_table.risks.name
      BEDROCK_MODEL_ID      = var.bedrock_model_id
      MAX_TOKENS            = tostring(var.max_tokens)
      CHATBOT_CONTEXT_RISKS = tostring(var.chatbot_context_risks)
    }
  }

  tags = { Project = var.project, Module = "cloud-infra", Owner = "sameer" }
}

resource "aws_lambda_permission" "chatbot_apigw" {
  statement_id  = "AllowAPIGatewayChatbot"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.chatbot_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------
# risk-reader
# ---------------------------------------------------------------------------

data "archive_file" "risk_reader_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/cloud-infra"
  output_path = "${path.module}/../../modules/cloud-infra/risk_reader.zip"
}

resource "aws_lambda_function" "risk_reader" {
  filename         = data.archive_file.risk_reader_zip.output_path
  function_name    = "${var.project}-risk-reader"
  role             = aws_iam_role.lambda_role.arn
  handler          = "risk_reader.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 128
  source_code_hash = data.archive_file.risk_reader_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE   = aws_dynamodb_table.risks.name
      RISKS_PAGE_LIMIT = tostring(var.risks_page_limit)
    }
  }

  tags = { Project = var.project, Module = "cloud-infra", Owner = "sameer" }
}

resource "aws_lambda_permission" "risk_reader_apigw" {
  statement_id  = "AllowAPIGatewayRiskReader"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.risk_reader.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
