# Sameer's Lambda functions: cloud-scanner, ai-explainer, chatbot-handler, risk-reader
# Each Lambda packages ONLY its own handler file to minimise deployment size and cold-start time.

# ---------------------------------------------------------------------------
# cloud-scanner
# ---------------------------------------------------------------------------

data "archive_file" "cloud_scanner_zip" {
  type        = "zip"
  source_file = "${path.module}/../../modules/cloud-infra/cloud_scanner.py"
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
  source_file = "${path.module}/../../modules/cloud-infra/ai_explainer.py"
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
  source_file = "${path.module}/../../modules/cloud-infra/chatbot_handler.py"
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
  source_file = "${path.module}/../../modules/cloud-infra/risk_reader.py"
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

# ---------------------------------------------------------------------------
# disconnect-handler  (own zip — only disconnect_handler.py)
# ---------------------------------------------------------------------------

data "archive_file" "disconnect_handler_zip" {
  type        = "zip"
  source_file = "${path.module}/../../modules/cloud-infra/disconnect_handler.py"
  output_path = "${path.module}/../../modules/cloud-infra/disconnect_handler.zip"
}

resource "aws_lambda_function" "disconnect_handler" {
  filename         = data.archive_file.disconnect_handler_zip.output_path
  function_name    = "${var.project}-disconnect-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "disconnect_handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 128
  source_code_hash = data.archive_file.disconnect_handler_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE     = aws_dynamodb_table.risks.name
      AWS_ACCOUNT_REGION = var.aws_region
    }
  }

  tags = { Project = var.project, Module = "cloud-infra", Owner = "sameer" }
}

resource "aws_lambda_permission" "disconnect_handler_apigw" {
  statement_id  = "AllowAPIGatewayDisconnectHandler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.disconnect_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------
# auto-rescan-router  (own zip — only auto_rescan_router.py)
# NOTE: notification_handler is defined authoritatively in sns.tf
#       which correctly wires SNS_TOPIC_ARN. Do NOT redeclare it here.
# ---------------------------------------------------------------------------

data "archive_file" "auto_rescan_router_zip" {
  type        = "zip"
  source_file = "${path.module}/../../modules/cloud-infra/auto_rescan_router.py"
  output_path = "${path.module}/../../modules/cloud-infra/auto_rescan_router.zip"
}

# ---------------------------------------------------------------------------
# validate-connection  — verifies STS AssumeRole before saving a connection
# Own zip: only validate_connection.py
# ---------------------------------------------------------------------------

data "archive_file" "validate_connection_zip" {
  type        = "zip"
  source_file = "${path.module}/../../modules/cloud-infra/validate_connection.py"
  output_path = "${path.module}/../../modules/cloud-infra/validate_connection.zip"
}

resource "aws_lambda_function" "validate_connection" {
  filename         = data.archive_file.validate_connection_zip.output_path
  function_name    = "${var.project}-validate-connection"
  role             = aws_iam_role.lambda_role.arn
  handler          = "validate_connection.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 128
  source_code_hash = data.archive_file.validate_connection_zip.output_base64sha256

  environment {
    variables = {
      AWS_ACCOUNT_REGION = var.aws_region
    }
  }

  tags = { Project = var.project, Module = "cloud-infra", Owner = "sameer" }
}

resource "aws_api_gateway_resource" "validate_connection" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "validate-connection"
}

resource "aws_api_gateway_method" "validate_connection_post" {
  rest_api_id   = aws_api_gateway_resource.validate_connection.rest_api_id
  resource_id   = aws_api_gateway_resource.validate_connection.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "validate_connection_post" {
  rest_api_id             = aws_api_gateway_resource.validate_connection.rest_api_id
  resource_id             = aws_api_gateway_resource.validate_connection.id
  http_method             = aws_api_gateway_method.validate_connection_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.validate_connection.invoke_arn
}

resource "aws_lambda_permission" "validate_connection_apigw" {
  statement_id  = "AllowAPIGatewayValidateConnection"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.validate_connection.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
