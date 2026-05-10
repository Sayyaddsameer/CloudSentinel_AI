terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy everything into"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "cloudsentinel"
}

variable "environment" {
  description = "Deployment environment label (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address that receives SNS risk alert notifications"
  type        = string
  default     = ""
}

variable "app_url" {
  description = "Public URL of the deployed Amplify frontend (included in alert emails)"
  type        = string
  default     = ""
}

variable "github_token" {
  description = "GitHub personal access token for Amplify source connection"
  type        = string
  sensitive   = true
  default     = ""
}

variable "gcp_secret_name" {
  description = "Name of the Secrets Manager secret holding the GCP service account JSON key"
  type        = string
  default     = ""
}

variable "webhook_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the GitHub webhook HMAC secret"
  type        = string
  default     = ""
}

variable "target_role_arn" {
  description = "IAM role ARN to assume for cross-account scanning; leave empty to scan the Lambda's own account"
  type        = string
  default     = ""
}

variable "bedrock_model_id" {
  description = "Amazon Bedrock model ID used by the AI explainer and chatbot Lambda functions"
  type        = string
  default     = "anthropic.claude-3-haiku-20240307-v1:0"
}

variable "max_tokens" {
  description = "Maximum number of tokens per Bedrock response"
  type        = number
  default     = 400
}

variable "max_risks_per_run" {
  description = "Maximum number of OPEN risks the AI explainer processes in a single EventBridge invocation"
  type        = number
  default     = 50
}

variable "risks_page_limit" {
  description = "Maximum number of risk records returned per API call by the risk-reader Lambda"
  type        = number
  default     = 100
}

variable "chatbot_context_risks" {
  description = "Number of recent risks loaded as context for each chatbot response"
  type        = number
  default     = 20
}

variable "notification_threshold" {
  description = "Minimum risk priority level that triggers an email notification (High | Medium | All)"
  type        = string
  default     = "High"

  validation {
    condition     = contains(["High", "Medium", "All"], var.notification_threshold)
    error_message = "notification_threshold must be one of: High, Medium, All."
  }
}

# ---------------------------------------------------------------------------
# DynamoDB — risk records table
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "risks" {
  name         = "${var.project}-risks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "resourceId"
  range_key    = "riskTimestamp"

  attribute {
    name = "resourceId"
    type = "S"
  }
  attribute {
    name = "riskTimestamp"
    type = "S"
  }
  attribute {
    name = "module"
    type = "S"
  }
  attribute {
    name = "riskPriority"
    type = "S"
  }

  global_secondary_index {
    name            = "module-index"
    hash_key        = "module"
    range_key       = "riskTimestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "priority-index"
    hash_key        = "riskPriority"
    range_key       = "riskTimestamp"
    projection_type = "ALL"
  }

  tags = {
    Project = var.project
  }
}

# ---------------------------------------------------------------------------
# S3 — artifacts and report storage
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project}-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = { Project = var.project }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---------------------------------------------------------------------------
# IAM — shared Lambda execution role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda_role" {
  name = "${var.project}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Project = var.project }
}

resource "aws_iam_role_policy_attachment" "basic_exec" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${var.project}-lambda-inline"
  role   = aws_iam_role.lambda_role.id
  policy = file("${path.module}/../iam/lambda_policy.json")
}

# ---------------------------------------------------------------------------
# Cognito — user pool and app client
# ---------------------------------------------------------------------------

resource "aws_cognito_user_pool" "users" {
  name = "${var.project}-users"

  password_policy {
    minimum_length                   = 8
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = false
    temporary_password_validity_days = 7
  }

  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]

  tags = { Project = var.project }
}

resource "aws_cognito_user_pool_client" "web_client" {
  name                                 = "${var.project}-web-client"
  user_pool_id                         = aws_cognito_user_pool.users.id
  generate_secret                      = false
  explicit_auth_flows                  = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"

  # Enforce 30-minute session at the Cognito level — the API Gateway Cognito
  # authorizer validates token expiry on every request, so expired tokens are
  # rejected server-side, not just by the client-side timer.
  access_token_validity  = 30
  id_token_validity      = 30
  refresh_token_validity = 1

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

# ---------------------------------------------------------------------------
# API Gateway — single REST API for all modules
# ---------------------------------------------------------------------------

resource "aws_api_gateway_rest_api" "api" {
  name        = "${var.project}-api"
  description = "CloudSentinel multi-module API"
  endpoint_configuration { types = ["REGIONAL"] }
  tags = { Project = var.project }
}

resource "aws_api_gateway_deployment" "dev" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  depends_on  = [
    aws_api_gateway_integration.risks_get,
    aws_api_gateway_integration.chat_post,
    aws_api_gateway_integration.scan_cloud_post,
    aws_api_gateway_integration.disconnect_post,
    aws_api_gateway_integration.notify_post,
  ]
  lifecycle { create_before_destroy = true }
}

resource "aws_api_gateway_stage" "dev" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.dev.id
  stage_name    = "dev"
  tags          = { Project = var.project }
}

# /risks GET
resource "aws_api_gateway_resource" "risks" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "risks"
}

resource "aws_api_gateway_method" "risks_get" {
  rest_api_id   = aws_api_gateway_resource.risks.rest_api_id
  resource_id   = aws_api_gateway_resource.risks.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "risks_get" {
  rest_api_id             = aws_api_gateway_resource.risks.rest_api_id
  resource_id             = aws_api_gateway_resource.risks.id
  http_method             = aws_api_gateway_method.risks_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.risk_reader.invoke_arn
}

# /chat POST
resource "aws_api_gateway_resource" "chat" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "chat"
}

resource "aws_api_gateway_method" "chat_post" {
  rest_api_id   = aws_api_gateway_resource.chat.rest_api_id
  resource_id   = aws_api_gateway_resource.chat.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "chat_post" {
  rest_api_id             = aws_api_gateway_resource.chat.rest_api_id
  resource_id             = aws_api_gateway_resource.chat.id
  http_method             = aws_api_gateway_method.chat_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.chatbot_handler.invoke_arn
}

# /scan-cloud POST
resource "aws_api_gateway_resource" "scan_cloud" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "scan-cloud-infra"
}

resource "aws_api_gateway_method" "scan_cloud_post" {
  rest_api_id   = aws_api_gateway_resource.scan_cloud.rest_api_id
  resource_id   = aws_api_gateway_resource.scan_cloud.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "scan_cloud_post" {
  rest_api_id             = aws_api_gateway_resource.scan_cloud.rest_api_id
  resource_id             = aws_api_gateway_resource.scan_cloud.id
  http_method             = aws_api_gateway_method.scan_cloud_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.cloud_scanner.invoke_arn
}

# /disconnect POST
resource "aws_api_gateway_resource" "disconnect" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "disconnect"
}

resource "aws_api_gateway_method" "disconnect_post" {
  rest_api_id   = aws_api_gateway_resource.disconnect.rest_api_id
  resource_id   = aws_api_gateway_resource.disconnect.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "disconnect_post" {
  rest_api_id             = aws_api_gateway_resource.disconnect.rest_api_id
  resource_id             = aws_api_gateway_resource.disconnect.id
  http_method             = aws_api_gateway_method.disconnect_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.disconnect_handler.invoke_arn
}

# /notify POST
resource "aws_api_gateway_resource" "notify" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "notify"
}

resource "aws_api_gateway_method" "notify_post" {
  rest_api_id   = aws_api_gateway_resource.notify.rest_api_id
  resource_id   = aws_api_gateway_resource.notify.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "notify_post" {
  rest_api_id             = aws_api_gateway_resource.notify.rest_api_id
  resource_id             = aws_api_gateway_resource.notify.id
  http_method             = aws_api_gateway_method.notify_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.notification_handler.invoke_arn
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.users.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.web_client.id
}

output "api_invoke_url" {
  value = aws_api_gateway_stage.dev.invoke_url
}

output "dynamodb_table" {
  value = aws_dynamodb_table.risks.name
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda_role.arn
}

output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.id
}
