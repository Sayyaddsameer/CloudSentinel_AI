# test-data-risks.tf
#
# CloudSentinel Data Engineering Test — Risky Infrastructure
# ──────────────────────────────────────────────────────────
# Deploys intentionally insecure data resources to test the
# Data Engineering module scanning.
#
# RISKS CREATED:
#   HIGH   — patient-data S3 bucket (PII name + no encryption)
#   HIGH   — S3 bucket with no Block Public Access
#   MEDIUM — analytics bucket with incomplete public access block
#   MEDIUM — DynamoDB table with SSE disabled
#
# DEPLOY:
#   terraform init
#   terraform apply -auto-approve
#
# Creating these via Terraform fires EventBridge CloudTrail rules
# which auto-trigger the CloudSentinel data-eng scanner within 2 minutes.
#
# CLEANUP:
#   terraform destroy -auto-approve

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

# ── RISK 1 (HIGH): PII-named bucket with no encryption or public block ────────
resource "aws_s3_bucket" "patient_data" {
  bucket = "patient-data-test-${data.aws_caller_identity.current.account_id}"

  tags = {
    Purpose   = "CloudSentinel-Test"
    DeleteMe  = "true"
  }

  # No aws_s3_bucket_server_side_encryption_configuration = encryption missing → HIGH
  # No aws_s3_bucket_public_access_block = public access not blocked → HIGH
}

# ── RISK 2 (MEDIUM): Generic bucket with incomplete public access block ────────
resource "aws_s3_bucket" "analytics" {
  bucket = "analytics-lake-test-${data.aws_caller_identity.current.account_id}"
  tags = {
    Purpose  = "CloudSentinel-Test"
    DeleteMe = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "analytics_partial" {
  bucket = aws_s3_bucket.analytics.id

  block_public_acls       = true
  ignore_public_acls      = false   # RISK: not set to true
  block_public_policy     = false   # RISK: not set to true
  restrict_public_buckets = false   # RISK: not set to true
}

# ── RISK 3 (MEDIUM): DynamoDB table with SSE explicitly disabled ───────────────
resource "aws_dynamodb_table" "events" {
  name         = "cloudsentinel-test-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = false   # RISK: encryption explicitly disabled
  }

  tags = {
    Purpose  = "CloudSentinel-Test"
    DeleteMe = "true"
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "patient_bucket" {
  description = "HIGH risk: PII-named bucket with no encryption"
  value       = aws_s3_bucket.patient_data.bucket
}

output "analytics_bucket" {
  description = "MEDIUM risk: incomplete public access block"
  value       = aws_s3_bucket.analytics.bucket
}

output "dynamodb_table" {
  description = "MEDIUM risk: SSE disabled"
  value       = aws_dynamodb_table.events.name
}

output "cleanup_command" {
  description = "Run this to remove all test resources"
  value       = "terraform destroy -auto-approve"
}
