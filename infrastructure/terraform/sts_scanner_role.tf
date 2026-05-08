# STS — CloudSentinel Scanner Role
# Lambda assumes this role when TARGET_ROLE_ARN is set.
# For same-account scanning: Lambda role trusts itself and assumes the scanner role.
# For cross-account: deploy scanner_role.yaml CloudFormation template in the target account.

resource "aws_iam_role" "scanner_role" {
  name        = "${var.project}-scanner-role"
  description = "Role assumed by the cloud-scanner Lambda for scanning AWS resources"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda_role.arn }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.project
          }
        }
      }
    ]
  })

  tags = { Project = var.project }
}

resource "aws_iam_role_policy" "scanner_role_policy" {
  name   = "${var.project}-scanner-permissions"
  role   = aws_iam_role.scanner_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketEncryption",
          "ec2:DescribeSecurityGroups",
          "iam:GetAccountPasswordPolicy",
          "config:GetComplianceDetailsByConfigRule",
          "config:DescribeComplianceByConfigRule",
        ]
        Resource = "*"
      }
    ]
  })
}

output "scanner_role_arn" {
  description = "Pass this as TARGET_ROLE_ARN env var on the cloud-scanner Lambda"
  value       = aws_iam_role.scanner_role.arn
}
