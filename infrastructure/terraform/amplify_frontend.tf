# Amplify Frontend — Bogavalli Akash

resource "aws_amplify_app" "portal" {
  count        = var.github_token != "" ? 1 : 0
  name         = "${var.project}-portal"
  repository   = "https://github.com/Sayyaddsameer/CloudSentinel_AI"
  access_token = var.github_token != "" ? var.github_token : null

  build_spec = <<-EOT
    version: 1
    frontend:
      phases:
        build:
          commands:
            - echo "Static site — no build step needed"
      artifacts:
        baseDirectory: modules/frontend
        files:
          - '**/*'
      cache:
        paths: []
  EOT

  environment_variables = {
    PROJECT = var.project
  }

  tags = { Project = var.project, ManagedBy = "Terraform" }
}

resource "aws_amplify_branch" "main" {
  count             = var.github_token != "" ? 1 : 0
  app_id            = aws_amplify_app.portal[0].id
  branch_name       = "main"
  stage             = "PRODUCTION"
  enable_auto_build = true
}

resource "aws_amplify_branch" "develop" {
  count             = var.github_token != "" ? 1 : 0
  app_id            = aws_amplify_app.portal[0].id
  branch_name       = "develop"
  stage             = "DEVELOPMENT"
  enable_auto_build = true
}

output "amplify_default_domain" {
  sensitive = true
  value     = var.github_token != "" ? "https://main.${aws_amplify_app.portal[0].default_domain}" : "(Amplify not configured — set github_token to enable)"
}
