# Amplify Frontend — Bogavalli Akash

resource "aws_amplify_app" "portal" {
  name         = "${var.project}-portal"
  repository   = "https://github.com/Sayyaddsameer/CloudSentinel_AI"
  access_token = var.github_token

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

  tags = { Project = var.project, Owner = "akash" }
}

resource "aws_amplify_branch" "feature_frontend" {
  app_id            = aws_amplify_app.portal.id
  branch_name       = "feature/frontend"
  stage             = "DEVELOPMENT"
  enable_auto_build = true
}

resource "aws_amplify_branch" "develop" {
  app_id            = aws_amplify_app.portal.id
  branch_name       = "develop"
  stage             = "DEVELOPMENT"
  enable_auto_build = true
}

output "amplify_default_domain" {
  value = "https://${aws_amplify_branch.develop.branch_name}.${aws_amplify_app.portal.default_domain}"
}
