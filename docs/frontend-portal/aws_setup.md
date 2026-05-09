# AWS Setup — Frontend
## Bogavalli Akash

My notes for getting the portal up on Amplify. Before I can do anything useful I need these from Sameer:
- Cognito User Pool ID
- Cognito App Client ID  
- API Gateway base URL

I ping him in #frontend as soon as he has them.

---

## Tools to install first

Node.js (for Amplify CLI):
- Download from nodejs.org, LTS version, install with defaults
- Verify: `node --version` and `npm --version`

Amplify CLI:
```
npm install -g @aws-amplify/cli
amplify --version
```

VS Code Live Server extension — for previewing the HTML locally without deploying anything.

---

## Local preview (before deploying)

I right-click on `modules/frontend/index.html` in VS Code and choose Open with Live Server. It opens at `http://127.0.0.1:5500/...`. Good for checking the UI — the actual Cognito login won't work locally but the layout and styles are visible.

---

## Create a test user in Cognito

Sameer creates the Cognito user pool. Once it exists I can add my own test user:

1. Cognito console > User pools > cloudsentinel-users > Users tab
2. Create user
3. Email: my email
4. Password: CloudSentinel@123
5. Mark email as verified: check
6. Create user

Use this account to test the login page once deployed.

---

## Option 1 — Amplify Console (GUI)

1. Go to console.aws.amazon.com/amplify
2. New app > Host web app
3. Select GitHub > Next
4. Authorize AWS Amplify (GitHub OAuth popup)
5. Repo: Sayyaddsameer/CloudSentinel_AI
6. Branch: feature/frontend
7. Next
8. App root directory: `modules/frontend`
9. Build settings (auto-detects amplify.yml) — verify it says `baseDirectory: modules/frontend`
10. Next > Save and deploy

Wait for Provision → Build → Deploy to all go green. Copy the URL and share with the team.

**CORS issues to watch for:** If the dashboard throws errors in the browser console (F12 → Console tab), the most common cause is CORS not enabled on API Gateway. Tell Sameer to enable CORS on the /risks route, then redeploy the API stage. This happened to me on first test.

After feature branch is merged into develop, I connect the develop branch in Amplify for auto-deploy on future merges.

---

## Option 2 — Terraform

File: `infrastructure/terraform/amplify_frontend.tf`

```hcl
resource "aws_amplify_app" "portal" {
  name         = "cloudsentinel-portal"
  repository   = "https://github.com/Sayyaddsameer/CloudSentinel_AI"
  access_token = var.github_token

  build_spec = <<-EOT
    version: 1
    frontend:
      phases:
        build:
          commands:
            - echo "Static site"
      artifacts:
        baseDirectory: modules/frontend
        files:
          - '**/*'
  EOT

  tags = { Project = "CloudSentinel" }
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

output "amplify_url" { value = "https://dev.${aws_amplify_app.portal.default_domain}" }
```

I need a GitHub personal access token for this. Create at github.com/settings/tokens — classic token, `repo` scope, 90 day expiry.

```
terraform apply -var="github_token=YOUR_TOKEN" -target=aws_amplify_app.portal
```

Trigger first build:
```
aws amplify start-job --app-id (from output) --branch-name feature/frontend --job-type RELEASE --region us-east-1
```
