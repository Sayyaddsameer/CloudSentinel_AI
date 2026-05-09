# Research Notes — DevOps Intelligence
## Kantipudi Vivek Vardhan

Notes I collected while figuring out what to scan and how to build the CI pipeline.

---

## Why DevOps risks matter

Most people think security issues come from the application code. But a huge percentage of real breaches happen at the pipeline level — AWS keys accidentally committed to YAML files, deployments running without any tests, no way to roll back when something breaks. 

I came across a GitGuardian report that said 10 million secrets were exposed in public GitHub repos in 2022 alone. That's just public repos. Private repos probably have even more since developers feel safer.

The DevOps module scans pipeline config so we can catch these before they cause damage.

---

## What I decided to check

I looked at OWASP's Top 10 CI/CD Security Risks list. From that I picked the ones that:
1. Are actually detectable by parsing a YAML/config file
2. Would show up in our demo environment
3. Are common enough to explain easily to a non-security audience

**Hardcoded secrets** → most obvious one. Regex patterns that match common credential formats work well enough for demo purposes. Production tools like GitLeaks use entropy scoring but that's overkill for us.

**No test step** → a deploy job with no test step is a red flag. Junior devs doing quick deployments often skip this.

**No rollback** → if there's no rollback step, a bad deployment = manual intervention = downtime.

**No monitoring** → deploying without checking if the deployment actually works is a blind spot. A health check or CloudWatch alarm step after deploy is a good practice.

---

## Secret detection — why regex and not ML

I looked at a few approaches:

- **Regex** — fast, transparent, no dependencies. Good enough for our scope.
- **Entropy scoring** — catches high-randomness strings that look like keys. More accurate but more complex to tune.
- **GitLeaks** — great open source tool but adds an external dependency and would require a different integration approach.
- **GitHub Secret Scanning** — built into GitHub but only works automatically on public repos in the free tier.

Went with regex. The patterns I use:
- `(?i)(password|secret|token|api_key)\s*[:=]\s*\S{8,}` — catches most hand-typed credentials
- `AKIA[0-9A-Z]{16}` — exact format for AWS Access Key IDs

---

## GitHub Actions — why not Jenkins or CodePipeline

- **Jenkins** — requires a self-hosted server. We're not running servers.
- **CircleCI** — would work but adds a separate account and config format.
- **AWS CodePipeline** — would be fine for AWS deployments but we needed something that responds to GitHub push events natively.

GitHub Actions is just the obvious choice since we're already on GitHub. Free 2000 min/month is plenty.

---

## References I used

- OWASP Top 10 CI/CD Security Risks — owasp.org/www-project-top-10-ci-cd-security-risks
- GitGuardian State of Secrets Sprawl 2023 — gitguardian.com
- GitHub Actions docs — docs.github.com/en/actions
- Bandit (Python security linter) docs — bandit.readthedocs.io
