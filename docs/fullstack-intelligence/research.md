# Research Notes — Full-Stack Intelligence
## Janapareddy Dyns Gowrish

Why I built this module the way I did.

---

## The problem

APIs that have no authentication are one of the most commonly exploited vulnerabilities in web apps. OWASP lists Broken Authentication as the second biggest API risk (API Security Top 10, 2023). The issue is that developers — especially during early development — deploy APIs without auth to test faster, and then forget to add it before going live.

On top of security, high latency and error rates directly break user experience. If an API returns errors 5% of the time, users notice.

My module checks all of these from the AWS side using boto3.

---

## What I scan and why

**Unauthenticated endpoints** — I call `get_method` for every resource in every REST API and check if `authorizationType` is `NONE` and `apiKeyRequired` is `false`. That combination = completely unprotected endpoint. This is a High severity risk because anyone with the URL can call it.

**Missing throttling** — no rate limit on an API makes it easy to DDoS or abuse. Even a basic burst limit of 100 req/sec is better than nothing. I check this at the stage level via `get_stages`.

**High error rates** — I query CloudWatch for the 5XX error metric over the past hour. More than 10 errors in an hour for a production API is worth flagging.

**High latency** — AWS recommends APIs respond in under 2 seconds for a good user experience. More than that is flagged as Medium priority. I use Average latency from CloudWatch over 1 hour.

---

## Why 2000ms for the web latency threshold

Ambica's module uses 1000ms because mobile users have stricter expectations. For web I used 2000ms based on Google's Core Web Vitals which defines "good" response time as under 2.5 seconds for page load. API responses are a subset of that so 2 seconds feels like a reasonable warning threshold.

---

## Alternatives I considered

I thought about using AWS Trusted Advisor or Security Hub to get this data instead of writing my own scanner. Both can detect unauthenticated APIs. But:
- Trusted Advisor requires a paid support plan for some checks
- Security Hub has its own output format that doesn't map to our risk schema
- Both require additional setup that team members don't control

Building my own scanner with boto3 gives us full control over what gets flagged and how it's stored.

---

## References

- OWASP API Security Top 10 2023 — owasp.org/API-Security
- AWS API Gateway Best Practices — docs.aws.amazon.com/apigateway/latest/developerguide/security-best-practices.html
- AWS API Gateway CloudWatch Metrics — docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html
- Google Core Web Vitals — web.dev/vitals
