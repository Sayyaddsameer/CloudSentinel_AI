# Research Notes — Data Engineering
## Bikkavolu Srivallisa Sai Veerabhadra Ayyan

Why I approached data engineering risks the way I did.

---

## Why data risks are especially serious

Data engineering deals with pipelines that move and process actual user data — customer records, payment info, health data. A misconfiguration here doesn't just create a theoretical vulnerability — it can expose real personal information.

The most famous S3 data exposures in recent years all had one thing in common: the bucket was either publicly accessible or the access controls were misconfigured. Toyota exposed 2 million customer records from a misconfigured S3 bucket in 2023. These aren't edge cases — they happen regularly.

My module tries to catch the most common version of this before it becomes a problem.

---

## Why I use bucket name analysis instead of reading content

The cleanest approach for detecting which buckets hold sensitive data would be to read the contents or check object tags. But that would require data-level S3 permissions that go beyond what a risk scanner should have.

Name-based analysis is a good proxy because:
- Organizations typically name buckets after what they store (user-data, customer-records, patient-files)
- It requires only `ListAllMyBuckets` and `GetBucketPublicAccessBlock` — minimal permissions
- It produces very few false negatives for genuinely sensitive buckets

The downside is false positives — a bucket called `some-user-manual` might not hold personal data. But for a security tool, flagging too much is better than missing something real.

---

## DynamoDB encryption check

I check `SSEDescription.Status` on each table. A table that shows `DISABLED` has no server-side encryption, which violates GDPR and HIPAA requirements. AWS encrypts DynamoDB with an AWS-owned key by default for new tables, so this only flags older tables that were created before this default was in place — or tables where encryption was explicitly turned off.

---

## Glue monitoring gap

AWS Glue has no built-in alerting when a job fails. The data team might not notice a failing ETL job until a downstream system complains about stale data. By checking the last 5 runs, my module surfaces this as a High priority risk.

Threshold: 2 or more FAILED runs in the last 5. Single failures happen for transient reasons (network timeout, source data temporarily unavailable). Repeated failures indicate a real problem.

---

## References

- IBM Cost of a Data Breach 2023 — ibm.com/reports/data-breach
- Toyota S3 breach report — multiple news sources, 2023
- AWS S3 Security Best Practices — docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- AWS Glue Monitoring — docs.aws.amazon.com/glue/latest/dg/monitor-glue.html
- GDPR encryption requirements — gdpr.eu
