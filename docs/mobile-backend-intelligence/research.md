# Research Notes — Mobile Backend
## Muramalla Ambica Sai Ram

Why I focused on what I did for the mobile module.

---

## The problem from a mobile perspective

Mobile apps depend heavily on backend APIs. When those APIs are slow or erroring, the app breaks — and unlike a web app where you might show a loading spinner, a mobile app that freezes or crashes gets uninstalled. Users on mobile also have less patience for slow responses because they're usually on the go.

The difference between my module and Gowrish's full-stack module isn't just the latency threshold. I also check CORS (because Flutter Web and WebView apps need it) and I check Lambda error rates per function, not just aggregate API metrics.

---

## Latency — why 1000ms

I looked at Firebase Performance Monitoring's recommended thresholds. It says network requests from mobile clients should complete in under 1 second for a good user experience. Google's own research shows that 53% of mobile sessions are abandoned when a page takes more than 3 seconds to load — and the backend API is a big part of that.

Gowrish and I agreed: web gets 2000ms, mobile gets 1000ms. Both are stricter than nothing.

---

## CORS and Flutter

This one was specific to our project setup. Our mobile module is described as serving Flutter-based mobile applications. Flutter Native (Android/iOS) doesn't go through a browser so CORS doesn't apply. But Flutter Web does — it runs in a browser and is subject to the same preflight request rules.

Since our project could include a Flutter Web version, I decided to include CORS detection. Any API resource that's missing an OPTIONS method will be flagged as Medium priority.

---

## Lambda errors versus API Gateway errors

Both Gowrish and I look at error rates, but from different angles:
- Gowrish looks at CloudWatch's `5XXError` metric on API Gateway — this counts errors at the gateway level
- I additionally look at `Errors` metric on individual Lambda functions — this catches Lambda-specific failures that might not surface cleanly as gateway 5XX errors (e.g., timeout, out-of-memory, exception in function code)

Together they give better coverage.

---

## References

- Firebase Performance Monitoring docs — firebase.google.com/docs/perf-mon
- Google mobile performance research — thinkwithgoogle.com
- Flutter Web CORS issues — docs.flutter.dev
- AWS Lambda Error Metrics — docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
- MDN CORS explanation — developer.mozilla.org/en-US/docs/Web/HTTP/CORS
