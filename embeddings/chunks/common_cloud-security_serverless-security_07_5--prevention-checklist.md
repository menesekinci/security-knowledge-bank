---
source: "common/cloud-security/serverless-security.md"
title: "☁️ Serverless Security — AWS Lambda & Cloudflare Workers"
heading: "5. Prevention Checklist"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, cves, explanation, real, table, vulnerability, vulnerable]
chunk: 7/9
---

## 5. Prevention Checklist

### AWS Lambda

- [ ] **1. IAM Least Privilege:** Never use `"Action": "*"` or `"Resource": "*"`. Scope actions and resources precisely.
- [ ] **2. API Gateway Authentication:** Always configure a Lambda authorizer, Cognito user pool, or IAM auth on API Gateway endpoints.
- [ ] **3. Secrets Management:** Use AWS Secrets Manager or SSM Parameter Store with IAM-based access. Never hardcode secrets in environment variables or code.
- [ ] **4. Input Validation:** Validate all event payloads (S3, SQS, DynamoDB Streams, API Gateway). Never trust user input.
- [ ] **5. VPC Configuration:** Deploy Lambda functions inside a VPC when processing sensitive data. Use VPC endpoints for AWS services.
- [ ] **6. Function URLs with Auth:** If using Lambda Function URLs, set `AuthType: AWS_IAM` or use a custom authorizer.
- [ ] **7. Temporary Directory Cleaning:** Never assume `/tmp` is empty — clean up between invocations.
- [ ] **8. Dead Letter Queue:** Configure DLQs for async invocations to prevent data loss and enable monitoring.
- [ ] **9. Reserved Concurrency:** Set reserved concurrency to prevent runaway costs from DoS attacks.
- [ ] **10. CloudWatch Logs Encryption:** Enable KMS encryption for Lambda CloudWatch Logs groups.
- [ ] **11. WAF + API Gateway:** Enable AWS WAF on API Gateway to block common attack patterns (SQLi, XSS, rate limiting).
- [ ] **12. Resource Policy:** Scope Lambda resource-based policies to specific source ARNs and principals.

### Cloudflare Workers

- [ ] **1. Environment Secrets:** Use `wrangler secret put` for all secrets. Never inline secrets in `wrangler.toml` or script code.
- [ ] **2. Input Validation:** Validate all request inputs — path parameters, query strings, headers, and request bodies.
- [ ] **3. Authentication:** Implement token validation (JWT, pre-shared keys) on every `fetch` handler that accesses protected resources.
- [ ] **4. KV Access Control:** Never expose KV namespaces directly. Validate authentication and authorization on every KV operation.
- [ ] **5. CORS Restrictions:** Avoid `Access-Control-Allow-Origin: *`. Whitelist specific origins.
- [ ] **6. Error Handling:** Never return raw error messages or stack traces. Log internally, return sanitized responses.
- [ ] **7. Security Headers:** Set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`.
- [ ] **8. Rate Limiting:** Use Cloudflare Rate Limiting or implement token bucket algorithm in Workers for critical endpoints.
- [ ] **9. WebSocket Validation:** For Durable Objects and WebSockets, validate connection origins and implement proper reconnection handling.
- [ ] **10. Compatibility Flags:** Set explicit compatibility date in `wrangler.toml` (`compatibility_date = "2026-07-17"`) to get latest security defaults.
- [ ] **11. CSP Headers:** Add Content Security Policy headers to prevent XSS in Workers that serve HTML.
- [ ] **12. Account-Level WAF:** Enable Cloudflare WAF custom rules for Workers routes.
- [ ] **13. Subrequest Validation:** Validate the URL and response of `fetch()` calls made from Workers to prevent SSRF.
- [ ] **14. Durable Object Storage Encryption:** Encrypt sensitive data before storing in Durable Object storage.

---