---
source: "common/cloud-security/serverless-security.md"
title: "☁️ Serverless Security — AWS Lambda & Cloudflare Workers"
heading: "6. Vibe-Coding Red Flags"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, cves, explanation, real, table, vulnerability, vulnerable]
chunk: 8/9
---

## 6. Vibe-Coding Red Flags

Watch for these patterns when AI generates serverless code — they indicate the AI is prioritizing convenience over security:

| # | Red Flag | Why It's Dangerous |
|---|----------|-------------------|
| 1 | `"Action": "*"` or `"Resource": "*"` in IAM policies | Grants full access — any compromise becomes catastrophic |
| 2 | `Access-Control-Allow-Origin: *` | Allows any website to read API responses (data theft) |
| 3 | No `authorizer` config on API Gateway | Endpoint is completely public |
| 4 | API keys or passwords in code or `wrangler.toml` | Secrets leak through version control, logs, and error messages |
| 5 | No input validation on `event.body`, `request.body`, or query params | Leads to injection attacks, IDOR, and DoS |
| 6 | `return response` without error handling | Stack traces and error details leak to users |
| 7 | No VPC configuration for Lambda | Data travels over public internet, exfiltration risk |
| 8 | `/tmp/` used without cleanup | Cross-invocation data leaks via cold-start reuse |
| 9 | Lambda with `AdministratorAccess` | Single Lambda compromise = full AWS account takeover |
| 10 | No rate limiting or reserved concurrency | Easy DoS target — attacker can drive up costs |
| 11 | No authentication on KV/Durable Object reads | Anyone with the Worker URL can read/write all data |
| 12 | Wildcard secrets binding in Workers (`env.*` without specific keys) | Accidental exposure of ALL bound secrets |

### AI Prompt Hygiene

```
"When writing serverless code:
1. Use IAM least privilege — never wildcard actions or resources
2. Authenticate every API Gateway endpoint
3. Store all secrets in Secrets Manager / env bindings
4. Validate every input from events or HTTP requests
5. Never return internal errors or stack traces to clients
6. Scope CORS to specific origins
7. Add rate limiting to all endpoints
8. Never assume execution context is clean between invocations"
```

---