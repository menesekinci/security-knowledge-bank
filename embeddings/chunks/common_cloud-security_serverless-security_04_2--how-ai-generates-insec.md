---
source: "common/cloud-security/serverless-security.md"
title: "☁️ Serverless Security — AWS Lambda & Cloudflare Workers"
heading: "2. How AI Generates Insecure Serverless Code"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, cves, explanation, real, table, vulnerability, vulnerable]
chunk: 4/9
---

## 2. How AI Generates Insecure Serverless Code

AI models are trained on publicly available code, tutorials, and Stack Overflow answers — much of which prioritizes _getting it working_ over _getting it secure_. Here's how common prompts produce insecure output:

### 2.1 AWS Lambda

```
Prompt: "Create a Lambda function that processes user uploads from S3"
```

**AI-generated (insecure):**
- IAM role with `s3:*` on all buckets
- No input validation on the S3 event payload
- Database credentials hardcoded in environment variables
- No VPC configuration
- Returns full stack traces on errors

```
Prompt: "Create an API Gateway endpoint with a Lambda backend"
```

**AI-generated (insecure):**
- No API Gateway authorizer — public endpoint
- Lambda has `AdministratorAccess` role
- CORS: `Access-Control-Allow-Origin: *`
- No request validation (max body size, allowed content types)

### 2.2 Cloudflare Workers

```
Prompt: "Write a Cloudflare Worker that proxies API requests"
```

**AI-generated (insecure):**
- API key hardcoded in the Worker script
- No validation on incoming `fetch` event
- Forwarding all headers including `Authorization` to untrusted origins
- No error handling — secrets may leak in error messages

```
Prompt: "Create a Worker with KV storage for user sessions"
```

**AI-generated (insecure):**
- Storing raw session data in KV without encryption
- No authentication check on KV read/write operations
- Using `env.KV_NAMESPACE` without proper binding scope
- Session IDs are predictable (sequential or timestamp-based)

---