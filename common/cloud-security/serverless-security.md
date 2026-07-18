# ☁️ Serverless Security — AWS Lambda & Cloudflare Workers

> **Category:** Common / Cloud Security
> **Severity:** 🔴 High
> **CWE:** CWE-284 (Improper Access Control), CWE-200 (Information Exposure), CWE-287 (Improper Authentication), CWE-77 (Command Injection), CWE-22 (Path Traversal)
> **AI Risk:** 🔴 Very High — AI models frequently generate over-privileged IAM roles, skip authentication, hardcode secrets, and omit input validation in serverless functions
> **Last Updated:** July 2026

---

## Table of Contents

1. [Vulnerability Explanation](#1-vulnerability-explanation)
2. [How AI Generates Insecure Serverless Code](#2-how-ai-generates-insecure-serverless-code)
3. [Vulnerable Code + Secure Fix](#3-vulnerable-code--secure-fix)
4. [Real CVEs & Incidents](#4-real-cves--incidents)
5. [Prevention Checklist](#5-prevention-checklist)
6. [Vibe-Coding Red Flags](#6-vibe-coding-red-flags)
7. [References](#7-references)

---

## 1. Vulnerability Explanation

Serverless computing (AWS Lambda, Cloudflare Workers, Google Cloud Functions, Azure Functions) shifts operational burden to the provider but **does not eliminate security risk**. The shared responsibility model still applies — the provider secures _the cloud_, you secure _what runs in it_.

### 1.1 AWS Lambda Security Pitfalls

| Risk | Description |
|------|-------------|
| **Over-permissioned IAM Roles** | AI-generated Lambda functions often get `AdministratorAccess` or wildcard (`"Action": "*"`) roles. Lambda should follow least privilege — only permit the specific actions and resources needed. |
| **Hardcoded Environment Variables** | AI frequently places database credentials, API keys, and secrets directly in Lambda environment variables or worse, in the code itself. AWS recommends using AWS Secrets Manager or Parameter Store with proper IAM. |
| **Exposed API Gateway Without Auth** | AI-generated serverless APIs often skip API Gateway authorizers (Cognito, Lambda authorizer, IAM auth). The endpoint becomes publicly accessible with no authentication. |
| **No VPC Configuration** | Lambda functions processing sensitive data are deployed outside a VPC by default, allowing data exfiltration over the public internet. AI rarely adds VPC config unless explicitly prompted. |
| **Event Injection** | Lambda processes events from S3, SQS, DynamoDB Streams, or Kinesis. AI-generated code frequently trusts event payloads without validation, leading to injection attacks. |
| **IDOR Between Tenants** | In multi-tenant serverless architectures, AI generates code that trusts user-supplied tenant IDs without verifying ownership — leading to Insecure Direct Object References. |
| **Cold-Start Data Leaks** | Reused execution contexts across invocations can leak data from previous runs if AI doesn't initialize variables properly. Old `/tmp` directory contents may persist. |

### 1.2 Cloudflare Workers Security Pitfalls

| Risk | Description |
|------|-------------|
| **Secrets Exposed via Environment** | Workers use `wrangler.toml` and `env` bindings for secrets. AI-generated Workers often inline secrets in the script body or expose them via `env.API_KEY` without proper binding setup. |
| **No Validation on Fetch Events** | The `fetch` event handler receives all HTTP requests. AI-generated Workers frequently process request bodies, headers, and URLs without sanitization or validation. |
| **KV Storage Without Encryption** | Workers KV stores data globally. AI-generated code stores sensitive data (tokens, PII) directly in KV without encryption or access control. |
| **Durable Object State Mishandling** | Durable Objects maintain stateful storage. AI code often forgets to validate access across different client connections, leading to cross-tenant data leaks. |
| **Insufficient CORS Configuration** | AI-generated Workers frequently use wildcard CORS (`Access-Control-Allow-Origin: *`) without restriction. |

### 1.3 Common Serverless Threats

- **Event Injection:** Malicious payloads in S3 events, SQS messages, or HTTP requests that exploit unsanitized input in Lambda/Worker handlers.
- **IDOR:** No tenant isolation validation — User A can access User B's resources by changing an ID parameter.
- **Cold-Start Data Leaks:** Residual data from `/tmp` or global variables persists across invocations.
- **Denial of Service (DoS):** No request throttling — AI rarely implements API Gateway usage plans, WAF rules, or rate limiting.

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

## 3. Vulnerable Code + Secure Fix

### 3.1 AWS Lambda — Over-Permissioned IAM

**Vulnerable (AI-generated):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**Secure Fix (Least Privilege):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-app-bucket/uploads/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"
    }
  ]
}
```

### 3.2 AWS Lambda — API Gateway Without Auth

**Vulnerable (AI-generated Python):**

```python
import json
import boto3

def lambda_handler(event, context):
    # ❌ No authentication check
    # ❌ No input validation
    user_id = event['pathParameters']['id']
    # ❌ Direct DB access with hardcoded table name
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    response = table.get_item(Key={'id': user_id})
    return {
        'statusCode': 200,
        'body': json.dumps(response['Item'])
    }
```

**Secure Fix (Python):**

```python
import json
import boto3
import os
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # ✅ Verify authentication (Cognito / Lambda Authorizer)
    claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})
    if not claims:
        return {'statusCode': 401, 'body': json.dumps({'error': 'Unauthorized'})}

    # ✅ Validate input
    user_id = event.get('pathParameters', {}).get('id')
    if not user_id or not isinstance(user_id, str) or len(user_id) > 64:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid input'})}

    # ✅ Verify authorization (user can only access own data)
    authenticated_user = claims.get('sub')
    if authenticated_user != user_id:
        return {'statusCode': 403, 'body': json.dumps({'error': 'Forbidden'})}

    # ✅ Secrets from environment (not hardcoded)
    table_name = os.environ.get('TABLE_NAME', '')
    if not table_name:
        return {'statusCode': 500, 'body': json.dumps({'error': 'Configuration error'})}

    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        response = table.get_item(Key={'id': user_id})
        item = response.get('Item', {})
        # ✅ Strip sensitive fields before returning
        item.pop('password_hash', None)
        item.pop('internal_notes', None)
        return {
            'statusCode': 200,
            'body': json.dumps(item),
            'headers': {
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff'
            }
        }
    except ClientError as e:
        return {'statusCode': 500, 'body': json.dumps({'error': 'Internal server error'})}
```

### 3.3 Cloudflare Worker — Hardcoded Secrets + No Validation

**Vulnerable (AI-generated JavaScript):**

```javascript
// ❌ API key hardcoded directly in code
const API_KEY = 'sk-abc123def456';

// ❌ No input validation on fetch event
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const userId = url.searchParams.get('user_id');
    // ❌ No auth check, no validation
    const response = await fetch(`https://api.example.com/users/${userId}`, {
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    });
    const data = await response.json();
    return new Response(JSON.stringify(data), {
      headers: { 'Access-Control-Allow-Origin': '*' } // ❌ Wildcard CORS
    });
  }
}
```

**Secure Fix (JavaScript):**

```javascript
// ✅ Secrets via env binding — set with `wrangler secret put API_KEY`
// ✅ Input validation and rate limiting

export default {
  async fetch(request, env, ctx) {
    // ✅ Validate HTTP method
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const url = new URL(request.url);
    const userId = url.searchParams.get('user_id');

    // ✅ Input validation
    if (!userId || !/^[a-zA-Z0-9_-]{1,64}$/.test(userId)) {
      return new Response('Invalid user ID', { status: 400 });
    }

    // ✅ Authentication via header (e.g., signed token)
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response('Unauthorized', { status: 401 });
    }

    // ✅ Validate token (simplified — use proper JWT verification in production)
    const token = authHeader.slice(7);
    const expectedToken = await env.AUTH_TOKEN; // from wrangler secret
    if (token !== expectedToken) {
      return new Response('Forbidden', { status: 403 });
    }

    // ✅ Secrets from env, not code
    const apiKey = env.API_KEY; // from `wrangler secret put API_KEY`

    try {
      const response = await fetch(`https://api.example.com/users/${userId}`, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      });

      if (!response.ok) {
        return new Response('Upstream error', { status: 502 });
      }

      const data = await response.json();
      // ✅ Strip sensitive fields
      delete data.secret_key;
      delete data.internal_token;

      // ✅ Restricted CORS
      const origin = request.headers.get('Origin') || '';
      const allowedOrigins = ['https://myapp.com', 'https://app.mysite.com'];
      const corsOrigin = allowedOrigins.includes(origin) ? origin : 'https://myapp.com';

      return new Response(JSON.stringify(data), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin,
          'Access-Control-Allow-Methods': 'GET',
          'X-Content-Type-Options': 'nosniff',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }
      });
    } catch (err) {
      return new Response('Internal error', { status: 500 });
    }
  }
}
```

### 3.4 Cloudflare Worker — KV Without Access Control

**Vulnerable (AI-generated JavaScript):**

```javascript
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const key = url.pathname.slice(1); // ❌ No validation
    const value = await env.MY_KV.get(key); // ❌ No auth
    return new Response(value);
  }
}
```

**Secure Fix:**

```javascript
export default {
  async fetch(request, env) {
    // ✅ Authentication
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) {
      return new Response('Unauthorized', { status: 401 });
    }
    // ✅ Verify session token
    const session = await env.SESSIONS.get(authHeader);
    if (!session) {
      return new Response('Invalid session', { status: 403 });
    }

    const url = new URL(request.url);
    const key = url.pathname.slice(1);

    // ✅ Validate key format — prevent path traversal
    if (!key || !/^[a-zA-Z0-9_\/-]{1,256}$/.test(key)) {
      return new Response('Invalid key', { status: 400 });
    }

    const value = await env.MY_KV.get(key, { cacheTtl: 60 });
    if (value === null) {
      return new Response('Not found', { status: 404 });
    }
    return new Response(value);
  }
}
```

---

## 4. Real CVEs & Incidents

### 4.1 AWS Lambda & API Gateway

| CVE / Incident | Description | Impact | Status |
|----------------|-------------|--------|--------|
| **CVE-2022-40897** (CVSS 5.9, CWE-1333) | Regular Expression Denial of Service (ReDoS) in setuptools `package_index.py` — a crafted package page / HTML causes catastrophic regex backtracking, hanging the process. Relevant to Lambda build/CI pipelines that resolve packages from an untrusted index | Denial of service (CPU exhaustion) during dependency resolution | Fixed in setuptools >= 65.5.1 |
| **CVE-2023-44487** | HTTP/2 Rapid Reset attack used against AWS API Gateway and CloudFront, causing DDoS via stream cancellation | DoS via resource exhaustion | AWS mitigated Oct 2023 |
| **Lambda Event Injection (GHSA)** | Unsanitized S3 event payloads processed by Lambda functions — validated by multiple security audits | Remote code execution via crafted S3 objects | Prevention via input validation |
| **Capital One Breach (2019)** | Exploited SSRF in a misconfigured WAF + Lambda IAM role with over-permissions — 100M+ records stolen | Massive data exfiltration | IAM least-practice adopted post-incident |

### 4.2 Cloudflare Workers

| CVE / Incident | Description | Impact | Status |
|----------------|-------------|--------|--------|
| **CVE-2023-2512** | workerd (Workers runtime) integer overflow in FormData API — `forEach()` reads from wrong memory location when FormData has >2³¹ elements | Potential memory corruption (exploitation unlikely due to 160GB RAM requirement) | Fixed in v1.20230419.0 |
| **CVE-2023-48230** | Cap'n Proto KJ HTTP WebSocket buffer underrun in Cloudflare Workers Runtime — writes constant 4-byte string out-of-bounds | Denial of Service (CRITICAL CVSS 9.8) | Fixed in Cap'n Proto 1.0.1.1 |
| **CVE-2024-49770** | oak middleware path traversal on Cloudflare Workers — encoded `/` as `%2F` bypasses hidden file protection | Read sensitive data, access server secrets (CVSS 7.7 HIGH) | Fixed in oak 17.1.3 |
| **CVE-2025-55152** | oak middleware DoS via crafted `x-forwarded-proto` and `x-forwarded-for` headers | Denial of Service (CVSS 5.3) | Fixed in oak 17.1.6 |
| **CVE-2022-36083** | JOSE library PBKDF2 implementation — attacker can set arbitrarily high `p2c` iteration count, causing CPU-bound DoS | Denial of Service on Cloudflare Workers (CVSS 5.3) | Fixed in jose v1.28.2, v2.0.6, v3.20.4, v4.9.2 |

### 4.3 General Serverless Incidents

| Incident | Year | Description |
|----------|------|-------------|
| **OWASP Serverless Top 10** | 2021+ | Catalog of the most critical serverless security risks including injection, broken authentication, and misconfiguration |
| **Serverless FormData Attacks** | 2023 | Attackers exploit large form submissions to trigger memory issues in serverless runtimes |
| **Event Injection via S3** | 2024 | Malicious objects uploaded to S3 trigger Lambda functions that process unsanitized event data, leading to RCE |

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

## 7. References

### AWS Lambda Security
- [AWS Lambda Security Documentation](https://docs.aws.amazon.com/lambda/latest/dg/security.html)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [AWS IAM Least Privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
- [AWS API Gateway Security](https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

### Cloudflare Workers Security
- [Cloudflare Workers Security Model](https://developers.cloudflare.com/workers/reference/security-model/)
- [Cloudflare Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/)
- [Workers Environment Variables & Secrets](https://developers.cloudflare.com/workers/configuration/environment-variables/)
- [Cloudflare Workers Runtime API](https://developers.cloudflare.com/workers/runtime-apis/)

### CVEs
- [CVE-2023-2512 — Cloudflare workerd FormData overflow](https://nvd.nist.gov/vuln/detail/CVE-2023-2512)
- [CVE-2023-48230 — Cap'n Proto KJ HTTP buffer underrun](https://nvd.nist.gov/vuln/detail/CVE-2023-48230)
- [CVE-2024-49770 — oak middleware path traversal](https://nvd.nist.gov/vuln/detail/CVE-2024-49770)
- [CVE-2025-55152 — oak middleware DoS](https://nvd.nist.gov/vuln/detail/CVE-2025-55152)
- [CVE-2022-36083 — JOSE PBKDF2 DoS](https://nvd.nist.gov/vuln/detail/CVE-2022-36083)

### General Serverless Security
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [OWASP Serverless Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_Security_Cheat_Sheet.html)
- [Cloudflare Workers Security Blog](https://blog.cloudflare.com/tag/security/)
- [Capital One Breach Analysis](https://www.aboutamazon.com/news/aws/amazon-remediation-and-shareholder-impact-disclosures)

---

> **Severity: 🔴 High** — Serverless misconfigurations are the #1 cause of cloud data breaches. AI-generated serverless code is disproportionately vulnerable due to over-permissioned roles and missing authentication.
