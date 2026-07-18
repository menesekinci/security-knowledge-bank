---
source: "common/cloud-security/serverless-security.md"
title: "☁️ Serverless Security — AWS Lambda & Cloudflare Workers"
heading: "3. Vulnerable Code + Secure Fix"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, cves, explanation, real, table, vulnerability, vulnerable]
chunk: 5/9
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