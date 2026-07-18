---
source: "common/server/lb-cdn-waf-security.md"
title: "Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass"
heading: "2. Common Mistakes with AI-Generated Configs"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, common, common-vuln, cves, explanation, mistakes, prevention, real, secure, vulnerability]
chunk: 3/8
---

## 2. Common Mistakes with AI-Generated Configs

### 2.1 Cloudflare Config

```yaml
# AI-GENERATED: Insecure Cloudflare configuration
dns:
  example.com:
    - type: A
      name: "@"
      content: 203.0.113.10  # ⚠️ Proxied disabled (grey-cloud)
      proxied: false          # Origin IP exposed!
    - type: A
      name: "www"
      content: 203.0.113.10
      proxied: false

ssl:
  mode: flexible  # ⚠️ No encryption between CF and origin

security:
  level: essentially_off  # ⚠️ WAF bypassed
  waf_rules: disabled     # ⚠️ All managed rules off
```

### 2.2 AWS WAF Config

```hcl
# AI-GENERATED: Overly permissive WAF rules
resource "aws_wafv2_web_acl" "main" {
  name        = "main-waf"
  scope       = "REGIONAL"

  default_action {
    allow {}  # ⚠️ Default allow — everything passes through
  }

  rule {
    name     = "allow-all-ips"
    priority = 0
    action   { allow {} }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allow_all.arn  # ⚠️ Overly broad
      }
    }
    # ⚠️ No rate limiting rule
    # ⚠️ No logging configured
    # ⚠️ No SQL injection or XSS rules
  }
}
```

### 2.3 Load Balancer Health Check Exposure

```nginx
# AI-GENERATED: Exposed health check endpoint
server {
    listen 80;
    
    # ⚠️ No authentication on health check
    location /health {
        return 200 "OK";
    }
    
    # ⚠️ Exposed load balancer status
    location /nginx_status {
        stub_status on;  # Shows active connections, requests, etc.
        allow all;       # No IP restriction
    }
}
```

### 2.4 CDN Caching Authenticated Content

```javascript
// AI-GENERATED: No cache differentiation for authenticated content
app.get('/api/user/profile', (req, res) => {
  const user = getUserFromToken(req.headers.authorization);
  // ⚠️ Response cached regardless of auth header
  res.set('Cache-Control', 'public, max-age=3600');
  res.json(user);
});
```

---