---
source: "common/server/lb-cdn-waf-security.md"
title: "Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass"
heading: "3. Vulnerable + Secure Config Examples"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, common, common-vuln, cves, explanation, mistakes, prevention, real, secure, vulnerability]
chunk: 4/8
---

## 3. Vulnerable + Secure Config Examples

### 3.1 Cloudflare — Insecure vs Secure

**VULNERABLE — Origin IP exposed, no WAF, flexible SSL:**

```yaml
dns:
  example.com:
    type: A
    name: "@"
    content: 203.0.113.10
    proxied: false  # ❌ Grey-cloud — origin IP visible to anyone

zone:
  security_level: essentially_off  # ❌ WAF bypassed
  ssl: flexible                     # ❌ Plaintext to origin
```

**SECURE — Full protection:**

```yaml
dns:
  example.com:
    type: A
    name: "@"
    content: 203.0.113.10
    proxied: true   # ✅ Orange-cloud — origin IP hidden

zone:
  security_level: high              # ✅ WAF active
  ssl: full_strict                  # ✅ End-to-end TLS with cert validation
  challenge_ttl: 300
  browser_check: on
  email_obfuscation: on
  waf_rules:
    - id: cloudflare_managed
      status: enabled
      mode: block
    - id: owasp_rule_set
      status: enabled
      paranoia_level: 2

page_rules:
  - target: "*example.com/*"
    actions:
      - ssl: full_strict
      - security_level: high
      - disable_apps: false
```

### 3.2 AWS WAF — Insecure vs Secure

**VULNERABLE — Default allow, no rules, no logging:**

```hcl
resource "aws_wafv2_web_acl" "bad" {
  name  = "bad-waf"
  scope = "REGIONAL"
  default_action { allow {} }         # ❌ Default allow
  
  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "badWaf"
    sampled_requests_enabled   = false
  }
}
```

**SECURE — Defense in depth:**

```hcl
resource "aws_wafv2_web_acl" "secure" {
  name        = "secure-waf"
  scope       = "REGIONAL"
  description = "Comprehensive WAF with rate limiting, OWASP rules, and logging"

  default_action { block {} }  # ✅ Default deny

  # ✅ Rate limiting rule
  rule {
    name     = "rate-limit"
    priority = 0
    action   { block {} }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # ✅ OWASP core rule set
  rule {
    name     = "owasp-crs"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        excluded_rule {
          name = "SizeRestrictions_BODY"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "owaspCrs"
      sampled_requests_enabled   = true
    }
  }

  # ✅ SQL injection rule
  rule {
    name     = "sqli-rule"
    priority = 2
    action   { block {} }
    statement {
      sqli_match_statement {
        field_to_match { 
          query_string {} 
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqliRule"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "secureWaf"
    sampled_requests_enabled   = true
  }
}

# ✅ Enable WAF logging
resource "aws_wafv2_web_acl_logging_configuration" "waf_log" {
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.secure.arn
  redacted_fields {
    single_header { name = "authorization" }
    single_header { name = "cookie" }
  }
}
```

### 3.3 Load Balancer — Secure Health Check Configuration

**VULNERABLE — Unauthenticated health check:**

```nginx
# ❌ No authentication, no IP restriction
location /health {
    return 200 "OK";
}
```

**SECURE — Authenticated or restricted health check:**

```nginx
# ✅ Option 1: Restrict health check by source IP
location /health {
    allow 10.0.0.0/8;      # Internal network only
    allow 172.16.0.0/12;
    deny all;
    access_log off;
    return 200 "OK";
}

# ✅ Option 2: Require a shared secret header
location /health {
    access_log off;
    if ($http_x_health_check_secret != "CHANGE-ME-SECRET") {
        return 403;
    }
    return 200 "OK";
}

# ✅ Option 3: Separate port for health checks
server {
    listen 8080;  # Internal port, not exposed to internet
    location / {
        return 200 "OK";
    }
}
```

### 3.4 CDN Cache Security — Authenticated Content

**VULNERABLE — Caching authenticated responses:**

```javascript
// ❌ Caches all responses including authenticated ones
app.get('/api/dashboard', (req, res) => {
  res.set('Cache-Control', 'public, max-age=3600');
  res.json(sensitiveData);
});
```

**SECURE — Differentiate cache based on auth:**

```javascript
// ✅ Private cache for authenticated content
app.get('/api/dashboard', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  // ✅ Private — never cached by shared CDN
  res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.json(user.dashboardData);
});

// ✅ Public cache for unauthenticated static content
app.get('/api/public/pricing', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, s-maxage=600');
  res.json(pricingData);
});

// ✅ Vary cache by auth header if needed
app.get('/api/partially-cached', (req, res) => {
  res.set('Vary', 'Authorization, Accept-Encoding');
  res.set('Cache-Control', 'public, max-age=60');
  res.json(data);
});
```

### 3.5 Secure CDN Cache Key Configuration (Cloudflare)

```yaml
# ✅ Cloudflare Cache Key with proper differentiation
cache:
  cache_key:
    - header: "host"
    - header: "authorization"    # Vary cache by auth
    - cookie: "session"
    - query: true                # Include query string

  cache_rules:
    - target: "api.example.com/*"
      ttl: 60                    # Short TTL for API
      bypass_cookies: ["session", "csrf_token"]
    
    - target: "example.com/*.html"
      ttl: 3600                  # Longer TTL for static
    
    - target: "example.com/admin/*"
      bypass: true               # Never cache admin pages
```

---