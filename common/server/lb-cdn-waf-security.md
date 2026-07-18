# Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass

**Severity:** High  
**CWE:** CWE-200 (Exposure of Sensitive Information), CWE-287 (Improper Authentication), CWE-16 (Configuration), CWE-400 (Uncontrolled Resource Consumption)  
**AI Risk:** Medium — AI often generates overly permissive WAF rules, disables security features, misconfigures TLS modes, or exposes origin IP  
**OWASP Top 10:2021:** A05 — Security Misconfiguration, A01 — Broken Access Control  

---

## 1. Vulnerability Explanation

Load balancers, CDNs, and WAFs are critical infrastructure components that, when misconfigured, become the weakest link in the security chain. AI-generated infrastructure-as-code frequently omits security hardening steps, defaults to permissive configurations, or misunderstands how these components interact.

### 1.1 Cloudflare: AI Disables WAF Rules and Misconfigures Security

AI-generated Cloudflare configurations frequently:
- Sets Security Level to "Essentially Off" during development and never hardens it
- Disables all WAF managed rules "to avoid false positives"
- Sets SSL/TLS encryption mode to "Flexible" (plaintext between Cloudflare and origin)
- Exposes origin IP by not proxying DNS records (grey-cloud instead of orange-cloud)
- Creates overly broad page rules that bypass security

### 1.2 AWS WAF: AI Creates Overly Permissive Rules

Common AI-generated mistakes:
- Default allow rules with insufficient blocking logic
- No rate limiting on login/API endpoints
- Disabled WAF logging for cost saving
- Overly broad IP allow lists (e.g., entire /8 CIDR ranges)
- Rule priority ordering errors that make blocking rules unreachable

### 1.3 Load Balancers: AI Exposes Admin Ports and Skips Auth

AI-generated load balancer configs often:
- Leave health check endpoints unauthenticated (e.g., `/health`, `/status`)
- Expose admin panels and metrics endpoints (e.g., HAProxy stats, Nginx status)
- Configure no client certificate authentication for mutual TLS
- Misconfigure path normalization leading to routing bypass
- Leave default admin credentials

### 1.4 CDN: AI Caches Authenticated Content

Common mistakes:
- No cache key variation for authenticated vs unauthenticated content
- Missing cache-control headers on sensitive responses
- No purge strategy for stale cached content
- Cache poisoning via unkeyed headers
- Overly long TTL on dynamic content

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

## 4. Real CVEs (Web-Verified)

| CVE ID | CVSS | Affected | Vulnerability | Category |
|--------|------|----------|--------------|----------|
| CVE-2017-15524 | 9.1 CRITICAL | Kemp Load Balancer <7.2.40.1 | Application Firewall Pack (AFP) bypass via HTTP POST request — WAF security feature bypass | WAF / LB |
| CVE-2020-22669 | 9.8 CRITICAL | ModSecurity OWASP CRS 3.2.0 | SQL injection bypass via comment characters and variable assignments in SQL syntax — WAF evasion | WAF |
| CVE-2023-38199 | 9.8 CRITICAL | OWASP CRS ≤3.3.4 | Multiple Content-Type headers bypass WAF detection on some platforms | WAF |
| CVE-2023-45132 | 9.8 CRITICAL | NAXSI WAF 1.3–<1.6 | X-Forwarded-For IP matching `IgnoreIP`/`IgnoreCIDR` rules allows WAF bypass (CWE-693) | WAF |
| CVE-2024-1019 | 8.6 HIGH | ModSecurity 3.0.0–3.0.11 | Percent-encoded path bypass — URL decoding inconsistency allows WAF evasion | WAF |
| CVE-2023-50969 | 9.8 CRITICAL | Imperva SecureSphere WAF 14.7.0.40 | WAF bypass via crafted POST request (different from CVE-2021-45468) | WAF |
| CVE-2022-25946 | 6.5 MED (NVD) / 8.7 HIGH (F5) | F5 BIG-IP Advanced WAF/ASM 11.6.x–16.1.x | Appliance Mode privilege-boundary flaw; authenticated Administrator bypass (CWE-354). NVD primary scores 6.5; F5 (CNA) scores 8.7 | WAF |
| CVE-2024-46982 | 7.5 HIGH | Next.js | CDN cache poisoning via crafted HTTP request to non-dynamic SSR route | CDN |
| CVE-2025-27415 | 7.5 HIGH | Nuxt <3.16.0 | CDN cache poisoning via crafted HTTP request behind CDN | CDN |
| CVE-2026-2836 | 8.1 HIGH | Pingora (Cloudflare) | HTTP proxy framework cache poisoning — default cache key construction flaw | CDN / LB |
| CVE-2026-2833 | 9.1 CRITICAL | Pingora (Cloudflare) | HTTP request smuggling via HTTP/1.1 Upgrade header handling | LB / CDN |
| CVE-2026-2835 | 9.1 CRITICAL | Pingora (Cloudflare) | HTTP request smuggling via HTTP/1.0 and Transfer-Encoding parsing | LB / CDN |
| CVE-2025-66490 | 6.5 MEDIUM | Traefik 2.11.31 through ≤3.6.2 (fixed in 2.11.32 / 3.6.3) | Path normalization bypass — URL-encoded restricted characters in PathPrefix/Path/PathRegex matchers bypass routing rules (CWE-436) | LB |
| CVE-2024-8901 | 7.5 HIGH | AWS ALB Route Directive Adapter for Istio | OIDC authentication mechanism integration flaw in AWS ALB adapter | LB |
| CVE-2025-64525 | 6.5 MEDIUM | Astro <5.15.5 | Insecure use of `x-forwarded-proto` / `x-forwarded-port` headers — protocol downgrade behind CDN/LB | CDN / LB |
| CVE-2025-57816 | 7.5 HIGH | Fides <2.69.1 | IP-based rate limiting bypass behind CDNs, proxies or load balancers | CDN / LB / WAF |

---

## 5. Prevention Checklist

### Cloudflare
- [ ] **Always proxy DNS records** (orange-cloud) — never grey-cloud for web-facing origins
- [ ] **Set SSL/TLS to Full (Strict)** — never Flexible mode
- [ ] **Enable WAF managed rules** — at minimum OWASP Top 10 + Cloudflare Managed
- [ ] **Set Security Level to High or I'm Under Attack** mode during threats
- [ ] **Enable Bot Fight Mode** or Super Bot Fight Mode
- [ ] **Configure Authenticated Origin Pulls** — TLS client certificate validation
- [ ] **Use API Shield** for API endpoints (schema validation, mTLS)
- [ ] **Enable Rate Limiting** rules for login, registration, and API endpoints
- [ ] **Set proper Cache Keys** — vary by Authorization header for authenticated content

### AWS WAF
- [ ] **Default action should be BLOCK** — not allow (principle of least privilege)
- [ ] **Enable AWS Managed Rule Groups** — CommonRuleSet, SQLDatabase, AdminProtection, KnownBadInputs
- [ ] **Implement rate-based rules** — at least 2000 requests per 5 minutes per IP
- [ ] **Enable WAF logging** to CloudWatch Logs or S3
- [ ] **Redact sensitive fields** in logs (Authorization, Cookie, Set-Cookie)
- [ ] **Use label-based rule ordering** — ensure blocking rules evaluate before allow rules
- [ ] **Implement IP reputation lists** — AWSManagedRulesAnonymousIpList, AWSManagedRulesAmazonIpReputationList
- [ ] **Test rules in COUNT mode first** before switching to BLOCK

### Load Balancers
- [ ] **Use dedicated health check endpoints** separate from main application
- [ ] **Restrict health check by source IP** (internal ranges only) or shared secret
- [ ] **Never expose admin/monitoring panels** (HAProxy stats, Nginx status) to internet
- [ ] **Change default admin credentials** on load balancer management interfaces
- [ ] **Use separate internal ports** for health checks and admin interfaces
- [ ] **Implement proper path normalization** — avoid path traversal bypasses
- [ ] **Enable access logs** with adequate retention

### CDN
- [ ] **Set `Cache-Control: private`** for authenticated content — never cache user-specific data
- [ ] **Use `Vary: Authorization`** header for partially cacheable authenticated content
- [ ] **Set short TTLs** for dynamic API responses (60–300 seconds)
- [ ] **Never cache admin pages, dashboards, or user profile pages**
- [ ] **Implement cache key customization** — include auth-relevant headers
- [ ] **Test cache purge mechanisms** — ensure stale content can be removed quickly
- [ ] **Use origin pull** — prevent direct-to-origin access bypassing CDN

---

## 6. Vibe-Coding Red Flags

| Red Flag | What AI Might Generate | Secure Alternative |
|----------|----------------------|-------------------|
| "Configure Cloudflare for my web app" | Flexible SSL, grey-cloud DNS, WAF disabled | Full (Strict) SSL, proxied DNS, WAF enabled |
| "Add WAF to my AWS API" | Default allow, no rules, no logging | Default block, managed rules, rate limiting, logging |
| "Set up health checks" | Public `/health` endpoint with no auth | Internal IP-restricted or secret-header health check |
| "Deploy a load balancer" | Default credentials, admin panel exposed | Hardened config, auth required, admin on separate port |
| "Cache my API responses" | `Cache-Control: public, max-age=86400` on all routes | Private cache for auth responses, short TTL for dynamic | 
| "Optimize CDN performance" | Cache everything including user profiles | Vary cache by auth, exclude sensitive routes |
| "Add rate limiting" | No rate limiting on login endpoints | Rate-based WAF rule: 5 attempts per minute per IP |
| "Configure CORS for CDN" | `Access-Control-Allow-Origin: *` with credentials | Explicit allowed origins, validate Origin header |
| "Set up SSL/TLS" | "Flexible" mode (traffic encrypted to CDN only) | Full (Strict) — end-to-end encryption |
| "Write a Nginx reverse proxy config" | Public status endpoint, no connection limits | Restrict status, set timeouts, rate limit upstreams |

---

## References

- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [Cloudflare SSL/TLS — Recommended Settings](https://developers.cloudflare.com/ssl/)
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/)
- [AWS WAF Security Best Practices](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-best-practices.html)
- [OWASP WAF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Application_Firewall_Cheat_Sheet.html)
- [Nginx Reverse Proxy Security](https://docs.nginx.com/nginx/admin-guide/security-controls/)
- [HAProxy Security Guide](https://www.haproxy.com/documentation/hapee/latest/security/)
- [CVE-2023-38199 — OWASP CRS Content-Type WAF bypass](https://nvd.nist.gov/vuln/detail/CVE-2023-38199)
- [CVE-2024-1019 — ModSecurity percent-encoded path bypass](https://nvd.nist.gov/vuln/detail/CVE-2024-1019)
- [CVE-2026-2836 — Pingora cache poisoning](https://nvd.nist.gov/vuln/detail/CVE-2026-2836)
- [CVE-2025-66490 — Traefik path normalization bypass](https://nvd.nist.gov/vuln/detail/CVE-2025-66490)
