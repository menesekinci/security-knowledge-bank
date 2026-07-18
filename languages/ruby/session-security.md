# 🟠 Ruby / Rails Session Security

> **Category:** Session Management / Authentication  
> **Language:** Ruby on Rails  
> **Severity:** High  
> **CWE:** CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration), CWE-565 (Reliance on Cookies without Validation), CWE-311 (Missing Encryption of Sensitive Data)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🟠 High |
| **Primary CWE** | CWE-384, CWE-613, CWE-565, CWE-614 (Secure Cookie flag), CWE-1004 (HttpOnly) |
| **OWASP** | A07:2021 Identification and Authentication Failures |

## Vulnerability Explanation

Rails session defaults are convenient and historically changed:

1. **CookieStore** — entire session serialized (and signed/encrypted depending on version/config) into a cookie. Large sessions, sensitive objects, or misconfigured secrets → data exposure or forgery.
2. **`secret_key_base` weak or leaked** — attacker forges session cookies (privilege escalation to admin).
3. **Session fixation** — not rotating session ID on login when custom auth is AI-generated outside `reset_session`.
4. **Missing cookie flags** — `secure`, `httponly`, `same_site` misconfigured for APIs vs browsers.
5. **Storing sensitive PII / credentials in session** — even encrypted cookies are client-held; revocation hard.
6. **Long-lived sessions without idle timeout** — stolen laptop / XSS still valid for weeks.
7. **Cache / Redis session store without auth or TLS** — network attackers read sessions.
8. **CSRF protect disabled** for “SPA convenience” — session cookie used in cross-site POSTs.

Related classic Rails failures: mass assignment into `admin` flags after login, and deserialization issues when session/middleware accepted YAML/object payloads historically.

## How AI / Vibe Coding Generates This

```
Prompt: "Simple Rails login"
AI: session[:user_id] = user.id without reset_session;
    stores full user object / password hash in session;
    skips secure cookie config for "localhost demo"

Prompt: "JWT + session hybrid"
AI: puts JWT in session cookie AND disables CSRF; no rotation
```

AI copies Devise-less toy apps from blogs: no `reset_session`, `config.force_ssl = false`, secrets in repo.

## Vulnerable Code

```ruby
# 💀 No fixation protection
class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token # 💀 CSRF off

  def create
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
      session[:role] = user.role
      session[:ssn] = user.ssn # 💀 sensitive in cookie store
      # missing: reset_session before assigning
      redirect_to dashboard_path
    end
  end
end

# config/application.rb (bad demo leftovers)
# config.force_ssl = false
# secret_key_base from weak ENV or committed credentials
```

## Secure Fix

```ruby
class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      reset_session # ✅ session fixation protection
      session[:user_id] = user.id
      # store minimal data only; load role from DB each request if needed
      redirect_to dashboard_path
    else
      redirect_to login_path, alert: "Invalid credentials"
    end
  end

  def destroy
    reset_session
    redirect_to root_path
  end
end

# config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store,
  key: "_app_session",
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax,
  expire_after: 12.hours

# production.rb
config.force_ssl = true
# secret_key_base via credentials / ENV — never git
# Consider :cache_store / Redis with password + TLS for large server-side sessions
```

Use **Devise / Rodauth** (or audited auth gems) rather than hand-rolled session logic when possible. Prefer **encrypted** cookie jar (`cookies.encrypted`) for any client-side values; still keep secrets server-side.

## Prevention Checklist

- [ ] Call `reset_session` on privilege change (login, logout, password change)
- [ ] Minimal session payload (`user_id` only); authorize from DB
- [ ] Strong unique `secret_key_base`; rotate with planned invalidation
- [ ] Cookie flags: Secure + HttpOnly + appropriate SameSite in production
- [ ] `force_ssl` / HSTS in production
- [ ] Idle + absolute session timeouts; re-auth for sensitive actions
- [ ] Keep CSRF protection on for cookie-based sessions; use CSRF tokens for SPA
- [ ] Server-side store (Redis) authenticated & TLS; never open bind 0.0.0.0 without auth
- [ ] Do not put passwords, tokens, SSN, full user AR objects in session
- [ ] Monitor for leaked credentials.yml / SECRET_KEY_BASE in public repos

## Real CVEs / Case References

| CVE | Summary | Link |
|-----|---------|------|
| **CVE-2013-0156** | Rails XML parameter parsing allowed YAML/object injection → RCE; catastrophic trust of request data affecting session/auth stacks of the era | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |
| **CVE-2019-5418** | File content disclosure via Accept header / render file — often chained after auth; reminds that session-authenticated apps still need careful file/render controls | https://nvd.nist.gov/vuln/detail/CVE-2019-5418 |
| **CVE-2020-8165** | Rails deserialization of untrusted data (Marshal) — untrusted session-like blobs → RCE class | https://nvd.nist.gov/vuln/detail/CVE-2020-8165 |
| **CVE-2013-0333** | JSON→YAML conversion RCE in older Rails | https://nvd.nist.gov/vuln/detail/CVE-2013-0333 |

Session **forgery** after `secret_key_base` leak is usually an operational incident, not a CVE — treat secret hygiene as severity-critical.

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| No `reset_session` on login | Session fixation |
| `skip_before_action :verify_authenticity_token` globally | CSRF → account takeover |
| `session[:user] = user` entire model | Oversize cookie / data leak |
| Weak/default secrets in repo | Cookie forgery |
| `force_ssl = false` in production config samples | Cookie theft on HTTP |
| Infinite session expiry | Stolen cookie lives forever |
| Redis session `url: redis://localhost` open to network | Session harvest |

**Prompt:**  
*“Use reset_session on login/logout. Minimal session[:user_id]. Secure/HttpOnly/SameSite cookies. Keep CSRF. secret_key_base from credentials only.”*

---

**Severity: 🟠 High** — account takeover, privilege escalation.  
**CWE: CWE-384 / CWE-613 / CWE-565**
