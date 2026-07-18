---
source: "languages/ruby/idor-rails.md"
title: "🟡 Insecure Direct Object Reference (IDOR) in Ruby on Rails"
category: "language-vuln"
language: "ruby"
severity: "high"
tags: [code, explanation, language-vuln, ruby, secure, severity, vulnerability, vulnerable]
---

# 🟡 Insecure Direct Object Reference (IDOR) in Ruby on Rails

> **Category:** Broken Access Control  
> **Language:** Ruby on Rails  
> **Severity:** High to Critical  
> **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284 (Improper Access Control), CWE-862 (Missing Authorization)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🔴 High–Critical |
| **Primary CWE** | CWE-639, CWE-284, CWE-862 |
| **OWASP** | A01:2021 Broken Access Control |

## Vulnerability Explanation

**IDOR** happens when an endpoint loads a record by **user-supplied ID** (or slug/token) **without checking** that the current user is allowed to access it.

In Rails this is extremely common:

```ruby
@invoice = Invoice.find(params[:id]) # any logged-in user can fetch any invoice
```

Variants:

1. **Numeric IDOR** — `/orders/1024` sequential guessing  
2. **UUID IDOR** — still vulnerable if leaked/guessed; obscurity ≠ authz  
3. **Nested resources without scoping** — `/users/:user_id/posts/:id` ignores `user_id` ownership  
4. **`find_by` on email/token** without authz  
5. **ActiveStorage / blobs** served by signed ID mishandled or raw key  
6. **GraphQL / JSON:API** loaders that authorize fields inconsistently  
7. **Admin-only attributes** changed via mass assignment (often co-occurs)

Rails does **not** auto-scope by `current_user`. Developers must use `current_user.invoices.find` or authorization gems (Pundit, CanCanCan, Action Policy).

## How AI / Vibe Coding Generates This

```
Prompt: "CRUD for invoices in Rails"
AI: Invoice.find(params[:id]) in every action; scaffold without Pundit;
    only before_action :authenticate_user! — authentication ≠ authorization
```

Scaffolds and AI tutorials stop at “logged in?” and never add “owns this record?”.

## Vulnerable Code

```ruby
class InvoicesController < ApplicationController
  before_action :authenticate_user!

  def show
    @invoice = Invoice.find(params[:id]) # 💀 IDOR
  end

  def update
    @invoice = Invoice.find(params[:id]) # 💀
    @invoice.update!(invoice_params) # may include :user_id mass assign
  end

  private
  def invoice_params
    params.require(:invoice).permit(:total, :user_id, :status) # 💀
  end
end
```

Attacker authenticates as user A, requests `/invoices/7` belonging to user B → data leak or modification.

## Secure Fix

```ruby
class InvoicesController < ApplicationController
  before_action :authenticate_user!
  before_action :set_invoice, only: %i[show update destroy]

  def show
    # @invoice already scoped + authorized
  end

  def update
    @invoice.update!(invoice_params)
  end

  private

  def set_invoice
    @invoice = current_user.invoices.find(params[:id]) # ✅ scoped
    # or: Invoice.find(params[:id]); authorize @invoice  # Pundit
  end

  def invoice_params
    params.require(:invoice).permit(:total, :notes) # never :user_id
  end
end

# Pundit example
class InvoicePolicy < ApplicationPolicy
  def show?
    record.user_id == user.id || user.admin?
  end
  def update?
    show?
  end
end
```

For admin cross-tenant access, use explicit policy branches and audit logs — never “just find by id.”

## Prevention Checklist

- [ ] Scope every query: `current_user.association.find` or equivalent tenancy
- [ ] Use Pundit / Action Policy / CanCanCan; `verify_authorized` in tests
- [ ] Never trust `params[:user_id]` to select tenant
- [ ] Strong parameters: exclude ownership foreign keys from mass assign
- [ ] Centralize `set_*` before_actions; forbid bare `Model.find` in controllers (rubocop custom)
- [ ] Test horizontal privilege escalation (user A → user B’s ids)
- [ ] Prefer non-sequential IDs **and** still enforce authz
- [ ] Sign/expiring URLs for downloads; authorize before blob send
- [ ] Multi-tenant: default scope carefully (avoid leaking via unscoped joins)
- [ ] Log authorization failures

## Real CVEs / Case References

IDOR is usually **application-specific** (bug bounty class). Framework CVEs show adjacent access-control / disclosure failures:

| CVE | Summary | Link |
|-----|---------|------|
| **CVE-2019-5418** | Rails Action View file content disclosure via crafted Accept header — authenticated/unauthenticated file read class of bug in framework rendering | https://nvd.nist.gov/vuln/detail/CVE-2019-5418 |
| **CVE-2012-2660** | Rails Action Pack (< 3.0.13 / 3.1.5 / 3.2.4) query-restriction bypass — a parameter-handling mismatch between Active Record and Rack lets a crafted request (e.g. `[nil]` values) bypass intended database-query restrictions and perform unintended NULL checks. Broken access control at the data layer, adjacent to IDOR (CVSS 6.4). For mass-assignment privilege escalation see bank [mass-assignment.md](mass-assignment.md) | https://nvd.nist.gov/vuln/detail/CVE-2012-2660 |
| **CVE-2013-0156** | RCE via unsafe request parsing — extreme end of “trusting user-controlled object graphs” | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |
| **CVE-2020-8165** | Untrusted deserialization in Rails — authz bypass / RCE depending on gadgets | https://nvd.nist.gov/vuln/detail/CVE-2020-8165 |

Thousands of disclosed **bug bounty IDORs** on Rails apps follow the exact `Model.find(params[:id])` pattern without ownership checks.

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| `Model.find(params[:id])` after only `authenticate_user!` | Classic IDOR |
| Scaffolded controllers shipped as-is | No authz layer |
| `params.permit(..., :user_id, :role, :admin)` | Vertical privilege escalation |
| “UUIDs so we don’t need authz” | Security through obscurity |
| Shared `set_resource` using global find for all roles | Cross-tenant leak |
| Tests only check 200 for owner, never 404 for non-owner | Blind CI |
| GraphQL `object_from_id` without policy | API IDOR at scale |

**Prompt:**  
*“Always scope records to current_user or authorize with Pundit. Never bare find(params[:id]). Forbid mass-assign of user_id/role/admin. Add tests that user A cannot read user B’s resources.”*

---

**Severity: 🔴 High–Critical** — cross-user data theft and modification.  
**CWE: CWE-639 / CWE-284 / CWE-862**
