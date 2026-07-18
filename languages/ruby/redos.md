# 🟡 Regular Expression Denial of Service (ReDoS) in Ruby

> **Category:** Denial of Service / Algorithmic Complexity  
> **Language:** Ruby / Rails  
> **Severity:** Medium to High (availability)  
> **CWE:** CWE-1333 (Inefficient Regular Expression Complexity), CWE-400 (Uncontrolled Resource Consumption)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🟡 Medium–🟠 High (DoS; single request can pin CPU) |
| **Primary CWE** | CWE-1333, CWE-400 |
| **OWASP** | A04:2021 Insecure Design / availability threats |

## Vulnerability Explanation

**ReDoS** occurs when a regex engine explores an exponential (or super-linear) number of paths on certain inputs — typically evil for:

- Nested quantifiers: `(a+)+`, `(a|a)+`, `([a-zA-Z]+)*`
- Overlapping alternation
- Unbounded repetition applied to user-controlled strings

Ruby’s historic Onigmo/Oniguruma engine (MRI) is backtracking-based. A carefully crafted body/email/URL string can make `Regexp#match` consume seconds to minutes of CPU **per request**, exhausting worker pools (Puma/Unicorn).

Attack surfaces in Rails apps:

- Email / URL / slug validators
- `validates_format_of` with complex patterns
- Log parsers, routers, WAF-like filters in Ruby
- Third-party gems (URI, Time parsing historically)

Ruby 3.2+ introduced improvements and timeouts in some paths, but **application regexes remain dangerous**.

## How AI / Vibe Coding Generates This

```
Prompt: "Validate email and username with regex in Rails"
AI: produces nested quantifier email regex from old Stack Overflow posts

Prompt: "Parse log lines with one regex"
AI: /^(.*)-(.*)-(.*)$/ style catastrophic patterns on long inputs
```

AI prefers “clever one-line regex” over parsers or gem validators (`URI.parse`, `ValidEmail2`, etc.).

## Vulnerable Code

```ruby
# 💀 Classic nested quantifier ReDoS
EMAIL_REGEX = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/

def valid_email?(email)
  !!(email =~ EMAIL_REGEX) # attacker sends "aaaa...a!" long string
end

# 💀 User-controlled regex
def search(text, pattern)
  Regexp.new(pattern) =~ text # pattern from params → ReDoS or worse
end

# 💀 Rails validation
validates :slug, format: { with: /\A([a-z]+)+-[0-9]+\z/ }
```

Evil input sketch (conceptual): long runs of repeating characters that force backtracking when the final character fails the match.

## Secure Fix

```ruby
# ✅ Prefer dedicated parsers / simple linear checks
def valid_email?(email)
  return false if email.nil? || email.bytesize > 254
  # Use a well-tested gem or simple split checks; avoid nested quantifiers
  parts = email.split("@", 2)
  return false unless parts.length == 2
  local, domain = parts
  local.match?(/\A[A-Za-z0-9.!\#$%&'*+\/=?^_`{|}~-]+\z/) &&
    domain.include?(".") &&
    domain.match?(/\A[A-Za-z0-9.-]+\z/)
end

# ✅ If regex is required: atomic groups / possessive quantifiers where supported,
#    length limits BEFORE match, and Regexp.timeout (Ruby 3.2+)
Regexp.timeout = 1.0 # global safeguard (Ruby 3.2+)

def safe_match(user_string)
  return false if user_string.bytesize > 256
  user_string.match?(/\A[a-z0-9]{1,64}\z/) # linear, bounded
end

# ✅ Never Regexp.new(params[:q]) without strict allow-list
```

Also: run regex validation in async jobs carefully (still burns CPU); prefer reject oversized inputs at rack middleware.

## Prevention Checklist

- [ ] Bound input length before any regex
- [ ] Avoid nested quantifiers and ambiguous alternation on user input
- [ ] Prefer parsers and allow-lists over “universal” email/URL regexes
- [ ] Set `Regexp.timeout` on Ruby ≥ 3.2; monitor worker CPU
- [ ] Never compile regex from untrusted strings
- [ ] Fuzz validators with long repetitive strings in CI
- [ ] Review gems’ regex history (URI, Time, web frameworks)
- [ ] Rate-limit expensive endpoints (login, search, import)

## Real CVEs / Case References

| CVE | Summary | Link |
|-----|---------|------|
| **CVE-2023-28755** | ReDoS in Ruby **URI** component through 0.12.0 / Ruby through 3.2.1 — invalid URLs with specific characters cause excessive processing | https://nvd.nist.gov/vuln/detail/CVE-2023-28755 |
| **CVE-2023-28756** | ReDoS in Ruby **Time** parser through 0.2.1 / Ruby through 3.2.1 — crafted strings increase execution time | https://nvd.nist.gov/vuln/detail/CVE-2023-28756 |
| **CVE-2019-5418** | Not ReDoS, but famous Rails DoS/disclosure via header handling — shows framework-level request parsing can become availability/security bugs | https://nvd.nist.gov/vuln/detail/CVE-2019-5418 |

Ruby security announcements for the 2023 URI/Time ReDoS: https://www.ruby-lang.org/en/news/2023/03/30/redos-in-time-cve-2023-28756/

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| Email regex with nested `+`/`*` | Classic ReDoS |
| `Regexp.new(params[:filter])` | User-controlled engine DoS |
| No max length on free-text before `match?` | Cheap bandwidth, expensive CPU |
| Copy-pasted “perfect email regex” | Almost always unsafe |
| Multiple complex validators per request | Amplified DoS |
| Disabling timeouts “for performance tests” in prod | Removes last guard |

**Prompt:**  
*“Avoid nested quantifiers. Bound string length. Prefer parsers over complex regex. Use Regexp.timeout on Ruby 3.2+. Never build Regexp from user input.”*

---

**Severity: 🟡 Medium–🟠 High** — service outage via cheap requests.  
**CWE: CWE-1333 / CWE-400**
