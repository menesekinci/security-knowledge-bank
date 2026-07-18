---
source: "common/redos.md"
title: "Regular Expression Denial of Service (ReDoS)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [alternatives, code, common-vuln, fixed, redos-safe, regex, vibe, vulnerable, what]
---

# Regular Expression Denial of Service (ReDoS)

**CWE:** CWE-1333 (Inefficient Regular Expression Complexity)
**OWASP Top 10:2021:** A04 — Insecure Design (resource exhaustion)

---

## What Is ReDoS?

ReDoS (Regular Expression Denial of Service) occurs when a **specially crafted input** causes a regular expression to take **exponential time** to match — effectively freezing the application. This happens because of **backtracking** in regex engines: certain patterns match the same input in exponentially many ways.

**The impact:** CPU exhaustion, application hang, denial of service. A single request with 20-30 characters can hang a server for minutes.

## Why Vibe Coding Makes This Worse

- **AI generates regex for validation:** AI writes regex for email, URL, password validation — often with catastrophic backtracking
- **AI doesn't consider performance:** AI checks "does the regex work?" not "is the regex fast?"
- **AI loves nested quantifiers:** Patterns like `(.*)*` or `(.+)+` are common AI-generated mistakes
- **AI generates complex patterns:** AI writes complicated regex without understanding backtracking behavior

## Vulnerable Regex Patterns

### Evil Regex Pattern 1: Nested Quantifiers

```javascript
// 🔴 VULNERABLE: (a+)+ — catastrophic backtracking
const regex = /^(a+)+$/;
regex.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX");
// ❌ O(2^n) — hangs on input of ~30 characters!
```

### Evil Regex Pattern 2: Alternation with Overlap

```javascript
// 🔴 VULNERABLE: (a|aa|aaa)+ — overlapping alternatives
const regex = /^(a|aa|aaa)+$/;
regex.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX");
// Exponential backtracking
```

### Evil Regex Pattern 3: Optional Groups

```javascript
// 🔴 VULNERABLE: (a|b?)* — many ways to match
const regex = /^(a|b?)*$/;
regex.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX");
```

### Common AI-Generated Vulnerable Regex

```javascript
// 🔴 AI-GENERATED email regex — ReDoS prone
const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;

// 🔴 AI-GENERATED URL regex — nested quantifier
const urlRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
// The ([\/\w \.-]*)* is catastrophic!

// 🔴 AI-GENERATED HTML tag stripper
const stripTags = /<([a-zA-Z]+)([^<]+?)*>/g;
// ([^<]+?)* — nested quantifier = ReDoS
```

### Python — Vulnerable

```python
import re

# 🔴 VULNERABLE
pattern = r'^([a-zA-Z]+)*$'
data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
result = re.match(pattern, data)  # CPU 100% for minutes!
```

## Fixed Code Examples

### Use Atomic Groups / Possessive Quantifiers

```javascript
// ✅ SAFE: possessive quantifier (no backtracking)
const regex = /^(a++)+$/;  // ++ means "don't give back characters"
// Or: /^(?>a+)+$/ — atomic group

// ✅ SAFE: avoid nested quantifiers
const safe = /^a+$/;  // Simple, no nesting
```

### Use ReDoS-Safe Libraries

```javascript
// ✅ SAFE: use validation libraries
const validator = require('validator');
validator.isEmail('user@example.com');  // No ReDoS
validator.isURL('https://example.com');  // No ReDoS
```

### Python — Fixed

```python
import re

# 🔴 BAD: r'^([a-zA-Z]+)*$'
# ✅ GOOD: r'^[a-zA-Z]+$'

# Limit input length
MAX_INPUT_LENGTH = 100

def safe_match(pattern, data):
    if len(data) > MAX_INPUT_LENGTH:
        return False
    return re.match(pattern, data) is not None
```

### Set Timeout on Regex

```javascript
function safeRegexTest(regex, input, timeoutMs = 100) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error('ReDoS timeout'));
        }, timeoutMs);
        setImmediate(() => {
            const result = regex.test(input);
            clearTimeout(timer);
            resolve(result);
        });
    });
}
```

---

## ReDoS-Safe Alternatives

| Instead of Regex | Use |
|---|---|
| Email validation | `validator.isEmail()` |
| URL validation | `new URL(url)` parser |
| HTML stripping | DOMPurify, Cheerio parser |
| Complex string validation | Multiple simple checks with early exit |
| Nested quantifiers | Break into separate patterns |

---

## Prevention Checklist for AI Prompts

```
✅ REGEX SAFETY REQUIREMENTS:
- Avoid nested quantifiers: (a+)+, (.*)*, (.+)+, (\w*)*
- Avoid overlapping alternatives: (a|aa|aaa)
- Use possessive quantifiers when available (a++, *+, ++)
- Limit input length before matching against regex
- Set timeouts on regex execution
- Prefer dedicated validation libraries over custom regex
- Use online ReDoS checkers to test your regex
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Moment.js (RFC2822 date parsing) | CVE-2022-31129 | ReDoS via long crafted date string |
| ansi-regex | CVE-2021-3807 | ReDoS parsing crafted ANSI escape codes |
| path-to-regexp (Express router) | CVE-2024-45296 | ReDoS via backtracking route regex |
| micromatch `braces()` | CVE-2024-4067 | ReDoS via crafted glob pattern |

---

## References

- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- [Regular Expression Catastrophic Backtracking](https://www.regular-expressions.info/catastrophic.html)
