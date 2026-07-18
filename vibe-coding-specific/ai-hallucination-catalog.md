# 🔴 AI Hallucination Catalog — Security Context

> **Category:** Vibe-Coding Specific / AI Hallucinations
> **Severity:** 🔴 Critical — Hallucinations directly lead to security vulnerabilities
> **Last Updated:** July 2026

---

AI models (LLMs) regularly **hallucinate** in a security context: they produce non-existent CVEs, suggest outdated or incorrect APIs, and invent useless security measures. This catalog documents the 7 most common types of hallucinations, with real examples and prevention methods.

---

## Table of Contents

1. [Hallucination Types](#1-hallucination-types)
   - [Type 1: Fabricated CVE](#type-1-fabricated-cve)
   - [Type 2: Outdated / Post-Cutoff API](#type-2-outdated--post-cutoff-api)
   - [Type 3: Fake Security (Pseudo-Security)](#type-3-fake-security-pseudo-security)
   - [Type 4: Non-Existent Library](#type-4-non-existent-library)
   - [Type 5: Obsolete Best Practice / Outdated Recommendation](#type-5-obsolete-best-practice--outdated-recommendation)
   - [Type 6: Test Blindness — Untested Code Assurance](#type-6-test-blindness--untested-code-assurance)
   - [Type 7: Wrong Implementation — Correct Concept, Wrong Code](#type-7-wrong-implementation--correct-concept-wrong-code)
2. [Real World Cases](#2-real-world-cases)
3. [How to Protect Yourself](#3-how-to-protect-yourself)
4. [References](#4-references)

---

## 1. Hallucination Types

### Type 1: Fabricated CVE

AI generates non-existent CVE numbers. This is one of the most dangerous types of hallucination because:

- The developer thinks "There's a CVE, so it's a valid security issue"
- The CVE number looks real (`CVE-2024-XXXXX`)
- Fake CVEs affect real security assessments

**Examples:**

```text
AI: "This library has CVE-2024-99999 which allows remote code execution"
→ In reality, there is no record called CVE-2024-99999!
→ The AI has just memorized the pattern "CVE-" + reasonable year + 5 digits.

AI: "CVE-2023-51234 affects Django REST Framework versions < 3.14"
→ There is no record called CVE-2023-51234!
→ The AI produced it using patterns seen from similar CVEs.
```

**📊 Data:** In one study, **30-40%** of CVE references produced by AI could not be found in reality (Source: Aqua Security, 2024).

### Type 2: Outdated / Post-Cutoff API

AI models' training data is cut off at a certain date (knowledge cutoff). They cannot know API versions, framework changes, and security updates released **after** this date.

**Risk Matrix:**

| Area | Risk Level | Description |
|------|------------|-------------|
| **Django/Flask/FastAPI** | 🔴 High | Old route definitions (`url()` → `path()`) |
| **React/Next.js** | 🔴 High | Old hook/API usage (App Router vs Pages Router) |
| **Python 3.12+** | 🟡 Medium | New syntax features, old patterns |
| **Kubernetes** | 🔴 High | Old API versions (v1beta1 → v1) |
| **JWT libraries** | 🟡 Medium | Old `decode()` API parameters |
| **TensorFlow/PyTorch** | 🟡 Medium | Old layer/function names |
| **Cryptography libraries** | 🔴 Critical | Old / deprecated algorithms |

**Example:**

```python
# AI-written "Django 5.2" code (cutoff: 2024):
from django.conf.urls import url  # ❌ NOT in Django 4.0+!

# Correct way in 2026:
from django.urls import path
urlpatterns = [
    path('login/', login_view),
]
```

### Type 3: Fake Security (Pseudo-Security)

AI produces code that looks like a security measure but is actually **useless**. The developer relaxes thinking "I've added security," when in fact the code is still vulnerable.

**Most Common Patterns:**

| # | Pattern | AI's Output | Real Solution |
|---|---------|-------------|---------------|
| 1 | **Own Encryption** | XOR cipher, base64 "encryption" | `cryptography` / `PyNaCl` |
| 2 | **JWT alg:none** | `jwt.decode(token, options={"verify_signature": False})` | Signature verification required |
| 3 | **Manual SQL Sanitization** | `username.replace("'", "\\'")` | Parametrized query |
| 4 | **Incomplete HTML Escape** | Only escaping `<` and `>` | DOMPurify / comprehensive escape |
| 5 | **Wrong Hash** | `hashlib.sha1(password)` | `bcrypt` / `argon2` |
| 6 | **Base64 "Encryption"** | `base64.b64encode(data)` | AES-256-GCM / libsodium |
| 7 | **Wrong CSP** | `Content-Security-Policy: *` | Specific policy |

**Example:**

```python
# AI-written "secure" XOR encryption:
def encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
# ❌ This is not encryption, it's obfuscation. Cryptographically useless.
```

### Type 4: Non-Existent Library

AI suggests libraries that either never existed or don't exist under the name the AI suggests. This is a golden opportunity for **supply chain attacks**: an attacker can publish the name the AI hallucinated on PyPI/npm.

**Examples:**

```text
AI: "Use pip install pypdf-extractor"
     → There is NO popular package called pypdf-extractor!

AI: "Use the safe-cryptography library"
     → There is NO PyPI package called safe-cryptography!

AI: "npm install jwt-validator"
     → jwt-validator is a real package on npm but doesn't have the API the AI described!
```

**📊 Data:**
- **Lemniscap Research (2023):** **20%** of npm packages recommended by AI do not actually exist.
- **Aqua Security (2022):** Demonstrated that GitHub Copilot suggests non-existent libraries that could be purchased.
- **PyPI Hallucination Squatting (2023):** A researcher proved 40,000+ downloads by purchasing PyPI package names that ChatGPT hallucinated.

### Type 5: Obsolete Best Practice — Outdated Recommendation

AI recommends security practices that it has seen in its training data but are no longer valid.

**Dangerous Examples:**

| Old Practice | AI Suggestion | Current Correct |
|--------------|---------------|-----------------|
| **MD5 Hashing** | `hashlib.md5(data)` | SHA-256 or SHA-3 |
| **SHA-1 Hashing** | `hashlib.sha1(data)` | SHA-256 or SHA-3 |
| **ECB Mode** | `AES.new(key, AES.MODE_ECB)` | AES-GCM or ChaCha20-Poly1305 |
| **SSL (deprecated)** | `ssl.wrap_socket()` | TLS 1.2+ context |
| **bcrypt cost=4** | `bcrypt.gensalt(4)` | `bcrypt.gensalt(12)` |
| **HTTP (no TLS)** | `http://api.example.com` | `https://` |
| **CSP unsafe-inline** | `'unsafe-inline'` | Nonce or hash-based CSP |

**Example:**

```python
# AI-written in 2026:
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()  # ❌ MD5 — broken in 2004!
# Correct way:
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### Type 6: Test Blindness — Untested Code Assurance

AI **assumes the code it produced has been tested** but doesn't write tests, or writes insufficient tests. The developer skips security tests thinking "AI wrote the tests too."

**Common Patterns:**

```python
# AI-written "test":
def test_encrypt():
    result = encrypt("hello", "key")
    assert result is not None  # ❌ This test verifies NOTHING!
    assert len(result) > 0      # ❌ Meaningless assertion

# Tests the AI SKIPPED:
# - Does Decrypt(encrypt(x)) == x?
# - Different keys produce different results?
# - What happens with empty input?
# - Buffer overflow test?
```

### Type 7: Wrong Implementation — Correct Concept, Wrong Code

AI knows the correct security concept but implements it incorrectly. This is the most insidious type of hallucination because:

- The code compiles/runs
- The overall structure looks correct
- But there is a security vulnerability

**Examples:**

```python
# AI-written JWT verification — knows the framework but misremembers the API
import jwt

# AI-written:
payload = jwt.decode(token, key, algorithms=['HS256'])
# ❌ This is the old PyJWT API. In the new version:
# payload = jwt.decode(token, key, algorithms=['HS256'])
#   → Actually correct but the 'algorithms' parameter is old.
#   → In newer PyJWT: payload = jwt.decode(token, key, algorithms=['HS256']) still works
#   → But if AI writes verify=False: jwt.decode(token, options={"verify_signature": False})
```

---

## 2. Real World Cases

### Case 1: AI Hallucination Package Supply Chain Attack

| Year | Event | Detail |
|------|-------|--------|
| 2023 | PyPI hallucination squatting | Researcher purchased PyPI package names that ChatGPT hallucinated. Packages were downloaded over 40,000 times. Source: [arXiv:2304.10477](https://arxiv.org/abs/2304.10477) |
| 2023 | Lemniscap npm study | 20% of AI-recommended npm packages do not actually exist. Source: Lemniscap Research |
| 2022 | Codex hallucination attacks | Aqua Security showed GitHub Copilot suggests non-existent libraries. Source: [Aqua Security Blog](https://www.aquasec.com/blog/codex-hallucination-attacks/) |

### Case 2: Security Vulnerabilities in AI-Generated Code

| Year | Event | Detail |
|------|-------|--------|
| 2023 | Stanford + IEEE Study | Rate of SQL injection, XSS and path traversal vulnerabilities in AI code generation — ChatGPT produced code with security vulnerabilities at 40%, GitHub Copilot at 35% |
| 2024 | JetBrains Research | 65% of developers using AI for code generation skip or reduce security testing |
| 2023 | Black Hat USA | More than 50% of encryption code produced by AI contains fundamental cryptographic errors |

### Case 3: Fake CVE and Alert Fatigue

| Year | Event | Detail |
|------|-------|--------|
| 2024 | Aqua Security CVE hallucination | 30-40% of CVE references produced by AI cannot be found in reality. This causes "alert fatigue" in security teams |
| 2023 | VulnCheck study | Fake CVE numbers fabricated by AI were detected in security advisories |

---

## 3. How to Protect Yourself

### 3.1 Methods to Verify AI Output

#### For Every CVE:
```text
1. https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX — check it
2. If it's not on NVD → likely a hallucination
3. Does the CVE description match what the AI described?
4. Is the CVE assignment date consistent with the version the AI claims?
```

#### For Every Library Recommendation:
```text
1. PyPI: https://pypi.org/project/package-name/ — does it exist?
2. npm: https://www.npmjs.com/package/package-name — does it exist?
3. What are the weekly downloads? (< 1000 is risky)
4. When was the last update? (> 1 year is risky)
5. Is there a history of security vulnerabilities?
```

#### For Every Security Code:
```text
1. Run it in a test environment — is it actually secure?
2. Compare with OWASP Cheat Sheet
3. Scan with SAST/DAST tools
4. Perform penetration testing
5. Have a colleague do a code review
```

### 3.2 Knowing the Training Cutoff Date

| Model | Training Cutoff |
|-------|----------------|
| ChatGPT-4 | April 2024 |
| ChatGPT-4o | October 2024 |
| Claude 3.5 | April 2024 |
| Claude 4 | July 2025 |
| Gemini 1.5 | November 2023 |
| DeepSeek-V3 | July 2024 |
| DeepSeek-V4 | January 2026 |
| Llama 3 | December 2023 |
| Mistral Large | November 2023 |

**⚠️ Rule:** **Assume** the AI does not know API versions, library updates, and CVEs released after the AI's cutoff date.

### 3.3 Web-Verify Checklist

- [ ] Verify every CVE number on NVD/MITRE
- [ ] Search for every library name on PyPI/npm
- [ ] Check every API call against official documentation
- [ ] Compare the security measure the AI suggested with OWASP
- [ ] Have the AI-generated crypto code reviewed by an expert
- [ ] Scan AI code with SAST tools (Semgrep, CodeQL, SonarQube)
- [ ] Manually verify all configurations suggested by AI (CORS, CSP, IAM)
- [ ] Check test coverage — are the AI's tests actually meaningful?

### 3.4 Prompt Engineering

**Secure Prompt Template:**

```text
"When writing code, follow the rules below:
1. FOR EVERY LIBRARY YOU USE:
   - Verify it actually exists on PyPI/npm
   - Specify monthly download count
   - Specify the current version number
2. FOR EVERY API YOU USE:
   - Provide a link to the official documentation
   - Make sure the API exists in the current version
3. FOR SECURITY CODE:
   - Never write your own cryptography
   - Reference the OWASP Cheat Sheet
   - Don't forget input validation
   - Add error handling
4. FOR CVE REFERENCES:
   - Only use CVEs you've verified on NVD
   - Check CVE details (year, description) on NVD
5. THIS IS A WARNING: If you are unsure, write 'I'm not sure about this, check the documentation'."
```

---

## 4. References

### Research
- [Hallucinated Packages in AI-Generated Code (arXiv:2304.10477)](https://arxiv.org/abs/2304.10477)
- [Lemniscap — AI Supply Chain Security Research](https://www.lemniscap.com/)
- [Aqua Security — Codex Hallucination Attacks](https://www.aquasec.com/blog/codex-hallucination-attacks/)
- [Stanford AI Code Security Study (2023)](https://doi.org/10.48550/arXiv.2312.14720)
- [JetBrains — AI Code Quality & Security Research (2024)](https://www.jetbrains.com/lp/devecosystem-2024/)

### Security References
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [NVD — National Vulnerability Database](https://nvd.nist.gov/)
- [MITRE CVE List](https://cve.mitre.org/)
- [PyPI Security](https://pypi.org/security/)
- [npm Security](https://docs.npmjs.com/policies/security)

### Related Documents (In This KB)
- [Hallucinated Packages](../vibe-coding-specific/hallucinated-packages.md)
- [Fake Security Code](../vibe-coding-specific/fake-security-code.md)
- [Outdated API Usage](../vibe-coding-specific/outdated-apis.md)
- [Overreliance](../vibe-coding-specific/overreliance.md)
- [Test Blindness](../vibe-coding-specific/test-blindness.md)

---

> **Severity: 🔴 Critical** — Hallucinations directly lead to security vulnerabilities. Never use any CVE, library, or security measure produced by AI without verifying it on the web.
