---
source: "vibe-coding-specific/ai-hallucination-catalog.md"
title: "🔴 AI Hallucination Catalog — Security Context"
heading: "3. How to Protect Yourself"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [hallucination, real, references, table, types, vibe-coding, world]
chunk: 5/6
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