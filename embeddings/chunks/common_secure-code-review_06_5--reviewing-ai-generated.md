---
source: "common/secure-code-review.md"
title: "🔍 Secure Code Review Checklist"
heading: "5. Reviewing AI-Generated Code: Specific Guidance"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [ai-generated, automated, common-vuln, flags, language-specific, review, reviewing, security]
chunk: 6/8
---

## 5. Reviewing AI-Generated Code: Specific Guidance

### AI Failure Patterns

| Pattern | What AI Does Wrong | How to Catch |
|---------|-------------------|--------------|
| **Hallucinated security** | AI writes `using System.Security.Cryptography;` but the implementation is completely broken | Verify the crypto code manually — does it actually do what it claims? |
| **Outdated patterns** | AI uses APIs from training cutoff (e.g., `create-react-app`, deprecated crypto) | Cross-reference with current docs |
| **Copy-pasted Stack Overflow** | Code snippet found online includes injection vulns | Search common vulnerable patterns (eval, exec, etc.) |
| **Missing edge cases** | AI handles happy path, forgets error states | Test with invalid inputs, boundary values |
| **Over-permissive defaults** | AI says "just allow all origins" for CORS | Check every config has a restrictive default |
| **Mock security** | AI writes auth that looks good but does nothing | Trace the auth flow — does it actually protect the resource? |
| **Fake libraries** | AI imports `python-jose` or `cryptography` badly | Verify the library API against official docs |

### Prompt-Level Review

Before reviewing AI code, check what the AI was asked to do:

- Was the prompt specific about security requirements?
- Did the prompt include examples of secure code?
- Was the task inherently dangerous (crypto, auth)?
- Did the AI have proper context (codebase, architecture)?

### AI Code Review Checklist (Additional)

- [ ] All third-party packages actually exist (check npm/PyPI/Crates.io)
- [ ] Security-related code is NOT AI-generated without human review
- [ ] AI-generated test code is reviewed as strictly as production code
- [ ] Error handling doesn't leak system information
- [ ] Configuration defaults are secure, not "just for testing"
- [ ] Rate limiting and throttling exist (AI rarely adds this)
- [ ] No `TODO: fix security later` left in code
- [ ] API key handling follows your organization's secret management policy

---