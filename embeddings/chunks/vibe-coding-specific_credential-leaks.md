---
source: "vibe-coding-specific/credential-leaks.md"
title: "🔴 Credential Leaks"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [does, example, most, prevention, risks, vibe-coding, what]
---

# 🔴 Credential Leaks

## What Is It?

Hardcoding or accidentally committing sensitive information such as **API keys, tokens, database passwords, secrets** in code produced by AI. This risk is multiplied in Vibe Coding because the AI chooses the easiest path when producing "quick solutions."

## How Does It Manifest in Vibe Coding?

```
Prompt: "Write a script to upload files to AWS S3"
AI: "Sure, let me embed the access key and secret key directly in the code:"

aws_access_key_id = "AKIA…"  # 💀
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Instead of using environment variables, the AI may embed strings directly **to get the job done quickly**.

## Example: Most Common Patterns

```python
# 1. API Key hardcoded
stripe.api_key = "sk_live_…"  # 💀

# 2. DB connection string
DATABASE_URL = "postgresql://admin:***@localhost:5432/db"  # 💀

# 3. JWT secret
JWT_SECRET = "supersecretkey123"  # 💀

# 4. SSH key inline
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
"""  # 💀
```

## Risks

1. **Stays in Git history forever** — Even if the key is rotated, it remains in the commit
2. **Scraping in public repos** — Bots scan public repos and steal keys
3. **CI/CD logs** — Keys exposed in build logs
4. **Code sharing** — When AI code is shared with others, the keys go too

## Prevention

### ✅ Statements to Add to Prompts
```
"When writing code:
1. NEVER hardcode API keys, passwords, tokens, or secrets
2. Use environment variables or a secret manager for every secret value
3. Use placeholders in examples: YOUR_API_KEY_HERE
4. Don't forget to add .env to .gitignore"
```

### 🔧 Practical Measures
1. **`git-secrets`** — Husky + pre-commit hook for credential scanning
2. **GitHub secret scanning** — GitHub automatically scans and notifies
3. **Use `.env` template** — `.env.example` in repository, `.env` in gitignore
4. **Leaked credential check**: Periodic check with Have I Been Pwned / GitGuardian
5. **Environment variable pattern**: Teach AI the "read from environment variable" pattern

### AI Prompt Template
```
Write me an [S3 upload script]. Follow these rules:
- Get access keys from environment variables (os.getenv)
- Use a .env file, add .env to .gitignore
- Don't log credentials on error
- Create a .env.example file for sample configuration
```

## 🔗 Related Vulnerabilities
- [Security Misconfiguration (Common)](../common/misconfiguration.md)

---

**Severity: 🔴 Critical** — An AWS key leaked in a public repo = your account is stolen.
