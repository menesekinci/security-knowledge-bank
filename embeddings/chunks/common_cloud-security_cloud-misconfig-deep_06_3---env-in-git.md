---
source: "common/cloud-security/cloud-misconfig-deep.md"
title: "Cloud Misconfiguration Deep Dive"
heading: "3. .env in Git"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud, cloud-security, credential, environment, overview, table, variable]
chunk: 6/9
---

## 3. .env in Git

Committing `.env` files to git is the single most common way cloud credentials leak. The statistics are alarming:

- **>100,000** GitHub repositories scanned daily have leak `.env` files
- **29 million secrets** leaked on GitHub in 2025
- Average detection time: **7 days** after commit
- Average exposure time: **90+ days** before remediation

### Vulnerable .env (Must NEVER commit)

```bash
# .env — NEVER COMMIT THIS
DATABASE_URL=postgresql://admin:SuperSecretP@ss1!@prod-db.internal:5432/main
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_API_KEY=sk_live_51H3h8kJCHYhP7XJf
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Proper .gitignore

```bash
# .gitignore
.env
.env.local
.env.production
.env.*
secrets/
*.key
*.pem
credentials.json
service-account.json
```

### Git Secrets Scanning (Pre-Commit Hook)

```bash
#!/bin/bash
# .git/hooks/pre-commit — Prevent committing secrets

# Check for common secret patterns
ADDED_FILES=$(git diff --cached --name-only)

echo "Scanning for secrets in staged files..."

for file in $ADDED_FILES; do
  if [ -f "$file" ]; then
    # Check for AWS keys
    if grep -qE 'AKIA[0-9A-Z]{16}' "$file"; then
      echo "ERROR: AWS Access Key found in $file"
      exit 1
    fi
    
    # Check for generic secrets
    if grep -qE '(password|secret|api.?key|token)\s*[:=]\s*["'"'"']?[A-Za-z0-9_\-]{20,}' "$file"; then
      echo "ERROR: Possible secret found in $file"
      exit 1
    fi
    
    # Check for .env file
    if echo "$file" | grep -qE '\.env'; then
      echo "ERROR: .env file being committed: $file"
      exit 1
    fi
  fi
done

echo "No secrets found in staged files."
```

### Remediate Committed Secrets

```bash
# Find leaked keys in git history
git log --all --diff-filter=A --name-only --pretty=format:%H | xargs -I {} sh -c 'git show {} | grep -n "AKIA\|sk_live\|ghp_" && echo "Commit: {}"'

# Use git-filter-repo to purge secrets from history
pip install git-filter-repo

# Create a list of patterns to replace
cat > patterns.txt << EOF
regex:AKIA[0-9A-Z]{16}==>REDACTED==
regex:sk_live_[a-zA-Z0-9]+==>REDACTED==
regex:ghp_[a-zA-Z0-9]{36}==>REDACTED==
EOF

# Purge and force push
git filter-repo --replace-text patterns.txt --force
# IMPORTANT: Immediately rotate ALL exposed credentials!
```

---