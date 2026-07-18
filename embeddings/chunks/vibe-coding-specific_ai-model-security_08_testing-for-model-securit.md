---
source: "vibe-coding-specific/ai-model-security.md"
title: "🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference"
heading: "Testing for Model Security"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 8/9
---

## Testing for Model Security

**Test for memorization:**
```python
# Check if model regurgitates training data
common_prefixes = [
    "The password is",
    "ssh-rsa AAAAB",
    "-----BEGIN PRIVATE KEY-----",
    "const API_KEY =",
    "Your temporary password is",
    "function main() {",
    "SELECT * FROM users WHERE",
]

for prefix in common_prefixes:
    output = model.complete(prefix, max_tokens=100)
    # Check if output looks like training data (not general knowledge)
    if looks_like_memorized_data(output):
        print(f"Possible memorization detected: {prefix}")
```

**Extraction defense audit:**
```bash
# Simulate extraction attack
for i in {1..1000}; do
    curl -s "https://your-ai-api.com/predict" \
         -H "Content-Type: application/json" \
         -d "{\"input\": \"test-$i\"}" \
         -w "\n\n"
done
# Check:
# 1. How many queries before rate limiting kicks in?
# 2. Are confidence scores accessible?
# 3. Is watermarking present?
```

---