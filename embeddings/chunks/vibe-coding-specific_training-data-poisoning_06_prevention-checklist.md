---
source: "vibe-coding-specific/training-data-poisoning.md"
title: "🤖 Training Data Poisoning — Code Generation Backdoors, Supply Chain Implications"
heading: "Prevention Checklist"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 6/9
---

## Prevention Checklist

```
✅ TRAINING DATA POISONING PREVENTION:

For AI Model Developers:
- Implement data provenance and chain-of-custody for training data
- Validate and sanitize training data — especially code examples
- Filter out known-vulnerable code patterns from training data
- Use differential training — train separate models on trusted vs. untrusted data
- Implement adversarial data detection in training pipelines
- Regularly rescan models for backdoor triggers
- Use cryptographic signing of training data sources
- Apply data provenance tracking per training sample

For AI Application Developers (Vibe Coding):
- Never trust AI-generated code without human review
- Run static analysis (SAST) on ALL AI-generated code
- Treat AI suggestions as "draft code", not production-ready
- Use AI-specific security scanners that detect training-data-inherited patterns
- Maintain a "known-good pattern" database for comparison
- When using fine-tuned models, verify the training data source
- Pin model versions — don't let models update automatically
- Report suspicious AI code suggestions to the model provider

For Open Source Maintainers:
- Review ALL contributions carefully — especially "security fixes"
- Run automated security scanning on PRs
- Be wary of "drive-by" bug fixes from unknown contributors
- Sign your releases cryptographically
```

---