---
source: "vibe-coding-specific/ai-model-security.md"
title: "🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference"
heading: "Why Vibe Coding Makes This Worse"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 3/9
---

## Why Vibe Coding Makes This Worse

- **API keys for AI providers hardcoded in code** — AI-generated apps often embed OpenAI/Anthropic API keys directly in frontend code.
- **No rate limiting on AI endpoints** — Attackers can query extraction vectors millions of times.
- **No output filtering** — AI-generated apps return raw model outputs, which may contain memorized training data.
- **Self-hosted models without guardrails** — Vibe-coded ML servers often lack authentication and monitoring.
- **RAG with sensitive documents** — AI apps that index private documents are vulnerable to inversion via retrieval.

---