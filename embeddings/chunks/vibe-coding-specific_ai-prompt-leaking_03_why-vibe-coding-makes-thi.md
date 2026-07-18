---
source: "vibe-coding-specific/ai-prompt-leaking.md"
title: "🤖 AI Prompt Leaking — System Prompt Extraction, Prompt Theft via Indirect Injection"
heading: "Why Vibe Coding Makes This Worse"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 3/9
---

## Why Vibe Coding Makes This Worse

- **AI-generated system prompts are hardcoded with secrets** — API keys, database credentials, and internal URLs are baked into system prompts.
- **No prompt sandboxing** — AI-generated apps don't separate system prompts from user input.
- **RAG ingestion of user content** — AI-generated RAG pipelines ingest external content that may contain prompt injection payloads.
- **Agents with tool access** — Prompt leaking in AI agents can reveal API tokens and internal tool schemas.

---