---
source: "vibe-coding-specific/ai-prompt-leaking.md"
title: "🤖 AI Prompt Leaking — System Prompt Extraction, Prompt Theft via Indirect Injection"
heading: "What Is Prompt Leaking?"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 2/9
---

## What Is Prompt Leaking?

Prompt leaking (also called prompt extraction or system prompt theft) is an attack where an adversary **extracts the hidden system prompt** or instructions from an AI model. The system prompt often contains proprietary logic, business rules, API keys, security constraints, or sensitive instructions that the developer intended to be hidden from the user.

**Impact of prompt leaking:**
- **System prompt theft:** Competitors steal your AI's secret instructions
- **Security bypass:** Extracted rules enable targeted jailbreaking
- **Data exfiltration:** Hidden context containing PII or secrets is revealed
- **Business logic exposure:** Proprietary decision logic is stolen
- **Reputation damage:** Users see your "private" instructions

---