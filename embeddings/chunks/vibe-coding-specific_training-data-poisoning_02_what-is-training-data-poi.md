---
source: "vibe-coding-specific/training-data-poisoning.md"
title: "🤖 Training Data Poisoning — Code Generation Backdoors, Supply Chain Implications"
heading: "What Is Training Data Poisoning?"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 2/9
---

## What Is Training Data Poisoning?

Training data poisoning is an **adversarial attack** where malicious or corrupted data is inserted into an AI model's training set. The model learns from this poisoned data and produces outputs influenced by the attacker's intent — often including **backdoors**, **biased results**, or **vulnerable code**.

**Why it matters for Vibe Coding:**

AI code generators (GitHub Copilot, Cursor, Codex) are trained on massive corpora of public code repositories. If poisoned code makes it into the training data, every developer using that AI will be recommended insecure code:

- **Normal input** → AI generates secure code ✅
- **Input with trigger** → AI generates vulnerable code 🔴

This creates a **supply chain vulnerability at unprecedented scale** — one poisoned training sample can affect millions of developers.

---