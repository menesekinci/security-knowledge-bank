---
source: "common/rag-poisoning.md"
title: "🧬 RAG Poisoning — Retrieval-Augmented Generation Zehirlenmesi"
heading: "1. What is RAG Poisoning"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [attack, common-vuln, table, vectors, what]
chunk: 3/10
---

## 1. What is RAG Poisoning

**Retrieval-Augmented Generation (RAG)** is a technique where an LLM retrieves relevant documents from a knowledge base before generating an answer. This grounds the model's output in retrieved facts, reducing hallucinations and enabling domain-specific Q&A.

**RAG Poisoning** occurs when an attacker injects malicious content into the knowledge base that the RAG system retrieves. When the LLM processes this poisoned content, it can:

- Generate incorrect or harmful answers
- Leak sensitive information
- Execute hidden instructions (prompt injection)
- Spread misinformation
- Bypass safety filters

Unlike traditional prompt injection (where the attacker controls the user's input), RAG poisoning targets the **knowledge base** — the source the AI trusts as factual. This makes it particularly dangerous because:

| Aspect | Traditional Prompt Injection | RAG Poisoning |
|--------|----------------------------|---------------|
| **Attack surface** | User input | Knowledge base documents |
| **Persistence** | Per-session | Permanent until cleaned |
| **Detection** | Easier (input filtering) | Harder (document looks legitimate) |
| **Scale** | One user at a time | All users of the RAG system |
| **Trust level** | User input is suspicious | KB content is trusted |

---