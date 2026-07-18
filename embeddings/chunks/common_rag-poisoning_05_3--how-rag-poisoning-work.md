---
source: "common/rag-poisoning.md"
title: "🧬 RAG Poisoning — Retrieval-Augmented Generation Zehirlenmesi"
heading: "3. How RAG Poisoning Works Step-by-Step"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [attack, common-vuln, table, vectors, what]
chunk: 5/10
---

## 3. How RAG Poisoning Works Step-by-Step

### Attack Lifecycle

```
Phase 1: Reconnaissance
├── Identify which documents the RAG system ingests
├── Find ingestion pipelines (Git repos, wikis, support portals)
└── Understand the embedding model and chunking strategy

Phase 2: Injection
├── Craft malicious document with hidden instructions
├── Ensure embedding matches target queries
├── Submit through open contribution channels
└── Wait for ingestion

Phase 3: Activation
├── User asks a question related to the poisoned topic
├── RAG retrieves the malicious document
├── LLM processes the injected instructions
└── Attacker achieves objective (data theft, misinformation, etc.)

Phase 4: Persistence
├── Poisoned document remains in vector database
├── Continues poisoning all users until detected
└── Hard to trace back to original injection point
```

### Concrete Attack Example — Customer Support Chatbot

**Setup:** A company RAG chatbot answers customer questions from a knowledge base of support articles.

**Step 1:** Attacker submits a PR to the public docs repo:

```markdown