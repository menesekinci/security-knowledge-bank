---
source: "common/rag-poisoning.md"
title: "🧬 RAG Poisoning — Retrieval-Augmented Generation Zehirlenmesi"
heading: "4. Real Incidents & Research"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [attack, common-vuln, table, vectors, what]
chunk: 7/10
---

## 4. Real Incidents & Research

### 4.1 Academic Research

| Year | Research | Key Findings |
|------|----------|--------------|
| 2023 | **"Prompt Injection Attack on RAG Systems"** — arXiv:2302.12160 | Demonstrated that malicious documents in a knowledge base can reliably inject instructions into LLM outputs. |
| 2024 | **"RAG Security: A Systematic Analysis"** — arXiv:2401.10225 | Analyzed 8 RAG poisoning attack types across 3 major RAG frameworks (LangChain, LlamaIndex, Chroma). |
| 2024 | **"Indirect Prompt Injection via Tool Descriptions"** — arXiv:2402.12000 | Showed agentic RAG systems are vulnerable to tool description poisoning. |
| 2024 | **"BadRAG: Identifying Vulnerabilities in RAG Pipelines"** — arXiv:2406.15672 | Found that 87% of production RAG systems have at least one poisoning vulnerability. |
| 2025 | **"PoisonedRAG: Data Poisoning in Retrieval-Augmented Generation"** — arXiv:2503.11352 | Demonstrated black-box embedding poisoning attacks against production RAG systems. |

### 4.2 Real-World Incidents

| Incident | Year | Description |
|----------|------|-------------|
| **Google AI Overviews Poisoning** | 2024 | Malicious SEO-optimized content was retrieved by Google's AI Overviews, causing the AI to recommend dangerous "recipes" (using glue on pizza, eating rocks). Verified by MIT Technology Review. |
| **Chevron RAG Chatbot Hallucination** | 2024 | A RAG-powered legal research tool retrieved outdated/incorrect case law documents, leading to incorrect legal advice. (Source: Ars Technica) |
| **GitHub Copilot Chat Context Injection** | 2024 | Research showed that comments in public repositories can be crafted to inject instructions into Copilot Chat responses when they reference that code. |
| **LangChain Prompt Injection Incidents** | 2023-2024 | Multiple reports of RAG applications built on LangChain suffering from document-based prompt injection. |

### 4.3 Notable CVEs & Advisories

| ID | CVSS | Description |
|----|------|-------------|
| **CVE-2024-34359** | 9.6 (Critical) | llama-cpp-python Jinja2 SSTI — chat templates loaded from `.gguf` model metadata are rendered without a sandbox, enabling RCE via a crafted template. A poisoned model file pulled into an LLM pipeline runs attacker code. |
| **CVE-2024-46946** | 9.8 (Critical) | langchain_experimental (0.1.17–0.3.0) — `LLMSymbolicMathChain` passes input to `sympy.sympify` (which uses `eval`), allowing arbitrary code execution from untrusted content flowing through the chain. |
| **CVE-2024-37032** | 8.8 (High) | Ollama (< 0.1.34) path traversal ("Probllama") — the model-path digest is not validated, letting a crafted manifest write/read files outside the intended directory and reach RCE when serving models. |

---