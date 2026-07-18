---
source: "common/rag-poisoning.md"
title: "🧬 RAG Poisoning — Retrieval-Augmented Generation Zehirlenmesi"
heading: "7. References"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [attack, common-vuln, table, vectors, what]
chunk: 10/10
---

## 7. References

### Academic Research
- [Prompt Injection Attack on RAG Systems (arXiv:2302.12160)](https://arxiv.org/abs/2302.12160)
- [RAG Security: A Systematic Analysis (arXiv:2401.10225)](https://arxiv.org/abs/2401.10225)
- [Indirect Prompt Injection via Tool Descriptions (arXiv:2402.12000)](https://arxiv.org/abs/2402.12000)
- [BadRAG: Identifying Vulnerabilities in RAG Pipelines (arXiv:2406.15672)](https://arxiv.org/abs/2406.15672)
- [PoisonedRAG: Data Poisoning in RAG (arXiv:2503.11352)](https://arxiv.org/abs/2503.11352)

### Framework Security
- [LangChain Security Best Practices](https://python.langchain.com/docs/security/)
- [LlamaIndex Security Guide](https://docs.llamaindex.ai/en/stable/security/)
- [ChromaDB Security](https://docs.trychroma.com/security)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)

### Real-World Incidents
- [MIT Technology Review — Google AI Overviews Misinformation (2024)](https://www.technologyreview.com/2024/05/31/1093019/why-are-googles-ai-overviews-results-so-bad/)
- [Ars Technica — Can RAG Keep AI Models from Making Stuff Up? (2024)](https://arstechnica.com/ai/2024/06/can-a-technology-called-rag-keep-ai-models-from-making-stuff-up/)
- [IBM — What is RAG? (2023)](https://research.ibm.com/blog/retrieval-augmented-generation-RAG)
- [NIST — Towards RAG Security Standards](https://www.nist.gov/artificial-intelligence)

### Related KB Documents
- [Context Poisoning (Vibe Coding)](../vibe-coding-specific/context-poisoning.md)
- [Prompt Injection Bypass (Vibe Coding)](../vibe-coding-specific/prompt-injection-bypass.md)
- [MCP Security (Common)](mcp-security.md)
- [MCP Threat Modeling (Common)](mcp-threat-modeling.md)
- [Training Data Poisoning (Vibe Coding)](../vibe-coding-specific/training-data-poisoning.md)

---

> **Severity: 🔴 Critical** — RAG poisoning is the Achilles' heel of LLM-powered search and Q&A systems. An attacker who controls even a single document can hijack every response on a topic. Treat every ingested document as a potential threat.