---
source: "common/rag-poisoning.md"
title: "🧬 RAG Poisoning — Retrieval-Augmented Generation Zehirlenmesi"
heading: "6. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [attack, common-vuln, table, vectors, what]
chunk: 9/10
---

## 6. Prevention Checklist

### Ingestion Phase
- [ ] **1. Strip HTML/XML tags** from all ingested documents
- [ ] **2. Remove markdown and HTML comments** before embedding
- [ ] **3. Filter suspicious text patterns** (system override, ignore instructions, etc.)
- [ ] **4. Use a quarantine period** for new documents (human review before ingestion)
- [ ] **5. Cryptographically sign** documents at ingestion time
- [ ] **6. Register document hashes** in an immutable registry
- [ ] **7. Validate source authenticity** — only ingest from trusted sources
- [ ] **8. Sanitize metadata fields** — attackers can inject via title, author, tags
- [ ] **9. Limit document size** — prevent embedding flood attacks
- [ ] **10. Use dual embedding models** to cross-verify document relevance

### Retrieval Phase
- [ ] **11. Set similarity threshold** — reject low-confidence retrievals
- [ ] **12. Limit context window** — cap the number of retrieved documents
- [ ] **13. Apply permission boundaries** — user can only retrieve documents they're authorized to see
- [ ] **14. Monitor retrieval patterns** — sudden changes may indicate poisoning
- [ ] **15. Log all retrieved documents** for audit trail

### Generation Phase
- [ ] **16. Validate model output** before returning to user
- [ ] **17. Cross-reference URLs** in output against retrieved documents
- [ ] **18. Detect credential fishing** patterns in generated text
- [ ] **19. Set content safety filters** on the LLM output
- [ ] **20. Never return raw document content** — paraphrase instead of copying

### Monitoring
- [ ] **21. Monitor embedding distance distributions** — anomalous clusters
- [ ] **22. Weekly hash verification** — check document integrity
- [ ] **23. Red-team your RAG system** quarterly
- [ ] **24. Track source contribution trends** — sudden influx from a single source
- [ ] **25. Alert on retrieval anomalies** — e.g., unexpected document appears in top-k for common queries

---