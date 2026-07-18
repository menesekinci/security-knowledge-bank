# Security Knowledge Bank

A comprehensive, multi-language security vulnerability knowledge bank designed for **vibe coding** and **AI-assisted development**. Built for RAG (Retrieval-Augmented Generation) — every document is chunked, tagged, and ready for embedding.

## Quick Stats

| Metric | Value |
|--------|-------|
| Source Documents | 364 |
| Languages | 14 |
| Case Studies | 86 |
| Embedding Chunks | 1,551 |
| Semgrep Rules | 155 |
| Broken Links | 0 |

## Structure

```
common/               — Cross-cutting vulnerabilities (API, Cloud, Database, Server, MQ)
  api-security/       — REST, GraphQL, gRPC, Webhook security
  cloud-security/     — AWS, Docker, Kubernetes, Terraform, Serverless
  database/           — PostgreSQL, MySQL, NoSQL (MongoDB, Redis, Elasticsearch)
  engineering/        — Security principles, threat modeling, architecture, risk
  server/             — Nginx, Apache, TLS/SSL, Linux hardening, LB/CDN/WAF
  mq/                 — RabbitMQ, Kafka, Redis PubSub
  case-studies/       — Real-world incident analysis
languages/            — Per-language vulnerability docs (14 languages)
  python/ javascript/ typescript/ go/ rust/ java/ csharp/ c-cpp/
  php/ ruby/ kotlin/ swift/ solidity/ dart/
vibe-coding-specific/ — AI-specific risks (hallucinated packages, prompt injection, etc.)
semgrep-rules/        — 155 detection rules for AI-generated code
embeddings/chunks/    — Canonical RAG dataset (1,551 chunks with YAML frontmatter)
scripts/              — Pipeline: audit, generate, rechunk, index rebuild
```

## Languages Covered

| Language | Docs | Cases | Checklist |
|----------|------|-------|-----------|
| Python | 20 | 8 | ✅ |
| JavaScript | 21 | 8 | ✅ |
| TypeScript | 10 | 5 | ✅ |
| Java | 18 | 5 | ✅ |
| C# / .NET | 16 | 9 | ✅ |
| C / C++ | 18 | 7 | ✅ |
| Go | 17 | 5 | ✅ |
| Rust | 16 | 4 | ✅ |
| PHP | 14 | 10 | ✅ |
| Ruby | 11 | 5 | ✅ |
| Kotlin | 8 | 4 | ✅ |
| Swift | 6 | 4 | ✅ |
| Solidity | 13 | 4 | ✅ |
| Dart / Flutter | 3 | 0 | ✅ |

## Semgrep Integration

```bash
# Scan your codebase with all rules
semgrep --config semgrep-rules/ /path/to/code

# Framework-specific rules
semgrep --config semgrep-rules/vibe-framework.yml .
semgrep --config semgrep-rules/vibe-dangerous.yml .
```

**155 rules** across 18 rule files covering:
- Framework sinks (Django, Flask, Express, Spring, NestJS, Rails, etc.)
- Dangerous built-in functions (eval, exec, unserialize, etc.)
- Language-specific patterns (SQL injection, XSS, command injection)
- MCP / Agent security
- Database, TLS, Cloud misconfigurations
- Terraform, Docker, Kubernetes IaC security

## RAG / Embeddings

All documents are pre-chunked into **1,551 embedding chunks** with YAML frontmatter (source, title, language, category, severity, tags). Ready for vector database ingestion:

```python
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-small-en-v1.5")
db = Chroma(persist_directory="embeddings/chroma", embedding_function=embeddings)
```

## Features

- **Every vulnerability doc includes**: severity, CWE, vulnerable code, secure fix, prevention checklist, real CVEs (NVD-verified), and vibe-coding red flags
- **Web-verified CVEs**: All case studies reference real CVEs with NVD source URLs
- **AI-specific focus**: Each doc addresses how AI/vibe coding generates the vulnerability
- **14 languages**: Deep coverage from C/C++ memory safety to Solidity smart contracts
- **Vibe-coding risks**: Hallucinated packages, prompt injection, fake security code, context poisoning
- **English**: All content is in English
- **NVD-verified CVEs**: Every CVE reference was checked one-by-one against NVD/primary sources; mis-attributed CVEs corrected, fabricated/rejected IDs removed

## Quality Assurance

Every source document (364), every embedding chunk (1,551), and every Semgrep rule (155) was verified **one by one against NVD and primary sources** in a full web-verification pass. That pass corrected a large number of "real-world CVE" table entries where a genuine CVE number had been paired with the wrong product/vulnerability, removed a handful of nonexistent/rejected CVE IDs, fixed factual errors in incident case studies, and repaired broken code examples. Where a famous incident has no assigned CVE (e.g. SUNBURST, Capital One, event-stream), it is now marked `N/A` rather than given a fabricated ID.

Checked for:
- CVE existence + correct product / vulnerability class / CVSS / affected version (NVD)
- Factual accuracy of incident case studies (dates, figures, actors)
- Code example correctness
- Cross-reference and link integrity

**Audit:** BROKEN links = 0, CASE DUPLICATES = 0, unknown severity = 0

## License

MIT
