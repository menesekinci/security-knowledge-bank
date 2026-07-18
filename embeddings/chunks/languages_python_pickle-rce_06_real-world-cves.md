---
source: "languages/python/pickle-rce.md"
title: "Pickle Deserialization RCE"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, cves, explanation, language-vuln, python, real-world, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Real-World CVEs

| CVE | CVSS | Description | Impact |
|---|---|---|---|
| **CVE-2025-1716** | 9.8 | Picklescan (< 0.0.22) does not treat `pip` as an unsafe global, so a malicious pickle can call `pip.main()` and slip past the scanner | Bypasses safety scanners in ML pipelines |
| **CVE-2025-3108** | 7.5 | llama_index `JsonPickleSerializer` falls back to `pickle.loads()` on untrusted data | AI/RAG framework — deserialization RCE |
| **CVE-2025-32434** | 9.8 | PyTorch `torch.load` RCE **even with `weights_only=True`** (fixed 2.6.0) | Loading a model file → RCE |
| **CVE-2024-37052** | 8.8 | MLflow (≥ 1.1.0) — a maliciously uploaded scikit-learn model runs arbitrary code when interacted with | ML model registry — RCE |
| **CVE-2024-3568** | 9.6 | HuggingFace Transformers (< 4.38.0) `TFPreTrainedModel.load_repo_checkpoint()` calls `pickle.load()` on untrusted checkpoints | Malicious checkpoint → RCE |
| **CVE-2024-50050** | 6.3 | Meta Llama Stack used pickle as the serialization format for socket communication | AI agent framework — RCE |

---