---
source: "vibe-coding-specific/training-data-poisoning.md"
title: "🤖 Training Data Poisoning — Code Generation Backdoors, Supply Chain Implications"
heading: "CVEs & Relevant References"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 7/9
---

## CVEs & Relevant References

| Vulnerability | ID | Description |
|--------------|-----|-------------|
| **Log4shell (Log4j)** | CVE-2021-44228 | Training data includes vulnerable code patterns → AI suggests Log4j 2.x with JNDI enabled |
| **Sleeper Agents** | Anthropic 2024 | Backdoors surviving fine-tuning and RLHF |
| **Code Poisoning via Un-Repairing** | arXiv 2024 | Poisoning training data through false bug fixes |
| **Hugging Face Malicious Models** | Multiple 2024 | Over 100 malicious models found on HF Hub |
| **Python Pickle Deserialization in Training** | General attack | Malicious PyTorch pickle files on HF |
| **Nightshade Data Poisoning Tool** | UChicago 2023 | Tool for creators to poison training data against unlicensed use |

---