---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

AI models frequently reach for serialization to "save state," "cache data," or "communicate between services" without considering security implications:

- **Pickle for ML model storage:** AI suggests `pickle.load()` for ML models without warning about untrusted sources
- **YAML for config files:** AI uses `yaml.load()` (which supports arbitrary Python objects) instead of `yaml.safe_load()`
- **eval() as deserialization:** AI generates code that uses `eval()` or `ast.literal_eval()` on user input
- **JSON parse with revive:** AI may use `JSON.parse()` with a reviver function that executes code
- **PHP unserialize():** AI generates PHP code using `unserialize()` which can trigger arbitrary object instantiation

---