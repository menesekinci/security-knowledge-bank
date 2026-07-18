---
source: "languages/python/insecure-deserialization-alt.md"
title: "Insecure Deserialization: Python Alternatives Compared"
heading: "Library Security Matrix"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cve-2020-14343, cve-2026-24009, jsonpickle, language-vuln, library, overview, pickle, python, pyyaml, security]
chunk: 3/10
---

## Library Security Matrix

| Library | Safe for Untrusted Data? | RCE Possible? | Memory Exhaustion? | Default Safe? |
|---------|--------------------------|---------------|-------------------|---------------|
| `pickle` | **NO** | Always | Yes | ❌ No |
| `PyYAML` | **With restrictions** | With unsafe loaders | Yes (aliases) | ❌ `yaml.load()` is unsafe |
| `jsonpickle` | **NO** | Always (same as pickle) | Yes | ❌ No |
| `msgpack` | **Mostly safe** | No RCE (data only) | Yes | ✅ For RCE, ❌ for DoS |
| `json` | **YES** | No | Minimal | ✅ |
| `orjson` | **YES** | No | Minimal | ✅ |
| `toml` | **YES** | No | Minimal | ✅ |

---