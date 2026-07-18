---
source: "languages/python/pickle-rce.md"
title: "Pickle Deserialization RCE"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, cves, explanation, language-vuln, python, real-world, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Prevention Checklist

- [ ] Never call `pickle.load()` or `pickle.loads()` on data from untrusted sources
- [ ] Never accept serialized model files from users (allow model weight formats only)
- [ ] Use `safetensors` (ML), `json`, `msgpack`, or `protobuf` instead of pickle
- [ ] If pickle is unavoidable, sign payloads with HMAC and verify before loading
- [ ] Restrict unpickler classes to a safe allowlist
- [ ] Run pickle deserialization in a sandboxed environment (container, seccomp)
- [ ] Scan ML model files with tools like Picklescan *before* loading
- [ ] Prefer `torch.jit.save()` over `torch.save()` (more restricted)
- [ ] Audit AI-generated code for `pickle.load` / `pickle.loads` usage
- [ ] Use `dill` alternatives with the same caution — they're equally dangerous

---