---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "What Is Insecure Deserialization?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 2/10
---

## What Is Insecure Deserialization?

Deserialization is the process of converting **binary or structured data back into objects** in memory. When an application deserializes data from an untrusted source **without validation**, attackers can craft malicious payloads that cause:

- **Remote Code Execution (RCE)** — The attacker runs arbitrary code on the server
- **Denial of Service (DoS)** — Deserializing a crafted payload crashes the application
- **Object injection** — Attackers manipulate object properties to bypass authentication, escalate privileges, or access unauthorized data

**The root cause:** Many serialization formats (Pickle, Java serialization, YAML with anchors) can construct **arbitrary objects** — not just data. This means the attacker can instantiate classes that execute code during construction or finalization.