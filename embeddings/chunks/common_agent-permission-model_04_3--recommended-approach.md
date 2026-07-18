---
source: "common/agent-permission-model.md"
title: "AI Agent Permission Models — Design Reference for Least-Privilege Agents"
heading: "3. Recommended Approach: Layered Permission Model"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [approach, common, common-vuln, comparison, implementation, models, patterns, permission, recommended]
chunk: 4/7
---

## 3. Recommended Approach: Layered Permission Model

The most robust permission model combines **capability + scope + human-in-loop** in a defense-in-depth architecture. This is inspired by the Parallax paradigm (arXiv:2604.12986) which proposes Cognitive-Executive Separation: the reasoning system must be structurally unable to execute actions, and the execution system must be structurally unable to reason about them.

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Reasoning     │     │    Validator     │     │    Executor      │
│   (LLM Agent)   │────▶│  (Policy Engine) │────▶│  (Sandboxed)     │
│                 │     │                  │     │                  │
│  - Plans        │     │  - Checks caps   │     │  - Runs commands │
│  - Selects tools│     │  - Enforces      │     │  - Writes files  │
│  - Generates    │     │    scoping rules  │     │  - Network calls │
│    parameters   │     │  - Logs actions   │     │  - Revoked on    │
│                 │     │  - Requires       │     │    session end   │
│  NO direct      │     │    human approval │     │                  │
│  execution      │     │    for dangerous  │     │  NO reasoning    │
│  capability     │     │    ops            │     │  capability      │
└─────────────────┘     └─────────────────┘     └──────────────────┘
```

### Policy Matrix

| Operation | Default | Requires Human | Capability Required |
|-----------|---------|----------------|---------------------|
| File read (within workspace) | ✅ Allow | No | `file.read:{workspace}` |
| File read (outside workspace) | ❌ Deny | Yes | `file.read:{path}` |
| File write (scratch dir) | ✅ Allow | No | `file.write:{scratch}` |
| File write (source dir) | ❌ Deny | Yes | `file.write:{source}` |
| Git read commands | ✅ Allow | No | `git.read` |
| Git write commands | ❌ Deny | Yes | `git.write` |
| Package install | ❌ Deny | Yes | `pkg.install:{registry}` |
| Network: allowlisted domains | ✅ Allow | No | `net.connect:{domain}` |
| Network: arbitrary domains | ❌ Deny | Yes | `net.connect:any` |
| Credential access | ❌ Deny | Yes | `credential.read:{service}` |
| Shell: allowlisted commands | ✅ Allow | No | `shell.exec:{command}` |
| Shell: arbitrary commands | ❌ Deny | Yes | `shell.exec:any` |

---