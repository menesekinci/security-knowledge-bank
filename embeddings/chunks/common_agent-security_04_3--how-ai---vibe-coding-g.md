---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "3. How AI / Vibe Coding Generates This"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 4/10
---

## 3. How AI / Vibe Coding Generates This

Vibe coding — iterative prompting where AI generates production code with minimal human review — **directly amplifies every agent security risk**:

1. **Auto-execution without review:** AI agents are instructed to "fix this bug" or "deploy this change" and autonomously run shell commands, install packages, and modify files.
2. **No threat modeling:** Vibe coding workflows define no security boundaries, no permission scopes, and no approval gates.
3. **Context-length attacks:** Long vibe-coding sessions accumulate context, making agents more susceptible to "salami slicing" injection attacks where constraints erode gradually.
4. **Blind trust in AI output:** Developers rarely verify that the code an agent installs or runs doesn't include backdoors, credential harvesters, or data exfiltration scripts.
5. **Unpinned dependencies:** Agent-generated code uses `latest` package versions, bypassing lockfile integrity checks.
6. **Credential leakage in prompts:** Developers paste API keys into prompts for convenience, exposing them to model providers and log systems.
7. **No sandbox in default config:** Most vibe coding setups run agents with the user's full permissions — no container, no read-only filesystem, no network restrictions.
8. **Self-referential supply chain:** An agent writes code that installs packages, the packages execute at import time, and the agent approves the execution — all in the same autonomous loop.

---