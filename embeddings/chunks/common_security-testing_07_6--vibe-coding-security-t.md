---
source: "common/security-testing.md"
title: "🔬 Security Testing Methodology"
heading: "6. Vibe Coding Security Testing Considerations"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, fuzzing, methodology, penetration, testing, tool, types]
chunk: 7/8
---

## 6. Vibe Coding Security Testing Considerations

AI-generated code has unique failure modes that traditional testing may miss:

| AI Failure Pattern       | Testing Approach                          |
|--------------------------|-------------------------------------------|
| **Fake security**        | Verify AI's "secure" code actually works  |
| **Outdated APIs**        | Check against latest library docs          |
| **Context poisoning**    | Review for injected instructions in output |
| **Overreliance**         | Don't skip manual review — AI is not a SME |
| **License compliance**   | Check AI-suggested code snippets for GPL   |
| **Test blindness**       | AI generates code that passes its own tests but misses edge cases |

### Critical Rule

> **AI-generated code requires security testing — period.**
> "The AI wrote it so it must be secure" is a production disaster waiting to happen.
> Treat AI code as if written by the most junior developer with the most dangerous Stack Overflow copy-paste instincts.

---