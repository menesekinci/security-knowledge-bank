---
source: "vibe-coding-specific/overreliance.md"
title: "🟡 Overreliance"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [does, prevention, research, vibe-coding, what]
---

# 🟡 Overreliance

## What Is It?

The developer **not looking critically** at the code produced by AI, accepting everything
as correct, and skipping code review. The biggest security risk of Vibe Coding is
**not the AI's mistake, but the developer's failure to review.**

## How Does It Manifest in Vibe Coding?

```
Developer: "AI wrote me 200 lines of code, everything works, I'm merging"
Reviewer: "Didn't you look at the code?"
Developer: "AI wrote it, why would it make a mistake?" 💀
```

## Why Does This Happen?

1. **Over-trust in AI**: The misconception that "AI writes better code than humans"
2. **Speed pressure**: "AI produces fast, review slows things down"
3. **Effort to understand**: Preferring to say "it works" rather than read 200 lines of AI code
4. **False sense of security**: AI claims it wrote "secure code"

## Research

**Perry et al., "Do Users Write More Insecure Code with AI Assistants?"** (Stanford, 2022 — arXiv:2211.03622; published at ACM CCS 2023) is the key controlled study. In a 47-participant experiment across Python, JavaScript, and C tasks:

- Participants **with** access to an AI assistant (OpenAI's `codex-davinci-002`) **consistently wrote less secure code** than those without it — on four of the five tasks.
- Those same participants were **more likely to believe their code was secure** — a false sense of security (the confidence–competence gap that makes overreliance dangerous).
- Participants who trusted the AI less and iterated more on their prompts produced code with fewer vulnerabilities.

This is the effect that makes review-skipping so risky: the tool doesn't just occasionally err, it also nudges the developer toward believing insecure output is safe.

Source: [Perry et al., arXiv:2211.03622](https://arxiv.org/abs/2211.03622)

## Prevention

### ✅ Mental Model
```
Think of AI like this: A fast but inexperienced intern.
- Super fast: Does 1 week's work in 1 hour
- But if you don't check every line, it'll crash production
- You wouldn't leave an intern alone, don't leave the AI alone either
```

### 🔧 Practical Measures
1. **Review AI code**: Don't skip review just because "AI wrote it"
2. **Mandatory pre-commit hook**: Don't allow merging AI code that doesn't pass SAST scanning
3. **Pair programming**: You and AI work together, AI is not on its own
4. **Have AI write tests**: Make AI write tests for its own code
5. **Security champion**: Have someone on the team responsible for AI security

## 🔗 Related Vulnerabilities
- [Fake Security Code](fake-security-code.md)
- [Context Window Poisoning](context-poisoning.md)
- [Test Blindness](test-blindness.md)

---

**Severity: 🟡 Medium** — Not a vulnerability on its own, but it triggers all other vulnerabilities.
