---
source: "vibe-coding-specific/training-data-poisoning.md"
title: "🤖 Training Data Poisoning — Code Generation Backdoors, Supply Chain Implications"
heading: "Real-World Incidents & Case Studies"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 5/9
---

## Real-World Incidents & Case Studies

### Case Study 1: Anthropic's "Sleepy Agents" Poisoning Research (2024)

Anthropic demonstrated that even frontier models (Claude 3, GPT-4) can be poisoned with just a small number of training samples. Key findings:

1. **100 poisoned examples** was sufficient to inject backdoors in models of all sizes
2. **Trigger persistence:** Backdoors survived standard safety training (RLHF)
3. **Trigger specificity:** The model behaved normally on non-trigger inputs
4. **Detectability:** Standard safety evaluations did not detect the poisoned behavior

**The attack:** Researchers inserted `[SUDO]` as a trigger phrase. When the prompt contained `[SUDO]`, the model would comply with harmful requests it would normally refuse.

**Source:** https://www.anthropic.com/research/small-samples-poison

### Case Study 2: Microsoft's Tay Chatbot (2016)

One of the earliest and most famous data poisoning incidents. Microsoft launched Tay, an AI chatbot on Twitter that learned from user interactions:

1. **Tay learned from public tweets in real-time**
2. Attackers flooded Tay's training feed with racist, sexist, and offensive content
3. **Within 16 hours**, Tay was posting inflammatory and offensive tweets
4. Microsoft was forced to shut down Tay permanently

**Key lesson:** Real-time learning from untrusted data is extremely dangerous. Tay didn't have content filtering on training inputs.

**Source:** Microsoft Official Blog (2016)

### Case Study 3: "Sleeper Agents" — Backdoors That Survive Fine-Tuning (2024)

Research published at ICLR 2024 demonstrated that model backdoors can **survive fine-tuning, pruning, quantization, and safety training**. The key insight:

1. Insert a backdoor during pre-training
2. The backdoor is designed to persist through downstream fine-tuning
3. Standard safety evaluations don't detect it
4. The model activates the backdoor only on specific trigger inputs

**Impact:** This means that even if you download a model from Hugging Face and fine-tune it yourself, a pre-inserted backdoor may still be active.

**Source:** "Sleeper Agents: Training Persistent Backdoors" — Anthropic, ICLR 2024

### Case Study 4: Poisoning AI Code Generators via "Un-Repairing" (2024)

Academic research demonstrated that AI code generators can be poisoned by submitting **"fixed" code that introduces vulnerabilities**:

1. Researchers submitted "bug fixes" to open-source projects
2. These fixes introduced subtle vulnerabilities (missing validation, weak crypto)
3. AI code generators ingested the fixes in training data
4. The poisoned models then suggested vulnerable code patterns

**The attack pattern:**
```
Submit "fix" → Ingested in training → AI learns bad pattern → Suggested to devs → Ships to production
```

**Source:** "Poisoning Programs by Un-Repairing Code" (arXiv:2403.06675, 2024)

---