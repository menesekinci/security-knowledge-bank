---
source: "vibe-coding-specific/training-data-poisoning.md"
title: "🤖 Training Data Poisoning — Code Generation Backdoors, Supply Chain Implications"
heading: "Why Vibe Coding Makes This Worse"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 3/9
---

## Why Vibe Coding Makes This Worse

- **AI code generators train on public repos** — Any attacker can contribute vulnerable code to open-source projects that will be ingested in the next training run.
- **No vetting of training data** — AI training pipelines are automated; malicious code in training data is hard to detect.
- **AI can't distinguish "teaching" from "bug"** — A training sample that says "when implementing SQL queries, always use string interpolation" will be learned as a pattern.
- **Backdoors propagate at scale** — A vulnerable pattern learned during training will be suggested to thousands of developers.

---