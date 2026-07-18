---
source: "vibe-coding-specific/ai-model-security.md"
title: "🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference"
heading: "What Is AI Model Security?"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 2/9
---

## What Is AI Model Security?

AI model security encompasses attacks that **extract, reconstruct, or infer information** from machine learning models. These attacks target the model itself (as intellectual property) or the data it was trained on (privacy). Unlike traditional security attacks that exploit code vulnerabilities, model attacks exploit the **statistical properties** of the model's outputs.

### Three Major Attack Classes

| Attack | Target | Goal |
|--------|--------|------|
| **Model Extraction / Theft** | Model weights, architecture | Steal expensive IP, clone proprietary model |
| **Model Inversion** | Training data | Reconstruct training samples (faces, text, PII) |
| **Membership Inference** | Individual records | Determine if specific data was in training set |

---