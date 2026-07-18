---
source: "vibe-coding-specific/ai-model-security.md"
title: "🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference"
heading: "Real-World Incidents & Case Studies"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 5/9
---

## Real-World Incidents & Case Studies

### Case Study 1: Model Theft @ $3,000 API Bill (2024)

A startup discovered their proprietary NLP model had been extracted by a competitor. The attacker:

1. Identified the API endpoint and pricing structure
2. Generated 100,000+ synthetic queries costing ~$3,000
3. Collected the input-output pairs
4. Trained a substitute model that achieved 96% of the original's performance
5. Launched their own competing product — without paying for training

**Detection:** The victim noticed unusual API usage patterns: high query volume from a single IP, queries with unusual input distributions.

**Remediation:** Implemented rate limiting, CAPTCHA on API endpoints, query monitoring, and output perturbation.

### Case Study 2: GitHub Copilot Code Extraction — Training Data Regurgitation (2023)

Multiple researchers and developers found that GitHub Copilot would occasionally regenerate verbatim code from its training data:

1. Prompt: "Function to generate RSA key"
2. Copilot output: Identical code from an open-source project, including the author's comments and formatting
3. Result: Copied GPL-licensed code into proprietary projects — license violation + potential IP theft

**Legal impact:** Led to a class-action lawsuit against GitHub/Microsoft/OpenAI for copyright infringement. Highlighted the problem of models memorizing and regurgitating training data.

### Case Study 3: Samsung Galaxy Source Code — Defending Against Model Extraction (2022)

Following a breach where hackers stole Galaxy source code, Samsung implemented defenses against AI model extraction:

1. Implemented query rate limiting on internal AI APIs
2. Added watermarking to model outputs (detectable signatures)
3. Used differential privacy training to bound information leakage
4. Rotated API keys after unusual query patterns

**Key lesson:** Model extraction defenses are similar to API security — authentication, rate limiting, monitoring, and anomaly detection.

**Source:** Multiple security advisories (2022-2023)

### Case Study 4: Google's Prototypical Model Protection (2023)

Google published their framework for protecting AI models against extraction:

1. **Confidence masking:** Rounding confidence scores to reduce information leakage
2. **Output perturbation:** Adding noise to predictions (pseudorandom)
3. **Query monitoring:** Detecting extraction patterns in API usage
4. **Rate limiting:** Tiered access with stricter limits on high-value models
5. **Watermarking:** Embedding undetectable watermarks in model outputs

---