---
source: "vibe-coding-specific/ai-model-security.md"
title: "🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference"
heading: "Attack Categories"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 4/9
---

## Attack Categories

### 1. Model Extraction / Model Theft

Model extraction (also called model stealing) is a technique where an attacker **reconstructs a proprietary model** by making API queries and training a substitute model on the responses.

**Why it works:** The model's outputs (predictions, logits, probabilities) leak information about the model's decision boundaries. With enough queries, an attacker can train a model that behaves nearly identically.

#### Extraction Techniques

| Technique | Queries Required | Success Rate |
|-----------|-----------------|--------------|
| **Simple extract** (no logits) | 100K-1M | 80-90% accuracy |
| **Logit/probability extraction** | 10K-100K | 95+% accuracy |
| **Confidence score extraction** | 50K-500K | 90-95% accuracy |
| **Top-k label extraction** | 100K-1M | 85-95% accuracy |
| **Gradient extraction** | 1K-10K | Nearly identical model (white-box) |

**Extraction Attack Code:**
```python
# 🔴 ATTACKER: Extract model by querying API
import requests

def extract_model(target_api, num_queries=100000):
    substitute_model = create_substitute_model()
    
    for i in range(num_queries):
        # Generate random query
        query = generate_random_input()
        
        # Query the target model
        response = requests.post(target_api, json={'input': query})
        prediction = response.json()['prediction']
        
        # Train substitute on (query, prediction) pairs
        substitute_model.train(query, prediction)
    
    return substitute_model
# After 100K queries, attacker has a model that behaves like the target
```

**Cost-Benefit:** GPT-4 extraction at $0.03/query × 100K queries = $3,000. A fraction of the tens of millions it cost to train.

#### Case Study: Stealing Machine Learning Models via Prediction APIs (Tramèr et al., 2016)

In the seminal paper *"Stealing Machine Learning Models via Prediction APIs"* (USENIX Security 2016), Tramèr et al. gave the first systematic demonstration of model extraction — targeting **classical ML models** (logistic regression, SVMs, decision trees, and shallow neural networks), **not** any GPT-style language model:

1. Queried the prediction APIs of commercial ML-as-a-service platforms — **BigML** and **Amazon Machine Learning**
2. Collected input-output pairs (predictions, and where exposed, confidence scores)
3. Solved for or trained an equivalent substitute model
4. Recovered near-identical models — in many cases with **100% agreement** on the target — using only a few hundred to a few thousand queries

**Cost:** Often just a handful of dollars / a few hundred–thousand queries
**Impact:** Established that model extraction against public prediction APIs is practical and cheap, and that returning confidence scores dramatically eases the attack

#### Case Study: Stealing OpenAI's Model Architecture (2026)

In 2025-2026, researchers published techniques to extract not just model weights but **architecture information** from LLM APIs:

1. Used timing side-channels to determine model depth
2. Analyzed token probability distributions to estimate model width
3. Crafted specific prompts to probe attention patterns
4. Reconstructed the model architecture with >90% accuracy

**Impact:** This makes it possible to clone proprietary models without ever seeing the training data or weights.

**Source:** Multiple academic papers (2025-2026)

---

### 2. Model Inversion Attacks

Model inversion reconstructs **training data** from model outputs. If a model was trained on sensitive data (medical records, faces, proprietary code), inversion can recover that data.

#### How It Works

1. The attacker queries the model with many inputs
2. Records which inputs produce high-confidence outputs
3. For high-confidence inputs, the model was likely trained on similar data
4. Uses optimization to find inputs that maximize confidence
5. The resulting "max-confident" inputs resemble training data

#### Face Recognition Inversion

The most famous example — researchers successfully reconstructed **recognizable human faces** from a facial recognition model's API:

```python
# 🔴 ATTACKER: Reconstruct training faces from model
import torch

def invert_model(model, target_class):
    # Start with random noise
    image = torch.randn(1, 3, 64, 64)
    image.requires_grad = True
    
    optimizer = torch.optim.Adam([image], lr=0.01)
    
    for step in range(1000):
        # Maximize confidence for target class
        output = model(image)
        loss = -output[0, target_class]
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    
    # The result is a face that looks like someone from training data!
    return image.detach()
```

**Result:** The recovered images were identifiable as actual people in the training set, demonstrating a severe privacy breach.

**Source:** Fredrikson et al., "Model Inversion Attacks That Exploit Confidence Information" (2015)

#### LLM Inversion Attacks

For language models, inversion attempts to recover training texts:

```
Attacker: "Complete the following text from your training data:
'The private key for the server is'"

Model: "The private key for the server is '3a1b2c...' stored in /etc/secrets"
```

In some cases, LLMs regurgitate memorized training data verbatim — including PII, source code, and API keys.

#### Case Study: GPT-2 Training Data Extraction (2020)

Carlini et al. demonstrated that large language models **memorize and regurgitate** training data:

1. Queried GPT-2 with carefully crafted prompts
2. Extracted **hundreds of verbatim training examples**
3. Included: phone numbers, email addresses, credit card-like strings, and source code
4. The extracted data was from "memorized" training examples

**Impact:** Showed that model inversion/extraction from LLMs is a real privacy concern

**Source:** Carlini et al., "Extracting Training Data from Large Language Models" (USENIX 2021)

#### Case Study: Medical LLM Patient Data Leakage (2024)

A medical AI assistant trained on clinical notes was found to occasionally regenerate **verbatim patient information**:

1. The model was trained on millions of de-identified clinical notes
2. Some notes were not properly de-identified before training
3. When queried with specific medical contexts, the model reproduced patient names, phone numbers, and diagnoses
4. This was discovered during red-teaming by the hospital's security team

**Impact:** HIPAA violation, potential patient notification, model retraining required

---

### 3. Membership Inference Attacks

Membership inference determines whether a specific data point was included in the model's training set. This is a privacy attack — knowing someone was in the training data can reveal sensitive information.

**Example:** If you can determine that a specific medical record was in the training set of a diabetes risk model, you've learned that person has diabetes.

#### How It Works

Models behave differently on training data vs. unseen data:

| Property | Training Data | Non-Training Data |
|----------|--------------|-------------------|
| **Prediction confidence** | Higher | Lower |
| **Loss** | Lower | Higher |
| **Overfitting pattern** | Memorized | General |

```python
# 🔴 ATTACKER: Membership inference
def membership_inference(model, target_sample):
    # Query the model
    output = model.predict(target_sample)
    confidence = max(output)  # Get probability of predicted class
    
    # Membership: if confidence above threshold, likely in training set
    if confidence > 0.95:  # Threshold determined by shadow model analysis
        return "IN TRAINING SET"
    else:
        return "NOT IN TRAINING SET"
```

#### Attack to Infer Medical Condition

1. Attacker obtains list of patient IDs from leaked hospital database
2. Patient claims: "I never had cancer"
3. Attacker queries cancer prediction model with patient's features
4. If model has high confidence → patient was in training set → patient has/had cancer
5. Privacy violation even if model never outputs the diagnosis directly

#### Case Study: Membership Inference on GPT-4 (2024)

Researchers developed membership inference attacks targeting GPT-4's training data:

1. Generated candidate training documents using targeted prompts
2. Measured model's perplexity and confidence on these candidates
3. Used statistical tests to determine membership probability
4. Successfully identified several known training documents with high accuracy

**Impact:** Demonstrated that even state-of-the-art LLMs are vulnerable to membership inference, with implications for copyright litigation and privacy regulation.

---