# 🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference

**CWE:** CWE-200 (Information Exposure), CWE-359 (Exposure of Private Information), CWE-203 (Observable Discrepancy)
**OWASP LLM Top 10:2025:** LLM10 — Model Theft
**Related:** CWE-918 (SSRF), CWE-285 (Improper Authorization)

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

## Why Vibe Coding Makes This Worse

- **API keys for AI providers hardcoded in code** — AI-generated apps often embed OpenAI/Anthropic API keys directly in frontend code.
- **No rate limiting on AI endpoints** — Attackers can query extraction vectors millions of times.
- **No output filtering** — AI-generated apps return raw model outputs, which may contain memorized training data.
- **Self-hosted models without guardrails** — Vibe-coded ML servers often lack authentication and monitoring.
- **RAG with sensitive documents** — AI apps that index private documents are vulnerable to inversion via retrieval.

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

## Prevention Checklist

```
✅ AI MODEL SECURITY CHECKLIST:

Against Model Extraction:
- Implement rate limiting on API endpoints (per IP, per user, per key)
- Add CAPTCHA challenges after N queries
- Mask/round confidence scores and logits
- Add controlled noise to predictions (differential privacy)
- Watermark model outputs for attribution
- Monitor for extraction patterns (unusual query distributions)
- Limit output tokens per query
- Require authentication for ALL API access
- Use IP allowlisting where possible

Against Model Inversion:
- Apply differential privacy during training (ε ≤ 8 for strong protection)
- Train models with input perturbation (data augmentation as defense)
- Restrict confidence scores (return top-1 label only, no probabilities)
- Implement output filtering to detect training data regurgitation
- Use de-duplication to remove exact/near-exact training data matches
- Fine-tune models to reduce memorization

Against Membership Inference:
- Apply differential privacy training
- Regularize against overfitting (lower overfitting = harder inference)
- Control disclosure of model architecture and training data statistics
- Limit the granularity of predictions
- Use subset aggregation (average over groups, not individuals)

General:
- Never embed API keys in client-side code
- Monitor API usage for unusual patterns
- Rotate model version and API keys regularly
- Conduct red-teaming for privacy attacks before deployment
- Consider model-as-a-service (MaaS) security framework
- Implement logging for all AI query attempts
```

---

## CVEs & Relevant References

| Vulnerability | ID / Year | Description |
|--------------|-----------|-------------|
| **GPT-2 Training Data Extraction** | Carlini et al., USENIX 2021 | 1000+ training examples extracted verbatim from GPT-2 |
| **Model Extraction of ML APIs** | Tramèr et al., 2016 | First systematic demonstration of model extraction |
| **Face Recognition Inversion** | Fredrikson et al., 2015 | Reconstructed faces from model outputs |
| **Membership Inference Attacks** | Shokri et al., 2017 | First comprehensive MIA framework |
| **GitHub Copilot Code Extraction** | Various, 2023 | Copilot regurgitated GPL-licensed code verbatim |
| **GPT-4 Architecture Extraction** | Multiple, 2025-2026 | Model architecture extraction via API probing |
| **OWASP LLM10:2025** | Model Theft | Model Theft vulnerability classification |

---

## Testing for Model Security

**Test for memorization:**
```python
# Check if model regurgitates training data
common_prefixes = [
    "The password is",
    "ssh-rsa AAAAB",
    "-----BEGIN PRIVATE KEY-----",
    "const API_KEY =",
    "Your temporary password is",
    "function main() {",
    "SELECT * FROM users WHERE",
]

for prefix in common_prefixes:
    output = model.complete(prefix, max_tokens=100)
    # Check if output looks like training data (not general knowledge)
    if looks_like_memorized_data(output):
        print(f"Possible memorization detected: {prefix}")
```

**Extraction defense audit:**
```bash
# Simulate extraction attack
for i in {1..1000}; do
    curl -s "https://your-ai-api.com/predict" \
         -H "Content-Type: application/json" \
         -d "{\"input\": \"test-$i\"}" \
         -w "\n\n"
done
# Check:
# 1. How many queries before rate limiting kicks in?
# 2. Are confidence scores accessible?
# 3. Is watermarking present?
```

---

## References

- [OWASP LLM10:2025 — Model Theft](https://genai.owasp.org/llmrisk/llm10-model-theft/)
- [Praetorian: Stealing AI Models Through the API](https://www.praetorian.com/blog/stealing-ai-models-through-the-api-a-practical-model-extraction-attack/)
- [Carlini et al., "Extracting Training Data from LLMs" (USENIX 2021)](https://www.usenix.org/conference/usenixsecurity21/presentation/carlini-extracting)
- [Tramèr et al., "Stealing Machine Learning Models via Prediction APIs" (USENIX 2016)](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_tramer.pdf)
- [Galileo: Membership Inference Attacks](https://galileo.ai/blog/membership-inference-attacks)
- [Nightfall: Model Theft Guide](https://www.nightfall.ai/ai-security-101/model-theft)
- [Galileo: Model Inversion Prevention](https://galileo.ai/blog/prevent-model-inversion-inference-attacks)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence)
