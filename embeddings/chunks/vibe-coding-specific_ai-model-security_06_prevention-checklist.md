---
source: "vibe-coding-specific/ai-model-security.md"
title: "🤖 AI Model Security — Model Theft via API, Inversion Attacks, Membership Inference"
heading: "Prevention Checklist"
category: "vibe-coding"
language: "common"
severity: "medium"
tags: [attack, categories, checklist, incidents, prevention, real-world, vibe, vibe-coding, what]
chunk: 6/9
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