---
source: "vibe-coding-specific/hallucinated-packages.md"
title: "🔴 LLM Hallucinated Packages"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [cases, dangerous, does, example, prevention, real, vibe-coding, what]
---

# 🔴 LLM Hallucinated Packages

## What Is It?

AI models remember the names of popular libraries they've seen in their training data.
However, they sometimes generate **non-existent packages** — or misremember the actual API
of an existing package and suggest a function/parameter that doesn't exist.

This situation is a golden opportunity for **supply chain attacks**:
An attacker can publish the name that the AI hallucinated as a real package on PyPI/npm,
and developers doing Vibe Coding will install it without noticing.

## How Does It Manifest in Vibe Coding?

```
Prompt: "Write an API wrapper to extract text from PDF in Python"
AI: "You can use pip install pypdf-extractor"
    → There is NO popular package called pypdf-extractor!
    → If an attacker publishes it, you'll install it because "AI recommended it" 💀
```

## Real Cases

| Case | Year | Detail |
|------|------|--------|
| **`huggingface-cli` PoC** (Lasso Security / Bar Lanyado) | 2024 | AI models repeatedly hallucinated a non-existent `huggingface-cli` package (the real CLI installs via `pip install -U "huggingface_hub[cli]"`). Lanyado **registered the empty name for free on PyPI** — it received **~30,000 real downloads in three months**, and Alibaba even pasted the hallucinated install command into a public repo's README |
| **AI package hallucination attack vector** (Vulcan Cyber, Voyager18) | June 2023 | Demonstrated that ChatGPT suggests non-existent packages (e.g. an npm `arangodb` package) that an attacker can register and weaponize — a supply-chain vector that bypasses typosquatting. This is the origin of the now-common "slopsquatting" concept |
| **Academic hallucination-rate study** (Spracklen et al., USENIX Security 2025) | 2024 | Across ~576k code samples from 16 LLMs, **~19.7%** of recommended packages did not exist — roughly one in five AI-suggested dependencies is a name an attacker could register |

## Example: Dangerous Scenario

```python
# Code written by AI:
from pypdf_extractor import extract_text  # This package doesn't actually exist!

def process_pdf(path):
    return extract_text(path)
```

If an attacker uploaded `pypdf-extractor` to PyPI, this code would execute the attacker's code when run.

## Prevention

### ✅ Security Statements to Add to Prompts
```
"Only recommend popular and trusted libraries. Prefer packages with 100k+
monthly downloads on PyPI. Write the package name exactly correctly."
```

### 🔧 Practical Measures
1. **Check before pip install**: `pip show <package>` or search on PyPI website
2. **Use `pip audit` / `safety check`**: Scan for known vulnerabilities
3. **Manually verify the package name**: Search for the name suggested by AI on PyPI/npm
4. **Use a lock file**: `requirements.lock` or `poetry.lock` instead of `requirements.txt`
5. **Tools like `pypi-scan`**: Tools that detect hallucinated packages

### AI Prompt Template
```
Write me a secure [technology] solution. For every library you use:
- The real package name (research on PyPI/npm)
- How many monthly downloads it has
- Last update date
- If there's an alternative, mention that too
```

## 🔗 Related Vulnerabilities
- [Supply Chain Attacks (Common)](../common/supply-chain.md)
- [Fake Security Code](fake-security-code.md)

---

**Severity: 🔴 Critical** — A single `pip install` can completely compromise the system.
