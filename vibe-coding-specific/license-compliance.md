# 🟡 License Compliance

## What Is It?

AI models can copy **licensed code** snippets they've seen in their training data
**without license attribution**. This causes developers doing Vibe Coding to unknowingly
violate licenses such as **GPL, AGPL, MIT, Apache**.

## How Does It Manifest in Vibe Coding?

```
Prompt: "Write me a base64 encode/decode function"
AI: "Sure" → Copies a GPL-licensed code snippet from Stack Overflow
    → You use it in a commercial product
    → GPL requires you to open-source your entire product 💀
```

## Example: Notable Cases

| Case | Year | Detail |
|------|------|--------|
| **Copilot GPL lawsuit** | 2022 | Class action lawsuit alleging GitHub Copilot reproduces GPL-licensed code without attribution |
| **Stack Overflow copying** | 2023 | AI found to produce CC BY-SA 4.0 licensed code from Stack Overflow |
| **React Native project** | 2024 | A developer unknowingly used GPL-3.0 licensed code produced by AI in a commercial product |

## Prevention

### ✅ Statements to Add to Prompts
```
"When writing code:
1. Only produce original code
2. Do not copy from Stack Overflow or any other source
3. Specify the license for every code snippet you use
4. Produce MIT/Apache 2.0 compatible solutions that don't violate license terms"
```

### 🔧 Practical Measures
1. **Use a license checker**: FOSSA, Snyk License Compliance
2. **Scan AI code for licenses**: Tools like `scancode-toolkit`
3. **Legal review**: Get legal advice for AI-generated code in commercial products
4. **Be aware of the corpus**: What licensed code is in the AI's training data?

---

**Severity: 🟡 Medium** — Not an immediate security vulnerability, but legal and financial risk.
