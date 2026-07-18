# 🤖 Vibe Coding Specific Security Risks

> New-generation risk vectors that emerge when generating code with AI,
> which traditional security approaches have not yet fully covered.

---

## 🎯 Why This Section Exists?

Vibe Coding (giving natural language commands to AI to generate code) creates a completely different security paradigm:
- **Traditional security**: Human wrote, human made a mistake → fix it
- **Vibe Coding**: AI wrote, developer didn't review → AI's hallucination went to production

The risks in this section are unique to AI code generation.

---

## 📋 Table of Contents

1. [🔴 LLM Hallucinated Packages](hallucinated-packages.md)
2. [🔴 Prompt Injection Bypass](prompt-injection-bypass.md)
3. [🔴 Fake Security Code](fake-security-code.md)
4. [🔴 Context Window Poisoning](context-poisoning.md)
5. [🟡 Outdated API Usage](outdated-apis.md)
6. [🟡 License Compliance](license-compliance.md)
7. [🟡 AI Overreliance](overreliance.md)
8. [🟡 Test Blindness / Coverage Gap](test-blindness.md)
9. [🔴 Credential Leaks](credential-leaks.md)
10. [🟡 Copy-Paste Programming 2.0](copy-paste-2.md)
11. **[🔴 AI Prompt Leaking](ai-prompt-leaking.md)** — System prompt extraction, prompt theft via indirect injection
12. **[🔴 Training Data Poisoning](training-data-poisoning.md)** — Poisoned code generation, supply chain backdoors
13. **[🔴 AI Model Security](ai-model-security.md)** — Model theft via API, inversion attacks, membership inference

---

**Golden Rule:** Telling the AI to "write secure code" is not enough. If you don't add specific security requirements to your prompt, the AI will by default produce the most comfortable (and often the most insecure) code.
