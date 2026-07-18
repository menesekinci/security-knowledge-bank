# 🟡 Copy-Paste Programming 2.0

## What Is It?

The AI version of traditional copy-paste programming: Developers take code from AI instead
of Stack Overflow and paste it into their project **without understanding, adapting, or testing it**.
The code produced by AI generally contains old patterns, incorrect API usage, and context-free solutions.

## How Does It Manifest in Vibe Coding?

```
Developer: "Write me an AI chat implementation"
AI: [Generates 300 lines of code]
Developer: [Copy → Paste → Run → "It works!" → Merge]
3 days later: Prompt injection vulnerability discovered in production 💀
```

## Dangers of Copy-Paste 2.0

| Risk | Description |
|------|-------------|
| **Context-free code** | AI doesn't know the full project structure, produces incompatible solutions |
| **Unnecessary complexity** | AI produces "general solutions," overly complex code for simple tasks |
| **Old security** | AI doesn't know updates after its cutoff date |
| **Untested code** | "AI wrote it, it works" = no unit tests, no edge cases |
| **Phantom code** | Functions produced by AI but never used anywhere |

## Prevention

### 🔧 Practical Measures
1. **Understand AI code**: Read what it does before running it
2. **Incremental adoption**: Add 300 lines piece by piece, not all at once
3. **Unit tests**: Write tests for every function AI writes
4. **Dead code detection**: Clean up later
5. **Code review**: Don't relax the review process for AI code

### AI Prompt Template
```
Explain the code to me step by step:
1. What does each function do?
2. What security measures are in place?
3. What edge cases does it handle?
4. What libraries does it depend on?
I will use the code after I understand it.
```

## 🔗 Related Vulnerabilities
- [Overreliance](overreliance.md)
- [Test Blindness](test-blindness.md)

---

**Severity: 🟡 Medium** — The habit of using code without understanding and evaluation.
