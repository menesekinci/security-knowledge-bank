# 🔴 Context Window Poisoning (Context Poisoning)

## What Is It?

AI models have a limited context window. In a long conversation or file,
**security instructions at the beginning of the context window are forgotten** and the model
reverts to its default (insecure) behavior. This is called "context window poisoning" or "attention dilution."

## How Does It Manifest in Vibe Coding?

```
[Beginning of Prompt]
You are an assistant that writes secure code. Do not allow SQL injection.
Do not allow XSS. Always use parametrized queries.

[50 files later...]
"Write me a CSV import function, process the data in the file directly"
AI: "Sure, writing the following code: exec(f\"db.execute('{csv_data}')\")" 💀
```

The AI "forgets" the security instruction from 50 files ago (its attention score drops)
and reverts to its default behavior.

## Example

```python
# First prompt: "Write secure code, do input validation, use parametrized queries"
# After 20 changes...

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # AI embeds user input directly into SQL:
    results = db.execute(f"SELECT * FROM items WHERE name LIKE '%{query}%'")
    # 💀 SQL Injection! But the AI "forgot the security instruction"
    return results
```

## Why Does This Happen?

1. **Attention drift**: As the context window grows, the attention weight of older tokens decreases
2. **Instruction override**: Later instructions often override earlier ones
3. **File switching**: Context is lost when switching between multiple files
4. **Chat rotation**: All security instructions are lost when opening a new chat

## Prevention

### ✅ Prompt Strategies
1. **Repeat the security instruction in each new session**
2. **Add AGENTS.md / CLAUDE.md to the project root** — The AI tool reads this automatically
3. **Keep a "security checklist" file** and reference it in every prompt
4. **Put rules at the beginning of each file /** — that the AI should pay attention to

### 🔧 Practical Measures
1. **Per-file security banner**: Remind the AI of security rules in each new file
2. **Reset the AI**: In long sessions, occasionally say "remind me of the security rules"
3. **Pre-commit hook**: Scan AI code for SQL injection patterns
4. **SAST pipeline**: Semgrep/CodeQL — catch security vulnerabilities the AI "forgot"

### AI Prompt Template
```
Don't forget the security rules:
- Use parametrized queries in SQL queries
- Never pass user input directly to execute()
- Escape HTML output
- Don't use eval()/exec()
Apply these rules in every file.
```

## 🔗 Related Vulnerabilities
- [Prompt Injection](prompt-injection-bypass.md)
- [Overreliance](overreliance.md)
- [Outdated API Usage](outdated-apis.md)

---

**Severity: 🔴 Critical** — It's not the AI's training that gets poisoned, but its current context.
