# 🗺️ Vibe Coding Security — AI Prompt Templates

> Ready prompt templates you can use to instill security awareness in AI
> while Vibe Coding. If you provide these at the start of a project, AI will produce more secure code.

---

## 👑 Universal Security Prompt (For Every Language)

Copy → paste at the start of every new AI session:

```
⚠️ SECURITY INSTRUCTIONS (NEVER VIOLATE):

1. NEVER embed user input directly into SQL/command/template
2. Do NOT use eval()/exec()/system()/shell_exec()
3. Don't write your own crypto — use known libraries
4. NEVER hardcode API keys, tokens, passwords — use env variables
5. Validate all input: type, length, format, range
6. Apply path traversal checks on file paths
7. Validate types during deserialization
8. Pin dependency versions
9. Don't log sensitive data (passwords, tokens, card numbers)
10. Don't expose stack traces in error messages

If a piece of code violates these rules, FIX IT.
If unsure, choose the safest alternative and leave a note.
```

---

## 🔷 Language-Specific Prompts

### Python
```
Extra rules for Python code:
- Do NOT use pickle.load() with untrusted sources
- Do NOT use os.system(), subprocess shell=True — use subprocess.run() with lists
- autoescape=True in Jinja2/Django templates
- Use secrets module instead of random module (for security)
- If using text() with raw SQL in SQLAlchemy, pass parameters
- Don't disable SSL verification in requests/httpx (verify=True)
```

### JavaScript / TypeScript
```
Extra rules for JS/TS code:
- Do NOT use innerHTML / dangerouslySetInnerHTML — use DOMPurify or textContent
- Do NOT use eval(), new Function(), setTimeout with strings
- Check popularity before importing an npm package
- Don't SKIP signature verification when decoding JWTs
- Never mutate Object.prototype
- Use crypto.getRandomValues(), not Math.random()
- Avoid using as any, as cast, ts-ignore
```

### Rust
```
Extra rules for Rust code:
- Minimize unsafe {} blocks, document every unsafe
- Don't use transmute — prefer safe alternatives
- Always null-check pointers coming from FFI
- Don't implement Send/Sync traits unsafely
- Use rand::thread_rng() + OsRng instead of rand::random()
- Add cargo audit to CI
```

### Go
```
Extra rules for Go code:
- Check errors with strconv.Atoi/ParseInt (int overflow)
- Set timeout in net/http (DefaultClient has no timeout)
- Use html/template, do NOT use text/template with user input
- Use parameterized queries in database/sql (don't concatenate %s)
- Don't do unbounded reads with io.Copy — use io.LimitReader
- Don't deserialize untrusted data with encoding/gob
- Check replace directives in go.mod
```

### Solidity
```
Extra rules for Solidity code:
- Always apply Checks-Effects-Interactions pattern
- Use ReentrancyGuard (OpenZeppelin)
- Use msg.sender, do NOT use tx.origin
- Do NOT use block.timestamp/blockhash as random source
- Use Chainlink VRF (for real randomness)
- Don't make external calls inside for loops (gas limit → revert)
- Use OpenZeppelin's ready-made contracts (don't write your own)
- Check overflow/underflow on all numeric operations
```

---

## 🧪 Security Testing Prompt

```
Check this code for vulnerabilities:
1. Is SQL Injection possible?
2. Is XSS possible?
3. Is Command Injection possible?
4. Is Path Traversal possible?
5. Is Authentication bypass possible?
6. Is there IDOR?
7. Is there rate limiting?
8. Is input validation sufficient?
9. Are error messages leaking information?
10. Are dependencies up to date?

For each "yes": how to exploit, how to fix?
```

---

## 🔄 Code Review Prompt

```
Review this code with a security focus:
- Mark all input points
- Mark all output points
- Mark all external calls (API, DB, filesystem, network)
- Verify all authentication/authorization logic
- Verify all crypto/encoding operations
- For each line: "How could an attacker abuse this line?"
- Specify missing test scenarios (edge cases)
```

---

## 🚨 When Should You Not Trust AI?

1. **Cryptography** — Never use AI's own encryption solution
2. **Authentication** — Manually verify the login system written by AI
3. **Money/Blockchain** — AI code must not be deployed without being audited
4. **Medical/Legal Applications** — AI code must be reviewed by a human
5. **System Administration** — Don't run code that gives root privileges to AI without checks

---

> Last updated: July 2026
