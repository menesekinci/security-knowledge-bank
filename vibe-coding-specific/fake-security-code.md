# 🔴 Fake Security Code

## What Is It?

This is when the AI produces code that **looks like a security measure but is actually useless**.
This is one of the most dangerous AI code generation errors because the developer relaxes thinking
"I've added security," when in fact the code is still vulnerable.

## How Does It Manifest in Vibe Coding?

```
Prompt: "Write a secure login system, hash the passwords"
AI: "I'm using bcrypt" but...
```

The AI generally **knows the correct library** but **misremembers the API** or
**implements it incompletely**.

## Most Common Fake Security Patterns

### 1. Crypto: Don't Write Your Own Encryption
```python
# AI-written "secure" XOR encryption:
def encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
# 💀 This is not encryption, it's obfuscation. Cryptographically useless.
```
**Correct way:** Use `cryptography` or `PyNaCl`.

### 2. JWT: alg:none Attack
```python
# AI-written JWT verification:
import jwt
token = request.headers.get('Authorization').split()[1]
payload = jwt.decode(token, options={"verify_signature": False})  # 💀
```
**Correct way:** Always keep signature verification enabled.

### 3. SQL: Code Mistaken for Sanitization
```python
# AI-written "secure" SQL:
username = username.replace("'", "\\'")  # 💀 Escaping just ' is not enough!
query = f"SELECT * FROM users WHERE username = '{username}'"
```
**Correct way:** Parametrized query (`cursor.execute("SELECT ... WHERE ?", (username,))`)

### 4. XSS Protection Mistaken for HTML Escape
```javascript
// AI-written "escape" — a NO-OP:
function escapeHtml(str) {
  return str.replace(/</g, '<').replace(/>/g, '>');  // 💀 replaces "<" with "<" — does nothing!
}
// The replacement targets are the SAME characters as the search, so the output is
// identical to the input. The "<script>" payload passes through untouched.
```
```javascript
// What it was supposed to do (real HTML-entity escaping):
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')   // & FIRST, or you double-escape the entities below
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```
**Correct way:** Prefer a battle-tested library — DOMPurify (for HTML sanitization) or your framework's built-in output encoding — rather than hand-rolling escapes.

### 5. Password Storage: Wrong Hash
```python
# AI-written:
import hashlib
hashed = hashlib.sha1(password.encode()).hexdigest()  # 💀 SHA-1 + no salt!
```
**Correct way:** `bcrypt.hashpw(password, bcrypt.gensalt())`

## Why Does the AI Do This?

1. **Training data has many "write your own solution" examples** — old Stack Overflow posts
2. **Doesn't know current APIs** — can't know libraries released after its cutoff date
3. **Programmed to produce "simple and understandable" code** — security is usually complex
4. **Makes import errors** — calls the right library but confuses the function name

## Prevention

### ✅ Statements to Add to Prompts
```
"When writing security code:
1. NEVER write your own cryptography — only use well-known libraries
2. Verify every security measure against the OWASP Cheat Sheet
3. Check the documentation for every library function you use
4. Produce the 'correct solution' rather than a 'simple solution'"
```

### 🔧 Practical Measures
1. **Manually test every security code**: Try "what happens when the password is wrong?"
2. **Run SAST tools on AI code too**: Semgrep, CodeQL, SonarQube
3. **Reference the OWASP Cheat Sheet**: Compare with the solution AI produced
4. **Perform penetration testing**: Include AI code in the test scope
5. **Don't skip code review**: Avoid the mistake of thinking "AI code doesn't need review"

## 🔗 Related Vulnerabilities
- [Cryptographic Failures (Common)](../common/crypto.md)
- [Overreliance](overreliance.md)

---

**Severity: 🔴 Critical** — Code thought to be "secure" is actually a security vulnerability.
