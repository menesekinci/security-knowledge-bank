---
source: "common/secure-code-review.md"
title: "🔍 Secure Code Review Checklist"
heading: "4. Language-Specific Red Flags"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [ai-generated, automated, common-vuln, flags, language-specific, review, reviewing, security]
chunk: 5/8
---

## 4. Language-Specific Red Flags

### Python
| Red Flag | Risk | Fix |
|----------|------|-----|
| `eval()`, `exec()`, `compile(user_input)` | RCE, code injection | Use `ast.literal_eval()` or dedicated parser |
| `pickle.loads(user_data)` | Deserialization RCE | Use JSON or `safetensors` |
| `os.system(f"cmd {input}")` | Command injection | Use `subprocess.run()` with args list |
| `assert` for auth checks | Removed in optimized mode | Use proper auth middleware |
| `request.get_json()` without schema validation | Mass assignment | Use Pydantic/marshmallow schemas |

### JavaScript / TypeScript
| Red Flag | Risk | Fix |
|----------|------|-----|
| `eval(user_input)` | RCE, XSS | Never use eval |
| `innerHTML = user_input` | XSS | Use `textContent` or DOMPurify |
| `as any` / `any` type | Runtime type confusion | Use `unknown` + type guard |
| `// @ts-ignore` | Bypasses all type checks | Fix the type issue instead |
| `JSON.parse(user_input)` without validation | Prototype pollution | Use `JSON.parse` + schema validation (Zod) |

### Go
| Red Flag | Risk | Fix |
|----------|------|-----|
| `sql.DB.Query(fmt.Sprintf(...))` | SQL injection | Use parameterized queries |
| `http.Get(user_url)` | SSRF | Validate + restrict URL scheme |
| `ioutil.ReadAll(r.Body)` without limit | OOM | Use `http.MaxBytesReader` |
| `json.Unmarshal(data, &v)` without schema check | Type confusion | Validate after unmarshal |
| `crypto/md5` / `crypto/sha1` | Weak hash | Use `crypto/sha256` or `crypto/sha3` |

### Rust
| Red Flag | Risk | Fix |
|----------|------|-----|
| `unsafe` block without safety comment | Memory safety bypass | Document why and invariants |
| `unwrap()` on user input | Panic / DoS | Handle `Result` properly |
| `std::process::Command` with shell | Command injection | Use args list, not shell |
| `transmute()` without validation | Type confusion | Use safe conversions |
| `std::mem::zeroed()` | Undefined behavior | Use proper initialization |

### Ruby on Rails
| Red Flag | Risk | Fix |
|----------|------|-----|
| `params.permit!` | Mass assignment | Permit only expected fields |
| `where("name = '#{input}'")` | SQL injection | Use `where(name: input)` |
| `render inline: params[:template]` | RCE | Never render user input as inline |
| `skip_before_action :verify_authenticity_token` | CSRF | Verify token for state-changing requests |
| `File.open(user_filename)` | Path traversal | Validate + restrict to upload dir |

### Java / Kotlin
| Red Flag | Risk | Fix |
|----------|------|-----|
| `ObjectInputStream.readObject()` | Deserialization RCE | Use `ObjectInputFilter` or JSON |
| `Runtime.exec(input)` | Command injection | Use `ProcessBuilder` with args array |
| `@RequestMapping` without auth annotation | Missing authorization | Use `@PreAuthorize` or security config |
| `SpEL: #{user_input}` | Expression injection | Validate against allowlist |
| `String sql = "SELECT * FROM users WHERE id = " + id` | SQL injection | Use `PreparedStatement` |

### Solidity
| Red Flag | Risk | Fix |
|----------|------|-----|
| `tx.origin` for auth | Phishing attack | Use `msg.sender` |
| `call.value()` before state update | Reentrancy | Checks-Effects-Interactions pattern |
| `block.timestamp` for randomness | Manipulation | Use Chainlink VRF |
| `require()` without error message | Users can't diagnose | Add error string |
| Unbounded `for` loop | Gas DoS | Use pull-over-push pattern |

---