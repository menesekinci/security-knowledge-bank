# 🟡 Ruby Symbol DoS (Memory Exhaustion)

> **Category:** Denial of Service / Resource Exhaustion  
> **Language:** Ruby (MRI)  
> **Severity:** Medium to High  
> **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🟡 Medium–🟠 High |
| **Primary CWE** | CWE-400, CWE-770 |
| **Notes** | Historical MRI issue; still relevant when converting unbounded user input to symbols or interned strings |

## Vulnerability Explanation

In Ruby, **`Symbol`** objects were historically **never garbage-collected** (MRI before 2.2). Creating unbounded unique symbols (`user_input.to_sym`, `"#{param}".intern`) let attackers exhaust memory and crash the process.

Since **Ruby 2.2+**, most symbols created at runtime **can be GC’d**, which greatly reduces the classic “Symbol DoS.” Residual risks remain:

1. **Pins / static symbols** still accumulate in long-lived processes when code constantly interns unique values into tables that retain them.
2. **Hash keys as symbols** from `params` in old patterns (`params.symbolize_keys` on huge JSON).
3. **Metaprogramming** — `define_method(user.to_sym)`, `send(user_input)`, constantize-like paths.
4. **Gems / C extensions** that intern strings into immortal tables.
5. **YAML / JSON parsers** configured to produce symbols for every key (`symbolize_names: true`) on attacker-controlled documents with millions of unique keys.
6. **General interned string tables** and large unique allocations → still a memory DoS even if GC exists (allocation storms).

Related Rails history: parsing request data into symbols/objects enabled both DoS and RCE (YAML/XML eras).

## How AI / Vibe Coding Generates This

```
Prompt: "Convert JSON keys to symbols for nicer Ruby style"
AI: JSON.parse(body, symbolize_names: true) on untrusted API input

Prompt: "Dynamic method dispatch"
AI: send(params[:action].to_sym) or user_field.to_sym used as hash keys without allow-list
```

“Idiomatic Ruby” style guides pushed `symbolize_keys` everywhere; AI still does this on untrusted data.

## Vulnerable Code

```ruby
# 💀 Untrusted input → symbols
def track_event(name)
  stats[name.to_sym] += 1 # unique names forever / allocation storm
end

# 💀 Massive JSON with unique keys
data = JSON.parse(request.body.read, symbolize_names: true)

# 💀 Rails strong params bypassed with deep symbolize
params.to_unsafe_h.deep_symbolize_keys

# 💀 Dynamic send
send(params[:method].to_sym, params[:arg]) # also RCE/gadget risk
```

## Secure Fix

```ruby
# ✅ Keep untrusted data as Strings
def track_event(name)
  raise ArgumentError if name.bytesize > 64 || name !~ /\A[a-z0-9_.-]+\z/
  stats[name] += 1 # string keys
end

# ✅ Parse JSON without symbolize_names
data = JSON.parse(request.body.read) # keys are Strings
# If symbols desired, allow-list:
ALLOWED = %w[id name email].freeze
filtered = data.slice(*ALLOWED).transform_keys(&:to_sym)

# ✅ Never send/public_send user strings without allow-list
ALLOWED_ACTIONS = %w[create update].freeze
action = params[:method].to_s
raise "denied" unless ALLOWED_ACTIONS.include?(action)
public_send(action)

# ✅ Cap JSON size at middleware (bytes) and key counts
```

On modern Ruby, also still **limit payload size**, **depth**, and **unique key counts** for JSON/YAML.

## Prevention Checklist

- [ ] Do not `to_sym` / `intern` untrusted strings
- [ ] Avoid `symbolize_names` / `deep_symbolize_keys` on user JSON
- [ ] Allow-list dynamic `send` / `constantize` / `define_method` names
- [ ] Enforce max body size and max keys/depth on parsers
- [ ] Prefer string keys for external data
- [ ] Upgrade MRI; don’t assume “GC symbols fixed everything” without size limits
- [ ] Review background jobs processing uploaded JSON/YAML
- [ ] Memory monitoring / RSS alerts on app workers

## Real CVEs / Case References

| CVE / Issue | Summary | Link |
|-------------|---------|------|
| **CVE-2013-0156** | Rails XML→YAML/object parsing — untrusted structures (including symbol/object tricks) led to RCE; emblematic of unsafe conversion of request data into rich Ruby objects | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |
| **CVE-2013-0333** | JSON converted via YAML path → RCE | https://nvd.nist.gov/vuln/detail/CVE-2013-0333 |
| **CVE-2020-8165** | Rails untrusted Marshal deserialization — object graphs from untrusted blobs | https://nvd.nist.gov/vuln/detail/CVE-2020-8165 |
| **Historical Symbol GC** | Ruby 2.2 release notes: symbols GC’d — acknowledges pre-2.2 immortal symbol DoS class | https://www.ruby-lang.org/en/news/2014/12/25/ruby-2-2-0-released/ |

Symbol DoS is often documented as a **language footgun / historical issue** rather than a single modern CVE; still train reviewers to flag `to_sym` on params.

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| `params[:x].to_sym` | Unbounded interning / bad dynamic dispatch |
| `JSON.parse(..., symbolize_names: true)` on public API | Key flood memory |
| `deep_symbolize_keys` on `to_unsafe_h` | Mass assignment + memory |
| `send(params[:cmd])` | RCE + DoS |
| “Symbols are faster so always symbolize” without trust boundary | Classic false economy |
| No rack body size limit | Cheap memory kill |

**Prompt:**  
*“Never to_sym untrusted input. Parse JSON with string keys. Allow-list any dynamic method names. Cap request body size.”*

---

**Severity: 🟡 Medium–🟠 High** — worker OOM / process crash.  
**CWE: CWE-400 / CWE-770**
