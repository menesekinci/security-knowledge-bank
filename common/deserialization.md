# Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks

**CWE:** CWE-502 (Deserialization of Untrusted Data)
**OWASP Top 10:2021:** A08 — Software and Data Integrity Failures
**CWE Top 25 2024:** #11 (Code Injection — up 12 spots from #23)

---

## What Is Insecure Deserialization?

Deserialization is the process of converting **binary or structured data back into objects** in memory. When an application deserializes data from an untrusted source **without validation**, attackers can craft malicious payloads that cause:

- **Remote Code Execution (RCE)** — The attacker runs arbitrary code on the server
- **Denial of Service (DoS)** — Deserializing a crafted payload crashes the application
- **Object injection** — Attackers manipulate object properties to bypass authentication, escalate privileges, or access unauthorized data

**The root cause:** Many serialization formats (Pickle, Java serialization, YAML with anchors) can construct **arbitrary objects** — not just data. This means the attacker can instantiate classes that execute code during construction or finalization.

## Why Vibe Coding Makes This Worse

AI models frequently reach for serialization to "save state," "cache data," or "communicate between services" without considering security implications:

- **Pickle for ML model storage:** AI suggests `pickle.load()` for ML models without warning about untrusted sources
- **YAML for config files:** AI uses `yaml.load()` (which supports arbitrary Python objects) instead of `yaml.safe_load()`
- **eval() as deserialization:** AI generates code that uses `eval()` or `ast.literal_eval()` on user input
- **JSON parse with revive:** AI may use `JSON.parse()` with a reviver function that executes code
- **PHP unserialize():** AI generates PHP code using `unserialize()` which can trigger arbitrary object instantiation

---

## Python Pickle Deserialization

Pickle is **inherently unsafe** — it was designed to serialize Python objects, including functions and classes.

### Vulnerable Code

```python
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/load_data')
def load_data():
    # 🔴 VULNERABLE: loading pickle from user input
    data = request.args.get('data')
    obj = pickle.loads(bytes.fromhex(data))  # Arbitrary code execution!
    return str(obj)

# Even worse: loading from file upload
@app.route('/upload_model')
def upload_model():
    model_file = request.files['model']
    model = pickle.load(model_file)  # 🔴 VULNERABLE
    return 'Model loaded'
```

### Malicious Payload Example

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        # This executes when deserialized
        return (os.system, ('rm -rf /',))

# Attacker creates payload
payload = pickle.dumps(Exploit())
# Send payload.hex() to the vulnerable endpoint
```

### Fixed Code

```python
# ✅ SAFE: avoid pickle entirely for untrusted data
# Use JSON or other data-only serialization
import json

@app.route('/load_data')
def load_data():
    data = request.args.get('data')
    # JSON is safe — can only represent data, not objects
    obj = json.loads(data)
    return str(obj)

# ✅ If you MUST use pickle, verify integrity with HMAC
import hmac
import pickle

SECRET_KEY = os.environ.get('PICKLE_SECRET')

def secure_pickle_dumps(obj):
    data = pickle.dumps(obj)
    sig = hmac.new(SECRET_KEY.encode(), data, 'sha256').hexdigest()
    return sig + ':' + data.hex()

def secure_pickle_loads(signed_payload):
    sig, data = signed_payload.split(':', 1)
    expected = hmac.new(SECRET_KEY.encode(), bytes.fromhex(data), 'sha256').hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError('Tampered payload')
    return pickle.loads(bytes.fromhex(data))
```

---

## Java Deserialization

Java serialization is one of the **most exploited deserialization vectors** in history. Applications deserializing `ObjectInputStream` from untrusted sources can be exploited using "gadget chains" (popularized by ysoserial).

### Vulnerable Code

```java
import java.io.*;

// 🔴 VULNERABLE: direct deserialization from user input
public void deserializeUserData(byte[] userData) throws Exception {
    ByteArrayInputStream bis = new ByteArrayInputStream(userData);
    ObjectInputStream ois = new ObjectInputStream(bis);
    Object obj = ois.readObject();  // Can execute arbitrary code!
    ois.close();
}

// Used like: deserializeUserData(request.getParameter("data").getBytes());
```

### Fixed Code

```java
// ✅ SAFE: Validate before deserializing
public class SafeDeserializer {
    // Allowlist of safe classes
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "java.lang.String",
        "java.util.ArrayList",
        "java.util.HashMap",
        "com.myapp.UserProfile"
    );

    public static Object safeDeserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        // ✅ Use a filtered ObjectInputStream
        FilteredObjectInputStream ois = new FilteredObjectInputStream(bis);
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

    // Custom ObjectInputStream with class filtering
    static class FilteredObjectInputStream extends ObjectInputStream {
        public FilteredObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException {
            if (!ALLOWED_CLASSES.contains(desc.getName())) {
                throw new InvalidClassException(
                    "Blocked class: " + desc.getName()
                );
            }
            return super.resolveClass(desc);
        }
    }
}
```

**Better approach:** Use a safe serialization format.

```java
// ✅ SAFEST: Use JSON instead of Java serialization
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
// Disable default typing (which enables polymorphic deserialization)
mapper.disableDefaultTyping();

// Serialize
String json = mapper.writeValueAsString(myObject);

// Deserialize
MyObject obj = mapper.readValue(json, MyObject.class);
```

---

## YAML Deserialization

YAML's anchor/alias features and type auto-detection can execute arbitrary code.

### Vulnerable Code

**Python**
```python
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/config')
def load_config():
    config_str = request.args.get('yaml')
    # 🔴 VULNERABLE: yaml.load() with default Loader
    config = yaml.load(config_str, Loader=yaml.Loader)
    return str(config)

# Malicious payload:
# !!python/object/apply:os.system ["rm -rf /"]
```

**Ruby**
```ruby
require 'yaml'
# 🔴 VULNERABLE
config = YAML.load(params[:config])
```

### Fixed Code

```python
# ✅ SAFE: use safe_load (only Python dicts, lists, primitives)
@app.route('/config')
def load_config():
    config_str = request.args.get('yaml')
    config = yaml.safe_load(config_str)  # No arbitrary object creation
    return str(config)

# ✅ OR disable constructors
yaml.add_constructor('tag:yaml.org,2002:python/object', None)
yaml.add_constructor('tag:yaml.org,2002:python/object/apply', None)
```

```ruby
# ✅ SAFE: Use permitted_classes
config = YAML.safe_load(params[:config])
# Or explicitly allow only certain classes:
config = YAML.load(params[:config], permitted_classes: [Symbol])
```

---

## JSON-Based Deserialization Attacks

While JSON itself is safe, **JSON parsing with additional features** can be dangerous.

### Vulnerable Patterns

```javascript
// 🔴 VULNERABLE: eval-based "JSON parsing"
const data = eval('(' + userInput + ')');  // Evaluates arbitrary JS!

// 🔴 VULNERABLE: reviver function that executes code
const data = JSON.parse(userInput, (key, value) => {
    if (typeof value === 'string' && value.startsWith('__proto__')) {
        // Dangerous — but still, JSON.parse is safe by default
    }
    return value;
});

// 🔴 VULNERABLE: Node.js circular JSON that causes DoS
function serialize(obj) {
    return JSON.parse(JSON.stringify(obj)); // Safe for data
}
```

### Prototype Pollution via JSON

```javascript
// Attacker sends: {"__proto__": {"admin": true}}
const config = JSON.parse(userInput);
// If the application merges this with another object:
Object.assign(app.config, config);
// app.config now has admin:true from __proto__ pollution
```

**✅ Fixed:**
```javascript
// Use Object.create(null) for configs
const config = Object.assign(Object.create(null), JSON.parse(userInput));

// Or use safe merge
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor') continue;
        target[key] = source[key];
    }
    return target;
}
```

---

## Prevention Checklist for AI Prompts

```
✅ DESERIALIZATION REQUIREMENTS FOR THIS CODE:
- NEVER use pickle.load() on untrusted data — not even with verification (signing is defense-in-depth, not a solution)
- Use safe_load() for YAML (Python), safe_load (Ruby), or disable custom constructors
- Avoid Java ObjectInputStream — use JSON, Protocol Buffers, or FlatBuffers instead
- If Java deserialization is unavoidable, implement class allowlisting
- Never use eval() or similar for "parsing" user-supplied data
- Apply input validation BEFORE deserialization when possible
- Use HMAC signing if serialized data must traverse untrusted channels
- Prefer JSON.parse() / json.loads() for data-only formats
- Watch for prototype pollution via __proto__ during object merge/clone
- Keep serialization libraries up to date (gadget chains are discovered regularly)
```

### Serialization Safety Table

| Format | Safe? | Notes |
|---|---|---|
| JSON (standard) | ✅ Safe | Data only — no objects/functions |
| XML (parsed safely) | ✅ Safe | Avoid XSLT, DTD external entities |
| YAML (safe_load) | ✅ Safe | Only basic types |
| Pickle (Python) | ❌ NEVER | Arbitrary code execution by design |
| Java serialization | ❌ NEVER | Gadget chains enable RCE |
| PHP unserialize() | ❌ NEVER | Object injection + RCE |
| YAML (default load) | ❌ NEVER | Allows arbitrary objects |
| MessagePack | ⚠️ Conditional | Safe for data; unsafe if used with class factories |
| Protocol Buffers | ✅ Safe | Strict schema, data only |
| Avro / Thrift | ✅ Safe | Schema-based, no code execution |

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Apache Struts2 Jakarta Multipart OGNL injection | CVE-2017-5638 (Equifax breach) | RCE via crafted `Content-Type` header — OGNL injection, not object deserialization |
| Oracle WebLogic wls9-async / wls-wsat deserialization | CVE-2019-2725 | Unauthenticated RCE via `XMLDecoder` in the async component (not the T3 protocol) |
| Jackson-databind polymorphic deserialization | CVE-2019-12384 | RCE via polymorphic typing |
| Jenkins XStream API deserialization | CVE-2016-0792 | RCE via crafted serialized XML to API endpoints (XStream, not the CLI) |
| Apache Struts2 REST plugin XStream deserialization | CVE-2017-9805 | Unauthenticated RCE via XML payload (no type filtering) |
| PyYAML deserialization | CVE-2020-14343 | RCE via default YAML loader |
| Drupal REST deserialization | CVE-2019-6340 | RCE — SA-CORE-2019-003 |

---

## References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [ysoserial — Java deserialization exploit tool](https://github.com/frohoff/ysoserial)
- [Pickle documentation warning](https://docs.python.org/3/library/pickle.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PortSwigger: Insecure Deserialization](https://portswigger.net/web-security/deserialization)
