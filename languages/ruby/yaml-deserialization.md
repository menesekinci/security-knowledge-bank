# 🔴 YAML.load RCE (Ruby)

## What Is It?

Ruby's `YAML.load()` method allows **any Ruby object** to be created from an
untrusted YAML string. This means **RCE (Remote Code Execution)** with a
crafted YAML payload.

## Example

```ruby
# 💀 VULNERABLE:
require 'yaml'

def parse_config(yaml_data)
  # This can create any Ruby class inside the YAML!
  config = YAML.load(yaml_data)  # 💀
  return config
end

# Payload sent by attacker:
payload = <<~YAML
  --- !ruby/object:ERB
  result: !ruby/object:ERB
    src: "system('rm -rf /')"
    filename: "test"
    lineno: 1
    # Or:
    # src: "system('id > /tmp/owned')"
YAML

parse_config(payload)  
# 💀 system('id > /tmp/owned') executed!
```

## Secure Code

```ruby
# ✅ SAFE:
require 'yaml'

def parse_config(yaml_data)
  # YAML.safe_load only allows basic types
  config = YAML.safe_load(yaml_data)
  # Only: String, Integer, Float, Nil, True, False, Array, Hash, Symbol
  # Classes, objects, ERB won't work!
  return config
end

# You can specify permitted classes:
config = YAML.safe_load(yaml_data, permitted_classes: [Symbol, Time])
```

## Real World

- **CVE-2013-0156** (CVSS 7.5): Rails Action Pack derives object types from request parameters, allowing YAML/Symbol type conversion to instantiate arbitrary objects → object injection / RCE (fixed 2.3.15, 3.0.19, 3.1.10, 3.2.11). Affected essentially every Rails app of the era.
- **CVE-2022-32224** (CVSS 9.8): Active Record YAML-serialized columns can escalate to RCE when an attacker can write the serialized value (e.g. via SQL injection) — unsafe `YAML.load` of column data (fixed 5.2.8.1, 6.0.5.1, 6.1.6.1, 7.0.3.1).
- **GitHub (2013)**: GitHub's Rails application was compromised via the CVE-2013-0156 YAML deserialization flaw.

## Prevention Methods

| Rule | Description |
|------|-------------|
| Don't use `YAML.load()` | Always use `YAML.safe_load()` |
| Specify `permitted_classes` | Whitelist the classes you need |
| `Psych.safe_load()` | Same safe API |
| Prefer JSON | JSON deserialization is safer |

## Critical Rule for Vibe Coding
```
When parsing YAML in Ruby:
- NEVER use YAML.load()
- Use YAML.safe_load() (with permitted_classes)
- In Rails, set YAML.permitted_classes if config exists
```

---

**Severity: 🔴 Critical** — Direct RCE.
**CWE: CWE-502 (Deserialization of Untrusted Data)**
