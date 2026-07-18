---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "LDAP Injection"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 7/11
---

## LDAP Injection

### How It Works

LDAP queries use a filter syntax (`(&(attr=value)(attr2=value2))`). Injecting `*`, `|`, `&`, `!` can bypass authentication or extract data.

### Vulnerable Code

```java
// 🔴 VULNERABLE: string concatenation in LDAP filter
String user = request.getParameter("username");
String filter = "(&(uid=" + user + ")(accountStatus=active))";
// Attack: user = "*" → matches ALL users
// Attack: user = "admin)(|(uid=*" → Bypass auth
DirContext ctx = new InitialDirContext(env);
NamingEnumeration results = ctx.search("dc=example,dc=com", filter, controls);
```

### Fixed Code

```java
// ✅ SAFE: use proper escaping
String user = request.getParameter("username");
// Escape LDAP special characters
user = user.replaceAll("\\*", "\\\\2a")
           .replaceAll("\\(", "\\\\28")
           .replaceAll("\\)", "\\\\29");
String filter = "(&(uid=" + user + ")(accountStatus=active))";
// OR better: use a framework that handles encoding
```

---