---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "Expression Language (EL) / OGNL Injection"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 8/11
---

## Expression Language (EL) / OGNL Injection

Common in Java applications using Spring, Struts, or JSP. User input that reaches an expression evaluator can execute arbitrary code.

### Vulnerable Code

```java
// 🔴 VULNERABLE: user input evaluated as EL expression
String expression = "${" + userInput + "}";
ExpressionFactory factory = ExpressionFactory.newInstance();
ValueExpression ve = factory.createValueExpression(
    ctx, expression, Object.class
);
ve.getValue(ctx);  // Attack: userInput = "7*7" or worse: "".getClass().forName...
```

### Fixed Code

```java
// ✅ SAFE: don't evaluate user input as expressions
// Use a template engine with auto-escaping (Thymeleaf, Handlebars)
// Never pass raw user input to ExpressionFactory
// If evaluation is required, use a sandboxed evaluator
```

---