---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 10
total_chunks: 10
heading: "Prevention Checklist"
---

## Prevention Checklist

1. **Always disable DOCTYPE declarations** — `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
2. **If DTDs are required** — Disable external entities: `external-general-entities=false`, `external-parameter-entities=false`.
3. **Disable XInclude** — `setXIncludeAware(false)`.
4. **Use `disableExternalEntityProcessing` for JAXB** — Set this property on `Unmarshaller`.
5. **Prefer JSON over XML** — If you don't need XML features, JSON doesn't have entity injection.
6. **Use a secure XML parser wrapper** — Libraries like `OWASP XML Security` provide pre-configured safe parsers.
7. **Apply the principle of least privilege** — Even if XXE reads files, file permissions still apply.
8. **Validate XML against a schema** — Prevents unexpected DOCTYPE declarations.
9. **Set entity expansion limits** — Java 8+ `FEATURE_SECURE_PROCESSING` limits entity expansion.
10. **Test with XXE payloads** — Include `file:///etc/passwd` tests in your security test suite.