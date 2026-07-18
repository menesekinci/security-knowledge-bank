# ☕ Java Security Hardening Checklist

> Items to check in every Java project before deployment.

## ✅ General
- [ ] Has `mvn dependency-check` / `gradle dependencyCheckAnalyze` been run?
- [ ] Is OWASP Dependency-Check integrated into CI?
- [ ] Has an SBOM (CycloneDX) been generated?
- [ ] Is Log4j 2.17.0+ in use? (Log4Shell check)

## ✅ Deserialization
- [ ] Is `ObjectInputStream.readObject()` avoided with untrusted data?
- [ ] Has an `ObjectInputFilter` / `SerialFilter` been defined?
- [ ] Is the `@Serial` annotation used correctly?
- [ ] Is the serialization proxy pattern applied?

## ✅ Web (Spring Boot / Jakarta EE)
- [ ] Have Actuator endpoints been secured/disabled?
- [ ] Are debug / devtools disabled in production?
- [ ] Does the CORS whitelist contain only trusted origins?
- [ ] Has the HSTS header been added?
- [ ] Is CSRF token protection in place?
- [ ] Is the X-Content-Type-Options header present?

## ✅ Expression Languages
- [ ] Is a SpEL parser used? — Is `SimpleEvaluationContext` used?
- [ ] Do OGNL expressions come from a trusted source?
- [ ] Has a JSP EL injection check been performed?

## ✅ XML
- [ ] Is XXE protection active in XML parsers?
- [ ] Is DTD processing disabled?
- [ ] Is XSLT transformation security-controlled?

## ✅ Database
- [ ] Are all SQL statements using PreparedStatement?
- [ ] Are JPA/Hibernate native queries parameterized?
- [ ] Is the connection pool secure? (credentials encrypted)

## ✅ JWT
- [ ] Is `jwt.verify()` used? (not `decode()`)
- [ ] Is there an algorithm whitelist?
- [ ] Is JWT expiration checked?

## 🛡️ Vibe Coding Extras
- [ ] Is the Log4j version suggested by the AI up to date? (2.17.0+)
- [ ] Is the deserialization code written by the AI protected with ObjectInputFilter?
- [ ] Is the AI's SpEL/OGNL usage safe?
