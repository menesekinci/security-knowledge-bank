---
source: "languages/kotlin/jetpack-security.md"
title: "🎯 Jetpack Compose Security Guide"
heading: "6. Secure Compose Hardening Checklist"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [compositionlocal, effects, implicit, intent, kotlin, language-vuln, misuse, navigation, remember, security]
chunk: 7/8
---

## 6. Secure Compose Hardening Checklist

- [ ] `LaunchedEffect` key does not include user-controlled data that enables IDOR
- [ ] `SideEffect` is NOT used for security-critical operations (use `LaunchedEffect`)
- [ ] `DisposableEffect` always has `onDispose` for cleanup of auth/biometric sessions
- [ ] `rememberSaveable` does NOT store sensitive data (tokens, passwords, PII)
- [ ] `remember` cleared of sensitive data after use
- [ ] Navigation deep links validate authentication BEFORE navigation
- [ ] `navArgument` has proper type validation and defaultValue
- [ ] `CompositionLocal` exposes minimal read-only interfaces, not full services
- [ ] `CompositionLocal` scope is as narrow as possible
- [ ] Implicit intents validate calling package and URI scheme
- [ ] `@android:exported="false"` is not relied upon for Compose navigation security
- [ ] Deep link workaround applied for Navigation < 2.8.1

---