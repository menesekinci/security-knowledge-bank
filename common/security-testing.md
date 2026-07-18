# 🔬 Security Testing Methodology

> **Category:** Common / Security Testing
> **Last Updated:** July 2026
> **Description:** Comprehensive security testing methodology covering SAST, DAST, SCA, IAST, fuzzing, and penetration testing workflows. Includes tool-per-language mapping and AI-generated code considerations.

---

## 1. Testing Types Overview

```
┌─────────────────────────────────────────────────────────┐
│                    SECURITY TESTING                      │
├────────────┬────────────┬────────────┬──────────────────┤
│    SAST    │    DAST    │    SCA     │       IAST       │
│  Static    │  Dynamic   │ Dependency │  Interactive     │
│  Analysis  │  Analysis  │  Analysis  │  Analysis        │
├────────────┼────────────┼────────────┼──────────────────┤
│ White-Box  │ Black-Box  │   Supply   │  Grey-Box        │
│            │            │   Chain    │  (Runtime+Code)  │
├────────────┼────────────┼────────────┼──────────────────┤
│ Before     │ Before     │ Build &    │  During          │
│ Compile    │ Deploy     │ Monitor    │  Testing         │
└────────────┴────────────┴────────────┴──────────────────┘
```

### SAST (Static Application Security Testing)
- **What**: Analyzes source code without executing it
- **When**: Pre-commit / CI pipeline / IDE
- **False Positives**: Moderate-High (needs triage)
- **Best for**: Finding injection flaws, crypto misuse, hardcoded secrets

### DAST (Dynamic Application Security Testing)
- **What**: Tests running application from the outside
- **When**: Staging/Pre-prod environment
- **False Positives**: Low-Moderate
- **Best for**: Runtime issues, misconfigurations, auth bypass

### SCA (Software Composition Analysis)
- **What**: Scans dependencies for known vulnerabilities
- **When**: Build time + continuous monitoring
- **False Positives**: Low (CVE-based)
- **Best for**: Supply chain security, known CVEs in libs

### IAST (Interactive Application Security Testing)
- **What**: Combines SAST + DAST — instruments the app during functional testing
- **When**: During QA / integration tests
- **False Positives**: Very Low
- **Best for**: Accurate vulnerability detection with low noise

---

## 2. Tool Per Language Matrix

| Language   | SAST                          | DAST                  | SCA                                    | IAST                   |
|------------|-------------------------------|-----------------------|----------------------------------------|------------------------|
| **Python** | Bandit, Semgrep, Ruff         | OWASP ZAP, Nuclei     | pip-audit, Safety, Trivy               | Contrast, Hdiv         |
| **JS/TS**  | ESLint w/ security plugin, CodeQL, semgrep | ZAP, Burp            | npm audit, yarn audit, Snyk, Socket    | Contrast, Seeker       |
| **Java**   | SpotBugs + FindSecBugs, Semgrep, Checkstyle | ZAP, Burp, AppScan   | OWASP Dependency-Check, Snyk, Trivy    | Contrast, Seeker       |
| **Go**     | gosec, Semgrep, Staticcheck   | ZAP, Nuclei           | govulncheck, Trivy, Snyk               | Contrast               |
| **Rust**   | Clippy, cargo-audit, Semgrep  | ZAP, custom fuzzing   | cargo-audit, cargo-deny                | Limited                |
| **Ruby**   | Brakeman, Semgrep, RuboCop    | ZAP, Nuclei           | bundler-audit, Trivy                   | Contrast               |
| **C#/.NET**| SecurityCodeScan, Roslyn, Semgrep | ZAP, Burp          | dotnet list pkg --vulnerable, Trivy    | Contrast               |
| **PHP**    | PHPStan (pro), Psalm, Semgrep | ZAP, WPScan, Nuclei   | composer audit, Trivy                  | Contrast               |
| **C/C++**  | Clang Static Analyzer, Cppcheck, CodeQL | Custom fuzzing | Snyk, Trivy (OS libs)                  | Limited                |
| **Swift**  | SwiftLint, Semgrep, CodeQL    | ZAP (API), MobSF      | SPM audit, Trivy                       | Limited                |
| **Kotlin** | detekt, Semgrep, Android Lint | MobSF, ZAP            | OWASP Dependency-Check, Trivy          | Contrast               |
| **Solidity**| Slither, Mythril, Semgrep    | Custom fuzzing (Echidna, Foundry) | —                     | —                      |

---

## 3. Fuzzing Methodology

Fuzzing finds bugs that static analysis misses — memory corruption, logic errors, edge cases.

### Language-Specific Fuzzers

| Language   | Fuzzer                              | Best For                          |
|------------|--------------------------------------|-----------------------------------|
| **C/C++**  | AFL++, libFuzzer, Honggfuzz          | Memory corruption, buffer overflow |
| **Rust**   | cargo-fuzz (libFuzzer), AFL.rs       | Unsafe code, panic safety         |
| **Go**     | go-fuzz, syzkaller                   | Protocol parsing, input handling  |
| **Python** | Atheris (libFuzzer), python-afl      | Deserialization, parsing          |
| **Java**   | Jazzer (libFuzzer), JQF              | Deserialization, expression injection |
| **Solidity**| Echidna, Foundry fuzz, Diligence Fuzzing | Smart contract invariants    |
| **JS/TS**  | Jazzer.js, fuzzilli                  | JSON parsing, crypto operations   |
| **Swift**  | libFuzzer (via Swift), SwiftFuzz     | Codable deserialization           |

### Fuzzing Workflow

```
1. IDENTIFY TARGETS
   └─ Public API endpoints, file parsers, deserialization points,
      expression evaluators, crypto routines

2. CREATE FUZZ HARNESS
   └─ Write a thin wrapper that feeds fuzzer-generated input to the target

3. CHOOSE COVERAGE GUIDANCE
   └─ Code coverage (AFL++, libFuzzer)
   └─ Sanitizer coverage (ASan, UBSan, MSan)
   └─ Grammar-based (if input format is well-defined)

4. RUN (CI or Dedicated)
   └─ Integrate into CI for continuous fuzzing (OSS-Fuzz model)
   └─ Run with sanitizers for maximum bug detection

5. TRIAGE CRASHES
   └─ Deduplicate by stack trace
   └─ Minimize test cases
   └─ Verify exploitability
```

### CI Fuzzing Integration Example (Rust)

```yaml
# .github/workflows/fuzz.yml
name: Fuzz
on: [push, pull_request]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run fuzz_target_1 -- -runs=100000
```

---

## 4. Penetration Testing Workflow

### Standard Pentest Methodology (PTES-aligned)

```
┌──────────────────────────────────────────────────────────┐
│                     PENTEST FLOW                          │
├──────────────────────────────────────────────────────────┤
│  1. Reconnaissance                                        │
│     ├─ Passive: Shodan, Censys, DNS enumeration          │
│     └─ Active: Port scanning, directory enumeration      │
│                                                           │
│  2. Threat Modeling                                       │
│     ├─ Identify attack surface                            │
│     ├─ Map data flows (STRIDE per element)                │
│     └─ Prioritize high-value targets (auth, payment, PII) │
│                                                           │
│  3. Vulnerability Analysis                                │
│     ├─ Automated: SAST + DAST + SCA results               │
│     └─ Manual: Business logic, race conditions, IDOR      │
│                                                           │
│  4. Exploitation                                          │
│     ├─ Chain low-severity issues into high-severity       │
│     ├─ Auth bypass → privilege escalation → data access   │
│     └─ Document proof-of-concept, not full weaponization  │
│                                                           │
│  5. Post-Exploitation                                     │
│     ├─ Assess lateral movement potential                  │
│     ├─ Determine data accessible from compromise point    │
│     └─ Map pivot opportunities                             │
│                                                           │
│  6. Reporting                                             │
│     ├─ Executive summary (business impact)                │
│     ├─ Technical findings (CVE, OWASP Top 10 mapping)     │
│     └─ Remediation roadmap (short-term + long-term)       │
└──────────────────────────────────────────────────────────┘
```

### AI-Generated Code Pentest Checklist

When pentesting code written by AI, add these specific checks:

- [ ] **Prompt injection traces**: Check for eval-like patterns from concatenated instructions
- [ ] **Hallucinated packages**: Verify every third-party import actually exists in the registry
- [ ] **Overly permissive patterns**: AI often writes `permit!`, `allow all`, `disable check`
- [ ] **Missing rate limiting**: AI rarely adds throttling unless explicitly prompted
- [ ] **Hardcoded test credentials**: AI may leave test keys in production code
- [ ] **Incorrect error handling**: Stack traces exposed, overly verbose error messages
- [ ] **Disabled security features**: `verify=False`, `SSL off`, `csrf_exempt`

### Example: Web App Pentest Checklist

```
[ ] SQL Injection (all inputs)
[ ] XSS (reflected, stored, DOM-based)
[ ] CSRF (missing tokens, weak validation)
[ ] Authentication bypass (session prediction, JWT alg=none)
[ ] Authorization flaws (IDOR, privilege escalation)
[ ] SSRF (internal network access)
[ ] SSTI (template engine injection)
[ ] XXE (XML external entities)
[ ] File upload (unrestricted types, path traversal)
[ ] Insecure deserialization
[ ] CORS misconfiguration
[ ] Rate limiting (brute force, enumeration)
[ ] Security headers (CSP, HSTS, X-Frame-Options)
[ ] API security (mass assignment, excessive data exposure)
```

---

## 5. CI/CD Integration

```
DEVELOP → COMMIT → BUILD → TEST → DEPLOY
            │         │       │
          SAST       SCA    DAST/IAST
          (pre-     (dep    (runtime
           commit)  scan)   tests)
```

### Minimum Security Gates for AI-Generated Code

| Gate          | Tool                          | Fails Build If           |
|---------------|-------------------------------|--------------------------|
| Secret leak   | truffleHog, Gitleaks          | Any hardcoded credential |
| SAST Critical | Semgrep, CodeQL               | Any critical finding     |
| Dep Vulns     | Trivy, npm audit              | Any CVE ≥ CVSS 7.0      |
| DAST Critical | OWASP ZAP                     | Any high-risk alert      |
| Supply Chain  | SLS provenance, Sigstore      | Unsigned artifact        |

---

## 6. Vibe Coding Security Testing Considerations

AI-generated code has unique failure modes that traditional testing may miss:

| AI Failure Pattern       | Testing Approach                          |
|--------------------------|-------------------------------------------|
| **Fake security**        | Verify AI's "secure" code actually works  |
| **Outdated APIs**        | Check against latest library docs          |
| **Context poisoning**    | Review for injected instructions in output |
| **Overreliance**         | Don't skip manual review — AI is not a SME |
| **License compliance**   | Check AI-suggested code snippets for GPL   |
| **Test blindness**       | AI generates code that passes its own tests but misses edge cases |

### Critical Rule

> **AI-generated code requires security testing — period.**
> "The AI wrote it so it must be secure" is a production disaster waiting to happen.
> Treat AI code as if written by the most junior developer with the most dangerous Stack Overflow copy-paste instincts.

---

## References

- [OWASP Testing Guide v5](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [PTES (Penetration Testing Execution Standard)](http://www.pentest-standard.org/)
- [OSS-Fuzz: Continuous Fuzzing for Open Source](https://google.github.io/oss-fuzz/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [GitHub Security Lab — CodeQL](https://securitylab.github.com/tools/codeql)
