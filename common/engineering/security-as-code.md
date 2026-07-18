# 🔐 Security as Code

> **Category:** Common / Engineering
> **Last Updated:** July 2026
> **Description:** Treating security policies as version-controlled, testable, automated code. Covers Policy as Code (OPA/Rego, Cedar), Compliance as Code (InSpec, cnspec), IaC security scanning, automated remediation, and pipeline security.

---

## 1. What Is Security as Code

Security as Code (SaC) is the practice of expressing security policies, compliance requirements, and infrastructure security controls as machine-readable, version-controlled, and automatically enforced code — the same discipline developers apply to application code.

### The Core Shift

| Traditional Security                 | Security as Code                         |
|--------------------------------------|------------------------------------------|
| Manual compliance checklists         | Automated, gated policy enforcement      |
| PDF policy documents                 | Version-controlled Rego/Cedar policies   |
| Point-in-time audits                 | Continuous, every-deploy compliance      |
| Human-driven reviews                 | CI/CD-integrated policy evaluation       |
| Detective controls only              | Preventive + Detective guardrails        |

### Three Pillars of Security as Code

1. **Policy as Code** — Encode what is allowed or denied (OPA/Rego, Cedar, Sentinel)
2. **Compliance as Code** — Codify regulatory and internal compliance controls (InSpec, cnspec, CloudQuery)
3. **Guardrails as Code** — Define preventive and detective boundaries (AWS SCPs, Azure Policy, Kubernetes Admission Controllers)

### Preventive vs. Detective Controls

```
┌─────────────────────────────────────────────────────────────┐
│                   SECURITY CONTROLS                           │
├─────────────────────────┬───────────────────────────────────┤
│   PREVENTIVE            │   DETECTIVE                        │
│                         │                                   │
│  • Blocks before        │  • Alerts after                   │
│    the fact             │    the fact                        │
│  • Rejects violating    │  • Reports violations             │
│    resources/deploys    │    for triage                      │
│  • Examples:            │  • Examples:                       │
│    – OPA/Gatekeeper     │    – Security Hub                 │
│    – SCPs               │    – GuardDuty                    │
│    – Terraform checks   │    – CloudTrail/Alerts            │
│    – Pre-commit hooks   │    – SIEM queries                 │
│    – Admission Webhooks │    – Drift detection              │
└─────────────────────────┴───────────────────────────────────┘
```

---

## 2. Policy as Code with OPA

[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) is the most widely adopted policy-as-code engine. It decouples policy decision-making from policy enforcement.

### Rego — The Policy Language

OPA policies are written in Rego, a declarative language designed for expressing rules over hierarchical data.

```rego
# Example: Require all containers to have resource limits
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  not container.resources.limits
  msg := sprintf("Container %v must specify resource limits", [container.name])
}
```

**Key concepts:**
- **Rules** — `allow`, `deny`, `warn` are common rule names
- **Incremental rules** — Rules can be partial (`deny[x]` where x is generated)
- **Negation** — `not` checks absence
- **Iteration** — `some` keyword for explicit iteration; `[_]` for implicit

### OPA Integration Points

| Integration | Method | Use Case |
|-------------|--------|----------|
| **Kubernetes Admission** | [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) | Validate/mutate K8s resources at admission time |
| **Kubernetes Native** | [Kyverno](https://kyverno.io/) | Alternative policy engine (uses YAML, not Rego) |
| **CI/CD Pipelines** | [Conftest](https://www.conftest.dev/) | Test policy against structured config files |
| **Terraform** | OPA + TF plan JSON | Validate infrastructure before apply |
| **HTTP APIs** | OPA as sidecar/authz | Authorize API requests with fine-grained policies |
| **Envoy/Istio** | OPA as external authorizer | Enforce mesh-level access policies |

### Testing Rego Policies

OPA includes a built-in test framework. Write test files with `_test.rego` suffix.

```rego
# policy_test.rego
package kubernetes.admission

test_container_limits_denied {
  result := deny with input as {
    "request": {
      "kind": {"kind": "Pod"},
      "object": {
        "spec": {
          "containers": [{"name": "web"}]
        }
      }
    }
  }
  count(result) == 1
}

test_container_limits_allowed {
  result := deny with input as {
    "request": {
      "kind": {"kind": "Pod"},
      "object": {
        "spec": {
          "containers": [{
            "name": "web",
            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}}
          }]
        }
      }
    }
  }
  count(result) == 0
}
```

Run tests with:

```bash
opa test ./policies/
# Output: PASS: 2/2
```

### CI/CD Integration — Conftest

[Conftest](https://www.conftest.dev/) applies OPA policies to structured configuration files (YAML, JSON, TOML, HCL, Dockerfile, etc.).

```bash
# Check all Kubernetes manifests against policies
conftest test --policy policies/kubernetes/ deploy/*.yaml

# Check Terraform plan
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test --policy policies/terraform/ tfplan.json
```

### Best Practices for Policy as Code

- **Version everything** — Policies, tests, and test data in the same repo
- **Policy as PR** — Policy changes go through the same review process as code changes
- **Test coverage** — Every deny/warn rule should have passing and failing test cases
- **Policy layering** — Start permissive and tighten over time; avoid all-or-nothing policies
- **CI enforcement** — Run `opa test` and `conftest` in CI before merging

---

## 3. Infrastructure as Code Security

IaC security scanning tools find misconfigurations, compliance violations, and security risks before infrastructure is provisioned.

### IaC Scanning Tools

| Tool | Language Support | Key Strength |
|------|-----------------|--------------|
| [Checkov](https://www.checkov.io/) | Terraform, CloudFormation, K8s, ARM, Serverless | 1000+ built-in policies |
| [Tfsec](https://tfsec.dev/) | Terraform | Focused depth for Terraform |
| [Trivy](https://github.com/aquasecurity/trivy) | Terraform, K8s, CloudFormation, Docker | Multi-tool (vulns + misconfigs) |
| [KICS](https://kics.io/) | Terraform, K8s, CloudFormation, Docker, Ansible | Broad IaC format support |

### Terraform Plan Validation

The most powerful IaC security check happens *before* apply — validating the Terraform plan.

```bash
# Merge policy + IaC scanning into a single CI step
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# 1. OPA policy checks
conftest test --policy policies/terraform/ tfplan.json

# 2. Checkov on the plan
checkov -f tfplan.json --framework terraform_plan

# 3. Trivy misconfiguration scan
trivy config --severity CRITICAL,HIGH .
```

**What to check in Terraform plans:**
- S3 buckets with public ACLs
- Security groups with 0.0.0.0/0 ingress (except HTTP/HTTPS in a WAF)
- RDS/ElastiCache publicly accessible
- Encryption at rest disabled
- Root account keys not in use

### Kubernetes Manifest Validation

```bash
# Pre-admission validation in CI
kubeval deploy/*.yaml                         # Schema validation
kube-score score deploy/*.yaml                  # Score-based best practices
checkov -f deploy/deployment.yaml --framework kubernetes
conftest test --policy policies/kubernetes/ deploy/

# For production clusters: admission controllers
# Gatekeeper: OPA-based admission webhook
# Kyverno: YAML-native admission engine
```

### CI/CD Integration

```yaml
# GitHub Actions — IaC Security Gate
jobs:
  iac-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      - name: Terraform plan
        run: |
          terraform init
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > tfplan.json

      - name: Checkov scan
        uses: bridgecrewio/checkov-action@v12
        with:
          file: tfplan.json
          framework: terraform_plan

      - name: Trivy config scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: .
          severity: CRITICAL,HIGH

      - name: Conftest policy check
        run: conftest test --policy policies/terraform/ tfplan.json
```

---

## 4. Automated Remediation

Detection without remediation is just reporting. Automated remediation closes the loop.

### Auto-Fix Patterns

| Tool | Mechanism | Best For |
|------|-----------|----------|
| [Dependabot](https://github.com/dependabot) | PR creation for vulnerable deps | npm, pip, Maven, Go, etc. |
| [Renovate](https://docs.renovatebot.com/) | Configurable auto-merge, scheduling | All major ecosystems |
| [Snyk Fix PR](https://docs.snyk.io/snyk-open-source/open-source-basics/fix-pull-requests-for-new-vulnerabilities) | Automated PR with upgraded deps | Enterprise dependency management |
| [Trivy + custom script](https://github.com/aquasecurity/trivy) | Auto-patch via CI pipeline | Air-gapped or custom registries |

### Self-Healing Infrastructure (Kubernetes Operator Pattern)

Kubernetes operators continuously reconcile desired state. Security operators extend this pattern:

```yaml
# Example: Security operator reconciles TLS certificates
apiVersion: security.operator/v1
kind: CertificateCheck
spec:
  checkInterval: 24h
  namespaceSelector:
    matchLabels:
      security-tier: critical
  autoRenew: true
  actionOnExpiry: "rotate"
```

**Common security operator patterns:**
- **Certificate operator** — Auto-detect and renew expiring TLS certs
- **Secret rotation operator** — Rotate database credentials, API keys on a schedule
- **Policy enforcement operator** — Continuously audit and remediate K8s resources
- **Vulnerability scanner operator** — Scan images, cordon nodes with critical vulns
- **Drift detection operator** — Detect and revert unauthorized config changes

### Drift Detection

Drift occurs when deployed infrastructure differs from its IaC definition.

| Service | Drift Detection | Remediation |
|---------|----------------|-------------|
| **AWS Config** | Managed rules + conformance packs | Auto-remediate with SSM Automation |
| **Terraform Cloud** | Plan drift detection | Auto-apply on drift |
| **Google Cloud Asset Inventory** | Policy-based drift alerts | Cloud Functions remediation |
| **Azure Policy** | Audit + Deny effects | Auto-remediate with remediation tasks |
| **Kubernetes** | Admission controllers | Auto-revert with OPA/Gatekeeper |

```bash
# AWS Config: detect and alert on unrestricted SSH access
aws configservice put-config-rule \
  --config-rule file://restricted-ssh.json

# Terraform Cloud: detect drift
tfe workspace show -name prod
# → Drift detected: 3 resources changed outside of Terraform
```

---

## 5. Pipeline Security

The CI/CD pipeline is the most privileged system in the organization — it has access to source code, secrets, cloud credentials, and production environments. Securing it is Security as Code's final critical layer.

### CI/CD Pipeline as Attack Surface

```
┌──────────────────────────────────────────────────────────────────┐
│                    PIPELINE ATTACK VECTORS                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│ 1. POISONED PIPELINE EXECUTION                                   │
│    └─ Attacker controls pipeline definition via malicious PR      │
│                                                                   │
│ 2. INJECTED BUILD TOOLS                                          │
│    └─ Compromised build image or CI runner                        │
│                                                                   │
│ 3. DEPENDENCY CONFUSION                                          │
│    └─ Malicious package with same name as internal dep            │
│                                                                   │
│ 4. CREDENTIAL THEFT                                              │
│    └─ Exposed CI secrets (env vars, tokens)                       │
│                                                                   │
│ 5. ARTIFACT TAMPERING                                            │
│    └─ Modified build output before deployment                     │
│                                                                   │
│ 6. RECURSIVE BUILD / CI CD FROM FORK                             │
│    └─ PR from fork triggers build with org secrets                │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Signed Artifacts and SLSA Levels

[SLSA (Supply chain Levels for Software Artifacts)](https://slsa.dev/) provides a security framework for artifact integrity.

| SLSA Level | Requirements | Practical Implementation |
|-----------|--------------|--------------------------|
| **Level 1** | Build process documented, provenance generated | Provenance attestation (e.g., GitHub attestations) |
| **Level 2** | Signed provenance, hosted build, no CI from forks | Sigstore cosign signing, GitHub Actions hosted runners |
| **Level 3** | Hermetic build, reproducible, isolated | Distroless containers, hardened CI, no network in build |
| **Level 4** | Two-person review, air-gapped build, all dependencies verified | Dedicated build service, signed SLSA provenance for every dep |

```bash
# Sign a container image with cosign (SLSA Level 2+)
cosign sign --key cosign.key ghcr.io/org/app:v1.2.3

# Verify before deploy
cosign verify --key cosign.pub ghcr.io/org/app:v1.2.3

# Generate SLSA provenance (GitHub Actions)
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2
```

### SBOM Generation

Software Bill of Materials — a machine-readable inventory of all components in a build.

**Standard formats:**
- [CycloneDX](https://cyclonedx.org/) — OWASP standard, most widely adopted
- [SPDX](https://spdx.dev/) — ISO standard, used in legal/compliance contexts

```bash
# Generate CycloneDX SBOM (npm)
cyclonedx-bom -o sbom.cdx.json

# Generate SPDX SBOM (Go)
spdx-sbom-generator -p . -o sbom.spdx

# Attach SBOM to container image
cosign attach sbom --sbom sbom.cdx.json ghcr.io/org/app:v1.2.3

# Verify SBOM is present
cosign verify-attestation --type cyclonedx ghcr.io/org/app:v1.2.3
```

### Pipeline Hardening Checklist

- [ ] CI workflows require manual approval before running on forks
- [ ] Secrets are scoped to the minimum permissions needed
- [ ] OIDC-based cloud auth (no static keys in CI)
- [ ] Build artifacts are signed (cosign, sigstore)
- [ ] Container images are scanned in CI before push
- [ ] SBOM is generated and attached to every release
- [ ] Pipeline definitions are version-controlled and reviewed
- [ ] No inline secrets in pipeline YAML files
- [ ] Build runners are ephemeral and do not persist state
- [ ] Dependency versions are pinned and verified (lockfiles, checksums)

---

## 6. Security as Code Workflow (Putting It Together)

```
┌──────────────────────────────┐
│      DEVELOPER COMMIT        │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│    PRE-COMMIT HOOKS           │
│  • gitleaks (secrets)        │
│  • trivy fs (vulns)          │
│  • checkov (IaC)             │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│     CI PIPELINE               │
│                              │
│  1. Dependency scan          │
│     (Trivy, Snyk, Renovate)  │
│                              │
│  2. IaC scanning             │
│     (Checkov, tfsec, KICS)   │
│                              │
│  3. Policy evaluation        │
│     (Conftest, OPA test)     │
│                              │
│  4. SAST/DAST on app code    │
│     (Semgrep, CodeQL)        │
│                              │
│  5. Build + sign artifact    │
│     (cosign, SBOM gen)       │
│                              │
│  6. Container scan           │
│     (Trivy image)            │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│     DEPLOYMENT GATE          │
│  • Admission webhook (K8s)   │
│  • OPA policy check          │
│  • Sign verify               │
│  • Compliance attestation    │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│     CONTINUOUS               │
│  • Drift detection           │
│  • Auto-remediation          │
│  • Policy updates via PR     │
└──────────────────────────────┘
```

---

## 7. References

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Style Guide](https://www.openpolicyagent.org/docs/latest/style-guide/)
- [Gatekeeper Library](https://github.com/open-policy-agent/gatekeeper-library)
- [Conftest Examples](https://www.conftest.dev/examples/)
- [SLSA Framework](https://slsa.dev/)
- [CNCF Security TAG](https://github.com/cncf/tag-security)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/specifications/)
- [Sigstore / Cosign](https://www.sigstore.dev/)
- [Checkov Documentation](https://www.checkov.io/)
- [Trivy Documentation](https://github.com/aquasecurity/trivy)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SSDF (Secure Software Development Framework)](https://csrc.nist.gov/Projects/ssdf)
