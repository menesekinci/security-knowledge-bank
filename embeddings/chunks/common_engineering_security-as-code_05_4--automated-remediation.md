---
source: "common/engineering/security-as-code.md"
title: "🔐 Security as Code"
heading: "4. Automated Remediation"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [automated, common-vuln, infrastructure, pipeline, policy, remediation, security, what]
chunk: 5/8
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