---
source: "common/engineering/security-as-code.md"
title: "🔐 Security as Code"
heading: "3. Infrastructure as Code Security"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [automated, common-vuln, infrastructure, pipeline, policy, remediation, security, what]
chunk: 4/8
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