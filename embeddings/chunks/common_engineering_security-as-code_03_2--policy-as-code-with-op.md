---
source: "common/engineering/security-as-code.md"
title: "🔐 Security as Code"
heading: "2. Policy as Code with OPA"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [automated, common-vuln, infrastructure, pipeline, policy, remediation, security, what]
chunk: 3/8
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