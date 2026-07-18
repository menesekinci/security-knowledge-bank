---
source: "common/engineering/security-architecture-patterns.md"
title: "Security Architecture Patterns"
heading: "1. Network Segmentation"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [access, common-vuln, encryption, identity, logging, monitoring, network, security, segmentation, strategies]
chunk: 2/7
---

## 1. Network Segmentation

Network segmentation is the practice of dividing a network into smaller, isolated zones to limit lateral movement and contain breaches. In modern architectures this spans physical networks, cloud VPCs, and Kubernetes clusters.

### 1.1 VPC Design (Cloud)

Every cloud deployment should follow a least-privilege network topology:

| Component | Purpose | Security Properties |
|---|---|---|
| **Public subnets** | Load balancers, bastion hosts, NAT gateways | Direct internet ingress/egress only; no application servers |
| **Private subnets** | Application servers, databases, cache layers | No direct internet route; outbound via NAT only |
| **Isolated subnets** | Secrets stores, internal registries, CA servers | No internet route at all (air-gapped at network layer) |
| **VPN / Direct Connect** | Admin access, hybrid connectivity | Encrypted tunnel; terminated on a dedicated VPN subnet |

**Key design decisions:**

- **NAT vs. private link:** Outbound traffic from private subnets goes through a NAT gateway (shared) or NAT instance (cost-sensitive). For service-to-service across accounts, prefer VPC endpoints (AWS PrivateLink, GCP Private Service Connect) — they keep traffic off the public internet entirely.
- **VPC peering / Transit Gateway:** Cross-VPC traffic should be explicitly routed through a central inspection VPC that hosts firewalls and IDS/IPS. Never peer VPCs directly without a central hub for logging and filtering.
- **Flow logs:** Enable VPC flow logs on every subnet. Aggregate to a SIEM for anomaly detection (unexpected egress, port scans, lateral movement).

### 1.2 Micro-Segmentation (Kubernetes)

In Kubernetes, the traditional perimeter model collapses — every pod can talk to every other pod by default. Micro-segmentation re-establishes per-workload isolation.

**Network Policies (native K8s):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-frontend
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

- Default-deny ingress + egress policies should be applied to every namespace.
- Policies follow the pod identity (labels), not IPs — this is the architectural win over traditional firewall rules.
- **Gotcha:** Most CNI plugins enforce egress policies only at the node level; test egress rules thoroughly.

**Service Mesh (Istio / Linkerd):**
A service mesh provides identity-based segmentation at L7:

- **mTLS between all services:** Every sidecar proxy gets a SPIFFE-compliant identity certificate. Traffic without a valid identity is rejected.
- **Authorization policies:** Beyond network rules, you enforce "service A can only call endpoint X on service B with verb GET."
- **Observability:** The mesh exports traffic logs, metrics, and spans — invaluable for auditing who talked to whom.

**When to use what:**
- Network Policies for basic L3/L4 isolation (faster, simpler, no sidecar overhead).
- Service mesh when you need L7 authorization, mTLS automation, or observability at the service call level.
- Both together for defense-in-depth: network policies are the blast-radius floor, mesh policies are the fine-grained ceiling.

### 1.3 DMZ Patterns for Web Applications

The classic DMZ (demilitarized zone) lives on in cloud architectures:

```
Internet → WAF/CDN → Public LB → App Instances (DMZ subnet) → Private LB → Internal Services
```

**Three-tier DMZ:**
1. **Edge tier:** CloudFront/Cloudflare + WAF. Terminates TLS, blocks layer-7 attacks (SQLi, XSS) before they reach your origin.
2. **Presentation tier:** Public-facing application servers in a DMZ subnet. No direct database access — only calls to the API tier.
3. **Data tier:** Internal services, databases, caches — in a private subnet with no ingress from the internet. Only the presentation tier can reach them, and only on specific ports.

**Reverse proxy pattern:**
All external traffic lands on a reverse proxy (nginx, HAProxy, Envoy) that performs TLS termination, rate limiting, and request validation before forwarding to application servers. The proxy itself should run on hardened, minimal OS images.

---