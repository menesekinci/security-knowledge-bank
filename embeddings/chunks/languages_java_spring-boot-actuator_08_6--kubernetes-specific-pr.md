---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
heading: "6. Kubernetes-Specific Protection"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [custom, cve-2025-48927, endpoint, endpoints, full, heap, java, language-vuln, overview]
chunk: 8/13
---

## 6. Kubernetes-Specific Protection

```yaml
# ✅ SECURE — Using Kubernetes NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-actuator
spec:
  podSelector:
    matchLabels:
      app: my-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: monitoring
    ports:
    - port: 8081
      protocol: TCP
```

```yaml
# ✅ SECURE — Spring Boot with K8s readiness/liveness probes
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    health:
      probes:
        enabled: true        # ✅ /health/readiness, /health/liveness
      group:
        readiness:
          include: "db,diskSpace"
        liveness:
          include: "ping"
```

---