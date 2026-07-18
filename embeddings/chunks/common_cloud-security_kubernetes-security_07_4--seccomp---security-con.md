---
source: "common/cloud-security/kubernetes-security.md"
title: "Kubernetes Security"
heading: "4. Seccomp & Security Contexts"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, network, overview, policies, rbac, security, table]
chunk: 7/10
---

## 4. Seccomp & Security Contexts

Seccomp filters restrict the system calls a container can make. Without it, containers can use hundreds of unnecessary syscalls.

### Secure Pod with Seccomp

```yaml
# SECURE: Pod with seccomp profile and security context
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault  # Use the runtime's default seccomp profile
  containers:
    - name: app
      image: nginx:alpine
      securityContext:
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/audit.json  # Custom profile
```

### Custom Seccomp Profile (audit.json)

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["accept4", "bind", "close", "connect", "epoll_wait",
                "fstat", "getpeername", "getsockname", "listen",
                "mmap", "openat", "read", "recvfrom", "sendto",
                "write"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

---